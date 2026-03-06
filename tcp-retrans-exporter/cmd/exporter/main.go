// SPDX-License-Identifier: Apache-2.0
//
// tcp-retrans-exporter – Prometheus exporter for TCP retransmission metrics.
//
// It loads a compiled eBPF object that attaches to:
//   - tp_btf/tcp_retransmit_skb  → per-flow retransmission counter
//   - kprobe/__tcp_transmit_skb  → per-flow total-transmit counter
//
// The exporter reads the BPF LRU per-CPU hash map on each Prometheus scrape,
// aggregates per-CPU values, computes deltas and exposes Prometheus metrics
// on /metrics.

package main

import (
"bytes"
"encoding/binary"
"flag"
"fmt"
"log"
"net"
"net/http"
"os"
"os/signal"
"sort"
"sync"
"syscall"
"time"
"unsafe"

libbpf "github.com/aquasecurity/libbpfgo"
"github.com/prometheus/client_golang/prometheus"
"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ─────────────────────────── BPF struct mirrors ──────────────────────────────
//
// These Go structs MUST match the C structs in bpf/common.h byte-for-byte.
// Total sizes: FlowKey = 40 B, FlowVal = 16 B.

// FlowKey mirrors struct flow_key in bpf/common.h.
type FlowKey struct {
Family uint8
Pad    [3]uint8
Sport  uint16
Dport  uint16
Saddr  [16]uint8
Daddr  [16]uint8
}

// FlowVal mirrors struct flow_val in bpf/common.h (per-CPU counters).
type FlowVal struct {
Retrans uint64
Out     uint64
}

const (
flowKeySize = 40 // sizeof(struct flow_key)
flowValSize = 16 // sizeof(struct flow_val)
)

// ─────────────────────────── helpers ─────────────────────────────────────────

// addrPort formats an address + port as "ip:port".
func addrPort(addr [16]uint8, family uint8, port uint16) string {
var ip net.IP
if family == syscall.AF_INET {
ip = net.IP(addr[12:16])
} else {
ip = net.IP(addr[:])
}
return fmt.Sprintf("%s:%d", ip.String(), port)
}

// parseFlowKey decodes a raw 40-byte BPF key into a FlowKey.
func parseFlowKey(raw []byte) (FlowKey, error) {
if len(raw) < flowKeySize {
return FlowKey{}, fmt.Errorf("key too short: %d bytes", len(raw))
}
var k FlowKey
if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &k); err != nil {
return FlowKey{}, err
}
return k, nil
}

// aggregatePerCPU sums FlowVal values across all CPU slots.
//
// For LRU_PERCPU_HASH maps, GetValue returns a buffer of
// roundUp(valueSize, 8) * numCPU bytes, with one FlowVal per CPU slot.
// Since FlowVal is already 16 bytes (8-byte aligned), slot size == 16.
func aggregatePerCPU(raw []byte, numCPU int) FlowVal {
var agg FlowVal
// Each CPU slot is aligned to 8 bytes; FlowVal is 16 B so slotSize == 16.
slotSize := (flowValSize + 7) &^ 7
for i := 0; i < numCPU; i++ {
off := i * slotSize
if off+flowValSize > len(raw) {
break
}
var v FlowVal
_ = binary.Read(bytes.NewReader(raw[off:off+flowValSize]), binary.NativeEndian, &v)
agg.Retrans += v.Retrans
agg.Out += v.Out
}
return agg
}

// ─────────────────────────── state ───────────────────────────────────────────

// prevEntry holds previously seen counters plus the time they were last seen.
type prevEntry struct {
val      FlowVal
lastSeen time.Time
}

// flowStats holds the delta for one collection interval.
type flowStats struct {
key          FlowKey
src          string
dst          string
famStr       string
deltaRetrans uint64
deltaOut     uint64
retransRate  float64
}

// ─────────────────────────── collector ───────────────────────────────────────

// collector implements prometheus.Collector and drives the BPF map polling.
type collector struct {
mu     sync.Mutex
bpfMap *libbpf.BPFMap
numCPU int
topN   int
expiry time.Duration

// Prometheus descriptors.
descRetransTotal   *prometheus.Desc
descOutTotal       *prometheus.Desc
descRetransRate    *prometheus.Desc
descRetransByTuple *prometheus.Desc
descOutByTuple     *prometheus.Desc
descRateByTuple    *prometheus.Desc

// Previous-interval state for delta computation.
prev map[FlowKey]prevEntry
}

func newCollector(m *libbpf.BPFMap, numCPU, topN int, expiry time.Duration) *collector {
labels := []string{"src", "dst", "family"}
return &collector{
bpfMap: m,
numCPU: numCPU,
topN:   topN,
expiry: expiry,
prev:   make(map[FlowKey]prevEntry),

descRetransTotal: prometheus.NewDesc(
"tcp_retrans_segs_total",
"Cumulative TCP retransmitted segments observed since exporter start.",
nil, nil,
),
descOutTotal: prometheus.NewDesc(
"tcp_out_segs_total",
"Cumulative TCP transmitted segments observed since exporter start.",
nil, nil,
),
descRetransRate: prometheus.NewDesc(
"tcp_retrans_rate",
"Global TCP retransmission rate (delta_retrans/delta_out) in the last scrape interval.",
nil, nil,
),
descRetransByTuple: prometheus.NewDesc(
"tcp_retrans_segs_by_tuple",
"TCP retransmitted segments in the last scrape interval, per connection (TopN).",
labels, nil,
),
descOutByTuple: prometheus.NewDesc(
"tcp_out_segs_by_tuple",
"TCP transmitted segments in the last scrape interval, per connection (TopN).",
labels, nil,
),
descRateByTuple: prometheus.NewDesc(
"tcp_retrans_rate_by_tuple",
"TCP retransmission rate (delta_retrans/delta_out) in the last scrape interval, per connection (TopN).",
labels, nil,
),
}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
ch <- c.descRetransTotal
ch <- c.descOutTotal
ch <- c.descRetransRate
ch <- c.descRetransByTuple
ch <- c.descOutByTuple
ch <- c.descRateByTuple
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
c.mu.Lock()
defer c.mu.Unlock()

now := time.Now()

// ── Read current map state ───────────────────────────────────────────────
current := make(map[FlowKey]FlowVal)
iter := c.bpfMap.Iterator()
for iter.Next() {
rawKey := iter.Key()
k, err := parseFlowKey(rawKey)
if err != nil {
log.Printf("warn: parse key: %v", err)
continue
}

// GetValue on a PERCPU map returns all per-CPU values concatenated.
rawVal, err := c.bpfMap.GetValue(unsafe.Pointer(&rawKey[0]))
if err != nil {
log.Printf("warn: get value: %v", err)
continue
}
current[k] = aggregatePerCPU(rawVal, c.numCPU)
}
if err := iter.Err(); err != nil {
log.Printf("warn: map iterator: %v", err)
}

// ── Compute globals ──────────────────────────────────────────────────────
var totalRetrans, totalOut uint64
for _, v := range current {
totalRetrans += v.Retrans
totalOut += v.Out
}

// ── Compute deltas ───────────────────────────────────────────────────────
var flows []flowStats
for k, cur := range current {
pe, hasPrev := c.prev[k]
c.prev[k] = prevEntry{val: cur, lastSeen: now}

if !hasPrev {
continue
}

dr := cur.Retrans - pe.val.Retrans
do := cur.Out - pe.val.Out

var rate float64
if do > 0 {
rate = float64(dr) / float64(do)
}

famStr := "ipv4"
if k.Family == syscall.AF_INET6 {
famStr = "ipv6"
}

flows = append(flows, flowStats{
key:          k,
src:          addrPort(k.Saddr, k.Family, k.Sport),
dst:          addrPort(k.Daddr, k.Family, k.Dport),
famStr:       famStr,
deltaRetrans: dr,
deltaOut:     do,
retransRate:  rate,
})
}

// ── Expire stale prev entries ─────────────────────────────────────────────
for k, pe := range c.prev {
if now.Sub(pe.lastSeen) > c.expiry {
delete(c.prev, k)
}
}

// ── Emit global metrics ───────────────────────────────────────────────────
ch <- prometheus.MustNewConstMetric(c.descRetransTotal, prometheus.CounterValue, float64(totalRetrans))
ch <- prometheus.MustNewConstMetric(c.descOutTotal, prometheus.CounterValue, float64(totalOut))

var sumDR, sumDO uint64
for _, f := range flows {
sumDR += f.deltaRetrans
sumDO += f.deltaOut
}
var globalRate float64
if sumDO > 0 {
globalRate = float64(sumDR) / float64(sumDO)
}
ch <- prometheus.MustNewConstMetric(c.descRetransRate, prometheus.GaugeValue, globalRate)

// ── Emit TopN per-tuple metrics ───────────────────────────────────────────
// Sort by delta retrans descending so the highest-retransmitting flows
// are always included even when capped at topN.
sort.Slice(flows, func(i, j int) bool {
return flows[i].deltaRetrans > flows[j].deltaRetrans
})
limit := c.topN
if limit > len(flows) {
limit = len(flows)
}
for _, f := range flows[:limit] {
ch <- prometheus.MustNewConstMetric(c.descRetransByTuple, prometheus.GaugeValue,
float64(f.deltaRetrans), f.src, f.dst, f.famStr)
ch <- prometheus.MustNewConstMetric(c.descOutByTuple, prometheus.GaugeValue,
float64(f.deltaOut), f.src, f.dst, f.famStr)
ch <- prometheus.MustNewConstMetric(c.descRateByTuple, prometheus.GaugeValue,
f.retransRate, f.src, f.dst, f.famStr)
}
}

// ─────────────────────────── main ────────────────────────────────────────────

func main() {
var (
bpfObjPath = flag.String("bpf-obj", "tcpretrans.bpf.o", "Path to compiled BPF object file")
listenAddr = flag.String("listen", ":9101", "Address to expose /metrics on")
topN       = flag.Int("topn", 200, "Maximum number of per-tuple metrics to expose")
expirySec  = flag.Int("expiry", 30, "Seconds after which unseen flow entries are expired from prev-cache")
)
flag.Parse()

// ── Detect CPU count ─────────────────────────────────────────────────────
numCPU, err := libbpf.NumPossibleCPUs()
if err != nil {
log.Fatalf("get CPU count: %v", err)
}
log.Printf("possible CPUs: %d", numCPU)

// ── Load BPF object ──────────────────────────────────────────────────────
bpfModule, err := libbpf.NewModuleFromFile(*bpfObjPath)
if err != nil {
log.Fatalf("failed to load BPF object %q: %v", *bpfObjPath, err)
}
defer bpfModule.Close()

if err := bpfModule.BPFLoadObject(); err != nil {
log.Fatalf("failed to load BPF programs: %v", err)
}

// ── Attach tp_btf/tcp_retransmit_skb ────────────────────────────────────
retransProg, err := bpfModule.GetProgram("handle_retransmit")
if err != nil {
log.Fatalf("get program handle_retransmit: %v", err)
}
retransLink, err := retransProg.AttachGeneric()
if err != nil {
log.Fatalf("attach tp_btf tcp_retransmit_skb: %v", err)
}
defer retransLink.Destroy()

// ── Attach kprobe/__tcp_transmit_skb ────────────────────────────────────
transmitProg, err := bpfModule.GetProgram("handle_transmit")
if err != nil {
log.Fatalf("get program handle_transmit: %v", err)
}
transmitLink, err := transmitProg.AttachKprobe("__tcp_transmit_skb")
if err != nil {
log.Fatalf("attach kprobe __tcp_transmit_skb: %v", err)
}
defer transmitLink.Destroy()

// ── Get BPF map ──────────────────────────────────────────────────────────
flowMap, err := bpfModule.GetMap("flow_map")
if err != nil {
log.Fatalf("get BPF map flow_map: %v", err)
}

// ── Register Prometheus collector ────────────────────────────────────────
expiry := time.Duration(*expirySec) * time.Second
coll := newCollector(flowMap, numCPU, *topN, expiry)
prometheus.MustRegister(coll)

// ── HTTP server ──────────────────────────────────────────────────────────
http.Handle("/metrics", promhttp.Handler())
http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
fmt.Fprintln(w, "ok")
})

srv := &http.Server{
Addr:         *listenAddr,
ReadTimeout:  10 * time.Second,
WriteTimeout: 30 * time.Second,
}

go func() {
log.Printf("tcp-retrans-exporter listening on %s", *listenAddr)
if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
log.Fatalf("HTTP server: %v", err)
}
}()

// ── Graceful shutdown ────────────────────────────────────────────────────
sig := make(chan os.Signal, 1)
signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
<-sig
log.Println("shutting down")
}
