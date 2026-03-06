# tcp-retrans-exporter

A Prometheus exporter that uses eBPF to monitor TCP retransmission rates in real time, broken down by connection 4-tuple.

## Architecture

Two eBPF probes share a single `BPF_MAP_TYPE_LRU_PERCPU_HASH` map keyed by the connection 4-tuple (family + src/dst address + src/dst port):

| Probe | Hook | Counter incremented |
|-------|------|---------------------|
| `handle_retransmit` | `tp_btf/tcp_retransmit_skb` | `retrans` – one per retransmitted segment |
| `handle_transmit`   | `kprobe/__tcp_transmit_skb` | `out` – one per transmitted segment (denominator) |

The Go exporter reads the map on every Prometheus scrape, aggregates per-CPU values, computes per-interval deltas, and exposes `/metrics`.

## Prerequisites

### Kernel

| Requirement | Notes |
|---|---|
| Linux ≥ 5.5 | For `tp_btf` (BTF-powered raw tracepoints) |
| BTF enabled | `CONFIG_DEBUG_INFO_BTF=y` – check with `ls /sys/kernel/btf/vmlinux` |
| Tracepoint `tcp:tcp_retransmit_skb` | Standard since Linux 4.15 |
| Kprobe `__tcp_transmit_skb` | Symbol present in `CONFIG_KPROBES` kernels |
| `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN`) | Required to load BPF programs |

### Build host

| Tool | Notes |
|---|---|
| Go ≥ 1.21 | |
| clang / llvm | With BPF target (`clang --target=bpf` must work) |
| libbpf-dev (≥ 1.3) | Headers and shared library (`-lbpf`) |
| libelf-dev, zlib1g-dev | Transitive deps of libbpf |
| bpftool | Only needed for `make vmlinux` |

Install on Ubuntu / Debian:

```bash
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev linux-tools-generic
```

## Building

### 1. Generate `vmlinux.h` (once per target kernel)

`vmlinux.h` contains all kernel type definitions and is required for CO-RE compilation.  It must be generated **on the target machine** (or a machine running the same kernel version):

```bash
make vmlinux
# bpf/vmlinux.h is created under the bpf/ directory
```

Alternatively copy a pre-generated `vmlinux.h` into `bpf/` from a compatible kernel.

### 2. Build everything

```bash
make all
```

This produces:
- `tcpretrans.bpf.o` – compiled eBPF object
- `tcp-retrans-exporter` – Go binary

### Individual targets

```bash
make bpf      # compile only the eBPF C program
make go       # compile only the Go exporter (expects tcpretrans.bpf.o already built)
make clean    # remove artefacts
make help     # list targets
```

## Running

```bash
sudo ./tcp-retrans-exporter [flags]
```

Flags:

| Flag | Default | Description |
|---|---|---|
| `-bpf-obj` | `tcpretrans.bpf.o` | Path to the compiled BPF object |
| `-listen` | `:9101` | HTTP listen address for `/metrics` |
| `-topn` | `200` | Maximum number of per-tuple label sets to expose (TopN by retrans count) |
| `-expiry` | `30` | Seconds before an unseen flow is removed from the userspace prev-cache |

Example:

```bash
sudo ./tcp-retrans-exporter -bpf-obj ./tcpretrans.bpf.o -listen :9101 -topn 100
```

Health check endpoint: `GET /healthz` returns `ok`.

## Metrics

| Metric | Type | Description |
|---|---|---|
| `tcp_retrans_segs_total` | Counter | Cumulative retransmitted segments since exporter start |
| `tcp_out_segs_total` | Counter | Cumulative transmitted segments since exporter start |
| `tcp_retrans_rate` | Gauge | Global retransmission rate (`Δretrans / Δout`) in the last scrape interval |
| `tcp_retrans_segs_by_tuple{src,dst,family}` | Gauge | Per-connection Δretrans in the last scrape interval (TopN) |
| `tcp_out_segs_by_tuple{src,dst,family}` | Gauge | Per-connection Δout in the last scrape interval (TopN) |
| `tcp_retrans_rate_by_tuple{src,dst,family}` | Gauge | Per-connection retransmission rate (TopN) |

Label semantics:
- `src` – `<ip>:<port>` of the local endpoint
- `dst` – `<ip>:<port>` of the remote endpoint
- `family` – `ipv4` or `ipv6`

Counter semantics:
- `tcp_out_segs_total` counts every call to `__tcp_transmit_skb`, which includes retransmissions and new segments.
- `tcp_retrans_segs_total` counts every call to the `tcp_retransmit_skb` tracepoint.
- `tcp_retrans_rate` = `Δtcp_retrans_segs_total / Δtcp_out_segs_total` per scrape interval.

## Verifying with traffic

The following example uses `tc netem` to introduce packet loss, which causes retransmissions.

```bash
# 1. Start the exporter
sudo ./tcp-retrans-exporter &

# 2. On the test interface (e.g. lo), add 5 % packet loss
sudo tc qdisc add dev lo root netem loss 5%

# 3. Generate TCP traffic (e.g. with iperf3)
iperf3 -s &
iperf3 -c 127.0.0.1 -t 30

# 4. Observe metrics
curl -s http://localhost:9101/metrics | grep tcp_retrans

# 5. Clean up
sudo tc qdisc del dev lo root
```

Expected output (example):

```
# HELP tcp_retrans_rate Global TCP retransmission rate ...
# TYPE tcp_retrans_rate gauge
tcp_retrans_rate 0.047
# HELP tcp_retrans_rate_by_tuple TCP retransmission rate ...
# TYPE tcp_retrans_rate_by_tuple gauge
tcp_retrans_rate_by_tuple{dst="127.0.0.1:5201",family="ipv4",src="127.0.0.1:XXXXX"} 0.049
```

## Directory layout

```
tcp-retrans-exporter/
├── bpf/
│   ├── common.h             # Shared C ↔ Go struct definitions (flow_key, flow_val)
│   ├── tcpretrans.bpf.c     # eBPF program (tp_btf + kprobe)
│   └── vmlinux.h            # Generated – one per target kernel (not committed)
├── cmd/
│   └── exporter/
│       └── main.go          # Go Prometheus exporter
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## Security notes

- The exporter must run as root or with `CAP_BPF` + `CAP_PERFMON` capabilities.
- No network data is captured; only counter values (retrans/out per 4-tuple) are stored in the BPF map.
- The LRU map has a fixed maximum capacity (`MAX_ENTRIES = 65536`) to bound kernel memory usage.
