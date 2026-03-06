// SPDX-License-Identifier: GPL-2.0
/*
 * tcpretrans.bpf.c – eBPF program for TCP retransmission monitoring.
 *
 * Two probes share a single LRU per-CPU hash map keyed by connection 4-tuple:
 *
 *   1. tp_btf/tcp_retransmit_skb  – increments retrans counter per flow.
 *   2. kprobe/__tcp_transmit_skb  – increments out (total transmit) counter per flow.
 *
 * The user-space exporter reads the map periodically, aggregates per-CPU
 * values, computes deltas and exposes Prometheus metrics.
 *
 * Requires:
 *   - Kernel with BTF support (>= 5.5 recommended for tp_btf).
 *   - vmlinux.h generated from the target kernel (bpftool btf dump file
 *     /sys/kernel/btf/vmlinux format c > vmlinux.h).
 *   - clang/llvm with BPF target support.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "common.h"

/* Address-family constants (not in vmlinux.h as literals). */
#define AF_INET  2
#define AF_INET6 10

/* ────────────────────────── BPF map ────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key,   struct flow_key);
    __type(value, struct flow_val);
} flow_map SEC(".maps");

/* ────────────────────────── helpers ────────────────────────────────────── */

/*
 * fill_flow_key – extract 4-tuple from a struct sock * using CO-RE helpers.
 *
 * Returns 0 on success, -1 if the address family is unsupported.
 */
static __always_inline int fill_flow_key(struct sock *sk, struct flow_key *key)
{
    __u16 family;

    if (!sk)
        return -1;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return -1;

    key->family = (__u8)family;

    /* Ports -----------------------------------------------------------------
     * skc_num  : source port in HOST byte order (no conversion needed).
     * skc_dport: dest   port in NETWORK byte order (needs bpf_ntohs).
     */
    key->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    /* Addresses -------------------------------------------------------------
     * IPv4 : 32-bit addresses stored in the last 4 bytes of the 16-byte field.
     * IPv6 : full 128-bit address copied verbatim.
     */
    if (family == AF_INET) {
        __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        /* store IPv4 addresses in the last 4 bytes; network byte order (big-endian) as-is from kernel */
        __builtin_memcpy(key->saddr + 12, &saddr, sizeof(saddr));
        __builtin_memcpy(key->daddr + 12, &daddr, sizeof(daddr));
    } else {
        /* AF_INET6 */
        struct in6_addr saddr6, daddr6;
        BPF_CORE_READ_INTO(&saddr6, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&daddr6, sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(key->saddr, &saddr6, sizeof(saddr6));
        __builtin_memcpy(key->daddr, &daddr6, sizeof(daddr6));
    }

    return 0;
}

/*
 * update_map – look up the flow entry and increment the requested counter.
 * If the entry does not exist, insert a new one.
 *
 * counter_offset: 0 for retrans, 8 for out (byte offset within struct flow_val).
 */
static __always_inline void update_counter(struct flow_key *key, int is_retrans)
{
    struct flow_val *val;

    val = bpf_map_lookup_elem(&flow_map, key);
    if (val) {
        if (is_retrans)
            val->retrans++;
        else
            val->out++;
    } else {
        struct flow_val new_val = {};
        if (is_retrans)
            new_val.retrans = 1;
        else
            new_val.out = 1;
        bpf_map_update_elem(&flow_map, key, &new_val, BPF_ANY);
    }
}

/* ────────────────────────── programs ───────────────────────────────────── */

/*
 * handle_retransmit – fires on every TCP retransmission.
 *
 * Uses tp_btf so the kernel passes typed arguments matching TP_PROTO:
 *   TP_PROTO(struct sock *sk, struct sk_buff *skb)
 */
SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(handle_retransmit, struct sock *sk, struct sk_buff *skb)
{
    struct flow_key key = {};

    if (fill_flow_key(sk, &key) < 0)
        return 0;

    update_counter(&key, 1);
    return 0;
}

/*
 * handle_transmit – fires on every TCP segment transmission attempt.
 *
 * Signature: int __tcp_transmit_skb(struct sock *sk, struct sk_buff *skb,
 *                                    int clone_it, gfp_t gfp_mask, u32 rcv_nxt)
 */
SEC("kprobe/__tcp_transmit_skb")
int BPF_KPROBE(handle_transmit, struct sock *sk)
{
    struct flow_key key = {};

    if (fill_flow_key(sk, &key) < 0)
        return 0;

    update_counter(&key, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
