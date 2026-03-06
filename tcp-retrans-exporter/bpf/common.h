/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

/*
 * Shared key/value definitions for the TCP retransmit eBPF map.
 * This header is included by both the BPF C program and referenced in Go
 * (via mirrored structs that must match byte-for-byte).
 */

#ifndef __COMMON_H__
#define __COMMON_H__

/* Maximum number of flow entries in the LRU percpu hash map. */
#define MAX_ENTRIES 65536

/*
 * flow_key – 4-tuple + address-family used as the BPF map key.
 *
 * Addresses are stored as 16-byte fields so that both IPv4 and IPv6 flows
 * can live in the same map:
 *   - IPv4: only the last 4 bytes are set (bytes [12..15]), rest are zero.
 *   - IPv6: all 16 bytes are set.
 *
 * Ports are stored in host byte order.
 *
 * Total size: 40 bytes (no implicit compiler padding).
 */
struct flow_key {
    __u8  family;       /* AF_INET(2) or AF_INET6(10) */
    __u8  pad[3];       /* explicit padding – keeps sport at offset 4    */
    __u16 sport;        /* source port, host byte order                  */
    __u16 dport;        /* destination port, host byte order             */
    __u8  saddr[16];    /* source address (16 B; IPv4 stored in [12..15])*/
    __u8  daddr[16];    /* dest   address (16 B; IPv4 stored in [12..15])*/
};

/*
 * flow_val – per-CPU counters stored as the BPF map value.
 *
 *   retrans : incremented by the tcp_retransmit_skb tracepoint handler.
 *   out     : incremented by the __tcp_transmit_skb kprobe handler.
 *
 * Total size: 16 bytes.
 */
struct flow_val {
    __u64 retrans;
    __u64 out;
};

#endif /* __COMMON_H__ */
