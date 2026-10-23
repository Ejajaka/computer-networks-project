// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>  // internet protocol and addresses
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> //network is big and lappie is little

#define RATE_THRESHOLD 800
#define RATE_WINDOW_NS 1000000000ULL   // 1 second (UDP)

#define SYN_THRESHOLD 200
#define SYN_WINDOW_NS  1000000000ULL   // 1 second (SYN)

struct pkt_count {
    __u64 count;
    __u64 last_ts;
};

struct syn_count {
    __u64 count;
    __u64 last_ts;
};

struct stats {
    __u64 udp_total;
    __u64 udp_dropped;
    __u64 udp_alerted;
    __u64 syn_total;
    __u64 syn_dropped;
    __u64 syn_alerted;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct pkt_count);
} rate_map SEC(".maps"); // UDP count and timestamp for each source IP

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct syn_count);
} syn_map SEC(".maps"); // SYN count and timestamp for each source IP

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} stats_map SEC(".maps"); // total and dropped packet counters

SEC("xdp") // attach this function at the XDP network-card hook
int xdp_ddos_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end; // end of packet data
    void *data = (void *)(long)ctx->data;         // start of packet data

    struct ethhdr *eth = data; // first read the Ethernet header
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; // header is incomplete; let the normal stack handle it

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS; // not IPv4; this filter does not process it

    struct iphdr *ip = (void *)(eth + 1); // move to the IPv4 header
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS; // IPv4 header is incomplete

    __u32 src_ip = ip->saddr; // source IP identifies the sender
    __u32 key = 0;
    struct stats *st = bpf_map_lookup_elem(&stats_map, &key); // find counters

    if (ip->protocol == IPPROTO_UDP) {
        // UDP branch: count packets from this source IP.
        struct udphdr *udp = (void *)(ip + 1); // move to the UDP header
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS; // UDP header is incomplete

        if (st)
            __sync_fetch_and_add(&st->udp_total, 1); // UDP packet seen

        __u64 now = bpf_ktime_get_ns(); // current kernel time
        struct pkt_count *pc = bpf_map_lookup_elem(&rate_map, &src_ip);
        if (!pc) {
            // First UDP packet from this IP: start a one-second window.
            struct pkt_count init = { .count = 1, .last_ts = now };
            bpf_map_update_elem(&rate_map, &src_ip, &init, BPF_ANY);
            return XDP_PASS; // first packet is allowed
        }
        if (now - pc->last_ts >= RATE_WINDOW_NS) {
            // The old one-second window ended: start a new one.
            pc->last_ts = now;
            pc->count = 1;
            return XDP_PASS; // first packet in the new window is allowed
        }
        pc->count++; // count another UDP packet in this window
        if (pc->count > RATE_THRESHOLD) {
            if (st) {
                __sync_fetch_and_add(&st->udp_dropped, 1); // record a drop
                __sync_fetch_and_add(&st->udp_alerted, 1); // record an alert
            }
            if (st && st->udp_alerted % 1000 == 1)
                bpf_printk("UDP FLOOD DETECTED from %pI4 count=%llu\n",
                           &src_ip, pc->count);
            return XDP_DROP; // more than 800 UDP packets per second
        }
        return XDP_PASS; // UDP source is still below the limit
    }

    if (ip->protocol == IPPROTO_TCP) {
        // TCP branch: only new connection attempts are counted.
        struct tcphdr *tcp = (void *)(ip + 1); // move to the TCP header
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS; // TCP header is incomplete

        // only SYN without ACK
        if (!(tcp->syn) || tcp->ack)
            return XDP_PASS; // not a new TCP connection attempt

        if (st)
            __sync_fetch_and_add(&st->syn_total, 1); // SYN packet seen

        __u64 now = bpf_ktime_get_ns(); // current kernel time
        struct syn_count *sc = bpf_map_lookup_elem(&syn_map, &src_ip);
        if (!sc) {
            // First SYN from this IP: start a one-second window.
            struct syn_count init = { .count = 1, .last_ts = now };
            bpf_map_update_elem(&syn_map, &src_ip, &init, BPF_ANY);
            return XDP_PASS; // first SYN is allowed
        }
        if (now - sc->last_ts >= SYN_WINDOW_NS) {
            // The old one-second SYN window ended: start a new one.
            sc->last_ts = now;
            sc->count = 1;
            return XDP_PASS; // first SYN in the new window is allowed
        }
        sc->count++; // count another SYN from this source IP
        if (sc->count > SYN_THRESHOLD) {
            if (st) {
                __sync_fetch_and_add(&st->syn_dropped, 1); // record a drop
                __sync_fetch_and_add(&st->syn_alerted, 1); // record an alert
            }
            if (st && st->syn_alerted % 1000 == 1)
                bpf_printk("SYN FLOOD DETECTED from %pI4 count=%llu\n",
                           &src_ip, sc->count);
            return XDP_DROP; // more than 200 SYNs per second
        }
        return XDP_PASS; // SYN source is still below the limit
    }

    // UDP and TCP SYN were the only protected cases; other protocols pass.
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
