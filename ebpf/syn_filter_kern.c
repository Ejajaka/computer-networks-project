// SPDX-License-Identifier: GPL-2.0
// SYN flood detection based on per-source-IP connection (SYN) rate.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SYN_THRESHOLD 200
#define SYN_WINDOW_NS 1000000000ULL   // 1 second

struct syn_count {
    __u64 count;
    __u64 last_ts;
};

struct syn_stats {
    __u64 syn_total;     // SYN packets seen
    __u64 syn_dropped;   // SYN packets dropped as flood
    __u64 syn_alerted;   // alert throttle counter
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct syn_count);
} syn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct syn_stats);
} syn_stats_map SEC(".maps");

SEC("xdp")
int xdp_syn_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* SYN flood = high rate of SYN packets not part of an established
     * handshake (SYN set, ACK clear). */
    if (!(tcp->syn) || tcp->ack)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    __u32 key = 0;
    struct syn_stats *st = bpf_map_lookup_elem(&syn_stats_map, &key);
    if (st)
        __sync_fetch_and_add(&st->syn_total, 1);

    __u64 now = bpf_ktime_get_ns();

    struct syn_count *sc = bpf_map_lookup_elem(&syn_map, &src_ip);
    if (!sc) {
        struct syn_count init = { .count = 1, .last_ts = now };
        bpf_map_update_elem(&syn_map, &src_ip, &init, BPF_ANY);
        return XDP_PASS;
    }

    if (now - sc->last_ts >= SYN_WINDOW_NS) {
        sc->last_ts = now;
        sc->count = 1;
        return XDP_PASS;
    }

    sc->count++;
    if (sc->count > SYN_THRESHOLD) {
        if (st) {
            __sync_fetch_and_add(&st->syn_dropped, 1);
            __sync_fetch_and_add(&st->syn_alerted, 1);
        }
        if (st && st->syn_alerted % 1000 == 1)
            bpf_printk("SYN FLOOD DETECTED from %pI4 count=%llu\n", &src_ip, sc->count);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
