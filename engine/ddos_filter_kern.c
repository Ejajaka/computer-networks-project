// SPDX-License-Identifier: GPL-2.0
// Combined DDoS mitigation: UDP flood (per-source-IP packet rate) +
// SYN flood (per-source-IP connection rate). One XDP program, two classes.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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
} rate_map SEC(".maps");

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
    __type(value, struct stats);
} stats_map SEC(".maps");

SEC("xdp")
int xdp_ddos_filter(struct xdp_md *ctx)
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

    __u32 src_ip = ip->saddr;
    __u32 key = 0;
    struct stats *st = bpf_map_lookup_elem(&stats_map, &key);

    if (ip->protocol == IPPROTO_UDP) {
        /* ---------- UDP flood detection (per-source packet rate) ---------- */
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        if (st)
            __sync_fetch_and_add(&st->udp_total, 1);

        __u64 now = bpf_ktime_get_ns();
        struct pkt_count *pc = bpf_map_lookup_elem(&rate_map, &src_ip);
        if (!pc) {
            struct pkt_count init = { .count = 1, .last_ts = now };
            bpf_map_update_elem(&rate_map, &src_ip, &init, BPF_ANY);
            return XDP_PASS;
        }
        if (now - pc->last_ts >= RATE_WINDOW_NS) {
            pc->last_ts = now;
            pc->count = 1;
            return XDP_PASS;
        }
        pc->count++;
        if (pc->count > RATE_THRESHOLD) {
            if (st) {
                __sync_fetch_and_add(&st->udp_dropped, 1);
                __sync_fetch_and_add(&st->udp_alerted, 1);
            }
            if (st && st->udp_alerted % 1000 == 1)
                bpf_printk("UDP FLOOD DETECTED from %pI4 count=%llu\n",
                           &src_ip, pc->count);
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_TCP) {
        /* ---------- SYN flood detection (per-source connection rate) ---------- */
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        /* Only new connection attempts (SYN set, ACK clear) */
        if (!(tcp->syn) || tcp->ack)
            return XDP_PASS;

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
                bpf_printk("SYN FLOOD DETECTED from %pI4 count=%llu\n",
                           &src_ip, sc->count);
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    /* Non-UDP/TCP (ICMP, etc.) passes */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
