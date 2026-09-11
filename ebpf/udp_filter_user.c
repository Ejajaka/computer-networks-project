// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <signal.h>
#include <net/if.h>
#include "udp_filter_skel.h"

struct stats {
    __u64 total;
    __u64 dropped;
    __u64 alerted;
};

static volatile sig_atomic_t stop = 0;
static void handle_sigint(int sig) { (void)sig; stop = 1; }

static int bump_memlock(void)
{
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <iface>\n", argv[0]);
        return 1;
    }
    const char *iface = argv[1];

    bump_memlock();

    struct udp_filter_kern *skel = udp_filter_kern__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    if (udp_filter_kern__load(skel)) {
        fprintf(stderr, "failed to load BPF program\n");
        udp_filter_kern__destroy(skel);
        return 1;
    }

    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "if_nametoindex failed: %s\n", strerror(errno));
        return 1;
    }

    printf("UDP flood filter attached to %s (ifindex %d)\n", iface, ifindex);

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    int stats_fd = bpf_map__fd(skel->maps.stats_map);
    int rate_fd = bpf_map__fd(skel->maps.rate_map);
    unsigned int nr_cpus = libbpf_num_possible_cpus();

    printf("%-10s %-12s %-12s %-12s %-8s\n", "t(s)", "pkts", "drops", "src_ips", "drop%");
    __u64 prev_total = 0;

    while (!stop) {
        __u64 total = 0, dropped = 0;
        for (unsigned int c = 0; c < nr_cpus; c++) {
            struct stats st = {0};
            if (bpf_map_lookup_elem(stats_fd, &(int){0}, &st) == 0) {
                total += st.total;
                dropped += st.dropped;
            }
        }

        int n_ips = 0;
        __u32 cur = 0, next_key = 0;
        while (bpf_map_get_next_key(rate_fd, &cur, &next_key) == 0) {
            n_ips++;
            cur = next_key;
        }

        double pct = total > 0 ? 100.0 * dropped / total : 0.0;
        printf("%-10llu %-12llu %-12llu %-12d %-8.1f\n",
               (unsigned long long)(total - prev_total),
               (unsigned long long)total,
               (unsigned long long)dropped,
               n_ips, pct);
        prev_total = total;
        sleep(1);
    }

    bpf_xdp_detach(ifindex, 0, NULL);
    udp_filter_kern__destroy(skel);
    printf("detached\n");
    return 0;
}
