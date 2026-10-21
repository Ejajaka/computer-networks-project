# COMPLETE REPLICATION GUIDE
## eBPF/XDP DDoS Detection & Mitigation
### Reproduction of arXiv:2508.00851 + SYN flood extension

This manual documents **everything** that was done to build this project, from an empty
machine to the final tested result. Anyone following these steps (on any Linux machine
with the right kernel) should be able to recreate the entire project.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Requirements](#2-requirements)
3. [Step 1 — Install the tools](#step-1--install-the-tools)
4. [Step 2 — Create the project folders](#step-2--create-the-project-folders)
5. [Step 3 — Write the eBPF/XDP programs](#step-3--write-the-ebpfxdp-programs)
6. [Step 4 — The Makefile (build system)](#step-4--the-makefile-build-system)
7. [Step 5 — Build the programs](#step-5--build-the-programs)
8. [Step 6 — Verify the kernel accepts the code](#step-6--verify-the-kernel-accepts-the-code)
9. [Step 7 — The Docker testbed setup script](#step-7--the-docker-testbed-setup-script)
10. [Step 8 — The user-space controller](#step-8--the-user-space-controller)
11. [Step 9 — Deploy & attach the filter](#step-9--deploy--attach-the-filter)
12. [Step 10 — Run the controller](#step-10--run-the-controller)
13. [Step 11 — Run the attacks & measure (demo.sh)](#step-11--run-the-attacks--measure-demosh)
14. [Step 12 — Formal WITH-vs-WITHOUT report (report.sh)](#step-12--formal-with-vs-without-report-reportsh)
15. [Step 13 — Benchmark script (bench_run.sh)](#step-13--benchmark-script-bench_runsh)
16. [Step 14 — Expected results](#step-14--expected-results)
17. [Step 15 — Troubleshooting](#step-15--troubleshooting)
18. [Step 16 — Cleanup](#step-16--cleanup)
19. [Appendix A — Full file listing](#appendix-a--full-file-listing)
20. [Appendix B — How the detection algorithm works](#appendix-b--how-the-detection-algorithm-works)

---

## 1. Project Overview

**Goal:** Detect and stop DDoS attacks (UDP floods and SYN floods) in real time using
**eBPF + XDP**, the earliest possible point in the Linux network stack, so that attack
packets are dropped *before* the kernel wastes memory/CPU on them.

**The design has two layers:**

| Layer | Software | Speed | Job |
|---|---|---|---|
| Kernel | eBPF/XDP program (C) | Fast (µs) | Count packets per source IP, drop flooders |
| User space | Python controller | Slow (flexible) | Read alerts, block IP with iptables, log |

**Result (measured):**
- UDP flood: ~99.7% of attack packets dropped
- SYN flood: ~99.8% of attack packets dropped
- Legitimate traffic: 0% dropped

**Testbed:** Docker — 3 containers (victim, attacker, benign) on a private network.

---

## 2. Requirements

| Requirement | Minimum |
|---|---|
| Linux kernel | 5.4+ (XDP), 5.5+ for veth native XDP (we used 6.8) |
| Architecture | x86_64 |
| RAM / Disk | 4 GB RAM / 10 GB free disk (recommended) |
| Root access | Yes (sudo) |

> **Important:** eBPF/XDP only works on Linux. A virtual machine works too (our whole
> testbed runs inside Docker), but for the *most realistic* CPU numbers, run on real
> hardware.

---

## Step 1 — Install the tools

Open a terminal and run:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2 \
  clang llvm libbpf-dev libelf-dev pahole \
  linux-tools-common linux-tools-generic \
  hping3 iperf3 tcpdump python3-requests

# allow your user to use Docker (then log out/in, or run: newgrp docker)
sudo usermod -aG docker $USER
```

**Why each package:**

| Package | Purpose |
|---|---|
| `docker.io` | Creates the isolated test network |
| `clang`, `llvm` | Compile C → eBPF bytecode |
| `libbpf-dev` | eBPF helper headers (`bpf_helpers.h`) |
| `pahole` | BTF generation support |
| `linux-tools-*` | Provides `bpftool` (load/attach eBPF) |
| `hping3` | Sends the attack floods |
| `iperf3` | Sends legitimate traffic / runs the victim's server |
| `python3-requests` | (optional) for the controller |

**Verify:**
```bash
docker run --rm hello-world     # should print "Hello from Docker!"
clang --version                 # should show a version
```

---

## Step 2 — Create the project folders

```bash
mkdir -p ~/Desktop/CN/engine ~/Desktop/CN/testbed ~/Desktop/CN/controller ~/Desktop/CN/results
cd ~/Desktop/CN
```

Folder layout:

```
CN/
├── engine/        # the eBPF/XDP C programs + Makefile (the main engine)
├── controller/    # the Python controller
├── testbed/       # Docker setup + run/report/benchmark scripts
├── results/       # measured results + alerts log
├── docs/          # README.md, HOW_TO_RUN.md, REPLICATION_GUIDE.md, references/, website/
└── .github/       # Pages deployment workflow
```

---

## Step 3 — Write the eBPF/XDP programs

We wrote three C programs. Each is compiled to eBPF bytecode and attached to the
victim's network card at the **XDP hook**.

| File | Purpose |
|---|---|
| `udp_filter_kern.c` | UDP flood detection (reproduces the paper) |
| `syn_filter_kern.c` | SYN flood detection (our extension) |
| `ddos_filter_kern.c` | **Combined** UDP + SYN in one program (main deliverable) |

### File: `engine/udp_filter_kern.c`

```c
// SPDX-License-Identifier: GPL-2.0
// UDP flood detection: per-source-IP packet rate (reproduces the paper).
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define RATE_THRESHOLD 800
#define WINDOW_NS      1000000000ULL   // 1 second

struct pkt_count {
    __u64 count;
    __u64 last_ts;
};

struct stats {
    __u64 total;
    __u64 dropped;
    __u64 alerted;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct pkt_count);
} rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} stats_map SEC(".maps");

SEC("xdp")
int xdp_udp_filter(struct xdp_md *ctx)
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
    if (st)
        __sync_fetch_and_add(&st->total, 1);

    __u64 now = bpf_ktime_get_ns();

    struct pkt_count *pc = bpf_map_lookup_elem(&rate_map, &src_ip);
    if (!pc) {
        struct pkt_count init = { .count = 1, .last_ts = now };
        bpf_map_update_elem(&rate_map, &src_ip, &init, BPF_ANY);
        return XDP_PASS;
    }

    if (now - pc->last_ts >= WINDOW_NS) {
        pc->last_ts = now;
        pc->count = 1;
        return XDP_PASS;
    }

    pc->count++;
    if (pc->count > RATE_THRESHOLD) {
        if (st) {
            __sync_fetch_and_add(&st->dropped, 1);
            __sync_fetch_and_add(&st->alerted, 1);
        }
        if (st && st->alerted % 1000 == 1)
            bpf_printk("UDP FLOOD DETECTED from %pI4 count=%llu\n",
                       &src_ip, pc->count);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### File: `engine/syn_filter_kern.c`

```c
// SPDX-License-Identifier: GPL-2.0
// SYN flood detection: per-source-IP connection (SYN) rate.  (Our extension)
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
    __u64 syn_total;
    __u64 syn_dropped;
    __u64 syn_alerted;
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
            bpf_printk("SYN FLOOD DETECTED from %pI4 count=%llu\n",
                       &src_ip, sc->count);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### File: `engine/ddos_filter_kern.c`  (the main combined program)

```c
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
```

---

## Step 4 — The Makefile (build system)

### File: `engine/Makefile`

```make
CLANG ?= clang
BPF_TARGET ?= bpf
BPF_CFLAGS := -O2 -g -Wall -Wno-unused-value -Wno-pointer-sign
BPF_CFLAGS += -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_x86
BPF_CFLAGS += -I/usr/include/x86_64-linux-gnu
BPF_CFLAGS += -I/usr/include

SRCS_KERN := udp_filter_kern.c syn_filter_kern.c ddos_filter_kern.c
OBJS_KERN := $(SRCS_KERN:.c=.o)

all: $(OBJS_KERN)

$(OBJS_KERN): %.o: %.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS_KERN)

.PHONY: all clean
```

**Why `-target bpf`?** It tells clang to emit eBPF bytecode (the instruction set the
kernel understands) instead of normal x86 machine code.

**Why the `-I` include paths?** `asm/types.h` lives under the glibc multiarch include dir
on Ubuntu; eBPF programs need it.

---

## Step 5 — Build the programs

```bash
cd ~/Desktop/CN/engine
make
```

**Expected output:**
```
clang -O2 -g -Wall ... -c udp_filter_kern.c -o udp_filter_kern.o
clang -O2 -g -Wall ... -c syn_filter_kern.c -o syn_filter_kern.o
clang -O2 -g -Wall ... -c ddos_filter_kern.c -o ddos_filter_kern.o
```

Verify the `.o` files exist:
```bash
ls -la *.o
```

---

## Step 6 — Verify the kernel accepts the code

The kernel runs a **verifier** (a static safety analysis) before loading any eBPF
program. It guarantees the code terminates quickly and cannot crash the system.

```bash
cd ~/Desktop/CN/engine
sudo bpftool prog load ddos_filter_kern.o /sys/fs/bpf/vcheck
sudo rm -rf /sys/fs/bpf/vcheck
```

- Exit code `0` + no error = the verifier approved the program.
- If the verifier rejects it, you'll see an error describing the unsafe instruction.

---

## Step 7 — The Docker testbed setup script

This script creates the private network and three containers.

### File: `testbed/setup_testbed.sh`

```bash
#!/usr/bin/env bash
# Sets up the Docker testbed: creates network + 3 containers (victim/attacker/benign).
# Run with sudo (or as a user in the docker group).

set -euo pipefail

NET="ddos-net"
IMG="ubuntu:22.04"

echo "==> Creating network $NET"
docker network create --driver bridge --subnet 172.30.0.0/24 "$NET" 2>/dev/null || echo "  (network already exists)"

echo "==> Starting victim container"
docker rm -f victim 2>/dev/null || true
docker run -d --name victim --network "$NET" --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add SYS_RESOURCE \
  --security-opt seccomp=unconfined --privileged \
  --ip 172.30.0.10 \
  "$IMG" sleep infinity
echo "    victim IP: 172.30.0.10"

echo "==> Starting attacker container"
docker rm -f attacker 2>/dev/null || true
docker run -d --name attacker --network "$NET" --ip 172.30.0.20 "$IMG" sleep infinity
echo "    attacker IP: 172.30.0.20"

echo "==> Starting benign container"
docker rm -f benign 2>/dev/null || true
docker run -d --name benign --network "$NET" --ip 172.30.0.30 "$IMG" sleep infinity
echo "    benign IP: 172.30.0.30"

echo "==> Installing tools inside containers"
for c in victim attacker benign; do
  docker exec "$c" bash -c 'apt-get update -qq && apt-get install -y -qq iperf3 net-tools iproute2 >/dev/null 2>&1' &
done
wait
echo "    base tools installed"

echo "==> Installing iptables (for the controller's block rule) in victim"
docker exec victim bash -c 'apt-get install -y -qq iptables >/dev/null 2>&1'

echo "==> Installing hping3 in attacker only"
docker exec attacker bash -c 'apt-get install -y -qq hping3 >/dev/null 2>&1' &
wait

echo "==> Starting UDP server (iperf3) on victim :5201"
docker exec -d victim iperf3 -s -p 5201

echo "==> Done. Testbed ready:"
docker ps --format 'table {{.Names}}\t{{.IPAddress}}\t{{.Status}}' | grep -E "victim|attacker|benign"
```

**Key points:**
- The `victim` container is created **privileged** with `NET_ADMIN`/`SYS_ADMIN` so it can
  attach an XDP program to its own `eth0`.
- Subnet `172.30.0.0/24` is private — the attack never leaves the machine.
- The victim runs a UDP server on port 5201 (the "service" we protect).

**Run it:**
```bash
cd ~/Desktop/CN/testbed
sudo bash setup_testbed.sh
```

**Verify:**
```bash
sudo docker ps
# victim, attacker, benign should all show "Up"
docker ps --format 'table {{.Names}}\t{{.Status}}'   # containers are running
```

---

## Step 8 — The user-space controller

### File: `controller/controller.py`

```python
#!/usr/bin/env python3
"""
User-space controller (paper section 3.2, mitigation logic part 2).

Reads the kernel trace_pipe for eBPF alert messages, extracts the malicious
source IP, and applies a persistent block (iptables) inside the victim container,
plus logs each alert.

Run on the host with the victim container's eBPF/XDP filter active.
"""
import re
import subprocess
import sys
import time
from datetime import datetime

TRACE_PIPE = "/sys/kernel/tracing/trace_pipe"
VICTIM = "victim"
LOG_FILE = "/home/sanjeev/Desktop/CN/results/alerts.log"

# IPs that must never be blocked (the victim itself / Docker gateway / bridge)
SELF_IPS = {"172.30.0.10", "172.30.0.1", "127.0.0.1"}

# Alert format from udp_filter_kern.c / syn_filter_kern.c
ALERT_RE = re.compile(
    r"(UDP FLOOD|SYN FLOOD) DETECTED from (\d+\.\d+\.\d+\.\d+)"
)

BLOCKED = set()


def run(cmd, sudo=False):
    if sudo:
        cmd = ["sudo", "-S"] + cmd
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout.strip()
    except Exception as e:
        return -1, str(e)


def block_ip(ip):
    """Persistent block via iptables INSIDE the victim container."""
    rule = ["docker", "exec", VICTIM, "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    rc, out = run(rule)
    return rc == 0


def log(msg):
    line = f"[{datetime.now().isoformat()}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def main():
    print(f"Controller started. Monitoring {TRACE_PIPE} (Ctrl+C to stop)")
    with open(TRACE_PIPE, "r") as tp:
        for line in tp:
            m = ALERT_RE.search(line)
            if not m:
                continue
            kind, ip = m.group(1), m.group(2)
            if ip in SELF_IPS:
                continue
            if ip in BLOCKED:
                continue
            BLOCKED.add(ip)
            log(f"{kind} detected from {ip} -- blocking via iptables")
            if block_ip(ip):
                log(f"BLOCKED {ip} (iptables rule added in {VICTIM})")
            else:
                log(f"FAILED to block {ip}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nController stopped.")
        sys.exit(0)
```

**How it works:**
1. The XDP program calls `bpf_printk()` when it detects a flood. That writes a line to
   the kernel's trace buffer (`/sys/kernel/tracing/trace_pipe`).
2. The controller reads that pipe line by line.
3. It matches lines like `UDP FLOOD DETECTED from 172.30.0.20` with a regex.
4. It blocks that IP with `iptables -A INPUT -s <ip> -j DROP` inside the victim
   (a persistent, second layer of defense).
5. It logs everything to `results/alerts.log`.

> **Note:** the controller runs on the *host*, but inserts the iptables rule *inside*
> the victim container via `docker exec`.

### File: `testbed/start_controller.sh`

```bash
#!/usr/bin/env bash
# Runs the controller as a background daemon and returns.
set -euo pipefail
LOG="/tmp/ddos_controller.log"
rm -f "$LOG"
sudo -n sh -c "nohup python3 /home/sanjeev/Desktop/CN/controller/controller.py > '$LOG' 2>&1 &"
echo "controller started, log: $LOG"
```

---

## Step 9 — Deploy & attach the filter

The filter must be copied into the victim container and attached to its `eth0` at the
XDP hook.

```bash
cd ~/Desktop/CN

# 1. copy the compiled program into the victim container
sudo docker cp engine/ddos_filter_kern.o victim:/tmp/ddos_filter_kern.o

# 2. find bpftool inside the victim (version independent) and attach
sudo docker exec victim bash -c '
  BPF=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1)
  [ -n "$BPF" ] || BPF=bpftool
  ip link set dev eth0 xdp off 2>/dev/null
  rm -rf /sys/fs/bpf/ddos
  $BPF prog loadall /tmp/ddos_filter_kern.o /sys/fs/bpf/ddos
  ip link set dev eth0 xdp pinned /sys/fs/bpf/ddos/xdp
  ip link show dev eth0'
```

**Expected output** (last line):
```
2: eth0@if6: ... xdp ... prog/xdp id 59 ... name xdp_ddos_filter ... jited
```

- `prog loadall` loads the bytecode into the kernel and pins it under `/sys/fs/bpf/ddos`.
- `ip link set dev eth0 xdp pinned ...` attaches it to the XDP hook of the victim's NIC.

> **Why inside the container?** The paper attaches the filter to the *victim device's*
> interface. Our victim is a container, so we attach to its `eth0`.

### Helper script: `testbed/ctl_udp.sh` (attach/detach quickly)

```bash
#!/usr/bin/env bash
# Attach/detach the UDP filter INSIDE the victim container (matches paper design).
# usage: ctl_udp.sh <on|off>
set -euo pipefail
ACTION="${1:-on}"

# Find bpftool regardless of linux-tools version installed in the container
find_bpf() {
  docker exec victim bash -c \
    'B=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1); [ -n "$B" ] && echo "$B" || echo bpftool'
}
BPF="$(find_bpf)"

if [ "$ACTION" = "on" ]; then
  docker exec victim bash -c "
    rm -rf /sys/fs/bpf/udp
    $BPF prog loadall /tmp/udp_filter_kern.o /sys/fs/bpf/udp
    ip link set dev eth0 xdp pinned /sys/fs/bpf/udp/xdp
  " 2>/dev/null
  echo "UDP filter ON (attached to victim eth0)"
else
  docker exec victim bash -c "
    ip link set dev eth0 xdp off
    rm -rf /sys/fs/bpf/udp
  " 2>/dev/null
  echo "UDP filter OFF (detached)"
fi
```

---

## Step 10 — Run the controller

```bash
cd ~/Desktop/CN/testbed
sudo bash start_controller.sh
```

Check it started:
```bash
cat /tmp/ddos_controller.log
# should show: Controller started. Monitoring /sys/kernel/tracing/trace_pipe
```

---

## Step 11 — Run the attacks & measure (demo.sh)

### File: `testbed/demo.sh`  (one-command full demo)

```bash
#!/usr/bin/env bash
# =============================================================================
# One-shot demo: runs the full DDoS mitigation simulation and prints results.
# Usage:  sudo bash demo.sh
# =============================================================================
set -uo pipefail

VICTIM=172.30.0.10
ATTACKER=172.30.0.20
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m    $*\033[0m"; }
warn() { echo -e "\033[1;33m    $*\033[0m"; }

# --- bpftool finder inside the victim container (version independent) --------
bpf_path() {
  docker exec victim bash -c \
    'ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1 || echo bpftool'
}

# --- read the XDP stats map inside the victim --------------------------------
read_stats() {
  local BPF; BPF=$(bpf_path)
  docker exec victim bash -c "$BPF map dump name stats_map 2>/dev/null" 2>/dev/null \
    | grep -oE '"(udp_total|udp_dropped|syn_total|syn_dropped)": [0-9]+' \
    | awk -F': ' '{s[$1]+=$2} END{
        printf "%d %d %d %d",
        s["\"udp_total\""]+0, s["\"udp_dropped\""]+0,
        s["\"syn_total\""]+0, s["\"syn_dropped\""]+0 }'
}

say "Step 0: make sure the containers are running"
docker start victim attacker benign >/dev/null 2>&1 || true
docker ps --format '    {{.Names}}  {{.Status}}' | grep -E 'victim|attacker|benign'

say "Step 1: start the UDP server on the victim"
docker exec -d victim pkill -9 iperf3 >/dev/null 2>&1 || true
docker exec -d victim iperf3 -s -p 5201 >/dev/null 2>&1
ok "iperf3 UDP server listening on victim:5201"

say "Step 2: install bpftool + iptables in victim if missing, then attach the combined filter"
docker exec victim bash -c 'command -v bpftool >/dev/null 2>&1 || ls /usr/lib/linux-tools/*/bpftool >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq linux-tools-generic linux-tools-common)' >/dev/null 2>&1
docker exec victim bash -c 'command -v iptables >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq iptables)' >/dev/null 2>&1
BPF=$(bpf_path)
docker cp "$PROJECT_DIR/engine/ddos_filter_kern.o" victim:/tmp/ddos_filter_kern.o >/dev/null 2>&1
docker exec victim bash -c "
  ip link set dev eth0 xdp off 2>/dev/null
  rm -rf /sys/fs/bpf/ddos
  $BPF prog loadall /tmp/ddos_filter_kern.o /sys/fs/bpf/ddos && \
  ip link set dev eth0 xdp pinned /sys/fs/bpf/ddos/xdp"
docker exec victim bash -c 'ip link show eth0 | grep -q xdp' \
  && ok "combined filter attached to victim eth0 (xdp)" \
  || { warn "filter attach FAILED"; exit 1; }

say "Step 3: start the user-space controller (reads alerts, blocks IPs, logs)"
pkill -f controller.py 2>/dev/null || true
nohup python3 "$PROJECT_DIR/controller/controller.py" > /tmp/ddos_controller.log 2>&1 &
sleep 2
ok "controller running (log: /tmp/ddos_controller.log)"

# ---------------------------------------------------------------------------
say "Step 4: UDP flood test (~100 Mbps from attacker)"
read -r U0 UD0 S0 SD0 < <(read_stats)
for i in 1 2 3 4; do docker exec -d attacker hping3 -2 -p 5201 --flood $VICTIM >/dev/null 2>&1; done
sleep 8
docker exec attacker pkill -9 hping3 >/dev/null 2>&1 || true
sleep 1
read -r U1 UD1 S1 SD1 < <(read_stats)
UT=$((U1-U0)); UDD=$((UD1-UD0))
awk -v t=$UT -v d=$UDD 'BEGIN{printf "    UDP: seen=%d dropped=%d  drop_rate=%.1f%%\n",t,d,(t?100*d/t:0)}'

# ---------------------------------------------------------------------------
say "Step 5: SYN flood test"
read -r U0 UD0 S0 SD0 < <(read_stats)
for i in 1 2 3 4; do docker exec -d attacker hping3 -S -p 5201 --flood $VICTIM >/dev/null 2>&1; done
sleep 8
docker exec attacker pkill -9 hping3 >/dev/null 2>&1 || true
sleep 1
read -r U1 UD1 S1 SD1 < <(read_stats)
ST=$((S1-S0)); SDD=$((SD1-SD0))
awk -v t=$ST -v d=$SDD 'BEGIN{printf "    SYN: seen=%d dropped=%d  drop_rate=%.1f%%\n",t,d,(t?100*d/t:0)}'

# ---------------------------------------------------------------------------
say "Step 6: legitimate traffic test (should NOT be dropped)"
read -r U0 UD0 S0 SD0 < <(read_stats)
docker exec benign iperf3 -c $VICTIM -p 5201 -u -b 3M -t 5 >/dev/null 2>&1
read -r U1 UD1 S1 SD1 < <(read_stats)
UDD=$((UD1-UD0))
echo "    benign UDP extra drops: $UDD  (expected: 0)"

# ---------------------------------------------------------------------------
say "Step 7: controller log (detections + blocks)"
cat /tmp/ddos_controller.log 2>/dev/null | grep -E "FLOOD|BLOCKED" || echo "    (no alerts)"

# ---------------------------------------------------------------------------
say "Done. Summary"
echo "    UDP flood drop rate : see Step 4"
echo "    SYN flood drop rate : see Step 5"
echo "    Legit traffic drops : see Step 6 (expected 0)"
echo "    Full log            : /tmp/ddos_controller.log"
echo "    Alerts log          : ~/Desktop/CN/results/alerts.log"
```

**Run it:**
```bash
cd ~/Desktop/CN
make -C engine          # ensure filters are built
sudo bash testbed/demo.sh
```

**What each step does:**
- Step 0 — restart containers if the machine rebooted.
- Step 1 — ensure the victim's UDP server (the service we protect) is running.
- Step 2 — install missing tools in the victim, attach the combined filter.
- Step 3 — start the controller (alerts → block → log).
- Step 4 — UDP flood: 4 hping3 workers ≈ 100 Mbps, then read the drop rate.
- Step 5 — SYN flood: same, for SYN packets.
- Step 6 — benign iperf3 traffic: confirm 0 drops.
- Step 7 — show the controller log.

---

## Step 12 — Formal WITH-vs-WITHOUT report (report.sh)

### File: `testbed/report.sh`

The complete source is in the repository. It:

1. Runs each flood **WITHOUT** the filter (measures: packets reaching the app via
   the application counter, host CPU, and victim resource-load model).
2. Runs the same flood **WITH** the filter (reads the XDP stats map → drop rate,
   delivered packets, CPU, memory, and optional GPU utilization).
3. Prints a formal report + a final difference table.

Key measurement functions:
- `xdp_stats()` — reads `stats_map` inside the victim (seen/dropped counters).
- `rx_pkts()` — reads the victim's `eth0` rx packet counter from `/proc/net/dev`.
- `host_cpu()` — overall host CPU % from `/proc/stat` (two samples 1s apart).
- `app_pkts()` — reads packets received by the victim IP stack after XDP.
- `gpu_one()` — reads optional NVIDIA GPU utilization.

**Run it:**
```bash
cd ~/Desktop/CN
sudo bash testbed/report.sh
```

**Sample output:**
```
WITH vs WITHOUT FILTER — DIFFERENCE
Metric                     WITHOUT filter   WITH filter      Difference
UDP drop rate              0.0%             99.8%            +99.8 pp
UDP packets to app         2,380,910        7,200            99.7% less
UDP host CPU               24.6%            24.4%            -
SYN drop rate              0.0%             99.8%            +99.8 pp
SYN packets to app         2,161,213        1,800            99.9% less
SYN host CPU               24.4%            10.5%            -
Legitimate traffic drop    -                0                unaffected
```

---

## Step 13 — Benchmark script (bench_run.sh)

### File: `testbed/bench_run.sh`

Measures host CPU and victim resource load during a UDP flood, for a given filter
state. It measures CPU and victim resource load only.

```bash
cd ~/Desktop/CN/testbed
sudo bash bench_run.sh filter-off 10    # baseline (no filter)
sudo bash bench_run.sh filter-on  10    # with filter
```

(Full source in the repository.)

---

## Step 14 — Expected results

| Test | Expected | Paper |
|---|---|---|
| UDP flood drop rate | ~99% (we got 99.7–99.8%) | ~99% (Docker) |
| SYN flood drop rate | ~99% (we got 99.8–99.9%) | not covered |
| Combined | ~99.8% | — |
| Legit traffic | 0% dropped | unaffected |
| Detect → block | < 2 s | < 2 s |

> **CPU note:** on a many-core host the flood doesn't saturate a core, so host CPU is
> similar with/without the filter. The paper's big CPU saving (45%→12%) is visible on a
> resource-constrained device (Raspberry Pi). The **drop rate** reproduces cleanly here.

---

## Step 15 — Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `container ... is not running` | Machine rebooted; containers stopped | `sudo docker start victim attacker benign` |
| `bpftool: No such file or directory` | Victim recreated without linux-tools | run `demo.sh` (auto-installs bpftool) or install `linux-tools-generic` inside the victim |
| `iptables: not found` | Fresh victim container | `demo.sh` auto-installs iptables |
| Verifier rejects program | Unsafe eBPF code | Check bounds checks (`data_end` comparisons) and loops |
| Drop rate slightly < 99% | Threshold/attack variance | Still a success (paper ~99%); raise flood intensity |
| `docker` permission denied | User not in docker group | `sudo usermod -aG docker $USER` then log out/in |

---

## Step 16 — Cleanup

```bash
sudo docker exec victim ip link set dev eth0 xdp off
sudo pkill -f controller.py
sudo docker rm -f victim attacker benign
sudo docker network rm ddos-net
```

---

## Appendix A — Full file listing

```
CN/
├── engine/
│   ├── Makefile              # build system
│   ├── udp_filter_kern.c     # UDP flood filter (paper reproduction)
│   ├── syn_filter_kern.c     # SYN flood filter (extension)
│   ├── ddos_filter_kern.c    # combined UDP+SYN filter (main)
│   └── hello_xdp.c           # (dev only) XDP smoke test
├── controller/
│   └── controller.py         # alert reader + iptables blocker + logger
├── testbed/
│   ├── setup_testbed.sh      # create network + containers
│   ├── demo.sh               # one-command full demo
│   ├── report.sh             # formal WITH-vs-WITHOUT report
│   ├── bench_run.sh          # CPU benchmark
│   ├── bench_udp.sh          # (dev) older benchmark
│   ├── ctl_udp.sh            # attach/detach filter
│   ├── container_veth.sh     # container → veth mapping
│   └── start_controller.sh   # launch controller daemon
├── results/
│   ├── UDP_results.md        # detailed measured results
│   └── alerts.log            # event log (generated)
├── docs/
│   ├── HOW_TO_RUN.md
│   ├── REPLICATION_GUIDE.md
│   ├── Project_Explanation.docx / .pdf
│   ├── references/
│   │   ├── paper.txt                    # extracted paper text
│   │   └── tolay2025_ebpf_ddos_iot.pdf  # the original paper
│   └── website/                         # interactive GitHub Pages site
├── README.md
└── .github/workflows/deploy-pages.yml   # Pages deployment
```

---

## Appendix B — How the detection algorithm works

Both detectors use the same pattern, applied to different packet types:

**UDP flood (per-source packet rate):**
1. Parse the packet → get the source IP.
2. Look up `{count, last_time}` for that IP in `rate_map` (a hash map).
3. If the map has no entry, create one with `count=1`.
4. If more than 1 second has passed since `last_time`, reset the count to 1.
5. Otherwise increment the count.
6. If count > **800** → `XDP_DROP` (drop at the network card).

**SYN flood (per-source connection rate):**
1. Check the TCP flags: only count packets with **SYN set and ACK clear**
   (i.e., a brand-new connection attempt).
2. Same count-in-window logic in `syn_map`.
3. If count > **200** per second → `XDP_DROP`.

**Why XDP makes it fast:** the program runs at the network-driver hook, before the
kernel allocates an `sk_buff` (the memory structure every packet normally gets) and
before the TCP/IP stack runs. Dropped packets cost almost nothing.

**Why two thresholds:** UDP floods are pure data (normal users can burst), so the limit
is high (800/s). SYN floods are connection attempts (rarer for real users), so the limit
is lower (200/s) — making detection accurate for both.

---

*End of manual. Follow the steps in order and you will reproduce the entire project.*
