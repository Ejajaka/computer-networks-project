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
