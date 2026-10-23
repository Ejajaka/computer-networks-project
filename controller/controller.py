#!/usr/bin/env python3
"""Reads filter alerts, blocks the source IP with iptables, and logs it."""
import os
import re
import subprocess  # allows to write terminal commands from inside python and get their output
import sys   # for command line arguments
import time
from datetime import datetime

# kernel trace pipe where bpf_printk messages appear
TRACE_PIPE = "/sys/kernel/tracing/trace_pipe"
VICTIM = "victim"   # container to protect
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "results", "alerts.log")   # alert log

# IPs that must never be blocked
SELF_IPS = {"172.30.0.10", "172.30.0.1", "127.0.0.1"}

# matches "UDP/SYN FLOOD DETECTED from <ip>"
ALERT_RE = re.compile(
    r"(UDP FLOOD|SYN FLOOD) DETECTED from (\d+\.\d+\.\d+\.\d+)"
)

# IPs already blocked
BLOCKED = set()


def run(cmd, sudo=False):
    """Run a shell command and return (exit code, output)."""
    if sudo:
        cmd = ["sudo", "-S"] + cmd
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout.strip()
    except Exception as e:
        return -1, str(e)


def block_ip(ip):
    """Add an iptables DROP rule for this IP inside the victim."""
    rule = ["docker", "exec", VICTIM, "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    rc, out = run(rule)
    return rc == 0


def log(msg):
    """Print a timestamped line and append it to alerts.log."""
    line = f"[{datetime.now().isoformat()}] {msg}"
    print(line, flush=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def main():
    print(f"Controller started. Monitoring {TRACE_PIPE} (Ctrl+C to stop)")
    # read the trace pipe forever
    with open(TRACE_PIPE, "r") as tp:
        for line in tp:
            # only act on flood alerts
            m = ALERT_RE.search(line)
            if not m:
                continue
            kind, ip = m.group(1), m.group(2)
            # never block our own IPs
            if ip in SELF_IPS:
                continue
            # skip already-blocked IPs
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
