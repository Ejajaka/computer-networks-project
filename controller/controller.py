#!/usr/bin/env python3
"""
User-space controller (paper section 3.2, mitigation logic part 2).

The "security guard" that reacts to alerts. The user-space half of the defence:
  - the XDP filter (kernel, C) is the FAST part - drops flood packets instantly,
    but it's tiny and can't do complicated things
  - this controller (Python) is the SLOW-but-SMART part - reads the filter's
    alert message, then sets up a permanent block for that source IP.

Analogy: the XDP filter is the bouncer turning people away at the door; the
controller is the manager who writes the troublemaker's name on a banned list.

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

# A special file in Linux where eBPF programs can print messages (via bpf_printk).
# Reading it is like listening to the kernel's notice board.
TRACE_PIPE = "/sys/kernel/tracing/trace_pipe"
VICTIM = "victim"   # the container name to protect
LOG_FILE = "/home/sanjeev/Desktop/CN/results/alerts.log"   # where alerts are saved (hardcoded)

# Safety list of IPs that must NEVER be blocked: the victim itself (.10),
# the Docker gateway (.1), and localhost. Without it, a mistake could block
# our own network.
SELF_IPS = {"172.30.0.10", "172.30.0.1", "127.0.0.1"}

# A regular expression (text-search pattern): matches lines containing
# "UDP FLOOD" or "SYN FLOOD", then "DETECTED from", then an IP address.
# It captures two pieces: the type of flood and the IP.
ALERT_RE = re.compile(
    r"(UDP FLOOD|SYN FLOOD) DETECTED from (\d+\.\d+\.\d+\.\d+)"
)

# Memory of IPs already blocked, so the same IP isn't blocked over and over.
# (a set holds each item only once)
BLOCKED = set()


def run(cmd, sudo=False):
    """Helper: run a shell command from Python and return (exit code, output).
    If sudo=True it adds `sudo -S` in front. Has a 30-second timeout and
    catches errors so the program doesn't crash."""
    if sudo:
        cmd = ["sudo", "-S"] + cmd
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout.strip()
    except Exception as e:
        return -1, str(e)


def block_ip(ip):
    """Persistent block via iptables INSIDE the victim container.
    Runs: docker exec victim iptables -A INPUT -s <ip> -j DROP
      - docker exec victim   -> run the command inside the victim container
      - iptables -A INPUT    -> append a rule to the incoming-traffic list
      - -s <ip>              -> match packets from that source IP
      - -j DROP              -> silently discard them
    Returns True if the command succeeded.
    (Note: no sudo here, so the controller itself must run with enough
    privileges - start_controller.sh handles that by starting it with sudo.)"""
    rule = ["docker", "exec", VICTIM, "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    rc, out = run(rule)
    return rc == 0


def log(msg):
    """Add a timestamp, print to screen, and append to alerts.log.
    That's the audit trail you see in Step 7 of demo.sh."""
    line = f"[{datetime.now().isoformat()}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def main():
    print(f"Controller started. Monitoring {TRACE_PIPE} (Ctrl+C to stop)")
    # Open the trace pipe and read it line by line, FOREVER.
    # The read waits until the kernel writes something new.
    with open(TRACE_PIPE, "r") as tp:
        for line in tp:
            # Check if the line matches the alert pattern. If not, skip it.
            m = ALERT_RE.search(line)
            if not m:
                continue
            # Pull out the flood type and the IP.
            kind, ip = m.group(1), m.group(2)
            # Skip if the IP is one of our own (never block yourself).
            if ip in SELF_IPS:
                continue
            # Skip if the IP is already blocked (already handled).
            if ip in BLOCKED:
                continue
            # Otherwise: remember it, log "detected", block it, then log the result.
            BLOCKED.add(ip)
            log(f"{kind} detected from {ip} -- blocking via iptables")
            if block_ip(ip):
                log(f"BLOCKED {ip} (iptables rule added in {VICTIM})")
            else:
                log(f"FAILED to block {ip}")


if __name__ == "__main__":
    # When run directly, call main(). Ctrl+C exits cleanly.
    try:
        main()
    except KeyboardInterrupt:
        print("\nController stopped.")
        sys.exit(0)
