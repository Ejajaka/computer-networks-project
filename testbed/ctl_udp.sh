#!/usr/bin/env bash
# Attach/detach the UDP filter INSIDE the victim container (matches paper design).
# usage: ctl_udp.sh <on|off>
set -euo pipefail
ACTION="${1:-on}"
BPF="/usr/lib/linux-tools/5.15.0-190-generic/bpftool"

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
