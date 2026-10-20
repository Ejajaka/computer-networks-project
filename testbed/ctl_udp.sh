#!/usr/bin/env bash
set -euo pipefail
ACTION="${1:-on}"

# Find the loader used to load the compiled UDP filter.
find_bpf() {
  docker exec victim bash -c \
    'B=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1); [ -n "$B" ] && echo "$B" || echo bpftool'
}
BPF="$(find_bpf)"

if [ "$ACTION" = "on" ]; then
  # ON flow: remove old pin -> load filter -> pin it -> attach to eth0.
  docker exec victim bash -c "
    rm -rf /sys/fs/bpf/udp
    $BPF prog loadall /tmp/udp_filter_kern.o /sys/fs/bpf/udp
    ip link set dev eth0 xdp pinned /sys/fs/bpf/udp/xdp
  " 2>/dev/null
  echo "UDP filter ON (attached to victim eth0)"
else
  # OFF flow: detach the filter -> remove its pinned files.
  docker exec victim bash -c "
    ip link set dev eth0 xdp off
    rm -rf /sys/fs/bpf/udp
  " 2>/dev/null
  echo "UDP filter OFF (detached)"
fi
