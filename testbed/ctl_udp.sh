#!/usr/bin/env bash
# Attach/detach the UDP filter INSIDE the victim container (matches paper design).
# usage: ctl_udp.sh <on|off>
#
# Same idea as attach_xdp.sh, but the commands run INSIDE the victim
# container via docker exec, attaching to the victim's own eth0
# (the container-side end of the cable). The "paper design" comment means
# this is how the research paper being reproduced attaches the filter:
# on the victim's own network card.

set -euo pipefail
ACTION="${1:-on}"

# Find bpftool regardless of linux-tools version installed in the container
# (the version number in its path varies, e.g. .../linux-tools/6.8.0-.../bpftool;
# fall back to plain `bpftool` if none is found).
find_bpf() {
  docker exec victim bash -c \
    'B=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1); [ -n "$B" ] && echo "$B" || echo bpftool'
}
BPF="$(find_bpf)"

if [ "$ACTION" = "on" ]; then
  # Load the compiled UDP filter into the kernel (verifier checks it),
  # pin it under /sys/fs/bpf/udp, and attach it to the victim's eth0.
  docker exec victim bash -c "
    rm -rf /sys/fs/bpf/udp              # remove any old pinned files first
    $BPF prog loadall /tmp/udp_filter_kern.o /sys/fs/bpf/udp
    ip link set dev eth0 xdp pinned /sys/fs/bpf/udp/xdp
  " 2>/dev/null
  echo "UDP filter ON (attached to victim eth0)"
else
  # Remove the filter from eth0 and delete the pinned files.
  docker exec victim bash -c "
    ip link set dev eth0 xdp off
    rm -rf /sys/fs/bpf/udp
  " 2>/dev/null
  echo "UDP filter OFF (detached)"
fi
