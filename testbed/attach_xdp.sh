#!/usr/bin/env bash
# Attach the UDP flood filter to a container's veth.
# usage: attach_xdp.sh <container> <obj.o> [on|off]
set -euo pipefail
container="$1"
obj="$2"
action="${3:-on}"

hostif=$(container_veth.sh "$container")
pin="/sys/fs/bpf/${container}_udp"

case "$action" in
  on)
    echo "==> Attaching $obj to $container's veth ($hostif)"
    bpftool prog loadall "$obj" "$pin"
    ip link set dev "$hostif" xdp pinned "$pin/xdp_udp_filter"
    echo "    attached. Show:"
    ip link show dev "$hostif"
    ;;
  off)
    echo "==> Detaching XDP from $hostif"
    ip link set dev "$hostif" xdp off
    rm -rf "$pin"
    echo "    detached"
    ;;
esac
