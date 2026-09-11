#!/usr/bin/env bash
# Helper: map a container name to its host-side veth interface.
# usage: container_veth.sh <container>
set -euo pipefail
container="$1"
iflink=$(docker exec "$container" cat /sys/class/net/eth0/iflink | tr -d '\r')
hostif=$(ip -o link | awk -v v="$iflink" '$0 ~ "veth" && index($0, v ":") {print $2}' | sed 's/@.*//')
# more robust: find interface whose index == iflink
for iface in $(ls /sys/class/net); do
  if [ "$(cat /sys/class/net/$iface/ifindex 2>/dev/null)" = "$iflink" ]; then
    echo "$iface"
    exit 0
  fi
done
exit 1
