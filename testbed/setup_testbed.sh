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
  docker exec "$c" bash -c 'apt-get update -qq && apt-get install -y -qq iperf3 iputils-ping net-tools iproute2 >/dev/null 2>&1' &
done
wait
echo "    base tools installed"

echo "==> Installing hping3 in attacker only"
docker exec attacker bash -c 'apt-get install -y -qq hping3 >/dev/null 2>&1' &
wait

echo "==> Starting UDP server (iperf3) on victim :5201"
docker exec -d victim iperf3 -s -p 5201

echo "==> Done. Testbed ready:"
docker ps --format 'table {{.Names}}\t{{.IPAddress}}\t{{.Status}}' | grep -E "victim|attacker|benign"
