#!/usr/bin/env bash
# Creates a virtual network (ddos-net) and starts three Ubuntu containers
# (victim/attacker/benign) with fixed IPs, installs their tools, and starts
# the victim's server.
# Run with sudo (or as a user in the docker group).

set -euo pipefail

# Network name and base image (Ubuntu 22.04 for all three machines)
NET="ddos-net"
IMG="ubuntu:22.04"

# Create the virtual network "ddos-net"
# (docker bridge network on subnet 172.30.0.0/24 acts as the "internet")
echo "==> Creating network $NET"
docker network create --driver bridge --subnet 172.30.0.0/24 "$NET" 2>/dev/null || echo "  (network already exists)"

# Start the victim container with fixed IP 172.30.0.10
echo "==> Starting victim container"
docker rm -f victim 2>/dev/null || true
# Extra permissions because the victim must load XDP programs:
#   --privileged        full access (needed to load eBPF / attach XDP)
#   NET_ADMIN           control the network (attach XDP, iptables)
#   SYS_ADMIN           admin syscalls needed for eBPF/XDP setup
#   SYS_RESOURCE        raise memory-lock limits (BPF maps need this)
#   seccomp=unconfined  no syscall restrictions (so loading BPF isn't blocked)
#   sleep infinity      keeps the container alive so we can docker exec into it
docker run -d --name victim --network "$NET" --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add SYS_RESOURCE \
  --security-opt seccomp=unconfined --privileged \
  --ip 172.30.0.10 \
  "$IMG" sleep infinity
echo "    victim IP: 172.30.0.10"

# Start the attacker container with fixed IP 172.30.0.20
# (no extra permissions - it only sends traffic)
echo "==> Starting attacker container"
docker rm -f attacker 2>/dev/null || true
docker run -d --name attacker --network "$NET" --ip 172.30.0.20 "$IMG" sleep infinity
echo "    attacker IP: 172.30.0.20"

# Start the benign container with fixed IP 172.30.0.30
# (normal traffic, to prove legit packets still get through)
echo "==> Starting benign container"
docker rm -f benign 2>/dev/null || true
docker run -d --name benign --network "$NET" --ip 172.30.0.30 "$IMG" sleep infinity
echo "    benign IP: 172.30.0.30"

# Install the base tools in all three containers
echo "==> Installing tools inside containers"
#   iperf3     generates and receives traffic
#   ping       measures delay
#   net-tools  provides ifconfig/netstat
#   iproute2   provides the ip command
for c in victim attacker benign; do
  docker exec "$c" bash -c 'apt-get update -qq && apt-get install -y -qq iperf3 iputils-ping net-tools iproute2 >/dev/null 2>&1' &
done
wait
echo "    base tools installed"

# Install iptables in the victim only
# (firewall tool the controller uses to block the attacker's IP)
echo "==> Installing iptables (for the controller's block rule) in victim"
docker exec victim bash -c 'apt-get install -y -qq iptables >/dev/null 2>&1'

# Install hping3 in the attacker only
# (the attack tool that sends the UDP/SYN floods)
echo "==> Installing hping3 in attacker only"
docker exec attacker bash -c 'apt-get install -y -qq hping3 >/dev/null 2>&1' &
wait

# Start the victim's server: iperf3 listening on UDP port 5201
# (the "real app" under attack - the flood targets this port)
echo "==> Starting UDP server (iperf3) on victim :5201"
docker exec -d victim iperf3 -s -p 5201

echo "==> Done. Testbed ready:"
docker ps --format 'table {{.Names}}\t{{.IPAddress}}\t{{.Status}}' | grep -E "victim|attacker|benign"
