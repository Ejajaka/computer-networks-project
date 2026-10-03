#!/usr/bin/env bash
# =============================================================================
# One-shot demo: runs the full DDoS mitigation simulation and prints results.
# Usage:  sudo bash demo.sh
#
# The quick one-shot demo. It walks through numbered steps and prints
# coloured output:
#   Step 0-1: start the containers and the iperf3 server.
#   Step 2  : make sure bpftool + iptables are installed in the victim, copy
#             the combined filter (ddos_filter_kern.o, UDP + SYN floods) in,
#             and attach it.
#   Step 3  : start the controller (controller.py). It reads alerts from the
#             filter, blocks attacker IPs and logs them.
#   Step 4  : UDP flood for 8 s, then prints seen / dropped / drop rate.
#   Step 5  : SYN flood, same measurement.
#   Step 6  : normal traffic from benign - extra drops should be 0.
#   Step 7  : show the controller log lines about detections and blocks.
# =============================================================================
set -uo pipefail

VICTIM=172.30.0.10
ATTACKER=172.30.0.20
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m    $*\033[0m"; }
warn() { echo -e "\033[1;33m    $*\033[0m"; }

# --- bpftool finder inside the victim container (version independent) --------
# (the linux-tools version in the path varies, so find it dynamically)
bpf_path() {
  docker exec victim bash -c \
    'ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1 || echo bpftool'
}

# --- read the XDP stats map inside the victim --------------------------------
# Returns: udp_total udp_dropped syn_total syn_dropped
read_stats() {
  local BPF; BPF=$(bpf_path)
  docker exec victim bash -c "$BPF map dump name stats_map 2>/dev/null" 2>/dev/null \
    | grep -oE '"(udp_total|udp_dropped|syn_total|syn_dropped)": [0-9]+' \
    | awk -F': ' '{s[$1]+=$2} END{
        printf "%d %d %d %d",
        s["\"udp_total\""]+0, s["\"udp_dropped\""]+0,
        s["\"syn_total\""]+0, s["\"syn_dropped\""]+0 }'
}

say "Step 0: make sure the containers are running"
docker start victim attacker benign >/dev/null 2>&1 || true
docker ps --format '    {{.Names}}  {{.Status}}' | grep -E 'victim|attacker|benign'

say "Step 1: start the UDP server on the victim"
docker exec -d victim pkill -9 iperf3 >/dev/null 2>&1 || true
docker exec -d victim iperf3 -s -p 5201 >/dev/null 2>&1
ok "iperf3 UDP server listening on victim:5201"

say "Step 2: install bpftool + iptables in victim if missing, then attach the combined filter"
# install bpftool (to load/pin the XDP program) and iptables (used by controller)
docker exec victim bash -c 'command -v bpftool >/dev/null 2>&1 || ls /usr/lib/linux-tools/*/bpftool >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq linux-tools-generic linux-tools-common)' >/dev/null 2>&1
docker exec victim bash -c 'command -v iptables >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq iptables)' >/dev/null 2>&1
BPF=$(bpf_path)
# copy the combined (UDP + SYN) filter into the victim, load it, pin it, attach to eth0
docker cp "$PROJECT_DIR/engine/ddos_filter_kern.o" victim:/tmp/ddos_filter_kern.o >/dev/null 2>&1
docker exec victim bash -c "
  ip link set dev eth0 xdp off 2>/dev/null
  rm -rf /sys/fs/bpf/ddos
  $BPF prog loadall /tmp/ddos_filter_kern.o /sys/fs/bpf/ddos && \
  ip link set dev eth0 xdp pinned /sys/fs/bpf/ddos/xdp"
docker exec victim bash -c 'ip link show eth0 | grep -q xdp' \
  && ok "combined filter attached to victim eth0 (xdp)" \
  || { warn "filter attach FAILED"; exit 1; }

say "Step 3: start the user-space controller (reads alerts, blocks IPs, logs)"
pkill -f controller.py 2>/dev/null || true
nohup python3 "$PROJECT_DIR/controller/controller.py" > /tmp/ddos_controller.log 2>&1 &
sleep 2
ok "controller running (log: /tmp/ddos_controller.log)"

# ---------------------------------------------------------------------------
say "Step 4: UDP flood test (~100 Mbps from attacker)"
read -r U0 UD0 S0 SD0 < <(read_stats)          # counters BEFORE
for i in 1 2 3 4; do docker exec -d attacker hping3 -2 -p 5201 --flood $VICTIM >/dev/null 2>&1; done
sleep 8
docker exec attacker pkill -9 hping3 >/dev/null 2>&1 || true
sleep 1
read -r U1 UD1 S1 SD1 < <(read_stats)          # counters AFTER
UT=$((U1-U0)); UDD=$((UD1-UD0))
awk -v t=$UT -v d=$UDD 'BEGIN{printf "    UDP: seen=%d dropped=%d  drop_rate=%.1f%%\n",t,d,(t?100*d/t:0)}'

# ---------------------------------------------------------------------------
say "Step 5: SYN flood test"
# hping3 -S sends SYN packets (the first packet of a TCP connection). Flooding
# them makes the server hold half-open connections until it runs out of room.
read -r U0 UD0 S0 SD0 < <(read_stats)          # counters BEFORE
for i in 1 2 3 4; do docker exec -d attacker hping3 -S -p 5201 --flood $VICTIM >/dev/null 2>&1; done
sleep 8
docker exec attacker pkill -9 hping3 >/dev/null 2>&1 || true
sleep 1
read -r U1 UD1 S1 SD1 < <(read_stats)          # counters AFTER
ST=$((S1-S0)); SDD=$((SD1-SD0))
awk -v t=$ST -v d=$SDD 'BEGIN{printf "    SYN: seen=%d dropped=%d  drop_rate=%.1f%%\n",t,d,(t?100*d/t:0)}'

# ---------------------------------------------------------------------------
say "Step 6: legitimate traffic test (should NOT be dropped)"
# normal user sends 3 Mbps for 5 s - extra drops should be 0
read -r U0 UD0 S0 SD0 < <(read_stats)
docker exec benign iperf3 -c $VICTIM -p 5201 -u -b 3M -t 5 >/dev/null 2>&1
read -r U1 UD1 S1 SD1 < <(read_stats)
UDD=$((UD1-UD0))
echo "    benign UDP extra drops: $UDD  (expected: 0)"

# ---------------------------------------------------------------------------
say "Step 7: controller log (detections + blocks)"
cat /tmp/ddos_controller.log 2>/dev/null | grep -E "FLOOD|BLOCKED" || echo "    (no alerts)"

# ---------------------------------------------------------------------------
say "Done. Summary"
echo "    UDP flood drop rate : see Step 4"
echo "    SYN flood drop rate : see Step 5"
echo "    Legit traffic drops : see Step 6 (expected 0)"
echo "    Full log            : /tmp/ddos_controller.log"
echo "    Alerts log          : ~/Desktop/CN/results/alerts.log"
