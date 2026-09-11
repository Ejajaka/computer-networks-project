#!/usr/bin/env bash
# Run a UDP flood benchmark against the victim and report metrics.
# usage: bench_udp.sh <seconds> <mode: filter-on|filter-off>
set -euo pipefail

SECS="${1:-10}"
MODE="${2:-filter-on}"
VICTIM_VETH="eth0"
BPFTOOL="/usr/lib/linux-tools/5.15.0-190-generic/bpftool"

read_stats() {
  docker exec victim bash -c "$BPFTOOL map dump name stats_map 2>/dev/null" 2>/dev/null \
    | grep -oE '\"(total|dropped)\": [0-9]+' \
    | awk -F': ' '{s[$1]+=$2} END{print s["\"total\""]+0, s["\"dropped\""]+0}'
}

echo "===== UDP Flood Benchmark: $MODE ($SECS s) ====="
echo "Baseline traffic setup: benign iperf3 -> victim"

# Record baseline stats
read -r T0 D0 < <(read_stats)

# Start benign UDP traffic (iperf3 client from benign to victim) in background
docker exec -d benign iperf3 -c 172.30.0.10 -p 5201 -u -b 5M -t "$SECS" >/dev/null 2>&1

# Start the attack: UDP flood from attacker to victim
docker exec -d attacker hping3 -2 -p 5201 --flood 172.30.0.10 >/dev/null 2>&1
echo ">> attack started (hping3 UDP flood)"

# Monitor CPU of victim container while attack runs
docker stats --no-stream --format '{{.Name}} CPU={{.CPUPerc}}' victim > /tmp/cpu_sample.txt &
STATS_PID=$!

# Measure ping latency to victim during attack
( for i in $(seq 1 "$SECS"); do
    ping -c 1 -W 1 172.30.0.10 2>/dev/null | grep -oP 'time=\K[0-9.]+' 
    sleep 1
  done ) > /tmp/latency.txt &
LAT_PID=$!

sleep "$SECS"

# Stop attack
docker exec attacker pkill -9 hping3 2>/dev/null || true

# Final stats
read -r T1 D1 < <(read_stats)
TOTAL=$((T1 - T0)); DROPPED=$((D1 - D0))
if [ "$TOTAL" -gt 0 ]; then
  PCT=$(awk -v d="$DROPPED" -v t="$TOTAL" 'BEGIN{printf "%.1f", 100*d/t}')
else
  PCT="0.0"
fi

echo ""
echo "===== Results ($MODE) ====="
echo "Total packets (seen by XDP):  $TOTAL"
echo "Dropped (malicious):          $DROPPED"
echo "Drop rate:                    $PCT%"

echo "--- CPU (victim) ---"
cat /tmp/cpu_sample.txt
echo "--- Ping latency (ms) during attack ---"
cat /tmp/latency.txt | sort -n | awk 'NR==1{min=$1}{a[NR]=$1}END{print "  count="NR, "min="min, "max="a[NR]}'
cat /tmp/latency.txt
