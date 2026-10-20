#!/usr/bin/env bash
# Runs one UDP benchmark (filter on/off): attack + CPU + latency.
# usage: bench_run.sh <filter-on|filter-off> <seconds>
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="$1"; SECS="${2:-10}"

# turn filter on/off
if [ "$MODE" = "filter-on" ]; then
  "$DIR/ctl_udp.sh" on >/dev/null
else
  "$DIR/ctl_udp.sh" off >/dev/null
fi

echo "##### MODE: $MODE ($SECS s) #####"

# host CPU sampler (1/s)
( for i in $(seq 1 "$SECS"); do
    line1=$(grep '^cpu ' /proc/stat)
    sleep 1
    line2=$(grep '^cpu ' /proc/stat)
    echo "$line1 $line2" | awk '{idle1=$5+$6; tot1=$2+$3+$4+$5+$6+$7+$8; idle2=$16+$17; tot2=$13+$14+$15+$16+$17+$18+$19; printf "%.1f\n", 100*(1-(idle2-idle1)/(tot2-tot1))}'
  done ) > /tmp/hostcpu_$MODE.txt &
HCPUID=$!

# victim CPU sampler (1/s)
( for i in $(seq 1 "$SECS"); do
    docker stats --no-stream --format '{{.CPUPerc}}' victim 2>/dev/null
    sleep 1
  done ) > /tmp/cpu_$MODE.txt &
CPUID=$!

# ping latency sampler (1/s)
( for i in $(seq 1 "$SECS"); do
    ping -c 1 -W 1 172.30.0.10 2>/dev/null | grep -oP 'time=\K[0-9.]+'
  done ) > /tmp/lat_$MODE.txt &
LATID=$!

# normal traffic: benign -> victim 5 Mbps
docker exec -d benign iperf3 -c 172.30.0.10 -p 5201 -u -b 5M -t "$SECS" >/dev/null 2>&1

# attack: 4 UDP flood workers
for i in 1 2 3 4; do
  docker exec -d attacker hping3 -2 -p 5201 --flood 172.30.0.10 >/dev/null 2>&1
done

# run for SECS then stop the attack
sleep "$SECS"
docker exec attacker pkill -9 hping3 2>/dev/null

# wait for samplers then print results
wait $CPUID $LATID $HCPUID 2>/dev/null

echo "== Host CPU samples (%) =="; cat /tmp/hostcpu_$MODE.txt | sort -n | awk '{s+=$1; a[NR]=$1}END{print "  avg="s/NR"% min="a[1]"% max="a[NR]"%"}' ; cat /tmp/hostcpu_$MODE.txt | tr '\n' ' '; echo ""
echo "== Victim container CPU samples (%) =="; cat /tmp/cpu_$MODE.txt | sort -n | awk '{s+=$1; a[NR]=$1}END{print "  avg="s/NR"% min="a[1]"% max="a[NR]"%"}' ; cat /tmp/cpu_$MODE.txt | tr '\n' ' '; echo ""
echo "== Ping latency samples (ms) =="; cat /tmp/lat_$MODE.txt | sort -n | awk '{s+=$1;a[NR]=$1}END{print "  count="NR" min="a[1]" max="a[NR]" avg="s/NR}'
cat /tmp/lat_$MODE.txt | tr '\n' ' '; echo ""
