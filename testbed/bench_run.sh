#!/usr/bin/env bash
# Full UDP benchmark for one mode. usage: bench_run.sh <filter-on|filter-off> <seconds>
set -uo pipefail
MODE="$1"; SECS="${2:-10}"

# Set filter state
if [ "$MODE" = "filter-on" ]; then
  /home/sanjeev/Desktop/CN/testbed/ctl_udp.sh on >/dev/null
else
  /home/sanjeev/Desktop/CN/testbed/ctl_udp.sh off >/dev/null
fi

echo "##### MODE: $MODE ($SECS s) #####"

# host CPU sampler (overall utilization via /proc/stat)
( for i in $(seq 1 "$SECS"); do
    line1=$(grep '^cpu ' /proc/stat)
    sleep 1
    line2=$(grep '^cpu ' /proc/stat)
    echo "$line1 $line2" | awk '{idle1=$5+$6; tot1=$2+$3+$4+$5+$6+$7+$8; idle2=$16+$17; tot2=$13+$14+$15+$16+$17+$18+$19; printf "%.1f\n", 100*(1-(idle2-idle1)/(tot2-tot1))}'
  done ) > /tmp/hostcpu_$MODE.txt &
HCPUID=$!

# start CPU sampler on victim (docker stats every 1s)
( for i in $(seq 1 "$SECS"); do
    docker stats --no-stream --format '{{.CPUPerc}}' victim 2>/dev/null
    sleep 1
  done ) > /tmp/cpu_$MODE.txt &
CPUID=$!

# latency sampler from host
( for i in $(seq 1 "$SECS"); do
    ping -c 1 -W 1 172.30.0.10 2>/dev/null | grep -oP 'time=\K[0-9.]+'
  done ) > /tmp/lat_$MODE.txt &
LATID=$!

# start benign UDP load
docker exec -d benign iperf3 -c 172.30.0.10 -p 5201 -u -b 5M -t "$SECS" >/dev/null 2>&1

# start attack (4 parallel hping3 workers ~ 100 Mbps)
for i in 1 2 3 4; do
  docker exec -d attacker hping3 -2 -p 5201 --flood 172.30.0.10 >/dev/null 2>&1
done

sleep "$SECS"
docker exec attacker pkill -9 hping3 2>/dev/null

wait $CPUID $LATID $HCPUID 2>/dev/null

echo "== Host CPU samples (%) =="; cat /tmp/hostcpu_$MODE.txt | sort -n | awk '{s+=$1; a[NR]=$1}END{print "  avg="s/NR"% min="a[1]"% max="a[NR]"%"}' ; cat /tmp/hostcpu_$MODE.txt | tr '\n' ' '; echo ""
echo "== Victim container CPU samples (%) =="; cat /tmp/cpu_$MODE.txt | sort -n | awk '{s+=$1; a[NR]=$1}END{print "  avg="s/NR"% min="a[1]"% max="a[NR]"%"}' ; cat /tmp/cpu_$MODE.txt | tr '\n' ' '; echo ""
echo "== Ping latency samples (ms) =="; cat /tmp/lat_$MODE.txt | sort -n | awk '{s+=$1;a[NR]=$1}END{print "  count="NR" min="a[1]" max="a[NR]" avg="s/NR}'
cat /tmp/lat_$MODE.txt | tr '\n' ' '; echo ""
