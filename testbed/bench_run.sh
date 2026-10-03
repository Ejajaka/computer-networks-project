#!/usr/bin/env bash
# Full UDP benchmark for one mode. usage: bench_run.sh <filter-on|filter-off> <seconds>
#
# One complete benchmark run for a given mode:
#   - turns the filter on or off (via ctl_udp.sh)
#   - starts three background "measurers", sampling once per second:
#       host CPU usage   (read from /proc/stat)
#       victim container CPU (docker stats)
#       ping latency to the victim
#   - starts NORMAL traffic: benign container sends a small 5 Mbps UDP stream
#   - starts the ATTACK: 4 parallel hping3 processes flooding UDP at port 5201
#     (about 100 Mbps total)
#   - waits, kills the attack, prints min/avg/max for CPU and latency
#
# The idea: with the filter ON, CPU should stay lower and ping should stay
# healthy (fewer bad packets reaching the victim's stack).
set -uo pipefail
MODE="$1"; SECS="${2:-10}"

# Set filter state (turn the UDP filter on/off inside the victim)
if [ "$MODE" = "filter-on" ]; then
  /home/sanjeev/Desktop/CN/testbed/ctl_udp.sh on >/dev/null
else
  /home/sanjeev/Desktop/CN/testbed/ctl_udp.sh off >/dev/null
fi

echo "##### MODE: $MODE ($SECS s) #####"

# host CPU sampler (overall utilization via /proc/stat, sampled 1/s).
# Takes two snapshots of the cpu counters, computes the % that was busy.
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

# latency sampler from host (ping the victim once per second)
( for i in $(seq 1 "$SECS"); do
    ping -c 1 -W 1 172.30.0.10 2>/dev/null | grep -oP 'time=\K[0-9.]+'
  done ) > /tmp/lat_$MODE.txt &
LATID=$!

# start benign UDP load (normal traffic: 5 Mbps from benign to victim :5201)
docker exec -d benign iperf3 -c 172.30.0.10 -p 5201 -u -b 5M -t "$SECS" >/dev/null 2>&1

# start attack (4 parallel hping3 workers ~ 100 Mbps UDP flood to :5201)
for i in 1 2 3 4; do
  docker exec -d attacker hping3 -2 -p 5201 --flood 172.30.0.10 >/dev/null 2>&1
done

# let it run for SECS seconds, then kill the attack
sleep "$SECS"
docker exec attacker pkill -9 hping3 2>/dev/null

# wait for the three samplers to finish, then print min/avg/max for each
wait $CPUID $LATID $HCPUID 2>/dev/null

echo "== Host CPU samples (%) =="; cat /tmp/hostcpu_$MODE.txt | sort -n | awk '{s+=$1; a[NR]=$1}END{print "  avg="s/NR"% min="a[1]"% max="a[NR]"%"}' ; cat /tmp/hostcpu_$MODE.txt | tr '\n' ' '; echo ""
echo "== Victim container CPU samples (%) =="; cat /tmp/cpu_$MODE.txt | sort -n | awk '{s+=$1; a[NR]=$1}END{print "  avg="s/NR"% min="a[1]"% max="a[NR]"%"}' ; cat /tmp/cpu_$MODE.txt | tr '\n' ' '; echo ""
echo "== Ping latency samples (ms) =="; cat /tmp/lat_$MODE.txt | sort -n | awk '{s+=$1;a[NR]=$1}END{print "  count="NR" min="a[1]" max="a[NR]" avg="s/NR}'
cat /tmp/lat_$MODE.txt | tr '\n' ' '; echo ""
