#!/usr/bin/env bash
# Runs the controller as a background daemon and returns.
#
# Deletes the old log, then starts controller.py with sudo in the background
# using nohup, so it keeps running even after this script exits.
# NOTE: the path /home/sanjeev/Desktop/CN is hardcoded (like bench_run.sh),
# so this only works on this machine unless edited.
set -euo pipefail
LOG="/tmp/ddos_controller.log"
rm -f "$LOG"   # delete the old log before starting fresh
sudo -n sh -c "nohup python3 /home/sanjeev/Desktop/CN/controller/controller.py > '$LOG' 2>&1 &"
echo "controller started, log: $LOG"
