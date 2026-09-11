#!/usr/bin/env bash
# Runs the controller as a background daemon and returns.
set -euo pipefail
LOG="/tmp/ddos_controller.log"
rm -f "$LOG"
sudo -n sh -c "nohup python3 /home/sanjeev/Desktop/CN/controller/controller.py > '$LOG' 2>&1 &"
echo "controller started, log: $LOG"
