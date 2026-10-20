#!/usr/bin/env bash
# Starts the controller in the background.
# Note: the path below is hardcoded to this machine.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="/tmp/ddos_controller.log"
rm -f "$LOG"   # clear old log
sudo -n sh -c "nohup python3 '$DIR/controller/controller.py' > '$LOG' 2>&1 &"
echo "controller started, log: $LOG"
