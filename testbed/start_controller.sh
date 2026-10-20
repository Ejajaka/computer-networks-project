#!/usr/bin/env bash
set -euo pipefail
# Find the project root so the controller path works from any directory.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="/tmp/ddos_controller.log"
# Clear the previous controller log.
rm -f "$LOG"
# Start the controller in the background; it watches kernel flood alerts.
sudo -n sh -c "nohup python3 '$DIR/controller/controller.py' > '$LOG' 2>&1 &"
echo "controller started, log: $LOG"
