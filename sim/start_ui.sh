#!/usr/bin/env bash
# Start the live DDoS mitigation Simulator UI.
# Usage:  bash sim/start_ui.sh
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="/tmp/sim_ui.log"

# stop any previous instance (without killing our own shell)
pkill -f "sim/ui_server.py" 2>/dev/null || true
sleep 1

setsid nohup python3 -u "$DIR/ui_server.py" > "$LOG" 2>&1 < /dev/null &
sleep 3

if curl -s -m 2 http://localhost:8090/api/state >/dev/null 2>&1; then
  echo "Simulator UI running:  http://localhost:8090"
  echo "Open that URL in your browser."
  echo "Log: $LOG"
else
  echo "Failed to start. Log:"
  cat "$LOG" 2>/dev/null
fi

echo
echo "To stop:  pkill -f sim/ui_server.py"