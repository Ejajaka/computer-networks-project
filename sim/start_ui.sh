#!/usr/bin/env bash
set -euo pipefail  #makes the script stop of there is some command that fails or some variable missing
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="/tmp/sim_ui.log"  # for logging

# Step 1: remove an old simulator process, if one is still running.
pkill -f "sim/ui_server.py" 2>/dev/null || true
sleep 1

# Step 2: start the Python backend. It serves the page and controls the test.
setsid nohup python3 -u "$DIR/ui_server.py" > "$LOG" 2>&1 < /dev/null &

# Step 3: prepare() can take a while, so keep checking the health endpoint.
ready=0
for _ in $(seq 1 20); do
  if curl -s -m 2 http://localhost:8090/api/state >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done

# Step 4: report whether the backend is ready for the browser.
if [ "$ready" = "1" ]; then
  echo "Simulator UI running:  http://localhost:8090"
  echo "Open that URL in your browser."
  echo "Log: $LOG"
else
  echo "Failed to start. Log:"
  cat "$LOG" 2>/dev/null
fi

echo
echo "To stop:  pkill -f sim/ui_server.py"
