#!/usr/bin/env bash
# Start the live dashboard. usage: bash start_dashboard.sh
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$DIR/dashboard.log"

# stop any previous dashboard
sudo pkill -f "monitor/dashboard.py" 2>/dev/null || true
sleep 1

# start it detached
sudo sh -c "nohup python3 $DIR/dashboard.py > $LOG 2>&1 &"
sleep 2

if curl -s -m 2 http://localhost:8080/api/stats >/dev/null 2>&1; then
  echo "Dashboard is running:  http://localhost:8080"
  echo "Log: $LOG"
else
  echo "Failed to start. Check $LOG"
  cat "$LOG" 2>/dev/null | tail -5
fi