#!/usr/bin/env bash
###############################################################################
# ralph-overnight.sh — Sleep-proof wrapper for Ralph
#
# - Uses caffeinate to prevent macOS sleep
# - Auto-restarts Ralph if it crashes unexpectedly
# - Logs supervisor events separately
# - Safe to close terminal (runs under nohup + disown)
#
# Usage: nohup ./ralph-overnight.sh &
###############################################################################
set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$PROJECT_DIR/.ralph-logs"
SUPERVISOR_LOG="$LOG_DIR/supervisor.log"
RALPH_STDOUT="$LOG_DIR/ralph_stdout.log"

mkdir -p "$LOG_DIR"

slog() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >> "$SUPERVISOR_LOG"
}

# Kill any existing Ralph processes to avoid duplicates
existing=$(pgrep -f "ralph\.sh" | grep -v $$ || true)
if [[ -n "$existing" ]]; then
  slog "Killing existing Ralph processes: $existing"
  echo "$existing" | xargs kill 2>/dev/null || true
  sleep 2
fi

# Kill any leftover claude processes from previous runs
pkill -f "claude.*ralph-prompt" 2>/dev/null || true

slog "=========================================="
slog "Ralph overnight supervisor started"
slog "PID: $$"
slog "=========================================="

# Save our PID for easy cleanup
echo $$ > "$LOG_DIR/supervisor.pid"

MAX_RESTARTS=5
restart_count=0

while true; do
  done_count=$(grep -c '^\[x\]' "$PROJECT_DIR/TODO.txt" 2>/dev/null || echo 0)
  remaining=$(grep -c '^\[ \]' "$PROJECT_DIR/TODO.txt" 2>/dev/null || echo 0)

  if [[ "$remaining" -eq 0 ]]; then
    slog "ALL TODOS COMPLETE ($done_count items). Supervisor exiting."
    exit 0
  fi

  slog "Starting Ralph (attempt $((restart_count + 1))). Progress: $done_count done, $remaining remaining."

  # caffeinate -i = prevent idle sleep (keeps CPU awake, screen can turn off)
  # -w $$ = release when this script exits
  caffeinate -i -w $$ &
  CAFE_PID=$!
  slog "caffeinate started (PID: $CAFE_PID)"

  # Run Ralph (blocking)
  "$PROJECT_DIR/ralph.sh" --model sonnet --max 200 --budget 5 --cooldown 8 \
    >> "$RALPH_STDOUT" 2>&1
  EXIT_CODE=$?

  # Stop caffeinate for this round
  kill "$CAFE_PID" 2>/dev/null || true

  slog "Ralph exited with code $EXIT_CODE"

  if [[ $EXIT_CODE -eq 0 ]]; then
    # Clean exit — either all done or max iterations
    done_count=$(grep -c '^\[x\]' "$PROJECT_DIR/TODO.txt" 2>/dev/null || echo 0)
    remaining=$(grep -c '^\[ \]' "$PROJECT_DIR/TODO.txt" 2>/dev/null || echo 0)
    slog "Ralph finished cleanly. Progress: $done_count done, $remaining remaining."

    if [[ "$remaining" -eq 0 ]]; then
      slog "All TODOs complete. Supervisor exiting."
      exit 0
    fi

    # Max iterations reached but items remain — restart fresh
    slog "Max iterations reached. Restarting with fresh counter..."
    restart_count=0
    sleep 10
    continue
  fi

  # Non-zero exit = failure
  restart_count=$((restart_count + 1))

  if [[ $restart_count -ge $MAX_RESTARTS ]]; then
    slog "FATAL: $MAX_RESTARTS consecutive failures. Supervisor giving up."
    slog "Check logs at: $LOG_DIR"
    exit 1
  fi

  slog "Ralph failed. Waiting 30s before restart ($restart_count/$MAX_RESTARTS)..."
  sleep 30
done
