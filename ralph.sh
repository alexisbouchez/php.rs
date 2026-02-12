#!/usr/bin/env bash
set -uo pipefail

###############################################################################
# ralph.sh — Autonomous TDD loop for php.rs
#
# Runs Claude Code in headless mode, one TODO item per iteration.
# Designed to run unattended overnight. Logs everything.
#
# Usage:
#   ./ralph.sh              # Run until all TODOs done or failure
#   ./ralph.sh --max 10     # Run at most 10 iterations
#   ./ralph.sh --dry-run    # Show what would be done without running
###############################################################################

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TODO_FILE="$PROJECT_DIR/TODO.txt"
PROMPT_FILE="$PROJECT_DIR/.claude/ralph-prompt.md"
LOG_DIR="$PROJECT_DIR/.ralph-logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_LOG="$LOG_DIR/run_${TIMESTAMP}.log"

# Defaults
MAX_ITERATIONS=200
MAX_TURNS=50
MAX_BUDGET=5.00
COOLDOWN=5
DRY_RUN=false
MODEL="sonnet"

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    --max)       MAX_ITERATIONS="$2"; shift 2 ;;
    --turns)     MAX_TURNS="$2"; shift 2 ;;
    --budget)    MAX_BUDGET="$2"; shift 2 ;;
    --cooldown)  COOLDOWN="$2"; shift 2 ;;
    --model)     MODEL="$2"; shift 2 ;;
    --dry-run)   DRY_RUN=true; shift ;;
    *)           echo "Unknown arg: $1"; exit 1 ;;
  esac
done

mkdir -p "$LOG_DIR"

# ─── Helpers ────────────────────────────────────────────────────────────────

log() {
  local msg="[$(date +'%H:%M:%S')] $*"
  echo "$msg" | tee -a "$RUN_LOG"
}

next_todo() {
  # Return the first unchecked [ ] line from TODO.txt
  grep -n '^\[ \]' "$TODO_FILE" | head -1 | sed 's/:.*//'
}

count_done() {
  grep -c '^\[x\]' "$TODO_FILE" 2>/dev/null || echo 0
}

count_remaining() {
  grep -c '^\[ \]' "$TODO_FILE" 2>/dev/null || echo 0
}

count_total() {
  grep -cE '^\[([ x~!])\]' "$TODO_FILE" 2>/dev/null || echo 0
}

# ─── Banner ─────────────────────────────────────────────────────────────────

cat <<'BANNER'

  ██████╗  █████╗ ██╗     ██████╗ ██╗  ██╗
  ██╔══██╗██╔══██╗██║     ██╔══██╗██║  ██║
  ██████╔╝███████║██║     ██████╔╝███████║
  ██╔══██╗██╔══██║██║     ██╔═══╝ ██╔══██║
  ██║  ██║██║  ██║███████╗██║     ██║  ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝
  Autonomous TDD Loop for php.rs

BANNER

log "═══════════════════════════════════════════════════"
log "Ralph loop started"
log "Project:    $PROJECT_DIR"
log "Model:      $MODEL"
log "Max iter:   $MAX_ITERATIONS"
log "Max turns:  $MAX_TURNS per iteration"
log "Budget:     \$$MAX_BUDGET per iteration"
log "Cooldown:   ${COOLDOWN}s between iterations"
log "Log file:   $RUN_LOG"
log "═══════════════════════════════════════════════════"

done_count=$(count_done)
remaining=$(count_remaining)
total=$(count_total)
log "Progress: $done_count/$total done, $remaining remaining"

if [[ "$DRY_RUN" == true ]]; then
  log "[DRY RUN] Would process $remaining items. Exiting."
  exit 0
fi

# ─── Pre-flight checks ─────────────────────────────────────────────────────

if ! command -v claude &>/dev/null; then
  log "ERROR: 'claude' CLI not found in PATH"
  exit 1
fi

if [[ ! -f "$TODO_FILE" ]]; then
  log "ERROR: TODO.txt not found at $TODO_FILE"
  exit 1
fi

if [[ ! -f "$PROMPT_FILE" ]]; then
  log "ERROR: ralph-prompt.md not found at $PROMPT_FILE"
  exit 1
fi

# Initialize git if needed
if [[ ! -d "$PROJECT_DIR/.git" ]]; then
  log "Initializing git repository..."
  cd "$PROJECT_DIR" && git init && git add -A && git commit -m "Initial commit: project scaffolding"
fi

# ─── Main loop ──────────────────────────────────────────────────────────────

iteration=0
consecutive_failures=0
MAX_CONSECUTIVE_FAILURES=3

while [[ $iteration -lt $MAX_ITERATIONS ]]; do
  iteration=$((iteration + 1))
  remaining=$(count_remaining)

  if [[ "$remaining" -eq 0 ]]; then
    log "════════════════════════════════════════"
    log "ALL TODOS COMPLETE! Stopping."
    log "════════════════════════════════════════"
    exit 0
  fi

  next_line=$(next_todo)
  next_task=$(sed -n "${next_line}p" "$TODO_FILE" 2>/dev/null | sed 's/^\[ \] //')

  log ""
  log "──────────────────────────────────────"
  log "Iteration $iteration/$MAX_ITERATIONS"
  log "Task: $next_task"
  log "Remaining: $remaining"
  log "──────────────────────────────────────"

  iter_log="$LOG_DIR/iter_$(printf '%03d' $iteration)_${TIMESTAMP}.json"

  # Run Claude headless
  output=$(cd "$PROJECT_DIR" && claude \
    -p "$(cat "$PROMPT_FILE")" \
    --output-format json \
    --model "$MODEL" \
    --max-turns "$MAX_TURNS" \
    --dangerously-skip-permissions \
    2>>"$RUN_LOG" || echo '{"result":"RALPH_FAIL: claude command exited non-zero"}')

  # Save raw output
  echo "$output" > "$iter_log"

  # Extract the result text
  result=$(echo "$output" | jq -r '.result // "NO_RESULT"' 2>/dev/null || echo "JSON_PARSE_ERROR")
  cost=$(echo "$output" | jq -r '.cost_usd // "?"' 2>/dev/null || echo "?")
  turns=$(echo "$output" | jq -r '.num_turns // "?"' 2>/dev/null || echo "?")
  session_id=$(echo "$output" | jq -r '.session_id // "?"' 2>/dev/null || echo "?")

  # Get the last meaningful status line
  status=$(echo "$result" | grep -oE 'RALPH_(OK|FAIL|BLOCKED|DONE)' | tail -1)
  status=${status:-"RALPH_UNKNOWN"}

  log "Status:  $status"
  log "Cost:    \$$cost"
  log "Turns:   $turns"
  log "Session: $session_id"

  # Save a snippet of the result (last 20 lines) for quick review
  echo "$result" | tail -20 >> "$RUN_LOG"

  # Handle status
  case "$status" in
    RALPH_OK)
      log "Task completed successfully."
      consecutive_failures=0
      done_count=$(count_done)
      total=$(count_total)
      log "Progress: $done_count/$total"
      ;;

    RALPH_DONE)
      log "════════════════════════════════════════"
      log "ALL TODOS COMPLETE! (reported by Claude)"
      log "════════════════════════════════════════"
      exit 0
      ;;

    RALPH_FAIL)
      consecutive_failures=$((consecutive_failures + 1))
      log "FAILURE ($consecutive_failures/$MAX_CONSECUTIVE_FAILURES consecutive)"

      if [[ $consecutive_failures -ge $MAX_CONSECUTIVE_FAILURES ]]; then
        log "════════════════════════════════════════"
        log "HALTING: $MAX_CONSECUTIVE_FAILURES consecutive failures"
        log "Last output saved to: $iter_log"
        log "════════════════════════════════════════"
        exit 1
      fi

      log "Will retry after extended cooldown..."
      sleep $((COOLDOWN * 5))
      continue
      ;;

    RALPH_BLOCKED)
      log "Task is blocked. Skipping to next..."
      # Mark as blocked in TODO.txt
      if [[ -n "$next_line" ]]; then
        cd "$PROJECT_DIR" && sed -i '' "${next_line}s/^\[ \]/[!]/" "$TODO_FILE"
        log "Marked line $next_line as [!] blocked"
      fi
      consecutive_failures=0
      ;;

    *)
      log "WARNING: Unknown status '$status'. Treating as partial success."
      consecutive_failures=0
      ;;
  esac

  # Cooldown between iterations
  log "Cooling down ${COOLDOWN}s..."
  sleep "$COOLDOWN"
done

log "════════════════════════════════════════"
log "Reached max iterations ($MAX_ITERATIONS). Stopping."
log "════════════════════════════════════════"
exit 0
