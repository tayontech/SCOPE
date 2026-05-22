#!/bin/bash
# SCOPE Agent Logger — PostToolUse / AfterTool hook (async)
# Auto-logs AWS CLI calls to agent-log.jsonl in the active run directory.
# Runs asynchronously — never blocks the agent.
#
# This hook supplements the agent's inline evidence logging by catching
# any AWS calls the agent might not explicitly log.

set -euo pipefail

INPUT=$(cat /dev/stdin)

# Ultra-fast exit: check raw stdin for 'aws' before any jq parsing.
# Skips 90%+ of hook invocations (mkdir, echo, cp, jq, etc.) with zero jq overhead.
if ! echo "$INPUT" | grep -q '"aws '; then
  exit 0
fi

COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Precise check on parsed command
if ! echo "$COMMAND" | grep -qE '^\s*aws\s'; then
  exit 0
fi

TOOL_RESPONSE=$(echo "$INPUT" | jq -r '.tool_response // empty')
CWD=$(echo "$INPUT" | jq -r '.cwd // empty')

if [ -z "$CWD" ]; then
  CWD="$(pwd)"
fi

# Fork to background — return control to the agent immediately.
# This prevents TUI flickering on platforms with synchronous hooks (Gemini CLI).
(
  # Find most recent run directory across all phases
  RUN_DIR=""
  LATEST_TIME=0
  for dir_pattern in "$CWD/runs/audit-"* "$CWD/exploit/exploit-"* "$CWD/hunt/hunt-"* "$CWD/runs/audit-"*/defend/defend-*; do
    for d in $dir_pattern; do
      [ -d "$d" ] || continue
      # Check modified within last 30 min
      if find "$d" -maxdepth 0 -mmin -30 -print -quit 2>/dev/null | grep -q .; then
        mod_time=$(stat -f %m "$d" 2>/dev/null || stat -c %Y "$d" 2>/dev/null || echo 0)
        if [ "$mod_time" -gt "$LATEST_TIME" ]; then
          LATEST_TIME=$mod_time
          RUN_DIR="$d"
        fi
      fi
    done
  done

  # No active run — skip
  if [ -z "$RUN_DIR" ]; then
    exit 0
  fi

  LOG_FILE="$RUN_DIR/agent-log.jsonl"

  # Parse the AWS command into service and action, skipping --flag value pairs
  parse_aws_args() {
    local skip_next=false
    for word in $1; do
      [ "$word" = "aws" ] && continue
      if [ "$skip_next" = true ]; then skip_next=false; continue; fi
      case "$word" in
        --*=*) continue ;;
        --*)   skip_next=true; continue ;;
      esac
      echo "$word"
    done
  }
  AWS_ARGS=$(parse_aws_args "$COMMAND")
  AWS_SERVICE=$(echo "$AWS_ARGS" | head -1)
  AWS_ACTION=$(echo "$AWS_ARGS" | sed -n '2p')

  # Determine response status from tool_response
  RESPONSE_STATUS="unknown"
  if echo "$TOOL_RESPONSE" | grep -qi 'error\|denied\|failed\|exception'; then
    RESPONSE_STATUS="error"
  elif echo "$TOOL_RESPONSE" | grep -qi 'AccessDenied\|UnauthorizedAccess'; then
    RESPONSE_STATUS="access_denied"
  else
    RESPONSE_STATUS="success"
  fi

  # Get next evidence ID (use flock to prevent race conditions from parallel subagents)
  (
    flock -w 2 200 2>/dev/null || true
    if [ -f "$LOG_FILE" ]; then
      LAST_ID=$(grep -oE '"ev-[0-9]+"' "$LOG_FILE" 2>/dev/null | tail -1 | tr -d '"' | sed 's/ev-//')
      NEXT_NUM=$((${LAST_ID:-0} + 1))
    else
      NEXT_NUM=1
    fi
    EV_ID=$(printf "ev-%03d" "$NEXT_NUM")

    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    jq -nc \
      --arg id "$EV_ID" \
      --arg ts "$TIMESTAMP" \
      --arg svc "$AWS_SERVICE" \
      --arg action "$AWS_ACTION" \
      --arg cmd "$COMMAND" \
      --arg status "$RESPONSE_STATUS" \
      --arg source "hook:scope-agent-logger" \
      '{
        type: "api_call",
        evidence_id: $id,
        timestamp: $ts,
        service: $svc,
        action: $action,
        command: $cmd,
        response_status: $status,
        source: $source
      }' >> "$LOG_FILE" 2>/dev/null || true
  ) 200>"$LOG_FILE.lock"
) &
disown

exit 0
