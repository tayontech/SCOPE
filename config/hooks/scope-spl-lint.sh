#!/bin/bash
# SCOPE SPL Semantic Lint — PostToolUse / AfterTool hook
# Runs after Write|Edit on files that contain SPL queries.
# Hard-fails on known anti-patterns defined in config/splunk-patterns.md.
# Multi-index aware: enforces named indexes without relying on static index config.
#
# Exit 0 = pass (with optional feedback), Exit 2 = not used (PostToolUse can't block)
# Instead, returns decision: "block" with reason in JSON to feed back to agent.

set -euo pipefail

INPUT=$(cat /dev/stdin)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // .toolCall.args.TargetFile // empty')

# Only lint files in controls/ directories or files with splunk/spl/detection in the name
if [ -z "$FILE_PATH" ]; then
  exit 0
fi

case "$FILE_PATH" in
  */controls/*|*detection*|*splunk*|*.spl)
    ;;
  *)
    exit 0
    ;;
esac

# Check if file exists
if [ ! -f "$FILE_PATH" ]; then
  exit 0
fi

CONTENT=$(cat "$FILE_PATH")
ERRORS=()

# --- Hard-fail lint rules ---

# Rule 1: Missing time bounds on any index= query (applies to ALL indexes, not just CloudTrail)
if grep -qE 'index=[a-zA-Z_]' <<<"$CONTENT" && ! grep -qE '(earliest=|latest=)' <<<"$CONTENT"; then
  ERRORS+=("SPL LINT WARNING: SPL query has no time bounds (earliest/latest). Unbounded queries are expensive and may timeout.")
fi

# Rule 2: Leading wildcard ban
if grep -qE '[a-zA-Z_]+=\*[a-zA-Z0-9_]' <<<"$CONTENT"; then
  ERRORS+=("SPL LINT FAIL: Leading wildcard detected (field=*value). Forces full raw-text scan. Use exact match or OR list instead.")
fi

# Rule 3: index=* ban
if grep -qE 'index=\*($|[^a-zA-Z0-9_-])' <<<"$CONTENT"; then
  ERRORS+=("SPL LINT FAIL: 'index=*' is not allowed. Always specify a named index.")
fi

# Rule 4: outputlookup ban
if grep -qi '| *outputlookup ' <<<"$CONTENT"; then
  ERRORS+=("SPL LINT FAIL: 'outputlookup' is not allowed in generated detections. It writes lookup content and requires operator-approved maintenance workflow.")
fi

# Rule 5: Expensive correlation and fan-out command bans
if grep -qiE '\| *(join|append|appendcols|selfjoin|map)($|[ =])' <<<"$CONTENT"; then
  ERRORS+=("SPL LINT FAIL: Expensive correlation/fan-out command detected. Generated detections must avoid join, append, appendcols, selfjoin, and map.")
fi

# Rule 6: Side-effect command bans
if grep -qiE '\| *(collect|mcollect|tscollect|outputcsv|delete|sendemail|sendalert|script|run)($|[ =])' <<<"$CONTENT"; then
  ERRORS+=("SPL LINT FAIL: Side-effect command detected. Generated detections must not write, delete, notify, or run external commands.")
fi

# --- Report results ---

if [ ${#ERRORS[@]} -gt 0 ]; then
  REASON=$(printf '%s\n' "${ERRORS[@]}")
  jq -n --arg reason "$REASON" --arg file "$FILE_PATH" '{
    decision: "block",
    reason: ("SPL lint failures in " + $file + ":\n" + $reason + "\n\nFix the SPL queries and rewrite the file.")
  }'
  exit 0
fi

# All checks passed
exit 0
