#!/bin/bash
# SCOPE SPL Semantic Lint — PostToolUse / AfterTool hook
# Runs after Write|Edit on files that contain SPL queries.
# Hard-fails on known anti-patterns from scope-verify-splunk.md.
#
# Exit 0 = pass (with optional feedback), Exit 2 = not used (PostToolUse can't block)
# Instead, returns decision: "block" with reason in JSON to feed back to agent.

set -euo pipefail

INPUT=$(cat /dev/stdin)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

# Only lint files in defend/ directories or files with splunk/spl/detection in the name
if [ -z "$FILE_PATH" ]; then
  exit 0
fi

case "$FILE_PATH" in
  */defend/*|*detection*|*splunk*|*.spl)
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

# Rule 1: Composite detections must NOT use 'transaction'
if echo "$CONTENT" | grep -qi '\[COMPOSITE\]' && echo "$CONTENT" | grep -qi '| *transaction '; then
  ERRORS+=("SPL LINT FAIL: Composite detection uses 'transaction'. Composites MUST use 'streamstats' for sliding-window correlation, not 'transaction'.")
fi

# Rule 2: All CloudTrail SPL must include index=cloudtrail
# Require 2+ CloudTrail-specific fields to trigger (reduces false positives from generic field names)
CT_FIELD_COUNT=0
for ct_field in 'userIdentity\.' 'eventName' 'sourceIPAddress' 'requestParameters\.' 'responseElements\.' 'eventSource.*\.amazonaws\.com'; do
  if echo "$CONTENT" | grep -qE "$ct_field"; then
    CT_FIELD_COUNT=$((CT_FIELD_COUNT + 1))
  fi
done
if [ "$CT_FIELD_COUNT" -ge 2 ] && ! echo "$CONTENT" | grep -q 'index=cloudtrail'; then
  ERRORS+=("SPL LINT FAIL: SPL references $CT_FIELD_COUNT CloudTrail fields but missing 'index=cloudtrail'. All CloudTrail queries must specify the index.")
fi

# Rule 3: Wrong field name — userName instead of userIdentity.userName
if echo "$CONTENT" | grep -qE '\buserName\b' && ! echo "$CONTENT" | grep -qE 'userIdentity\.userName|rename.*AS.*userName|eval.*userName'; then
  ERRORS+=("SPL LINT FAIL: Raw 'userName' field used — CloudTrail nests this as 'userIdentity.userName'. Use 'rename userIdentity.userName AS user' first.")
fi

# Rule 4: Composite without streamstats
if echo "$CONTENT" | grep -qi '\[COMPOSITE\]' && ! echo "$CONTENT" | grep -qi 'streamstats'; then
  ERRORS+=("SPL LINT FAIL: Composite detection missing 'streamstats'. Composites MUST use 'streamstats time_window=... by src_user_arn' for sliding-window correlation.")
fi

# Rule 5: sourceIP instead of sourceIPAddress
if echo "$CONTENT" | grep -qE '\bsourceIP\b' && ! echo "$CONTENT" | grep -qE 'sourceIPAddress|rename.*AS.*sourceIP'; then
  ERRORS+=("SPL LINT FAIL: 'sourceIP' is not a CloudTrail field. Use 'sourceIPAddress'.")
fi

# Rule 6: eventSource should not be used as a filter without .amazonaws.com
if echo "$CONTENT" | grep -qE 'eventSource\s*=' && ! echo "$CONTENT" | grep -qE 'eventSource\s*=\s*"[^"]*\.amazonaws\.com"'; then
  ERRORS+=("SPL LINT WARNING: eventSource filter should use full service name (e.g., 'iam.amazonaws.com'), not shorthand.")
fi

# Rule 7: Missing earliest/latest time bounds
if echo "$CONTENT" | grep -q 'index=cloudtrail' && ! echo "$CONTENT" | grep -qE '(earliest=|latest=|\-1h|\-24h|\-7d)'; then
  ERRORS+=("SPL LINT WARNING: CloudTrail query has no time bounds (earliest/latest). Unbounded queries are expensive and may timeout.")
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
