#!/bin/bash
# SCOPE SPL Semantic Lint — PostToolUse / AfterTool hook
# Runs after Write|Edit on files that contain SPL queries.
# Hard-fails on known anti-patterns defined in config/splunk-patterns.md.
# Multi-index aware: validates index= clauses against config/index.json allowlist when present.
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

# Rule 2: Composite without streamstats
if echo "$CONTENT" | grep -qi '\[COMPOSITE\]' && ! echo "$CONTENT" | grep -qi 'streamstats'; then
  ERRORS+=("SPL LINT FAIL: Composite detection missing 'streamstats'. Composites MUST use 'streamstats time_window=... by src_user_arn' for sliding-window correlation.")
fi

# Rule 3: Missing time bounds on any index= query (applies to ALL indexes, not just CloudTrail)
if echo "$CONTENT" | grep -qE 'index=[a-zA-Z_]' && ! echo "$CONTENT" | grep -qE '(earliest=|latest=|-1h|-24h|-7d)'; then
  ERRORS+=("SPL LINT WARNING: SPL query has no time bounds (earliest/latest). Unbounded queries are expensive and may timeout.")
fi

# Rule 4: Index allowlist validation (D-15)
# Requires config/index.json to exist; gracefully skips if absent (allows any index)
# Splunk ES internal indexes always bypass the allowlist check
INTERNAL_INDEXES="notable notable_summary risk threat_activity ioc ers ueba ueba_summaries endpoint_summary audit_summary _internal _audit _introspection summary history"

# Determine the config path relative to the hook's location or use absolute path
HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HOOK_DIR/../.." && pwd)"
INDEX_JSON="$REPO_ROOT/config/index.json"

ALLOWED=$(jq -r '.groups | to_entries[] | .value.indexes[]' "$INDEX_JSON" 2>/dev/null || true)

if [ -n "$ALLOWED" ]; then
  # Extract index= clause values from the written file (skip * which is handled by Rule 6)
  USED=$(grep -oP 'index=\K[a-zA-Z0-9_*-]+' "$FILE_PATH" 2>/dev/null | sort -u || true)

  for idx in $USED; do
    # Skip wildcard index=* — handled separately by Rule 6
    if [ "$idx" = "*" ]; then
      continue
    fi

    # Skip Splunk ES internal indexes — always valid
    if echo "$INTERNAL_INDEXES" | grep -qw "$idx"; then
      continue
    fi

    # Check against allowlist
    if ! echo "$ALLOWED" | grep -qx "$idx"; then
      ERRORS+=("SPL LINT FAIL: index=$idx not found in config/index.json allowlist. Add it to the appropriate group or run index discovery.")
    fi
  done
fi
# If config/index.json absent or parse failed — $ALLOWED is empty — fall through (allow any index per D-15)

# Rule 5: Leading wildcard ban
if echo "$CONTENT" | grep -qE '[a-zA-Z_]+=\*[^" ]'; then
  ERRORS+=("SPL LINT FAIL: Leading wildcard detected (field=*value). Forces full raw-text scan. Use exact match or OR list instead.")
fi

# Rule 6: index=* ban
if echo "$CONTENT" | grep -qE 'index=\*($|[^a-zA-Z0-9_-])'; then
  ERRORS+=("SPL LINT FAIL: 'index=*' is not allowed. Always specify a named index.")
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
