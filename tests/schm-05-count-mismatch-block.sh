#!/bin/bash
# SCHM-05: summary count mismatch must be blocked
set -euo pipefail
HOOK=".scope/hooks/scope-schema-validate.sh"
FIXTURE_BAD="tests/fixtures/defend-bad-counts.json"
FIXTURE_GOOD="tests/fixtures/defend-valid.json"
PASS=0; FAIL=0

# The hook only validates files matching */results.json -- use a temp results.json
TMPDIR_RUN=$(mktemp -d)
trap 'rm -rf "$TMPDIR_RUN"' EXIT

# Test 1: count mismatch should be BLOCKED
TMP_BAD="$TMPDIR_RUN/results.json"
cp "$FIXTURE_BAD" "$TMP_BAD"
OUTPUT=$(echo "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$TMP_BAD\"}}" | bash "$HOOK" 2>/dev/null || true)
if echo "$OUTPUT" | grep -q '"decision"' && echo "$OUTPUT" | grep -q '"block"'; then
  echo "PASS: count mismatch blocked"; ((PASS++))
else
  echo "FAIL: count mismatch NOT blocked"; ((FAIL++))
fi

# Test 2: matching counts should PASS (no output)
mkdir -p "$TMPDIR_RUN/valid"
TMP_GOOD="$TMPDIR_RUN/valid/results.json"
cp "$FIXTURE_GOOD" "$TMP_GOOD"
OUTPUT=$(echo "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$TMP_GOOD\"}}" | bash "$HOOK" 2>/dev/null || true)
if [ -z "$OUTPUT" ]; then
  echo "PASS: matching counts accepted"; ((PASS++))
else
  echo "FAIL: matching counts rejected -- output: $OUTPUT"; ((FAIL++))
fi

echo "---"
echo "SCHM-05: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
