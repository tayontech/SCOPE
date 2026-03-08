#!/bin/bash
# SCHM-02: Unknown edge_type in graph.edges must be blocked
set -euo pipefail
HOOK=".scope/hooks/scope-schema-validate.sh"
FIXTURE_BAD="tests/fixtures/audit-bad-edge-type.json"
FIXTURE_GOOD="tests/fixtures/audit-valid.json"
PASS=0; FAIL=0

# The hook only validates files matching */results.json -- use a temp results.json
TMPDIR_RUN=$(mktemp -d)
trap 'rm -rf "$TMPDIR_RUN"' EXIT

# Test 1: unknown edge_type should be BLOCKED
TMP_BAD="$TMPDIR_RUN/results.json"
cp "$FIXTURE_BAD" "$TMP_BAD"
OUTPUT=$(echo "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$TMP_BAD\"}}" | bash "$HOOK" 2>/dev/null || true)
if echo "$OUTPUT" | grep -q '"decision"' && echo "$OUTPUT" | grep -q '"block"'; then
  echo "PASS: unknown edge_type blocked"; ((PASS++))
else
  echo "FAIL: unknown edge_type NOT blocked"; ((FAIL++))
fi

# Test 2: valid edge_type should PASS (no output)
mkdir -p "$TMPDIR_RUN/valid"
TMP_GOOD="$TMPDIR_RUN/valid/results.json"
cp "$FIXTURE_GOOD" "$TMP_GOOD"
OUTPUT=$(echo "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$TMP_GOOD\"}}" | bash "$HOOK" 2>/dev/null || true)
if [ -z "$OUTPUT" ]; then
  echo "PASS: valid edge_type accepted"; ((PASS++))
else
  echo "FAIL: valid edge_type rejected -- output: $OUTPUT"; ((FAIL++))
fi

# Test 3: membership edge_type should PASS (valid type)
TMPDIR_MEMBERSHIP=$(mktemp -d)
TMP_MEMBERSHIP="$TMPDIR_MEMBERSHIP/results.json"
jq '.graph.edges[0].edge_type = "membership"' "$FIXTURE_GOOD" > "$TMP_MEMBERSHIP"
OUTPUT=$(echo "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$TMP_MEMBERSHIP\"}}" | bash "$HOOK" 2>/dev/null || true)
if [ -z "$OUTPUT" ]; then
  echo "PASS: membership edge_type accepted"; ((PASS++))
else
  echo "FAIL: membership edge_type rejected -- output: $OUTPUT"; ((FAIL++))
fi
rm -rf "$TMPDIR_MEMBERSHIP"

echo "---"
echo "SCHM-02: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
