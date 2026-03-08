#!/bin/bash
# SCHM-04: policy_json as string must be blocked
set -euo pipefail
HOOK=".scope/hooks/scope-schema-validate.sh"
FIXTURE_BAD="tests/fixtures/defend-bad-policy-json.json"
FIXTURE_GOOD="tests/fixtures/defend-valid.json"
PASS=0; FAIL=0

# The hook only validates files matching */results.json -- use a temp results.json
TMPDIR_RUN=$(mktemp -d)
trap 'rm -rf "$TMPDIR_RUN"' EXIT

# Test 1: string policy_json should be BLOCKED
TMP_BAD="$TMPDIR_RUN/results.json"
cp "$FIXTURE_BAD" "$TMP_BAD"
OUTPUT=$(echo "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$TMP_BAD\"}}" | bash "$HOOK" 2>/dev/null || true)
if echo "$OUTPUT" | grep -q '"decision"' && echo "$OUTPUT" | grep -q '"block"'; then
  echo "PASS: string policy_json blocked"; ((PASS++))
else
  echo "FAIL: string policy_json NOT blocked"; ((FAIL++))
fi

# Test 2: object policy_json should PASS (no output)
mkdir -p "$TMPDIR_RUN/valid"
TMP_GOOD="$TMPDIR_RUN/valid/results.json"
cp "$FIXTURE_GOOD" "$TMP_GOOD"
OUTPUT=$(echo "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$TMP_GOOD\"}}" | bash "$HOOK" 2>/dev/null || true)
if [ -z "$OUTPUT" ]; then
  echo "PASS: object policy_json accepted"; ((PASS++))
else
  echo "FAIL: object policy_json rejected -- output: $OUTPUT"; ((FAIL++))
fi

echo "---"
echo "SCHM-04: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
