#!/bin/bash
# SCHM-01: Uppercase severity in attack_paths must be blocked
set -euo pipefail
HOOK=".scope/hooks/scope-schema-validate.sh"
FIXTURE_BAD="tests/fixtures/audit-bad-severity.json"
FIXTURE_GOOD="tests/fixtures/audit-valid.json"
PASS=0; FAIL=0

# The hook only validates files matching */results.json -- use a temp results.json
TMPDIR_RUN=$(mktemp -d)
trap 'rm -rf "$TMPDIR_RUN"' EXIT

# Test 1: uppercase severity should be BLOCKED
TMP_BAD="$TMPDIR_RUN/results.json"
cp "$FIXTURE_BAD" "$TMP_BAD"
OUTPUT=$(echo "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$TMP_BAD\"}}" | bash "$HOOK" 2>/dev/null || true)
if echo "$OUTPUT" | grep -q '"decision"' && echo "$OUTPUT" | grep -q '"block"'; then
  echo "PASS: uppercase severity blocked"; ((PASS++))
else
  echo "FAIL: uppercase severity NOT blocked"; ((FAIL++))
fi

# Test 2: lowercase severity should PASS (no output)
TMP_GOOD="$TMPDIR_RUN/valid-results.json"
cp "$FIXTURE_GOOD" "$TMP_GOOD"
# Rename to results.json for the hook
TMP_GOOD2="$TMPDIR_RUN/valid/results.json"
mkdir -p "$TMPDIR_RUN/valid"
cp "$FIXTURE_GOOD" "$TMP_GOOD2"
OUTPUT=$(echo "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$TMP_GOOD2\"}}" | bash "$HOOK" 2>/dev/null || true)
if [ -z "$OUTPUT" ]; then
  echo "PASS: lowercase severity accepted"; ((PASS++))
else
  echo "FAIL: lowercase severity rejected -- output: $OUTPUT"; ((FAIL++))
fi

echo "---"
echo "SCHM-01: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
