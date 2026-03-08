#!/bin/bash
# ENUM-05 (Gate 3): Verify Gate 3 module_validation catches 0-byte files and shows per-service region table
set -euo pipefail

AGENT="agents/scope-audit.md"
PASS=0; FAIL=0

# Check 1: Has 0-byte file warning message
if grep -q 'file is empty (0 bytes)' "$AGENT"; then
  echo "PASS: $AGENT — has 'file is empty (0 bytes)' warning message"; ((PASS++))
else
  echo "FAIL: $AGENT — missing 'file is empty (0 bytes)' warning message"; ((FAIL++))
fi

# Check 2: Has non-empty file check syntax [ ! -s "$MODULE_FILE" ]
if grep -q '! -s "\$MODULE_FILE"' "$AGENT"; then
  echo "PASS: $AGENT — has non-empty file check syntax (! -s \"\$MODULE_FILE\")"; ((PASS++))
else
  echo "FAIL: $AGENT — missing non-empty file check syntax (! -s \"\$MODULE_FILE\")"; ((FAIL++))
fi

# Check 3: Has per-service region breakdown header
if grep -q 'Region Coverage (per service)' "$AGENT"; then
  echo "PASS: $AGENT — has 'Region Coverage (per service)' header"; ((PASS++))
else
  echo "FAIL: $AGENT — missing 'Region Coverage (per service)' header"; ((FAIL++))
fi

# Check 4: Has global service rows in the region table
if grep -q 'IAM:          global' "$AGENT"; then
  echo "PASS: $AGENT — has 'IAM:          global' row in region table"; ((PASS++))
else
  echo "FAIL: $AGENT — missing 'IAM:          global' row in region table"; ((FAIL++))
fi

echo "---"
echo "ENUM-05 (Gate 3): $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
