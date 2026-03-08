#!/bin/bash
# ENUM-03 (EC2 IMDS): Verify EC2 IMDS self-check uses STATUS: error with [VALIDATION] prefix
set -euo pipefail

AGENT="agents/subagents/scope-enum-ec2.md"
PASS=0; FAIL=0

# Check 1: Has [VALIDATION] ec2.json failed: IMDS check not completed message
if grep -q '\[VALIDATION\] ec2.json failed: IMDS check not completed' "$AGENT"; then
  echo "PASS: $AGENT — has [VALIDATION] ec2.json failed: IMDS check not completed message"; ((PASS++))
else
  echo "FAIL: $AGENT — missing [VALIDATION] ec2.json failed: IMDS check not completed message"; ((FAIL++))
fi

# Check 2: Has STATUS="error" in Post-Enum Self-Check section
if grep -q 'STATUS="error"' "$AGENT"; then
  echo "PASS: $AGENT — has STATUS=\"error\" in self-check"; ((PASS++))
else
  echo "FAIL: $AGENT — missing STATUS=\"error\" in self-check"; ((FAIL++))
fi

# Check 3: Does NOT contain the old "STOP and go back" pattern
if ! grep -q 'STOP and go back' "$AGENT"; then
  echo "PASS: $AGENT — old 'STOP and go back' pattern removed"; ((PASS++))
else
  echo "FAIL: $AGENT — still contains old 'STOP and go back' pattern"; ((FAIL++))
fi

echo "---"
echo "ENUM-03 (EC2 IMDS): $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
