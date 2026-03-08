#!/bin/bash
# ENUM-04 (defend gate): Verify defend coverage gate has independent SCP/RCP/detection gates with STATUS: partial
set -euo pipefail

AGENT="agents/scope-defend.md"
PASS=0; FAIL=0

# Check 1: Has controls_recommended advisory-only statement
if grep -q 'controls_recommended is advisory only' "$AGENT" || grep -q 'NOT part of this gate' "$AGENT"; then
  echo "PASS: $AGENT — has controls_recommended advisory-only statement"; ((PASS++))
else
  echo "FAIL: $AGENT — missing controls_recommended advisory-only statement"; ((FAIL++))
fi

# Check 2: Has independent RCP gate section
if grep -q 'RCP gate (independent)' "$AGENT" || grep -q 'RCP gate skipped' "$AGENT"; then
  echo "PASS: $AGENT — has independent RCP gate section"; ((PASS++))
else
  echo "FAIL: $AGENT — missing independent RCP gate section"; ((FAIL++))
fi

# Check 3: Has exact [INFO] RCP gate skip message
if grep -q '\[INFO\] RCP gate skipped -- no Organizations access' "$AGENT"; then
  echo "PASS: $AGENT — has exact [INFO] RCP gate skip message"; ((PASS++))
else
  echo "FAIL: $AGENT — missing exact [INFO] RCP gate skip message"; ((FAIL++))
fi

# Check 4: Has [COVERAGE] structured error format
if grep -q '\[COVERAGE\] No SCP for attack path:' "$AGENT"; then
  echo "PASS: $AGENT — has [COVERAGE] No SCP for attack path: structured error format"; ((PASS++))
else
  echo "FAIL: $AGENT — missing [COVERAGE] No SCP for attack path: structured error format"; ((FAIL++))
fi

# Check 5: Has STATUS: partial retry behavior
if grep -q 'STATUS: partial' "$AGENT"; then
  echo "PASS: $AGENT — has STATUS: partial retry exhaustion behavior"; ((PASS++))
else
  echo "FAIL: $AGENT — missing STATUS: partial retry exhaustion behavior"; ((FAIL++))
fi

# Check 6: Does NOT contain old combined "AND" threshold pattern
if ! grep -q 'at least 2 SCPs AND at least 3 detections' "$AGENT"; then
  echo "PASS: $AGENT — old combined 'SCPs AND detections' threshold pattern removed"; ((PASS++))
else
  echo "FAIL: $AGENT — still contains old combined 'SCPs AND detections' threshold pattern"; ((FAIL++))
fi

echo "---"
echo "ENUM-04 (defend gate): $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
