#!/bin/bash
# ENUM-02 (IAM/STS): Verify Post-Write Validation sections exist in IAM and STS enum agents
set -euo pipefail

IAM_AGENT="agents/subagents/scope-enum-iam.md"
STS_AGENT="agents/subagents/scope-enum-sts.md"
PASS=0; FAIL=0

# Test 1: IAM agent has Post-Write Validation section
if grep -q "## Post-Write Validation (MANDATORY)" "$IAM_AGENT"; then
  echo "PASS: scope-enum-iam.md has Post-Write Validation (MANDATORY) section"; ((PASS++))
else
  echo "FAIL: scope-enum-iam.md missing Post-Write Validation (MANDATORY) section"; ((FAIL++))
fi

# Test 2: IAM agent has [VALIDATION] iam.json failed: error prefix
if grep -q "\[VALIDATION\] iam\.json failed:" "$IAM_AGENT"; then
  echo "PASS: scope-enum-iam.md has [VALIDATION] iam.json failed: error prefix"; ((PASS++))
else
  echo "FAIL: scope-enum-iam.md missing [VALIDATION] iam.json failed: error prefix"; ((FAIL++))
fi

# Test 3: STS agent has Post-Write Validation section
if grep -q "## Post-Write Validation (MANDATORY)" "$STS_AGENT"; then
  echo "PASS: scope-enum-sts.md has Post-Write Validation (MANDATORY) section"; ((PASS++))
else
  echo "FAIL: scope-enum-sts.md missing Post-Write Validation (MANDATORY) section"; ((FAIL++))
fi

# Test 4: STS agent has [VALIDATION] sts.json failed: error prefix
if grep -q "\[VALIDATION\] sts\.json failed:" "$STS_AGENT"; then
  echo "PASS: scope-enum-sts.md has [VALIDATION] sts.json failed: error prefix"; ((PASS++))
else
  echo "FAIL: scope-enum-sts.md missing [VALIDATION] sts.json failed: error prefix"; ((FAIL++))
fi

# Test 5: IAM agent notes ENABLED_REGIONS is not applicable
if grep -q "ENABLED_REGIONS is not applicable" "$IAM_AGENT"; then
  echo "PASS: scope-enum-iam.md notes ENABLED_REGIONS is not applicable"; ((PASS++))
else
  echo "FAIL: scope-enum-iam.md missing ENABLED_REGIONS is not applicable note"; ((FAIL++))
fi

# Test 6: STS agent notes ENABLED_REGIONS is not applicable
if grep -q "ENABLED_REGIONS is not applicable" "$STS_AGENT"; then
  echo "PASS: scope-enum-sts.md notes ENABLED_REGIONS is not applicable"; ((PASS++))
else
  echo "FAIL: scope-enum-sts.md missing ENABLED_REGIONS is not applicable note"; ((FAIL++))
fi

# Test 7: IAM agent does NOT contain "Retry the jq write once" language
if ! grep -q "Retry the jq write once" "$IAM_AGENT"; then
  echo "PASS: scope-enum-iam.md does not contain retry language"; ((PASS++))
else
  echo "FAIL: scope-enum-iam.md contains forbidden retry language"; ((FAIL++))
fi

# Test 8: STS agent does NOT contain "Retry the jq write once" language
if ! grep -q "Retry the jq write once" "$STS_AGENT"; then
  echo "PASS: scope-enum-sts.md does not contain retry language"; ((PASS++))
else
  echo "FAIL: scope-enum-sts.md contains forbidden retry language"; ((FAIL++))
fi

echo "---"
echo "ENUM-02 (IAM/STS): $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
