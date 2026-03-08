#!/bin/bash
# ENUM-02 (consistency): Verify all 12 enum agents have canonical enhanced validation structure
set -euo pipefail

AGENTS=(
  agents/subagents/scope-enum-iam.md
  agents/subagents/scope-enum-sts.md
  agents/subagents/scope-enum-s3.md
  agents/subagents/scope-enum-kms.md
  agents/subagents/scope-enum-secrets.md
  agents/subagents/scope-enum-lambda.md
  agents/subagents/scope-enum-ec2.md
  agents/subagents/scope-enum-rds.md
  agents/subagents/scope-enum-sqs.md
  agents/subagents/scope-enum-sns.md
  agents/subagents/scope-enum-apigateway.md
  agents/subagents/scope-enum-codebuild.md
)

PASS=0; FAIL=0

for AGENT in "${AGENTS[@]}"; do
  NAME=$(basename "$AGENT")

  # Check 1: Has Post-Write Validation (MANDATORY) section heading
  if grep -q "## Post-Write Validation (MANDATORY)" "$AGENT"; then
    echo "PASS: $NAME — has Post-Write Validation (MANDATORY) section"; ((PASS++))
  else
    echo "FAIL: $NAME — missing Post-Write Validation (MANDATORY) section"; ((FAIL++))
  fi

  # Check 2: Has [VALIDATION] error prefix (enhanced error format)
  if grep -q "\[VALIDATION\]" "$AGENT"; then
    echo "PASS: $NAME — has [VALIDATION] error prefix"; ((PASS++))
  else
    echo "FAIL: $NAME — missing [VALIDATION] error prefix"; ((FAIL++))
  fi

  # Check 3: Has jq envelope check for required fields
  if grep -q 'jq -e ".module and .account_id and .findings"' "$AGENT"; then
    echo "PASS: $NAME — has jq envelope field check"; ((PASS++))
  else
    echo "FAIL: $NAME — missing jq envelope field check"; ((FAIL++))
  fi

  # Check 4: Has failure mode explanation paragraph
  if grep -q "Why this check exists" "$AGENT"; then
    echo "PASS: $NAME — has failure mode explanation"; ((PASS++))
  else
    echo "FAIL: $NAME — missing failure mode explanation"; ((FAIL++))
  fi

  # Check 5: Does NOT contain "Retry the jq write once" retry language (inverted)
  if ! grep -q "Retry the jq write once" "$AGENT"; then
    echo "PASS: $NAME — does not contain retry language"; ((PASS++))
  else
    echo "FAIL: $NAME — contains forbidden retry language"; ((FAIL++))
  fi
done

echo "---"
TOTAL=$(( ${#AGENTS[@]} * 5 ))
echo "ENUM-02 (consistency): $PASS passed, $FAIL failed out of $TOTAL checks"
[ "$FAIL" -eq 0 ] || exit 1
