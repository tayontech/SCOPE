#!/bin/bash
# ENUM-01 (regions): Verify ENABLED_REGIONS handling across all 12 enum agents
set -euo pipefail

REGIONAL_AGENTS=(
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

GLOBAL_AGENTS=(
  agents/subagents/scope-enum-iam.md
  agents/subagents/scope-enum-sts.md
)

PASS=0; FAIL=0

# Check regional agents: must have canonical ENABLED_REGIONS error message
for AGENT in "${REGIONAL_AGENTS[@]}"; do
  NAME=$(basename "$AGENT")

  # Check 1: Has canonical ENABLED_REGIONS error message
  if grep -q "ENABLED_REGIONS not received from orchestrator" "$AGENT"; then
    echo "PASS: $NAME — has canonical ENABLED_REGIONS error message"; ((PASS++))
  else
    echo "FAIL: $NAME — missing canonical ENABLED_REGIONS error message"; ((FAIL++))
  fi

  # Check 2: Does NOT contain hardcoded fallback region list (pattern: us-east-1.*us-west-2 outside of an ENABLED_REGIONS example context)
  # We check for literal region list assignments that would indicate a fallback, not just documentation examples
  if ! grep -E 'REGIONS=.*us-east-1.*us-west-2|fallback.*region|default.*region.*list' "$AGENT" > /dev/null 2>&1; then
    echo "PASS: $NAME — no hardcoded region fallback"; ((PASS++))
  else
    echo "FAIL: $NAME — contains hardcoded region fallback"; ((FAIL++))
  fi
done

# Check global agents: must note ENABLED_REGIONS is not applicable
for AGENT in "${GLOBAL_AGENTS[@]}"; do
  NAME=$(basename "$AGENT")

  # Check 3: Has "ENABLED_REGIONS is not applicable" note
  if grep -q "ENABLED_REGIONS is not applicable" "$AGENT"; then
    echo "PASS: $NAME — notes ENABLED_REGIONS is not applicable (global service)"; ((PASS++))
  else
    echo "FAIL: $NAME — missing ENABLED_REGIONS is not applicable note"; ((FAIL++))
  fi
done

echo "---"
REGIONAL_CHECKS=$(( ${#REGIONAL_AGENTS[@]} * 2 ))
GLOBAL_CHECKS=${#GLOBAL_AGENTS[@]}
TOTAL=$(( REGIONAL_CHECKS + GLOBAL_CHECKS ))
echo "ENUM-01 (regions): $PASS passed, $FAIL failed out of $TOTAL checks"
[ "$FAIL" -eq 0 ] || exit 1
