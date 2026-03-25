---
phase: 02-agent-correctness-and-performance-pass
plan: "04"
subsystem: infra
tags: [jq, bash, performance, enum-agents, s3, kms, sns, sqs, apigateway]

requires:
  - phase: 02-agent-correctness-and-performance-pass
    provides: "Plans 01-03 established O(n) temp-file append pattern for IAM, EC2, Lambda, Secrets, and other agents"

provides:
  - "S3 agent uses O(n) per-bucket temp-file append + jq -s merge"
  - "KMS agent uses O(n) per-key temp-file append + jq -s merge per region"
  - "SNS agent uses O(n) per-topic temp-file append + jq -s merge per region"
  - "SQS agent uses O(n) per-queue temp-file append + jq -s merge per region"
  - "API Gateway agent uses O(n) temp-file append for both REST and v2 loops with separate jq -s merges"
  - "All 9 PERF-02 agents now use O(n) accumulation — codebase-wide fix complete"

affects:
  - phase: 03-validation-and-hardening

tech-stack:
  added: []
  patterns:
    - "O(n) findings accumulation: echo FINDINGS >> $RUN_DIR/raw/<module>_findings_<region>.jsonl; then cat *.jsonl | jq -s 'add // []' after loops"
    - "Rerun safety: rm -f $RUN_DIR/raw/<module>_findings_*.jsonl before loops"
    - "API Gateway two-loop merge: REST and v2 findings accumulated separately, combined with jq -s 'add // []' post-loop"

key-files:
  created: []
  modified:
    - agents/subagents/scope-enum-s3.md
    - agents/subagents/scope-enum-kms.md
    - agents/subagents/scope-enum-sns.md
    - agents/subagents/scope-enum-sqs.md
    - agents/subagents/scope-enum-apigateway.md

key-decisions:
  - "API Gateway two-loop design: REST findings go to apigw_rest_findings_${REGION}.jsonl, v2 findings to apigw_v2_findings_${REGION}.jsonl — merged separately then combined with jq -s 'add // []'"
  - "S3 is global (no region loop) so uses single s3_findings.jsonl with direct jq -s rather than cat glob"

patterns-established:
  - "Per-resource append pattern: echo '$RESOURCE_FINDINGS' >> '$RUN_DIR/raw/<module>_findings_${CURRENT_REGION}.jsonl'"
  - "Post-loop merge pattern: cat '$RUN_DIR/raw/<module>_findings_'*.jsonl 2>/dev/null | jq -s 'add // []' 2>/dev/null || echo '[]'"
  - "Rerun cleanup before loops: rm -f '$RUN_DIR/raw/<module>_findings_'*.jsonl"

requirements-completed: [PERF-02]

duration: 2min
completed: "2026-03-25"
---

# Phase 02 Plan 04: O(n) Accumulation — S3, KMS, SNS, SQS, API Gateway Summary

**Eliminated O(n^2) jq argjson accumulation from all 5 remaining agents by replacing in-loop variable expansion with temp-file append + single post-loop jq -s merge, completing PERF-02 across the entire codebase**

## Performance

- **Duration:** ~2 min
- **Started:** 2026-03-25T19:24:47Z
- **Completed:** 2026-03-25T19:26:59Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- S3 agent: per-bucket findings now appended to `$RUN_DIR/raw/s3_findings.jsonl`; merged once with `jq -s 'add // []'` after the bucket loop
- KMS agent: per-key findings appended to `$RUN_DIR/raw/kms_findings_${CURRENT_REGION}.jsonl`; cat glob merged after all region loops
- SNS agent: per-topic findings appended to `$RUN_DIR/raw/sns_findings_${CURRENT_REGION}.jsonl`; cat glob merged after all region loops
- SQS agent: per-queue findings appended to `$RUN_DIR/raw/sqs_findings_${CURRENT_REGION}.jsonl`; cat glob merged after all region loops
- API Gateway agent: REST and v2 loops each write to separate `.jsonl` files (`apigw_rest_findings_${REGION}.jsonl` and `apigw_v2_findings_${REGION}.jsonl`); merged independently then combined — handles two independent accumulation loops correctly
- All 5 agents have `rm -f` cleanup before loops for rerun safety; TRUST_CLASSIFY_JQ untouched in all agents

## Task Commits

Each task was committed atomically:

1. **Task 1: S3 and KMS O(n) accumulation fix** - `75c6174` (perf)
2. **Task 2: SNS, SQS, and API Gateway O(n) accumulation fix** - `37feaf4` (perf)

**Plan metadata:** (docs commit — see below)

## Files Created/Modified

- `agents/subagents/scope-enum-s3.md` - Replaced per-bucket argjson accumulation with temp-file append + jq -s merge
- `agents/subagents/scope-enum-kms.md` - Replaced per-key argjson accumulation with temp-file append + jq -s merge per region
- `agents/subagents/scope-enum-sns.md` - Replaced per-topic argjson accumulation with temp-file append + jq -s merge per region
- `agents/subagents/scope-enum-sqs.md` - Replaced per-queue argjson accumulation with temp-file append + jq -s merge per region
- `agents/subagents/scope-enum-apigateway.md` - Replaced both REST and v2 API argjson accumulations with separate temp-file appends + jq -s merges

## Decisions Made

- API Gateway two-loop design: REST and v2 findings written to separate `.jsonl` file sets, merged independently, then combined post-loop — cleanest separation of the two independent loops
- S3 global service: single file (no region suffix) with `jq -s` directly on the file path (no cat glob needed since no region iteration)

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- PERF-02 fully resolved across all 9 affected agents (IAM/STS/CodeBuild already had O(n); Plans 01-03 fixed EC2/Lambda/Secrets/others; this plan fixes the final 5)
- All enum agents now use consistent O(n) accumulation pattern
- Ready for Phase 03 validation and hardening

---
*Phase: 02-agent-correctness-and-performance-pass*
*Completed: 2026-03-25*
