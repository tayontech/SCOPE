---
plan: 58-02
title: Update 12 enum agents — replace output contract and preamble with @include
status: complete
completed: 2026-04-19
---

# Plan 58-02 Summary

## What was done

Replaced the inline output contract (jq write block, agent-log append, post-write validation) in all 12 enum agent source files with `@include agents/shared/enum-output-contract.md`. Changes were committed in 4 batches of 3 agents each.

## Task results

| Task | Agent(s) | Result |
|------|---------|--------|
| 58-02-01 | Variable declaration pattern | Confirmed: MODULE, OUTPUT_FILE, AGENT_NAME, REGION, FINDINGS_JSON set before @include |
| 58-02-02 | scope-enum-iam | Complete — IAM uses `FINDINGS_JSON=$(jq -c '.' ...)` to load from temp file (--slurpfile pattern, per 58-01 decision) |
| 58-02-03 | scope-enum-sts | Complete |
| 58-02-04 | scope-enum-s3 | Complete |
| 58-02-05 | scope-enum-kms | Complete |
| 58-02-06 | scope-enum-secrets | Complete |
| 58-02-07 | scope-enum-lambda | Complete |
| 58-02-08 | scope-enum-ec2 | Complete |
| 58-02-09 | scope-enum-rds | Complete |
| 58-02-10 | scope-enum-sns | Complete |
| 58-02-11 | scope-enum-sqs | Complete |
| 58-02-12 | scope-enum-apigateway | Complete |
| 58-02-13 | scope-enum-codebuild | Complete |
| 58-02-14 | Verification + install.js | PASS — all 12 agents resolve without error |

## Variable declaration pattern

```bash
MODULE="<service>"          # e.g., "iam", "s3", "kms"
OUTPUT_FILE="$RUN_DIR/<service>.json"
AGENT_NAME="scope-enum-<service>"
REGION="<region-value>"     # "global", "multi-region", or $AWS_REGION
# FINDINGS_JSON must be set before this — pre-assembled by agent's extraction step
```
For IAM: `FINDINGS_JSON=$(jq -c '.' "$RUN_DIR/raw/iam_all_findings.json")` (loaded from temp file).

## Commits

- `7b4b6ba` refactor(enum): sts, s3, kms (batch 1)
- `ed0a8de` refactor(enum): secrets, lambda, ec2 (batch 2)
- `9ec4631` refactor(enum): rds, sns, sqs (batch 3)
- `02c3dbf` refactor(enum): apigateway, codebuild, iam (batch 4)

## Verification results

- All 12 agents: `@include agents/shared/enum-output-contract.md` present — PASS
- No inline `module: $module` jq write envelope blocks remain — PASS
- No inline agent-log append blocks remain — PASS
- install.js resolves all 12 enum agents without errors — PASS
- Service-specific content (METRICS, error handling, extraction templates) intact — PASS

## Character count

| Metric | Value |
|--------|-------|
| Pre-edit total | 185,283 bytes |
| Post-edit total | 173,826 bytes |
| Reduction | 11,457 bytes (6.2%) |

Note: The 30% target in the plan assumed the output contract blocks were ~30% of each agent's content. In practice the enum agents contain substantial enumeration logic and extraction templates, so the output contract was a smaller percentage per agent than estimated. The structural goal is fully achieved: zero inline output contract blocks remain.

## Decisions

- IAM agent: uses `FINDINGS_JSON=$(jq -c '.' ...)` to load from the combined temp file before @include runs. Consistent with 58-01 decision that IAM's --slurpfile form stays inline (converted to equivalent jq -c pipe instead of duplicating the write).
- Execution Workflow steps (documentation lines) that reference `node bin/validate-enum-output.js` are retained — these are prose descriptions, not bash blocks, and accurately describe what the shared file does.
- agent-preamble.md @include not added to enum agents: enum agents do not contain the repeated project-context paragraphs that agent-preamble.md addresses (these are only in orchestrator agents).
