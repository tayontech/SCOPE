---
phase: 02-agent-correctness-and-performance-pass
plan: "02"
subsystem: enumeration-agents
tags: [aws, ec2, ebs, elbv2, performance, api-optimization, shell-scripting, jq]

# Dependency graph
requires:
  - phase: 01-iam-bulk-migration
    provides: Established enumeration agent patterns and extraction template conventions

provides:
  - EC2 agent with O(1) snapshot public detection via bulk describe-snapshots API call
  - EC2 agent with O(n) ELBv2 listener accumulation via temp-file JSONL append
  - EC2 agent with O(n) region findings accumulation via temp-file JSONL append + jq -s merge

affects:
  - 02-agent-correctness-and-performance-pass
  - Any future EC2 enumeration agent work

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Bulk AWS API filter pattern: --restorable-by-user-ids all with --owner-ids self for public snapshot detection"
    - "Temp-file JSONL accumulation: append per-item with jq -c, merge with jq -s 'add // []' after loop"
    - "Idempotent temp-file cleanup: rm -f before loop, not after, to preserve data on partial failure"

key-files:
  created: []
  modified:
    - agents/subagents/scope-enum-ec2.md

key-decisions:
  - "Both --owner-ids self AND --restorable-by-user-ids all required for public snapshot detection — omitting --owner-ids self returns millions of AWS-wide public snapshots"
  - "Use jq -s 'add // []' (not jq -s 'add') for empty-file safety when merging JSONL region findings"
  - "describe-listeners per-LB call retained as unavoidable — no bulk API exists; only accumulation pattern fixed"

patterns-established:
  - "Temp-file JSONL pattern: append with jq -c per item, merge with jq -s after loop — applicable to any N-resource accumulation in any enum agent"

requirements-completed: [AFIX-02, PERF-02]

# Metrics
duration: 2min
completed: 2026-03-25
---

# Phase 2 Plan 02: EC2 Snapshot Detection and O(n^2) Accumulation Fix Summary

**EC2 agent public snapshot detection converted from N API calls to 1 bulk call, and two O(n^2) jq accumulation loops replaced with O(n) temp-file JSONL append patterns**

## Performance

- **Duration:** ~2 min
- **Started:** 2026-03-25T20:24:38Z
- **Completed:** 2026-03-25T20:26:18Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments

- Replaced per-snapshot `describe-snapshot-attribute` loop (N API calls) with single `describe-snapshots --owner-ids self --restorable-by-user-ids all` call; PUBLIC_SNAPSHOT_IDS array consumed identically by extraction template
- Replaced O(n^2) ELBv2 listener accumulation (`ELBV2_LISTENERS=$(echo ... | jq --argjson new ...)`) with temp-file JSONL append + `jq -s '.'` merge after loop
- Replaced O(n^2) region findings accumulation (`ALL_FINDINGS=$(echo ... | jq --argjson inst ... --argjson sg ...)`) with temp-file JSONL append per resource type + `jq -s 'add // []'` merge after all regions complete

## Task Commits

Each task was committed atomically:

1. **Task 1: Replace per-snapshot describe-snapshot-attribute loop with bulk filter (AFIX-02)** - `f342793` (fix)
2. **Task 2: Fix ELBv2 listener loop and region-level O(n^2) accumulation (PERF-02)** - `5e3347f` (perf)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `agents/subagents/scope-enum-ec2.md` - Bulk snapshot filter (AFIX-02) + temp-file JSONL accumulation patterns (PERF-02)

## Decisions Made

- Both `--owner-ids self` AND `--restorable-by-user-ids all` flags required on the bulk snapshot call — `--owner-ids self` scopes results to this account; without it the API returns millions of AWS-wide public snapshots
- `jq -s 'add // []'` chosen over `jq -s 'add'` for region findings merge — handles empty JSONL file without returning `null`
- `describe-listeners` per-LB call kept as-is (no bulk API available); only the accumulation pattern was fixed

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- AFIX-02 and PERF-02 requirements complete
- EC2 agent now uses efficient API patterns consistent with the IAM bulk migration approach from Phase 1
- Remaining Phase 2 plans (if any) can proceed — no blockers

---
*Phase: 02-agent-correctness-and-performance-pass*
*Completed: 2026-03-25*
