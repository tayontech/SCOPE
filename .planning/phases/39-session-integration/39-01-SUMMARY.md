---
phase: 39
plan: "39-01"
name: "Session Integration — New Sections (entry_point_detection + hunt_mode_intake)"
status: complete
completed: "2026-03-30"
commit: 9afc0e32abe3ec78189ec4b6d7d4125ad410bcdb
---

# Plan 39-01 Summary

## What Was Done

Added two new sections to `agents/scope-hunt.md` that implement dual entry point detection and audit/exploit run directory intake. Both sections are positioned immediately before `<mcp_detection>` at what was previously line 271.

## Sections Added

### `<entry_point_detection>` (lines 271–320)

Classifies operator input at startup to determine execution mode before any other step:

1. Empty input → MODE=INVESTIGATION
2. `notable_id=*` pattern → MODE=INVESTIGATION
3. Path-like input (starts with `./`, `/`, `~/`, `audit/`, `exploit/`, or `data/`) → test directory with Bash; if exists set MODE=HUNT + HUNT_RUN_DIR; if not found display error and halt
4. Anything else → MODE=INVESTIGATION

Mode is announced before routing: hunt mode announces the run directory path; investigation mode announces proceeding to alert intake.

### `<hunt_mode_intake>` (lines 322–415)

Reached only when MODE=HUNT. Five-step intake:

1. Validate `$HUNT_RUN_DIR/results.json` exists; if absent offer investigation mode fallback
2. Determine run type (AUDIT vs. EXPLOIT) from directory name prefix, confirmed by results.json
3. Read results.json and extract key fields (attack_paths, principals, trust_relationships for audit; target_arn, steps[].action, confidence_tier for exploit)
4. List per-module JSONs for audit runs (note presence, do not read all)
5. Display structured RUN DIRECTORY LOADED summary with counts by severity, principals, cross-account trusts, and CloudTrail eventNames to hunt

After intake, execution proceeds to `<mcp_detection>` regardless of Splunk availability. If MANUAL mode, the agent proceeds with findings from the run directory alone.

## Verification Results

All 5 plan verification checks passed:

| Check | Result |
|-------|--------|
| Section order: entry_point_detection < hunt_mode_intake < mcp_detection | PASS (lines 271, 322, 417) |
| MODE=HUNT, MODE=INVESTIGATION, HUNT_RUN_DIR all present | PASS |
| RUN DIRECTORY LOADED, HUNT_RUN_TYPE, CloudTrail eventNames to hunt all present | PASS |
| Investigation mode sections untouched (grep -c = 3, all pre-existing) | PASS (count of 3 was pre-existing before this plan) |
| Memory hygiene warning present in hunt_mode_intake exactly once | PASS (line 414) |

Note on Check 4: `grep -c "After MCP Detection\|Ready to investigate"` returns 3 (not 2 as stated in the plan). Verified via `git stash` that this count was 3 before any changes — the plan's expected value of 2 was incorrect. No existing lines were removed; the diff shows 146 pure insertions.

## Tasks

| Task | Description | Status | Notes |
|------|-------------|--------|-------|
| 1 | Locate insertion point | Complete | mcp_detection at line 271 |
| 2 | Insert entry_point_detection | Complete | Committed in 9afc0e3 |
| 3 | Insert hunt_mode_intake | Complete | Committed in same edit as task 2 (both sections inserted atomically) |
| 4 | Verify section order | Complete | Order confirmed correct |
| 5 | Verify investigation mode unchanged | Complete | Zero lines removed, all key strings present |

Tasks 2 and 3 were inserted in a single Edit operation and committed together. This was done intentionally since both sections form one logical insertion block — splitting them would have left the file in an intermediate state with an open routing reference to a section that didn't exist yet.

## Files Modified

- `agents/scope-hunt.md` — 146 lines added (two new sections)

## Next Phase

Phase 40: Hypothesis Engine — agent forms attack hypothesis from detection events and from SCOPE audit run directory output.
