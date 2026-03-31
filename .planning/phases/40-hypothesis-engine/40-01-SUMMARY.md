---
phase: 40
plan: "40-01"
name: "Hypothesis Engine — New <hypothesis_engine> Section (HYPO-01, HYPO-02, HYPO-03, HYPO-04)"
status: complete
completed: "2026-03-30"
requirements: [HYPO-01, HYPO-02, HYPO-03, HYPO-04]
---

# Summary: Plan 40-01 — Hypothesis Engine Section

## What Was Done

Inserted a new `<hypothesis_engine>` section into `agents/scope-hunt.md`, positioned between `</hunt_mode_intake>` (line 418) and `<mcp_detection>` (line 640 after insert). The section is 218 lines and implements all four HYPO requirements.

## Section Structure

The `<hypothesis_engine>` section branches on MODE to produce the right hypothesis type:

- **MODE=INVESTIGATION (HYPO-01):** Adversary goal mapping table with 13 alert types → hypothesis templates. Single hypothesis always auto-proceeds without selection prompt.
- **MODE=HUNT, HUNT_RUN_TYPE=AUDIT (HYPO-02):** Generates hypotheses from critical/high attack paths in results.json. Includes MITRE T-ID → CloudTrail eventName fallback table (8 entries). Medium paths pad if critical+high < 3; low paths excluded.
- **MODE=HUNT, HUNT_RUN_TYPE=EXPLOIT (HYPO-03):** Filters to GUARANTEED confidence paths first. Partitions steps by visibility (MGT/DATA = observable; NONE = unobservable). Hypothesis statement explicitly states unobservable step count.
- **Operator Selection (HYPO-04):** Single hypothesis auto-proceeds; multiple hypotheses display numbered list and wait. Options A (all sequential) and B (detail view) implemented. Gate enforced — never proceeds to investigation_loop without selected hypothesis.

## Verification Checks Passed

All 9 verification checks from the plan passed:

| Check | Result |
|-------|--------|
| V1 — Section order | PASS — 418 < 420 < 638 < 640 |
| V2 — MODE branching (≥3) | PASS — 11 matches |
| V3 — Alert type table (≥4) | PASS — 29 matches |
| V4 — MITRE table (≥5) | PASS — 6 matches |
| V5 — Visibility partitioning (≥3) | PASS — 3 matches |
| V6 — Selection prompt and gate (≥3) | PASS — 4 matches |
| V7 — active_hypothesis state (≥1) | PASS — 1 match |
| V8 — No confidence percentages | PASS — 0 matches |
| V9 — Existing sections intact (≥3) | PASS — 4 matches |

## Files Modified

- `agents/scope-hunt.md` — inserted `<hypothesis_engine>` section (220 lines added, 0 removed)

## Commits

1. `feat(40-01): insert <hypothesis_engine> section between </hunt_mode_intake> and <mcp_detection>`
2. `feat(40-01): verify section order, content completeness, and existing sections intact`

## Next Plan

Plan 40-02 — Investigation Loop (will add hypothesis-driven step selection and verdict assessment to `<investigation_loop>`).
