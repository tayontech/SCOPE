---
phase: 40
plan: "40-02"
name: "Hypothesis Engine — Update Existing Sections"
status: complete
completed: "2026-03-30"
commits: 6
requirements_satisfied:
  - HYPO-01
  - HYPO-02
  - HYPO-03
  - HYPO-04
---

# Summary: Plan 40-02

## What Was Done

Threaded the active hypothesis through four existing sections of `agents/scope-hunt.md` via six targeted edits. All other content in affected sections was preserved exactly.

## Tasks Completed

| Task | Description | Commit |
|------|-------------|--------|
| 1 | Added priority 0 "Hypothesis test" to reasoning_framework step selection hierarchy | b7d6779 |
| 2 | Added "Hypothesis test" field to REASONING block in investigation_loop | cb97b26 |
| 3 | Extended step 6 "After Results" with Confirms/Refutes/Inconclusive verdict labels | 14ec9fe |
| 4 | Added `hypothesis_verdict` field to `investigation_findings` accumulator | 6e81ec6 |
| 5 | Added HYPOTHESIS VERDICT block to output_format before Part 1 narrative | 1d21b32 |
| 6 | Updated artifact_saving so investigation.md includes Section 0 for verdict | 152f835 |
| 7 | Verification — all 10 checks passed | (no commit — verification only) |

## Key Changes

**reasoning_framework:** New priority 0 ensures hypothesis testing is the highest-priority step selection criterion when `active_hypothesis` is set. Priorities 1-5 (IOC match, Baseline deviation, Novel entity, FP pattern check, Reference pattern) apply when no hypothesis is active or all hypothesis-critical signals have been checked.

**investigation_loop REASONING block:** Fifth field "Hypothesis test" inserted between "Reference pattern" and "Independent reasoning". Provides explicit per-step reasoning about how the query tests the hypothesis.

**investigation_loop step results:** Three verdict labels added after result notes when `active_hypothesis` is set — Confirms hypothesis, Refutes hypothesis, Inconclusive. Each verdict is recorded in the `investigation_findings` accumulator via the new `hypothesis_verdict` field (values: `confirms | refutes | inconclusive | not_tested`).

**output_format:** New "Hypothesis Verdict" block displayed before Part 1 narrative summary when a hypothesis was active. Includes verdict determination logic (CONFIRMED / REFUTED / PARTIAL / INCONCLUSIVE), evidence step references, observable gaps, and analyst assessment field.

**artifact_saving:** investigation.md now has up to four sections — Section 0 (hypothesis verdict, conditional), Section 1 (narrative), Section 2 (event table), Section 3 (queries run).

## Verification Results

All 10 checks passed:

- Check 1: Priority 0 present in reasoning_framework — 1 match
- Check 2: Hypothesis test field in REASONING block — 1 match
- Check 3: hypothesis_verdict in accumulator schema — 1 match (+ 2 more uses in output_format)
- Check 4: Verdict labels present — 3 matches (Confirms/Refutes/Inconclusive)
- Check 5: HYPOTHESIS VERDICT block fields — 4+ matches
- Check 6: Verdict determination logic — 4 matches (one per verdict option)
- Check 7: artifact_saving sections — 3 matches (Section 0, 1, 2)
- Check 8: Existing priorities 1-5 intact — all 5 present
- Check 9: SPL construction rules unchanged — 3+ matches
- Check 10: Additions under 80 lines — 38 lines added

## Success Criteria

- [x] reasoning_framework has new priority 0 "Hypothesis test"
- [x] investigation_loop REASONING block has "Hypothesis test" field
- [x] Step results use confirms/refutes/inconclusive language
- [x] investigation_findings accumulator has hypothesis_verdict field
- [x] output_format has HYPOTHESIS VERDICT block before narrative summary
- [x] artifact_saving investigation.md has Section 0 for verdict
- [x] SUMMARY.md created

## Phase 40 Status

Both plans complete. Phase 40 (Hypothesis Engine) is done — HYPO-01 through HYPO-04 satisfied.
Next: Phase 41 (Hunt Techniques) — HUNT-01, HUNT-02, HUNT-03.
