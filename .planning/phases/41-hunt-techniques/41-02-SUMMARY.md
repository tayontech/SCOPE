---
phase: 41
plan: "41-02"
name: "Hunt Techniques — scope-hunt.md: hunt_technique_patterns, investigation_loop PURPOSE label, output_format hunt report"
status: complete
completed: "2026-03-30"
commits:
  - "feat(41-02): add <hunt_technique_patterns> section between hypothesis_engine and mcp_detection"
  - "feat(41-02): add PURPOSE label (step 3.5) and HYPOTHESIS CHECK citation to investigation_loop"
  - "feat(41-02): update output_format — UNABLE TO QUERY verdict and Recommended Response Actions for MODE=HUNT"
---

# Plan 41-02 Summary

## What Was Done

Three targeted edits to `agents/scope-hunt.md`, each committed atomically.

### Task 2 — `<hunt_technique_patterns>` section inserted

Inserted a new `<hunt_technique_patterns>` section immediately after `</hypothesis_engine>` and before `<mcp_detection>` (lines 640–691). The section:

- Applies only in MODE=HUNT (explicitly skipped for MODE=INVESTIGATION)
- Instructs the agent to read `config/hunt-techniques.json` after `active_hypothesis` is set, before entering `<investigation_loop>`
- Provides a 5-row adversary goal → category key mapping table (persistence, lateral_movement, defense_evasion, credential_abuse, data_exfiltration)
- Defines how each pattern field is used: `cloudtrail_signals` for query selection, `spl_templates` for SPL starting points, `confirm_criteria` / `refute_criteria` for HYPOTHESIS CHECK citations
- Includes the `data_event_caveat` warning block — displayed before any DATA-class query when the flag is `true` in the pattern
- Documents the extension model: new patterns go in the JSON file only, no agent changes required

### Task 3 — PURPOSE label (step 3.5) and HYPOTHESIS CHECK citation

**Edit 3a:** Added step 3.5 between the SPL query display block (step 3) and the analyst gate (step 4) in `<investigation_loop>`. The PURPOSE label states whether the query is designed to confirm or refute the hypothesis, derived from the active pattern's `cloudtrail_signals[].confirm_refute` field. Omitted in MODE=INVESTIGATION when no pattern is loaded.

**Edit 3b:** Added HYPOTHESIS CHECK citation block after the existing confirms/refutes/inconclusive verdict language in step 6. When a hunt technique pattern is active, the agent cites the specific `confirm_criteria` or `refute_criteria` field (verbatim excerpt) that drove the verdict.

### Task 4 — output_format: UNABLE TO QUERY verdict + Recommended Response Actions

**Edit 4a:** Added a fifth verdict state — `UNABLE TO QUERY` — to the HYPOTHESIS VERDICT determination block. The INCONCLUSIVE definition was updated to be explicit that it only applies when queries ran and results were gathered. UNABLE TO QUERY is the distinct state for when Splunk was not available and zero queries were executed.

**Edit 4b:** Extended the "Suggested follow-up actions" block with a MODE conditional. The original block is preserved and labeled as MODE=INVESTIGATION behavior. A MODE=HUNT conditional adds the "Recommended Response Actions" heading with hunt-specific framing: findings-tied, max 5 items, "Consider:" prefix required, never directive.

## Verification Results

All 14 checks from Task 5 passed:

| Check | Description | Result |
|-------|-------------|--------|
| 1 | hunt_technique_patterns open/close tags | 2 matches |
| 2 | Section order: hypothesis_engine → hunt_technique_patterns → mcp_detection | Correct |
| 3 | All 5 category key entries in mapping table | 7+ matches |
| 4 | data_event_caveat warning present | 2 matches |
| 5 | PURPOSE label in investigation_loop | 2 matches |
| 6 | HYPOTHESIS CHECK confirm/refute citations | 2 matches |
| 7 | UNABLE TO QUERY state present | 2+ matches |
| 8 | INCONCLUSIVE updated with Do NOT use clause | 1 match |
| 9 | Recommended Response Actions present | 1 match |
| 10 | Suggested follow-up actions preserved | 1 match |
| 11 | Phase 40 content count ≥5 | 21 matches |
| 12 | No confidence percentages in new sections | 0 matches (correct) |
| 13 | SPL rules intact (index=cloudtrail, sort _time, ISO 8601) | 3+ matches |
| 14 | Diff line count under 120 | 99 lines added |

All Phase 41 success criteria (SC-1 through SC-7) also passed.

## Files Modified

- `agents/scope-hunt.md` — 3 targeted edits, 99 lines added total

## Phase 41 Status After This Plan

Both plans complete. Phase 41 (Hunt Techniques) is done. HUNT-01, HUNT-02, and HUNT-03 are fully satisfied. Next is Phase 42 (Documentation Update).
