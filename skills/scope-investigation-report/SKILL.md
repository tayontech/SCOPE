---
name: scope-investigation-report
description: Use when scope-investigate completes an investigation and needs a facts-only analyst summary, evidence timeline, query appendix, investigation gaps, and optional saved investigation artifact.
---

# SCOPE Investigation Report

Use this skill after the analyst chooses `done` in `scope-investigate`, before the save prompt and before durable knowledge updates.

The top-level investigation agent provides:

- `MODE`: `INVESTIGATION`, `RUN`, or `INTEL`
- `active_hypothesis`
- `investigation_context`
- `investigation_findings`
- `KNOWLEDGE_CONTEXT`
- skipped steps and analyst pivots
- saved artifact path when persistence was approved

## Rules

- Present facts only. Do not assign severity, risk, suspicion, compromise, maliciousness, or confidence.
- Do not infer events that no query returned.
- Do not hide skipped steps or telemetry gaps.
- Prefix every follow-up option with `Consider:`.
- Cite `KNOWLEDGE_CONTEXT` entries only when they influenced reasoning.
- Use UTC timestamps.
- Deduplicate events that appeared in overlapping query windows.

## Required Sections

Return this structure:

```markdown
## Investigation Summary

[2-5 sentences. State what the data showed, what the data did not show, and what remains unknown.]

## Evidence Timeline

| Timestamp (UTC) | Event | Principal | Source IP | Details |
|-----------------|-------|-----------|-----------|---------|

## Key Indicators Found

- [Observable fact]

## Investigation Gaps

- [Skipped step, missing telemetry, or unanswered question]

## Environment Context Used

| Entity | Knowledge Entry | How It Informed Investigation |
|--------|-----------------|-------------------------------|

## Suggested Follow-Up Actions

- Consider: [optional next step]
```

Omit `Environment Context Used` when no knowledge entry influenced the investigation.

## Saved Artifact Appendix

When the analyst approves save, append:

```markdown
## Queries Run

| Step | Purpose | SPL | Result Summary |
|------|---------|-----|----------------|

## Skipped Or Pivoted Steps

| Step | Status | Reason |
|------|--------|--------|
```

## Output Contract

Return:

```text
INVESTIGATION_REPORT
  status: complete|skipped|error
  sections:
    - Investigation Summary
    - Evidence Timeline
    - Key Indicators Found
    - Investigation Gaps
    - Suggested Follow-Up Actions
  save_ready: true|false
  knowledge_update_candidates:
    - ...
```
