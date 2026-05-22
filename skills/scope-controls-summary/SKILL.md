---
name: scope-controls-summary
description: Use when scope-controls has assembled results.json and needs stakeholder executive summary and technical remediation artifacts from structured controls results and subagent outputs.
---

# Scope Controls Summary

Use this skill after `scope-controls` writes `$CONTROLS_RUN_DIR/results.json`.

The caller provides:
- `ACCOUNT_ID`
- `AUDIT_RUN_DIR`
- `CONTROLS_RUN_DIR`
- `VALIDATION_STATUS`
- `$CONTROLS_RUN_DIR/results.json`
- audit module envelopes from `$AUDIT_RUN_DIR/modules/**`
- `$CONTROLS_RUN_DIR/guardrails.json`
- `$CONTROLS_RUN_DIR/detections.json`
- `$CONTROLS_RUN_DIR/policy-replacements.json`
- `$CONTROLS_RUN_DIR/remediation-plan.md`
- `$CONTROLS_RUN_DIR/validation-report.md`
- optional narrative artifacts: `guardrails.md`, `detections.md`, `policy-replacements.md`

## Hard Rules

- Read `results.json` and structured JSON artifacts first.
- Do not infer structured fields from markdown.
- Preserve validation_status, runtime_assumptions, and coverage_caveats.
- Surface Audit Coverage Caveats before key findings.
- Do not claim controls cover resources that the audit did not enumerate.
- Do not write generic boilerplate such as "enable MFA" unless the audit evidence and attack paths support it.
- Use real account IDs, ARNs, resource names, policy names, and file paths from the artifacts.
- Treat `validation_status: conditional` as actionable with caveats.
- Keep recommendations tied to final `attack_paths[]`, not candidates, rejected validation entries, public entrypoints, or security observations.

## Audit Coverage Caveats

Read audit module envelopes for consumed audit runs. For every module with `status: partial` or `status: error`, explain the blind spot and the affected service.

If a module has field-level access failures, such as `<field>_status: denied`, mention the missing field when it affects the control recommendation.

If coverage was complete across consumed modules, write:

```text
Audit coverage was complete. SCOPE identified no blind spots in the consumed module envelopes.
```

## Required Outputs

Write both files:
- `$CONTROLS_RUN_DIR/executive-summary.md`
- `$CONTROLS_RUN_DIR/technical-remediation.md`

If a required input is missing, return `status: error` and write no partial summary.

## executive-summary.md

Audience: security leadership and service owners.

Length: under two pages.

Required sections:
- Account and audit context
- Risk posture and validation status
- Audit Coverage Caveats
- Key output counts
- Top attack paths and impact
- Defensive coverage summary
- Outstanding validation warnings or blocks

Use past tense. Keep claims evidence-backed. Include counts for guardrails, detections, policy replacements, remediation items, validation blocks, and validation warnings from `results.json`.

## technical-remediation.md

Audience: operators who will implement fixes.

Required sections:
- Prioritized action plan from `remediation-plan.md`
- Guardrail deployment references from `guardrails.json` and `policies/`
- IAM policy replacement references from `policy-replacements.json` and `replacements/`
- Detection deployment references from `detections.json` and `detections.md`
- Dependency map
- Validation caveats

Every remediation item needs:
- specific resource identifiers
- concrete action
- source attack path or control reference
- dependency notes when order matters
- validation caveat when the source path has runtime assumptions or coverage caveats

## Return Contract

```text
CONTROLS_SUMMARY
status: complete|skipped|error
files_written:
  - $CONTROLS_RUN_DIR/executive-summary.md
  - $CONTROLS_RUN_DIR/technical-remediation.md
warnings:
  - ...
```
