---
name: scope-detection-format
description: Use when formatting SCOPE controls detection candidates into detections.md, detections.json, dashboard-readable SPL sections, or controls-schema detection records.
---

# Scope Detection Format

This skill is format-only. It turns caller-provided detection decisions into the two controls artifacts: `detections.md` for humans and `detections.json` for the orchestrator, validator, and dashboard.

## Boundary

The caller owns detection quality.

- Do not decide alert vs hunt.
- Do not promote, reject, or downgrade detections.
- Do not change SPL logic.
- Do not invent required values.
- Do not add attack paths, event names, MITRE IDs, exclusions, noise controls, validation status, volume, or fidelity rationale that the caller did not provide.
- If a required field is missing, return `FORMAT_BLOCKS` with the missing fields and affected detection names.

## Inputs

Accept a caller-prepared detection list. Each detection must include these required fields:

- `name`
- `type`
- `objective`
- `spl`
- `severity`
- `category`
- `mitre_technique`
- `source_attack_paths`
- `source_public_exposure_findings`
- `source_run_ids`
- `promotion_decision`
- `fidelity_rationale`
- `noise_controls`
- `expected_volume`
- `validation_status`

Optional fields:

- `covered_hops`
- `coverage_caveats`
- `tuning_guidance`

## Normalization

Only apply mechanical formatting:

- Keep severity lowercase: `critical`, `high`, `medium`, `low`.
- Keep `type` as `atomic`, `composite`, `hunt_query`, or `coverage_gap`.
- Keep `promotion_decision` as `alert`, `hunt_query`, `coverage_gap`, or `reject`.
- Keep `expected_volume` as `low`, `medium`, `high`, or `unknown`.
- Keep `validation_status` as `not_validated`, `validated`, `too_noisy`, or `failed`.
- SPL in `detections.json` must be a single-line string with literal newlines replaced by spaces.
- Markdown SPL blocks must use fenced `spl` code blocks.
- Dashboard-readable text must be concise and avoid long inline SPL in prose.

If a value cannot be normalized mechanically, return `FORMAT_BLOCKS`.

## detections.md

Write sections in this order:

````markdown
# SPL Detections

Generated from: {AUDIT_RUN_DIR}
Account: {ACCOUNT_ID}
Attack paths analyzed: {N}
Detections generated: {N}

---

## Attack Path: {attack_path_name}

**Severity:** {severity}
**Category:** {category}
**Validation Status:** {validated|conditional}
**Runtime Assumptions:** {runtime_assumptions[] or "none"}
**Coverage Caveats:** {coverage_caveats[] or "none"}
**MITRE:** {technique_ids}

### Detection: {detection_name}

- **MITRE:** {mitre_technique}
- **Severity:** {severity}
- **Type:** {atomic|composite|hunt_query|coverage_gap}
- **Promotion:** {alert|hunt_query|coverage_gap|reject}
- **Expected Volume:** {low|medium|high|unknown}
- **Fidelity Rationale:** {fidelity_rationale}
- **Noise Controls:** {noise_controls[]}
- **Related Attack Paths:** {source_attack_paths[]}
- **Description:** {objective}

```spl
{spl as readable multiline query}
````

**False Positives:** {false_positive_guidance if caller provided it, otherwise "Not provided."}
**Tuning Guidance:** {tuning_guidance if caller provided it, otherwise "Not provided."}

---
```

Group detections by attack path name. If a detection maps to multiple attack paths, repeat a short reference under each related attack path or place it under the primary path and list the remaining names in `Related Attack Paths`.

## detections.json

Write an array of objects that match `config/schemas/controls.schema.json`:

```json
[
  {
    "name": "Detect IAM Policy Version Reversion",
    "type": "composite",
    "objective": "Detect IAM managed policy version manipulation that can activate attacker-controlled permissions",
    "spl": "index=<aws_api_index> earliest=-24h latest=now eventName=SetDefaultPolicyVersion | rename userIdentity.userName AS user, userIdentity.arn AS src_user_arn | stats count by src_user_arn, eventName, sourceIPAddress, awsRegion",
    "severity": "critical",
    "category": "privilege_escalation",
    "mitre_technique": "T1548",
    "source_attack_paths": ["attack_path_name"],
    "source_public_exposure_findings": [],
    "source_run_ids": ["audit_run_id"],
    "covered_hops": ["hop-1"],
    "promotion_decision": "alert",
    "fidelity_rationale": "Caller-provided rationale.",
    "noise_controls": ["Caller-provided control."],
    "expected_volume": "low",
    "validation_status": "not_validated",
    "coverage_caveats": [],
    "tuning_guidance": "Caller-provided tuning guidance."
  }
]
```

## Zero Detections

When the caller provides no detections, write:

- `detections.json`: `[]`
- `detections.md`: a short `# SPL Detections` document with `Detections generated: 0` and the reason supplied by the caller.

## Return

Return:

```text
STATUS: complete|blocked
FORMAT_BLOCKS: []
FILES: detections.md, detections.json
```

Set `STATUS: blocked` when required fields are missing or malformed.
