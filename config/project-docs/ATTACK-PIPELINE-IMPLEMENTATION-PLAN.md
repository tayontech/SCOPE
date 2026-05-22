# Attack Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the candidate attack-path, validation, linting, and orchestration pipeline described in `config/project-docs/ATTACK-PIPELINE-DESIGN.md`.

**Architecture:** Keep red-team path generation in `scope-attack-analyze`, fact-check candidate mechanics in `scope-attack-validate`, and enforce field contracts with Python linting between agents. Python owns deterministic schema checks, graph evidence checks, offline IAM policy evaluation, and stateful hop validation.

**Tech Stack:** Python 3.11, Pydantic already used by `scope.core.models`, pytest, jq hook integration, agent source markdown under `agents/`, repo-local skills under `skills/`.

**Current implementation note:** SCOPE now treats attack-pipeline contracts as Python-owned. Historical steps below that mention `tests/js/*`, `node tests/js/*`, or `npm test` map to pytest coverage under `tests/scope/attack/` and `tests/scope/contracts/`. Do not recreate JS tests for agent prompts, schemas, hooks, or pipeline contracts.

---

## File Structure

- Create `scope/attack/__init__.py`: package marker.
- Create `scope/attack/schema.py`: Pydantic models and constants for candidates, hops, validation records, observations, and promoted attack paths.
- Create `scope/attack/lint.py`: stage-aware CLI linter for `results.json`.
- Create `scope/attack/policy_eval.py`: offline IAM policy action/resource allow-deny evaluator for collected policy documents.
- Create `scope/attack/validate_graph.py`: graph edge/resource lookup helpers.
- Create `scope/attack/validate_paths.py`: stateful candidate path validator and promoter.
- Create `tests/scope/attack/test_schema.py`: schema model tests.
- Create `tests/scope/attack/test_lint.py`: linter stage and evidence tests.
- Create `tests/scope/attack/test_policy_eval.py`: IAM policy evaluator tests.
- Create `tests/scope/attack/test_validate_paths.py`: stateful validation tests.
- Modify `scope/runtime/post_processing.py`: initialize `candidate_attack_paths`, `attack_validation`, and `security_observations` as empty arrays.
- Modify `config/schemas/audit.schema.json`: document new attack pipeline fields and structured final `attack_paths[]`.
- Modify `config/hooks/scope-schema-validate.sh`: call Python attack linter for audit `results.json` when attack pipeline fields exist.
- Create `agents/subagents/scope-attack-validate.md`: validation subagent source.
- Modify `agents/subagents/scope-attack-analyze.md`: output candidates only and use attack path skill.
- Modify `agents/scope-audit.md`: orchestrate analyze -> linter -> validate -> linter -> verify.
- Create `skills/scope-attack-path-analysis/SKILL.md`: candidate generation method and rejection rules.
- Create `skills/scope-evidence-logging/SKILL.md`: artifact citation method.
- Modify downstream docs/prompts that reference confidence tiers or old attack path steps only when needed for schema compatibility.

## Task 1: Add Base Attack Pipeline Fields

**Files:**
- Modify: `scope/runtime/post_processing.py`
- Modify: `tests/scope/runtime/test_post_processing.py`
- Modify: `tests/scope/runtime/test_audit_dispatch.py`

- [ ] **Step 1: Write failing post-processing test expectations**

In `tests/scope/runtime/test_post_processing.py`, extend `test_build_results_includes_summary_graph_modules_and_empty_attack_paths` to assert the new arrays:

```python
    assert payload["candidate_attack_paths"] == []
    assert payload["attack_validation"] == []
    assert payload["security_observations"] == []
```

In `tests/scope/runtime/test_audit_dispatch.py`, extend the existing assertion near `assert results["attack_paths"] == []`:

```python
    assert results["candidate_attack_paths"] == []
    assert results["attack_validation"] == []
    assert results["security_observations"] == []
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
uv run pytest tests/scope/runtime/test_post_processing.py::test_build_results_includes_summary_graph_modules_and_empty_attack_paths tests/scope/runtime/test_audit_dispatch.py::test_audit_writes_graph_and_results_after_aggregation -q
```

Expected: FAIL with `KeyError` for at least one new field.

- [ ] **Step 3: Add fields to runtime base results**

In `scope/runtime/post_processing.py`, update `build_results()` return payload near `attack_paths`:

```python
        "candidate_attack_paths": [],
        "attack_validation": [],
        "attack_paths": [],
        "security_observations": [],
```

- [ ] **Step 4: Run focused tests and verify pass**

Run:

```bash
uv run pytest tests/scope/runtime/test_post_processing.py::test_build_results_includes_summary_graph_modules_and_empty_attack_paths tests/scope/runtime/test_audit_dispatch.py::test_audit_writes_graph_and_results_after_aggregation -q
```

Expected: PASS.

- [ ] **Step 5: Commit Task 1**

```bash
git add scope/runtime/post_processing.py tests/scope/runtime/test_post_processing.py tests/scope/runtime/test_audit_dispatch.py
git commit -m "feat: initialize attack pipeline result fields"
```

## Task 2: Add Attack Schema Models

**Files:**
- Create: `scope/attack/__init__.py`
- Create: `scope/attack/schema.py`
- Create: `tests/scope/attack/test_schema.py`

- [ ] **Step 1: Write schema tests**

Create `tests/scope/attack/test_schema.py`:

```python
from __future__ import annotations

import pytest
from pydantic import ValidationError

from scope.attack.schema import (
    AttackCandidate,
    AttackValidation,
    EvidenceRef,
    FinalAttackPath,
    Hop,
)


def test_candidate_accepts_structured_stateful_hops() -> None:
    candidate = AttackCandidate.model_validate(
        {
            "id": "cap-001",
            "name": "Public API reaches Lambda role",
            "category": "data_exposure",
            "severity": "high",
            "starting_position": {"type": "public_endpoint", "id": "gateway:apigw:api", "arn": None},
            "initial_context": {"principal": None, "capabilities": ["invoke_public_api"]},
            "hops": [
                {
                    "id": "cap-001-hop-001",
                    "transition": "invoke",
                    "from_context": "external:*",
                    "action": "execute-api:Invoke",
                    "target": "compute:lambda:handler",
                    "resulting_context": "compute:lambda:handler",
                    "capability_gained": "Attacker can trigger Lambda execution",
                    "required": True,
                    "validation_type": "graph",
                    "evidence": [
                        {
                            "type": "graph_edge",
                            "id": "edge:invokes:gateway:apigw:api->compute:lambda:handler",
                            "source_path": "modules/apigateway/us-east-1.json",
                        }
                    ],
                    "assumptions": [],
                }
            ],
            "impact": {"type": "data_access", "resource": "arn:aws:s3:::sensitive/*", "action": "s3:GetObject"},
            "affected_resources": ["arn:aws:s3:::sensitive"],
            "detection_opportunities": ["Invoke", "GetObject"],
            "mitre_techniques": ["T1078.004"],
            "remediation": ["Restrict the public API or remove role S3 access"],
        }
    )

    assert candidate.hops[0].transition == "invoke"
    assert candidate.impact.action == "s3:GetObject"


def test_candidate_rejects_unknown_transition() -> None:
    payload = {
        "id": "cap-001",
        "name": "Bad transition",
        "category": "data_exposure",
        "severity": "high",
        "starting_position": {"type": "public_endpoint", "id": "gateway:apigw:api", "arn": None},
        "initial_context": {"principal": None, "capabilities": []},
        "hops": [
            {
                "id": "cap-001-hop-001",
                "transition": "guess",
                "from_context": "external:*",
                "action": "execute-api:Invoke",
                "target": "compute:lambda:handler",
                "resulting_context": "compute:lambda:handler",
                "capability_gained": "Trigger execution",
                "required": True,
                "validation_type": "graph",
                "evidence": [],
                "assumptions": [],
            }
        ],
        "impact": {"type": "data_access", "resource": "arn:aws:s3:::sensitive/*", "action": "s3:GetObject"},
    }

    with pytest.raises(ValidationError):
        AttackCandidate.model_validate(payload)


def test_conditional_final_path_requires_assumption_or_caveat() -> None:
    base = {
        "id": "ap-001",
        "source_candidate_id": "cap-001",
        "validation_status": "conditional",
        "name": "Conditional path",
        "severity": "high",
        "category": "data_exposure",
        "description": "Authorization chain validates, runtime behavior remains unproven.",
        "hops": [
            {
                "id": "cap-001-hop-001",
                "transition": "invoke",
                "from_context": "external:*",
                "action": "execute-api:Invoke",
                "target": "compute:lambda:handler",
                "resulting_context": "compute:lambda:handler",
                "capability_gained": "Trigger execution",
                "required": True,
                "validation_type": "graph",
                "evidence": [
                    {
                        "type": "graph_edge",
                        "id": "edge:invokes:gateway:apigw:api->compute:lambda:handler",
                        "source_path": "modules/apigateway/us-east-1.json",
                    }
                ],
                "assumptions": [],
            }
        ],
        "runtime_assumptions": [],
        "coverage_caveats": [],
        "affected_resources": [],
        "detection_opportunities": [],
        "mitre_techniques": [],
        "remediation": [],
    }

    with pytest.raises(ValidationError):
        FinalAttackPath.model_validate(base)

    base["runtime_assumptions"] = ["Lambda code must read the target bucket on the invoked path."]
    assert FinalAttackPath.model_validate(base).validation_status == "conditional"
```

- [ ] **Step 2: Run schema tests and verify import failure**

Run:

```bash
uv run pytest tests/scope/attack/test_schema.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'scope.attack'`.

- [ ] **Step 3: Create attack schema models**

Create `scope/attack/__init__.py`:

```python
from __future__ import annotations
```

Create `scope/attack/schema.py`:

```python
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


Severity = Literal["critical", "high", "medium", "low"]
Category = Literal[
    "privilege_escalation",
    "trust_misconfiguration",
    "data_exposure",
    "credential_risk",
    "excessive_permission",
    "network_exposure",
    "persistence",
    "post_exploitation",
    "lateral_movement",
]
Transition = Literal[
    "invoke",
    "execute_as",
    "assume_role",
    "pass_role",
    "create_compute",
    "mutate_policy",
    "resource_policy_access",
    "data_access",
    "decrypt",
    "event_injection",
]
ValidationType = Literal["graph", "iam", "resource_policy", "runtime_assumption", "coverage_caveat"]
EvidenceType = Literal["graph_edge", "module_resource", "policy_document", "runtime_assumption", "coverage_caveat"]
ImpactType = Literal["admin_access", "data_access", "persistence", "lateral_movement", "exfiltration", "defense_evasion"]
ValidationStatus = Literal["validated", "conditional", "rejected"]
PromotionDecision = Literal["promote", "observe", "drop"]
FinalValidationStatus = Literal["validated", "conditional"]


class EvidenceRef(BaseModel):
    type: EvidenceType
    id: str | None = None
    source_path: str | None = None
    arn: str | None = None
    field: str | None = None

    @model_validator(mode="after")
    def require_handle(self) -> "EvidenceRef":
        if not any([self.id, self.source_path, self.arn]):
            raise ValueError("evidence must include id, source_path, or arn")
        return self


class AttackContext(BaseModel):
    principal: str | None = None
    capabilities: list[str] = Field(default_factory=list)


class StartingPosition(BaseModel):
    type: Literal["external", "principal", "resource", "public_endpoint"]
    id: str
    arn: str | None = None


class Hop(BaseModel):
    id: str
    transition: Transition
    from_context: str
    action: str
    target: str
    resulting_context: str
    capability_gained: str
    required: bool = True
    validation_type: ValidationType
    evidence: list[EvidenceRef] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_evidence_or_assumption(self) -> "Hop":
        if self.validation_type == "runtime_assumption":
            if not self.assumptions:
                raise ValueError("runtime_assumption hops require assumptions")
            return self
        if not self.evidence:
            raise ValueError("non-runtime hops require evidence")
        return self


class Impact(BaseModel):
    type: ImpactType
    resource: str
    action: str


class AttackCandidate(BaseModel):
    id: str
    name: str
    category: Category
    severity: Severity
    starting_position: StartingPosition
    initial_context: AttackContext
    hops: list[Hop]
    impact: Impact
    affected_resources: list[str] = Field(default_factory=list)
    detection_opportunities: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_hops(self) -> "AttackCandidate":
        if not self.hops:
            raise ValueError("candidate attack paths require at least one hop")
        return self


class SecurityObservation(BaseModel):
    id: str
    severity: Severity
    description: str
    affected_resources: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    reason_not_path: str


class AttackValidation(BaseModel):
    candidate_id: str
    status: ValidationStatus
    promotion_decision: PromotionDecision
    reason: str
    validated_hops: list[str] = Field(default_factory=list)
    conditional_hops: list[str] = Field(default_factory=list)
    failed_hops: list[str] = Field(default_factory=list)
    untested_hops: list[str] = Field(default_factory=list)
    runtime_assumptions: list[str] = Field(default_factory=list)
    coverage_caveats: list[str] = Field(default_factory=list)
    final_context: str | None = None
    validated_impact: Impact | None = None

    @model_validator(mode="after")
    def align_status_and_promotion(self) -> "AttackValidation":
        if self.status == "rejected" and self.promotion_decision == "promote":
            raise ValueError("rejected candidates cannot be promoted")
        if self.status == "validated" and self.failed_hops:
            raise ValueError("validated candidates cannot have failed hops")
        if self.status == "conditional" and not (self.conditional_hops or self.runtime_assumptions or self.coverage_caveats):
            raise ValueError("conditional validation requires conditional hops, runtime assumptions, or caveats")
        return self


class FinalAttackPath(BaseModel):
    id: str
    source_candidate_id: str
    validation_status: FinalValidationStatus
    name: str
    severity: Severity
    category: Category
    description: str
    hops: list[Hop]
    runtime_assumptions: list[str] = Field(default_factory=list)
    coverage_caveats: list[str] = Field(default_factory=list)
    affected_resources: list[str] = Field(default_factory=list)
    detection_opportunities: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_consistent_final_path(self) -> "FinalAttackPath":
        if not self.hops:
            raise ValueError("final attack paths require structured hops")
        if self.validation_status == "conditional" and not (self.runtime_assumptions or self.coverage_caveats):
            raise ValueError("conditional final paths require runtime assumptions or coverage caveats")
        return self
```

- [ ] **Step 4: Run schema tests**

Run:

```bash
uv run pytest tests/scope/attack/test_schema.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit Task 2**

```bash
git add scope/attack/__init__.py scope/attack/schema.py tests/scope/attack/test_schema.py
git commit -m "feat: add attack pipeline schema models"
```

## Task 3: Add Stage-Aware Attack Linter

**Files:**
- Create: `scope/attack/lint.py`
- Create: `tests/scope/attack/test_lint.py`

- [ ] **Step 1: Write linter tests**

Create `tests/scope/attack/test_lint.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

from scope.attack.lint import lint_results_file


def write_results(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "results.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def base_payload() -> dict:
    return {
        "source": "audit",
        "account_id": "123456789012",
        "region": "global",
        "timestamp": "2026-05-22T00:00:00Z",
        "summary": {"severity": "low"},
        "graph": {
            "nodes": [{"id": "compute:lambda:handler", "label": "handler", "type": "compute"}],
            "edges": [
                {
                    "id": "edge:invokes:gateway:apigw:api->compute:lambda:handler",
                    "source": "gateway:apigw:api",
                    "target": "compute:lambda:handler",
                    "edge_type": "invokes",
                }
            ],
        },
        "attack_paths": [],
        "principals": [],
        "trust_relationships": [],
        "candidate_attack_paths": [],
        "attack_validation": [],
        "security_observations": [],
    }


def candidate() -> dict:
    return {
        "id": "cap-001",
        "name": "Public API reaches Lambda",
        "category": "data_exposure",
        "severity": "high",
        "starting_position": {"type": "public_endpoint", "id": "gateway:apigw:api", "arn": None},
        "initial_context": {"principal": None, "capabilities": ["invoke_public_api"]},
        "hops": [
            {
                "id": "cap-001-hop-001",
                "transition": "invoke",
                "from_context": "external:*",
                "action": "execute-api:Invoke",
                "target": "compute:lambda:handler",
                "resulting_context": "compute:lambda:handler",
                "capability_gained": "Trigger Lambda",
                "required": True,
                "validation_type": "graph",
                "evidence": [
                    {
                        "type": "graph_edge",
                        "id": "edge:invokes:gateway:apigw:api->compute:lambda:handler",
                        "source_path": "modules/apigateway/us-east-1.json",
                    }
                ],
                "assumptions": [],
            }
        ],
        "impact": {"type": "data_access", "resource": "arn:aws:s3:::sensitive/*", "action": "s3:GetObject"},
    }


def test_candidate_stage_rejects_final_attack_paths(tmp_path: Path) -> None:
    payload = base_payload()
    payload["candidate_attack_paths"] = [candidate()]
    payload["attack_paths"] = [{"name": "bad", "severity": "high", "category": "data_exposure"}]
    path = write_results(tmp_path, payload)

    errors = lint_results_file(path, stage="candidates")

    assert any("attack_paths must stay empty" in error for error in errors)


def test_candidate_stage_accepts_valid_candidate(tmp_path: Path) -> None:
    payload = base_payload()
    payload["candidate_attack_paths"] = [candidate()]
    path = write_results(tmp_path, payload)

    assert lint_results_file(path, stage="candidates") == []


def test_validation_stage_rejects_rejected_promoted_path(tmp_path: Path) -> None:
    payload = base_payload()
    payload["candidate_attack_paths"] = [candidate()]
    payload["attack_validation"] = [
        {
            "candidate_id": "cap-001",
            "status": "rejected",
            "promotion_decision": "drop",
            "reason": "Required hop failed",
            "validated_hops": [],
            "conditional_hops": [],
            "failed_hops": ["cap-001-hop-001"],
            "untested_hops": [],
            "runtime_assumptions": [],
            "coverage_caveats": [],
            "final_context": None,
            "validated_impact": None,
        }
    ]
    promoted = dict(candidate())
    payload["attack_paths"] = [
        {
            "id": "ap-001",
            "source_candidate_id": "cap-001",
            "validation_status": "validated",
            "name": promoted["name"],
            "severity": promoted["severity"],
            "category": promoted["category"],
            "description": "Bad promotion.",
            "hops": promoted["hops"],
            "runtime_assumptions": [],
            "coverage_caveats": [],
            "affected_resources": [],
            "detection_opportunities": [],
            "mitre_techniques": [],
            "remediation": [],
        }
    ]
    path = write_results(tmp_path, payload)

    errors = lint_results_file(path, stage="validation")

    assert any("does not reference a promoted validation" in error for error in errors)
```

- [ ] **Step 2: Run linter tests and verify failure**

Run:

```bash
uv run pytest tests/scope/attack/test_lint.py -q
```

Expected: FAIL with `ModuleNotFoundError` for `scope.attack.lint`.

- [ ] **Step 3: Implement linter CLI**

Create `scope/attack/lint.py`:

```python
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from scope.attack.schema import AttackCandidate, AttackValidation, FinalAttackPath, SecurityObservation

Stage = Literal["auto", "candidates", "validation"]


def lint_results_file(path: Path, *, stage: Stage = "auto") -> list[str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"cannot read JSON: {exc}"]

    resolved_stage = _resolve_stage(payload, stage)
    errors: list[str] = []
    candidates = payload.get("candidate_attack_paths", [])
    validations = payload.get("attack_validation", [])
    final_paths = payload.get("attack_paths", [])
    observations = payload.get("security_observations", [])

    if not isinstance(candidates, list):
        errors.append("candidate_attack_paths must be an array")
        candidates = []
    if not isinstance(validations, list):
        errors.append("attack_validation must be an array")
        validations = []
    if not isinstance(final_paths, list):
        errors.append("attack_paths must be an array")
        final_paths = []
    if not isinstance(observations, list):
        errors.append("security_observations must be an array")
        observations = []

    candidate_models = _validate_models(candidates, AttackCandidate, "candidate_attack_paths", errors)
    validation_models = _validate_models(validations, AttackValidation, "attack_validation", errors)
    final_models = _validate_models(final_paths, FinalAttackPath, "attack_paths", errors)
    _validate_models(observations, SecurityObservation, "security_observations", errors)

    candidate_ids = [candidate.id for candidate in candidate_models]
    _append_duplicate_errors(candidate_ids, "candidate_attack_paths[].id", errors)
    hop_ids = [hop.id for candidate in candidate_models for hop in candidate.hops]
    _append_duplicate_errors(hop_ids, "candidate_attack_paths[].hops[].id", errors)

    graph_edge_ids = {
        edge.get("id")
        for edge in ((payload.get("graph") or {}).get("edges") or [])
        if isinstance(edge, dict) and edge.get("id")
    }
    for candidate in candidate_models:
        for hop in candidate.hops:
            for evidence in hop.evidence:
                if evidence.type == "graph_edge" and evidence.id not in graph_edge_ids:
                    errors.append(f"{hop.id} references missing graph edge {evidence.id}")

    if resolved_stage == "candidates":
        if final_paths:
            errors.append("attack_paths must stay empty after candidate generation")

    if resolved_stage == "validation":
        validation_by_candidate = {validation.candidate_id: validation for validation in validation_models}
        for validation in validation_models:
            if validation.candidate_id not in candidate_ids:
                errors.append(f"attack_validation references unknown candidate_id {validation.candidate_id}")
        promoted = {
            validation.candidate_id
            for validation in validation_models
            if validation.promotion_decision == "promote" and validation.status in {"validated", "conditional"}
        }
        for path_model in final_models:
            if path_model.source_candidate_id not in promoted:
                errors.append(f"{path_model.id} does not reference a promoted validation")
            validation = validation_by_candidate.get(path_model.source_candidate_id)
            if validation and validation.status != path_model.validation_status:
                errors.append(f"{path_model.id} validation_status does not match attack_validation status")

    return errors


def _resolve_stage(payload: dict[str, Any], requested: Stage) -> Literal["candidates", "validation"]:
    if requested != "auto":
        return requested
    if payload.get("attack_validation") or payload.get("attack_paths"):
        return "validation"
    return "candidates"


def _validate_models(items: list[Any], model: type[Any], label: str, errors: list[str]) -> list[Any]:
    valid = []
    for index, item in enumerate(items):
        try:
            valid.append(model.model_validate(item))
        except ValidationError as exc:
            errors.append(f"{label}[{index}] schema error: {exc.errors()[0]['msg']}")
    return valid


def _append_duplicate_errors(values: list[str], label: str, errors: list[str]) -> None:
    seen: set[str] = set()
    duplicates = sorted({value for value in values if value in seen or seen.add(value)})
    for duplicate in duplicates:
        errors.append(f"duplicate {label}: {duplicate}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scope.attack.lint")
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--stage", choices=["auto", "candidates", "validation"], default="auto")
    args = parser.parse_args(argv)

    results_path = args.results or (args.run_dir / "results.json" if args.run_dir else None)
    if results_path is None:
        parser.error("--results or --run-dir is required")

    errors = lint_results_file(results_path, stage=args.stage)
    if errors:
        for error in errors:
            print(error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run linter tests**

Run:

```bash
uv run pytest tests/scope/attack/test_lint.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit Task 3**

```bash
git add scope/attack/lint.py tests/scope/attack/test_lint.py
git commit -m "feat: lint attack pipeline contracts"
```

## Task 4: Wire Attack Linter Into Hook

**Files:**
- Modify: `config/hooks/scope-schema-validate.sh`
- Create: `tests/js/attack-linter-hook.test.js`
- Modify: `package.json` if the npm test runner lists individual JS tests manually.

- [ ] **Step 1: Write hook test**

Create `tests/js/attack-linter-hook.test.js`:

```javascript
const assert = require('node:assert');
const fs = require('node:fs');

const hook = fs.readFileSync('config/hooks/scope-schema-validate.sh', 'utf8');

assert.match(
  hook,
  /python -m scope\.attack\.lint/,
  'scope-schema-validate hook must call the Python attack linter'
);

assert.match(
  hook,
  /--stage auto/,
  'scope-schema-validate hook must run attack linter in auto stage'
);
```

- [ ] **Step 2: Run hook test and verify failure**

Run:

```bash
node tests/js/attack-linter-hook.test.js
```

Expected: FAIL because the hook does not call `scope.attack.lint`.

- [ ] **Step 3: Add hook call for audit results**

In `config/hooks/scope-schema-validate.sh`, inside the `audit)` case after the existing category validation block and before `;;`, add:

```bash
    # Attack pipeline contract validation. Keep complex path rules in Python.
    if [ "$(jq 'has("candidate_attack_paths") or has("attack_validation") or has("security_observations")' "$FILE_PATH")" = "true" ]; then
      if ! ATTACK_LINT_OUTPUT=$(uv run python -m scope.attack.lint --results "$FILE_PATH" --stage auto 2>&1); then
        ERRORS+=("attack pipeline contract validation failed: ${ATTACK_LINT_OUTPUT}")
      fi
    fi
```

- [ ] **Step 4: Run hook tests**

Run:

```bash
node tests/js/attack-linter-hook.test.js
bash -n config/hooks/scope-schema-validate.sh
```

Expected: both PASS.

- [ ] **Step 5: Commit Task 4**

```bash
git add config/hooks/scope-schema-validate.sh tests/js/attack-linter-hook.test.js package.json
git commit -m "feat: run attack contract linter from schema hook"
```

## Task 5: Add Offline IAM Policy Evaluator

**Files:**
- Create: `scope/attack/policy_eval.py`
- Create: `tests/scope/attack/test_policy_eval.py`

- [ ] **Step 1: Write policy evaluator tests**

Create `tests/scope/attack/test_policy_eval.py`:

```python
from __future__ import annotations

from scope.attack.policy_eval import evaluate_policy_documents


def test_allows_action_resource_match() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::sensitive/*",
                    }
                ],
            }
        ],
        action="s3:GetObject",
        resource="arn:aws:s3:::sensitive/file.txt",
    )

    assert result.decision == "allowed"


def test_explicit_deny_overrides_allow() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                    {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::sensitive/*"},
                ]
            }
        ],
        action="s3:GetObject",
        resource="arn:aws:s3:::sensitive/file.txt",
    )

    assert result.decision == "explicit_deny"


def test_condition_creates_conditional_decision() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                        "Condition": {"StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"}},
                    }
                ]
            }
        ],
        action="kms:Decrypt",
        resource="arn:aws:kms:us-east-1:123456789012:key/key-1",
    )

    assert result.decision == "conditional"
    assert "Condition" in result.caveats[0]


def test_no_matching_allow_is_implicit_deny() -> None:
    result = evaluate_policy_documents(
        [{"Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}],
        action="s3:GetObject",
        resource="arn:aws:s3:::sensitive/file.txt",
    )

    assert result.decision == "implicit_deny"
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
uv run pytest tests/scope/attack/test_policy_eval.py -q
```

Expected: FAIL with `ModuleNotFoundError` for `scope.attack.policy_eval`.

- [ ] **Step 3: Implement evaluator**

Create `scope/attack/policy_eval.py`:

```python
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any, Literal

Decision = Literal["allowed", "conditional", "explicit_deny", "implicit_deny", "unknown"]


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    matched_allow: list[dict[str, Any]] = field(default_factory=list)
    matched_deny: list[dict[str, Any]] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)


def evaluate_policy_documents(policy_documents: list[dict[str, Any]], *, action: str, resource: str) -> PolicyDecision:
    matched_allow: list[dict[str, Any]] = []
    matched_deny: list[dict[str, Any]] = []
    caveats: list[str] = []

    for document in policy_documents:
        for statement in _statements(document):
            if not _action_matches(statement.get("Action"), action):
                continue
            if not _resource_matches(statement.get("Resource"), resource):
                continue
            if statement.get("Condition"):
                caveats.append(f"Condition present on matching statement for {action}: {statement['Condition']}")
            effect = str(statement.get("Effect", "")).lower()
            if effect == "deny":
                matched_deny.append(statement)
            elif effect == "allow":
                matched_allow.append(statement)

    if matched_deny:
        return PolicyDecision("explicit_deny", matched_allow=matched_allow, matched_deny=matched_deny, caveats=caveats)
    if matched_allow and caveats:
        return PolicyDecision("conditional", matched_allow=matched_allow, caveats=caveats)
    if matched_allow:
        return PolicyDecision("allowed", matched_allow=matched_allow)
    return PolicyDecision("implicit_deny")


def _statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [statement for statement in statements if isinstance(statement, dict)]


def _action_matches(patterns: Any, action: str) -> bool:
    return _matches(patterns, action.lower())


def _resource_matches(patterns: Any, resource: str) -> bool:
    return _matches(patterns, resource)


def _matches(patterns: Any, value: str) -> bool:
    if isinstance(patterns, str):
        patterns = [patterns]
    if not isinstance(patterns, list):
        return False
    for pattern in patterns:
        if not isinstance(pattern, str):
            continue
        candidate = pattern.lower() if ":" in value and value.split(":", 1)[0].islower() else pattern
        if fnmatch.fnmatchcase(value, candidate):
            return True
    return False
```

- [ ] **Step 4: Run policy tests**

Run:

```bash
uv run pytest tests/scope/attack/test_policy_eval.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit Task 5**

```bash
git add scope/attack/policy_eval.py tests/scope/attack/test_policy_eval.py
git commit -m "feat: add offline IAM policy evaluator"
```

## Task 6: Add Graph and Stateful Path Validator

**Files:**
- Create: `scope/attack/validate_graph.py`
- Create: `scope/attack/validate_paths.py`
- Create: `tests/scope/attack/test_validate_paths.py`

- [ ] **Step 1: Write stateful validator tests**

Create `tests/scope/attack/test_validate_paths.py`:

```python
from __future__ import annotations

from scope.attack.validate_paths import validate_candidates


def test_validates_role_chain_and_promotes_final_path() -> None:
    payload = {
        "graph": {
            "nodes": [{"id": "role:RoleA"}, {"id": "role:RoleB"}],
            "edges": [{"id": "edge:trust:role:RoleA->role:RoleB", "source": "role:RoleA", "target": "role:RoleB"}],
        },
        "modules": [],
        "candidate_attack_paths": [
            {
                "id": "cap-001",
                "name": "RoleA chains into RoleB for S3 access",
                "category": "lateral_movement",
                "severity": "high",
                "starting_position": {"type": "principal", "id": "role:RoleA", "arn": "arn:aws:iam::123456789012:role/RoleA"},
                "initial_context": {"principal": "role:RoleA", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-001-hop-001",
                        "transition": "assume_role",
                        "from_context": "role:RoleA",
                        "action": "sts:AssumeRole",
                        "target": "role:RoleB",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "RoleB permissions",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [{"type": "graph_edge", "id": "edge:trust:role:RoleA->role:RoleB"}],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-001-hop-002",
                        "transition": "data_access",
                        "from_context": "role:RoleB",
                        "action": "s3:GetObject",
                        "target": "arn:aws:s3:::sensitive/*",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "Read sensitive objects",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [{"type": "policy_document", "id": "role:RoleB:inline:ReadSensitive"}],
                        "assumptions": [],
                    },
                ],
                "impact": {"type": "data_access", "resource": "arn:aws:s3:::sensitive/*", "action": "s3:GetObject"},
                "affected_resources": ["arn:aws:s3:::sensitive"],
                "detection_opportunities": ["AssumeRole", "GetObject"],
                "mitre_techniques": [],
                "remediation": ["Remove RoleA trust or RoleB S3 read access"],
            }
        ],
    }
    principal_policies = {
        "role:RoleB": [
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::sensitive/*"}
                ]
            }
        ]
    }

    result = validate_candidates(payload, principal_policies=principal_policies)

    assert result["attack_validation"][0]["status"] == "validated"
    assert result["attack_paths"][0]["validation_status"] == "validated"


def test_marks_runtime_assumption_as_conditional() -> None:
    payload = {
        "graph": {"nodes": [], "edges": [{"id": "edge:invokes:gateway:apigw:api->compute:lambda:handler"}]},
        "candidate_attack_paths": [
            {
                "id": "cap-002",
                "name": "Public API triggers Lambda",
                "category": "data_exposure",
                "severity": "high",
                "starting_position": {"type": "public_endpoint", "id": "gateway:apigw:api", "arn": None},
                "initial_context": {"principal": None, "capabilities": []},
                "hops": [
                    {
                        "id": "cap-002-hop-001",
                        "transition": "invoke",
                        "from_context": "external:*",
                        "action": "execute-api:Invoke",
                        "target": "compute:lambda:handler",
                        "resulting_context": "compute:lambda:handler",
                        "capability_gained": "Trigger Lambda",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [{"type": "graph_edge", "id": "edge:invokes:gateway:apigw:api->compute:lambda:handler"}],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-002-hop-002",
                        "transition": "data_access",
                        "from_context": "compute:lambda:handler",
                        "action": "s3:GetObject",
                        "target": "arn:aws:s3:::sensitive/*",
                        "resulting_context": "role:LambdaRole",
                        "capability_gained": "Return sensitive object",
                        "required": True,
                        "validation_type": "runtime_assumption",
                        "evidence": [],
                        "assumptions": ["Lambda code must read the target object and return it to the caller."],
                    },
                ],
                "impact": {"type": "data_access", "resource": "arn:aws:s3:::sensitive/*", "action": "s3:GetObject"},
                "affected_resources": ["arn:aws:s3:::sensitive"],
                "detection_opportunities": ["Invoke", "GetObject"],
                "mitre_techniques": [],
                "remediation": ["Restrict public invocation or remove role data access"],
            }
        ],
    }

    result = validate_candidates(payload, principal_policies={})

    assert result["attack_validation"][0]["status"] == "conditional"
    assert result["attack_paths"][0]["validation_status"] == "conditional"
    assert result["attack_paths"][0]["runtime_assumptions"]
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
uv run pytest tests/scope/attack/test_validate_paths.py -q
```

Expected: FAIL with `ModuleNotFoundError` for `scope.attack.validate_paths`.

- [ ] **Step 3: Implement graph helpers**

Create `scope/attack/validate_graph.py`:

```python
from __future__ import annotations

from typing import Any


def graph_edge_ids(graph: dict[str, Any]) -> set[str]:
    return {
        edge["id"]
        for edge in graph.get("edges", [])
        if isinstance(edge, dict) and isinstance(edge.get("id"), str)
    }


def graph_node_ids(graph: dict[str, Any]) -> set[str]:
    return {
        node["id"]
        for node in graph.get("nodes", [])
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    }
```

- [ ] **Step 4: Implement path validator**

Create `scope/attack/validate_paths.py`:

```python
from __future__ import annotations

from copy import deepcopy
from typing import Any

from scope.attack.policy_eval import evaluate_policy_documents
from scope.attack.schema import AttackCandidate, AttackValidation, FinalAttackPath
from scope.attack.validate_graph import graph_edge_ids


def validate_candidates(payload: dict[str, Any], *, principal_policies: dict[str, list[dict[str, Any]]] | None = None) -> dict[str, Any]:
    principal_policies = principal_policies or {}
    graph_edges = graph_edge_ids(payload.get("graph") or {})
    validations: list[dict[str, Any]] = []
    final_paths: list[dict[str, Any]] = []

    for raw_candidate in payload.get("candidate_attack_paths", []):
        candidate = AttackCandidate.model_validate(raw_candidate)
        validation = _validate_candidate(candidate, graph_edges=graph_edges, principal_policies=principal_policies)
        validations.append(validation.model_dump(mode="json"))
        if validation.promotion_decision == "promote":
            final_paths.append(_promote_candidate(candidate, validation))

    result = deepcopy(payload)
    result["attack_validation"] = validations
    result["attack_paths"] = final_paths
    return result


def _validate_candidate(
    candidate: AttackCandidate,
    *,
    graph_edges: set[str],
    principal_policies: dict[str, list[dict[str, Any]]],
) -> AttackValidation:
    validated_hops: list[str] = []
    conditional_hops: list[str] = []
    failed_hops: list[str] = []
    runtime_assumptions: list[str] = []
    coverage_caveats: list[str] = []
    current_context = candidate.initial_context.principal or candidate.starting_position.id

    for hop in candidate.hops:
        if hop.validation_type == "runtime_assumption":
            conditional_hops.append(hop.id)
            runtime_assumptions.extend(hop.assumptions)
            current_context = hop.resulting_context
            continue

        if hop.validation_type == "graph":
            missing_edges = [
                evidence.id
                for evidence in hop.evidence
                if evidence.type == "graph_edge" and evidence.id not in graph_edges
            ]
            if missing_edges:
                failed_hops.append(hop.id)
                continue
            validated_hops.append(hop.id)
            current_context = hop.resulting_context
            continue

        if hop.validation_type == "iam":
            policies = principal_policies.get(hop.from_context) or principal_policies.get(current_context) or []
            if not policies:
                conditional_hops.append(hop.id)
                coverage_caveats.append(f"No collected policy documents for {hop.from_context}")
                current_context = hop.resulting_context
                continue
            decision = evaluate_policy_documents(policies, action=hop.action, resource=hop.target)
            if decision.decision == "allowed":
                validated_hops.append(hop.id)
            elif decision.decision == "conditional":
                conditional_hops.append(hop.id)
                coverage_caveats.extend(decision.caveats)
            else:
                failed_hops.append(hop.id)
            current_context = hop.resulting_context
            continue

        conditional_hops.append(hop.id)
        coverage_caveats.append(f"{hop.validation_type} validation is not implemented for {hop.id}")
        current_context = hop.resulting_context

    if failed_hops:
        return AttackValidation(
            candidate_id=candidate.id,
            status="rejected",
            promotion_decision="drop",
            reason="One or more required hops failed validation.",
            validated_hops=validated_hops,
            conditional_hops=conditional_hops,
            failed_hops=failed_hops,
            runtime_assumptions=runtime_assumptions,
            coverage_caveats=coverage_caveats,
            final_context=current_context,
            validated_impact=None,
        )
    if conditional_hops or runtime_assumptions or coverage_caveats:
        return AttackValidation(
            candidate_id=candidate.id,
            status="conditional",
            promotion_decision="promote",
            reason="Authorization chain has runtime assumptions or coverage caveats.",
            validated_hops=validated_hops,
            conditional_hops=conditional_hops,
            failed_hops=[],
            runtime_assumptions=runtime_assumptions,
            coverage_caveats=coverage_caveats,
            final_context=current_context,
            validated_impact=candidate.impact,
        )
    return AttackValidation(
        candidate_id=candidate.id,
        status="validated",
        promotion_decision="promote",
        reason="Collected artifacts validate each required hop.",
        validated_hops=validated_hops,
        conditional_hops=[],
        failed_hops=[],
        runtime_assumptions=[],
        coverage_caveats=[],
        final_context=current_context,
        validated_impact=candidate.impact,
    )


def _promote_candidate(candidate: AttackCandidate, validation: AttackValidation) -> dict[str, Any]:
    path = FinalAttackPath(
        id=candidate.id.replace("cap-", "ap-", 1),
        source_candidate_id=candidate.id,
        validation_status="conditional" if validation.status == "conditional" else "validated",
        name=candidate.name,
        severity=candidate.severity,
        category=candidate.category,
        description=f"{candidate.name}: {candidate.impact.action} on {candidate.impact.resource}.",
        hops=candidate.hops,
        runtime_assumptions=validation.runtime_assumptions,
        coverage_caveats=validation.coverage_caveats,
        affected_resources=candidate.affected_resources,
        detection_opportunities=candidate.detection_opportunities,
        mitre_techniques=candidate.mitre_techniques,
        remediation=candidate.remediation,
    )
    return path.model_dump(mode="json")
```

- [ ] **Step 5: Run validation tests**

Run:

```bash
uv run pytest tests/scope/attack/test_validate_paths.py -q
```

Expected: PASS.

- [ ] **Step 6: Commit Task 6**

```bash
git add scope/attack/validate_graph.py scope/attack/validate_paths.py tests/scope/attack/test_validate_paths.py
git commit -m "feat: validate stateful attack path candidates"
```

## Task 7: Extend Audit JSON Schema

**Files:**
- Modify: `config/schemas/audit.schema.json`
- Modify: `tests/js/schema-audit-results.test.js`

- [ ] **Step 1: Write schema test for attack pipeline fields**

In `tests/js/schema-audit-results.test.js`, add:

```javascript
test('audit schema documents attack pipeline fields', () => {
  const props = schema.properties;
  for (const field of ['candidate_attack_paths', 'attack_validation', 'security_observations']) {
    assert.ok(props[field], `missing ${field}`);
    assert.strictEqual(props[field].type, 'array', `${field} must be an array`);
  }

  const finalProps = props.attack_paths.items.properties;
  for (const field of ['id', 'source_candidate_id', 'validation_status', 'hops', 'runtime_assumptions', 'coverage_caveats']) {
    assert.ok(finalProps[field], `missing attack_paths[].${field}`);
  }
});
```

- [ ] **Step 2: Run schema test and verify failure**

Run:

```bash
node tests/js/schema-audit-results.test.js
```

Expected: FAIL because new fields are missing from the schema.

- [ ] **Step 3: Add schema properties**

In `config/schemas/audit.schema.json`, add top-level array properties:

```json
"candidate_attack_paths": {
  "type": "array",
  "items": { "type": "object" }
},
"attack_validation": {
  "type": "array",
  "items": { "type": "object" }
},
"security_observations": {
  "type": "array",
  "items": { "type": "object" }
},
```

Extend `attack_paths.items.properties` with:

```json
"id": { "type": "string" },
"source_candidate_id": { "type": "string" },
"validation_status": { "type": "string", "enum": ["validated", "conditional"] },
"hops": { "type": "array", "items": { "type": "object" } },
"runtime_assumptions": { "type": "array", "items": { "type": "string" } },
"coverage_caveats": { "type": "array", "items": { "type": "string" } }
```

Keep the legacy `steps` property temporarily so downstream agents keep working during migration.

- [ ] **Step 4: Run schema tests**

Run:

```bash
node tests/js/schema-audit-results.test.js
```

Expected: PASS.

- [ ] **Step 5: Commit Task 7**

```bash
git add config/schemas/audit.schema.json tests/js/schema-audit-results.test.js
git commit -m "feat: document attack pipeline result schema"
```

## Task 8: Add Attack Validation Subagent

**Files:**
- Create: `agents/subagents/scope-attack-validate.md`
- Modify: `agents/subagents/README.md` only if deployment notes need a new row.
- Create: `tests/js/attack-validate-agent-contract.test.js`

- [ ] **Step 1: Write agent contract test**

Create `tests/js/attack-validate-agent-contract.test.js`:

```javascript
const assert = require('node:assert');
const fs = require('node:fs');

const prompt = fs.readFileSync('agents/subagents/scope-attack-validate.md', 'utf8');

assert.match(prompt, /^name: scope-attack-validate/m, 'frontmatter name missing');
assert.match(prompt, /candidate_attack_paths\[\]/, 'must consume candidate_attack_paths');
assert.match(prompt, /attack_validation\[\]/, 'must write attack_validation');
assert.match(prompt, /attack_paths\[\]/, 'must write promoted attack_paths');
assert.match(prompt, /python -m scope\.attack\.lint/, 'must run attack linter');
assert.match(prompt, /scope\.attack\.validate_paths/, 'must use Python validation helpers');
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
node tests/js/attack-validate-agent-contract.test.js
```

Expected: FAIL because the subagent file does not exist.

- [ ] **Step 3: Create validation subagent prompt**

Create `agents/subagents/scope-attack-validate.md`:

```markdown
---
name: scope-attack-validate
description: Attack path validation subagent — fact-checks candidate attack paths from results.json, uses Python validation helpers, and promotes validated or conditional paths into attack_paths.
tools: Read, Write, Bash, Glob, Grep
model: reasoning
---

<role>
You are SCOPE's attack path validation analyst. You do not generate new paths. You fact-check `candidate_attack_paths[]` produced by `scope-attack-analyze` and promote only supported paths into final `attack_paths[]`.
</role>

<input_contract>
Provided by parent:
- `RUN_DIR`
- `ACCOUNT_ID`

Required files:
- `$RUN_DIR/results.json`
- `$RUN_DIR/graph.json`
- `$RUN_DIR/modules/iam/global.json` when present
- `$RUN_DIR/modules/**` for resource context
</input_contract>

<method>
1. Read `$RUN_DIR/results.json`.
2. Confirm `candidate_attack_paths[]` exists.
3. Run `uv run python -m scope.attack.lint --run-dir "$RUN_DIR" --stage candidates`.
4. Use Python helpers from `scope.attack.validate_paths` to validate candidate mechanics. Do not hand-wave IAM validation in prose.
5. Preserve the runtime envelope and candidate data.
6. Write `attack_validation[]` and promoted `attack_paths[]`.
7. Run `uv run python -m scope.attack.lint --run-dir "$RUN_DIR" --stage validation`.
</method>

<validation_rules>
- `validated`: collected artifacts support every required authorization hop.
- `conditional`: collected artifacts support the control-plane chain, but runtime behavior or missing context remains.
- `rejected`: a required hop failed. Never promote rejected candidates.
- Do not run AWS IAM Policy Simulator by default.
- Missing AWS-managed policy documents, missing SCP visibility, unsupported policy conditions, or runtime code behavior create conditional caveats when the chain remains structurally supported.
</validation_rules>

<output_contract>
Update only attack-owned fields in `$RUN_DIR/results.json`:
- `attack_validation`
- `attack_paths`
- attack-specific summary fields under `summary`

Preserve:
- `candidate_attack_paths`
- `security_observations`
- runtime inventory fields
- graph
- modules
- resources

Print:
```text
STATUS: complete|partial|error
FILE: {run_dir}/results.json
METRICS: {candidates: N, promoted: N, validated: N, conditional: N, rejected: N}
ERRORS: []
```
</output_contract>
```

- [ ] **Step 4: Run agent contract test**

Run:

```bash
node tests/js/attack-validate-agent-contract.test.js
```

Expected: PASS.

- [ ] **Step 5: Commit Task 8**

```bash
git add agents/subagents/scope-attack-validate.md tests/js/attack-validate-agent-contract.test.js
git commit -m "feat: add attack validation subagent"
```

## Task 9: Rewrite Attack Analyze Contract

**Files:**
- Modify: `agents/subagents/scope-attack-analyze.md`
- Create: `tests/js/attack-analyze-contract.test.js`

- [ ] **Step 1: Write analyze contract test**

Create `tests/js/attack-analyze-contract.test.js`:

```javascript
const assert = require('node:assert');
const fs = require('node:fs');

const prompt = fs.readFileSync('agents/subagents/scope-attack-analyze.md', 'utf8');

assert.match(prompt, /candidate_attack_paths\[\]/, 'attack analyze must write candidate_attack_paths');
assert.match(prompt, /security_observations\[\]/, 'attack analyze must write security_observations');
assert.match(prompt, /does not write final `attack_paths\[\]`|Do not write final `attack_paths\[\]`/, 'attack analyze must not own final paths');
assert.match(prompt, /scope-attack-path-analysis/, 'attack analyze must use the attack path skill');
assert.match(prompt, /python -m scope\.attack\.lint --run-dir "\$RUN_DIR" --stage candidates/, 'attack analyze must run candidate linter');
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
node tests/js/attack-analyze-contract.test.js
```

Expected: FAIL until the prompt changes.

- [ ] **Step 3: Update attack analyze prompt**

Modify `agents/subagents/scope-attack-analyze.md` so the role and output contract state:

```markdown
Your output is candidate generation. You write `candidate_attack_paths[]` and `security_observations[]`. Do not write final `attack_paths[]`; `scope-attack-validate` owns promotion into final attack paths.
```

Replace the old attack path shape with the candidate contract from `config/project-docs/ATTACK-PIPELINE-DESIGN.md`.

Add:

```markdown
Before returning, run:
```bash
uv run python -m scope.attack.lint --run-dir "$RUN_DIR" --stage candidates
```
```

Add a skill instruction:

```markdown
Use `skills/scope-attack-path-analysis/SKILL.md` for chain construction and rejection rules. Use `skills/scope-evidence-logging/SKILL.md` for evidence handles.
```

- [ ] **Step 4: Run analyze contract test**

Run:

```bash
node tests/js/attack-analyze-contract.test.js
```

Expected: PASS.

- [ ] **Step 5: Commit Task 9**

```bash
git add agents/subagents/scope-attack-analyze.md tests/js/attack-analyze-contract.test.js
git commit -m "feat: make attack analysis output candidates"
```

## Task 10: Update Audit Orchestration

**Files:**
- Modify: `agents/scope-audit.md`
- Create: `tests/js/audit-attack-pipeline-contract.test.js`

- [ ] **Step 1: Write orchestration contract test**

Create `tests/js/audit-attack-pipeline-contract.test.js`:

```javascript
const assert = require('node:assert');
const fs = require('node:fs');

const prompt = fs.readFileSync('agents/scope-audit.md', 'utf8');

assert.match(prompt, /scope-attack-analyze/, 'audit must dispatch attack analyze');
assert.match(prompt, /scope-attack-validate/, 'audit must dispatch attack validate');
assert.match(prompt, /--stage candidates/, 'audit must run candidate linter');
assert.match(prompt, /--stage validation/, 'audit must run validation linter');
assert.match(prompt, /candidates generated/, 'Gate 4 must report candidates generated');
assert.match(prompt, /validated paths/, 'Gate 4 must report validated paths');
assert.match(prompt, /conditional paths/, 'Gate 4 must report conditional paths');
assert.match(prompt, /rejected paths/, 'Gate 4 must report rejected paths');
```

- [ ] **Step 2: Run test and verify failure**

Run:

```bash
node tests/js/audit-attack-pipeline-contract.test.js
```

Expected: FAIL until `scope-audit.md` mentions the new pipeline.

- [ ] **Step 3: Update attack pipeline section in scope-audit**

Replace the current `<attack_paths_dispatch>` section with:

```markdown
<attack_paths_dispatch>
## Attack Path Candidate + Validation Pipeline

The Python runtime generated `graph.json`, `resources.jsonl`, `summary.json`, and base `results.json`.

### Candidate Generation

Dispatch `scope-attack-analyze` with:
- `RUN_DIR`
- `ACCOUNT_ID`
- `OWNED_ACCOUNTS`

Expected: `candidate_attack_paths[]` and `security_observations[]` written to `$RUN_DIR/results.json`.

Run:
```bash
uv run python -m scope.attack.lint --run-dir "$RUN_DIR" --stage candidates
```

If candidate lint fails, stop before validation and surface the linter errors.

### Candidate Validation

Dispatch `scope-attack-validate` with:
- `RUN_DIR`
- `ACCOUNT_ID`

Expected: `attack_validation[]` and promoted `attack_paths[]` written to `$RUN_DIR/results.json`.

Run:
```bash
uv run python -m scope.attack.lint --run-dir "$RUN_DIR" --stage validation
```

If validation lint fails, stop before Gate 4 and surface the linter errors.
</attack_paths_dispatch>
```

Update Gate 4 display text:

```markdown
Display: candidates generated, validated paths, conditional paths, rejected paths, final attack path count by severity, and top 3 validated/conditional paths.
```

- [ ] **Step 4: Run orchestration contract test**

Run:

```bash
node tests/js/audit-attack-pipeline-contract.test.js
```

Expected: PASS.

- [ ] **Step 5: Commit Task 10**

```bash
git add agents/scope-audit.md tests/js/audit-attack-pipeline-contract.test.js
git commit -m "feat: orchestrate attack candidate validation pipeline"
```

## Task 11: Add First-Wave Repo Skills

**Files:**
- Create: `skills/scope-attack-path-analysis/SKILL.md`
- Create: `skills/scope-evidence-logging/SKILL.md`
- Create: `tests/js/repo-skills-contract.test.js`

- [ ] **Step 1: Write skill contract test**

Create `tests/js/repo-skills-contract.test.js`:

```javascript
const assert = require('node:assert');
const fs = require('node:fs');

for (const path of [
  'skills/scope-attack-path-analysis/SKILL.md',
  'skills/scope-evidence-logging/SKILL.md',
]) {
  assert.ok(fs.existsSync(path), `${path} must exist`);
  const body = fs.readFileSync(path, 'utf8');
  assert.match(body, /^---\nname: /, `${path} must have skill frontmatter`);
  assert.match(body, /description: Use when /, `${path} description must be trigger-focused`);
}

const attack = fs.readFileSync('skills/scope-attack-path-analysis/SKILL.md', 'utf8');
assert.match(attack, /candidate_attack_paths\[\]/, 'attack skill must target candidate paths');
assert.match(attack, /entry point -> new execution context -> new permission set -> impact/, 'attack skill must define chain quality bar');

const evidence = fs.readFileSync('skills/scope-evidence-logging/SKILL.md', 'utf8');
assert.match(evidence, /graph edge/, 'evidence skill must cover graph edges');
assert.match(evidence, /module/, 'evidence skill must cover module files');
```

- [ ] **Step 2: Run skill test and verify failure**

Run:

```bash
node tests/js/repo-skills-contract.test.js
```

Expected: FAIL because skill files do not exist.

- [ ] **Step 3: Create attack path skill**

Create `skills/scope-attack-path-analysis/SKILL.md`:

```markdown
---
name: scope-attack-path-analysis
description: Use when generating AWS attack path candidates from SCOPE runtime artifacts, graph relationships, IAM context, resource policies, or service pivots.
---

# Scope Attack Path Analysis

Generate `candidate_attack_paths[]`, not final `attack_paths[]`.

## Chain Quality Bar

A candidate path must show attacker state progression:

```text
entry point -> new execution context -> new permission set -> impact
```

Each hop must change position, principal context, capability, reachable resource, or impact.

## Accept

- Public endpoint invokes compute that executes as a role with meaningful access.
- Principal assumes a role, then uses the new role's permissions for a stronger action.
- Role can pass another role into compute and gain that compute role's permissions.
- Resource policy grants external access that leads to data access, decrypt, lateral movement, or persistence.

## Reject

- Single posture facts with no attacker progression.
- Permission lists with no context change.
- Chains missing a required hop.
- Data access claims without a target resource or required action.

## Output Rules

- Write `candidate_attack_paths[]` with structured `hops[]`.
- Write non-chain facts to `security_observations[]`.
- Mark runtime behavior as `runtime_assumption`.
- Do not write final `attack_paths[]`.
```

- [ ] **Step 4: Create evidence skill**

Create `skills/scope-evidence-logging/SKILL.md`:

```markdown
---
name: scope-evidence-logging
description: Use when writing SCOPE claims, attack path hops, validation records, findings, controls, or reports that depend on runtime artifacts.
---

# Scope Evidence Logging

Every claim needs a handle that another agent can resolve.

## Valid Evidence Handles

- `graph_edge`: graph edge ID from `$RUN_DIR/graph.json`.
- `module_resource`: module path plus resource ID or ARN.
- `policy_document`: principal/resource and policy name or ARN.
- `runtime_assumption`: explicit assumption text.
- `coverage_caveat`: module status, coverage check, or field status.

## Rules

- Prefer graph edge IDs for relationships.
- Use module paths for resource facts.
- Use ARNs for affected AWS resources.
- Label runtime behavior as an assumption.
- Do not use placeholders.
- Do not cite a file path that does not exist under the run directory.
```

- [ ] **Step 5: Run skill test**

Run:

```bash
node tests/js/repo-skills-contract.test.js
```

Expected: PASS.

- [ ] **Step 6: Commit Task 11**

```bash
git add skills/scope-attack-path-analysis/SKILL.md skills/scope-evidence-logging/SKILL.md tests/js/repo-skills-contract.test.js
git commit -m "feat: add attack pipeline skills"
```

## Task 12: Update Downstream Consumers for Validation Status

**Files:**
- Modify: `agents/scope-defend.md` or renamed `agents/scope-controls.md` if that migration has happened.
- Modify: `agents/subagents/scope-defend-splunk.md`
- Modify: `agents/subagents/scope-defend-remediation.md`
- Modify: `agents/subagents/scope-defend-guardrails.md`
- Modify: `agents/subagents/scope-synthesizer.md`
- Modify: `agents/subagents/scope-hunt-audit.md`
- Modify: `agents/scope-exploit.md`
- Create: `tests/js/downstream-validation-status-contract.test.js`

- [ ] **Step 1: Write downstream contract test**

Create `tests/js/downstream-validation-status-contract.test.js`:

```javascript
const assert = require('node:assert');
const fs = require('node:fs');

const files = [
  'agents/subagents/scope-defend-splunk.md',
  'agents/subagents/scope-defend-remediation.md',
  'agents/subagents/scope-defend-guardrails.md',
  'agents/subagents/scope-synthesizer.md',
  'agents/subagents/scope-hunt-audit.md',
  'agents/scope-exploit.md',
];

for (const file of files) {
  const body = fs.readFileSync(file, 'utf8');
  assert.doesNotMatch(body, /confidence_tier|confidence percentages|confidence_pct/, `${file} must not use confidence tiers`);
}

const controls = fs.readFileSync('agents/subagents/scope-defend-splunk.md', 'utf8');
assert.match(controls, /validation_status/, 'defend splunk must consume validation_status');
assert.match(controls, /runtime_assumptions/, 'defend splunk must preserve runtime assumptions');
```

- [ ] **Step 2: Run downstream test and verify failure**

Run:

```bash
node tests/js/downstream-validation-status-contract.test.js
```

Expected: FAIL because several prompts still mention confidence tiers.

- [ ] **Step 3: Replace old confidence language**

Make targeted replacements:

- `confidence_tier=GUARANTEED` -> `validation_status=validated`
- `confidence_tier=CONDITIONAL` -> `validation_status=conditional`
- "confidence" in findings context -> "validation status"
- detection tuning for conditional paths should reference `runtime_assumptions[]`.

In defend/control prompts, add:

```markdown
Consume final `attack_paths[]` where `validation_status` is `validated` or `conditional`. Preserve `runtime_assumptions[]` in control mappings. Do not treat `conditional` as low priority; it means SCOPE validated the control-plane chain but runtime behavior or missing context remains.
```

- [ ] **Step 4: Run downstream test**

Run:

```bash
node tests/js/downstream-validation-status-contract.test.js
```

Expected: PASS.

- [ ] **Step 5: Commit Task 12**

```bash
git add agents/scope-defend.md agents/subagents/scope-defend-splunk.md agents/subagents/scope-defend-remediation.md agents/subagents/scope-defend-guardrails.md agents/subagents/scope-synthesizer.md agents/subagents/scope-hunt-audit.md agents/scope-exploit.md tests/js/downstream-validation-status-contract.test.js
git commit -m "chore: migrate downstream agents to validation status"
```

## Task 13: Full Verification

**Files:**
- No source edits unless verification reveals a defect.

- [ ] **Step 1: Run Python attack tests**

Run:

```bash
uv run pytest tests/scope/attack -q
```

Expected: PASS.

- [ ] **Step 2: Run runtime tests touched by this plan**

Run:

```bash
uv run pytest tests/scope/runtime/test_post_processing.py tests/scope/runtime/test_audit_dispatch.py -q
```

Expected: PASS.

- [ ] **Step 3: Run JavaScript contract tests**

Run:

```bash
node tests/js/attack-linter-hook.test.js
node tests/js/attack-validate-agent-contract.test.js
node tests/js/attack-analyze-contract.test.js
node tests/js/audit-attack-pipeline-contract.test.js
node tests/js/repo-skills-contract.test.js
node tests/js/downstream-validation-status-contract.test.js
```

Expected: PASS.

- [ ] **Step 4: Run existing JS tests**

Run:

```bash
npm test -- --silent
```

Expected: PASS.

- [ ] **Step 5: Run full Python test suite**

Run:

```bash
uv run pytest -q
```

Expected: PASS.

- [ ] **Step 6: Run syntax and shell checks**

Run:

```bash
uv run python -m scope --help
uv run python -m scope.attack.lint --help
bash -n config/hooks/*.sh
git diff --check
```

Expected: all commands exit 0.

- [ ] **Step 7: Commit verification fixes if any**

If verification required fixes:

```bash
git add <changed-files>
git commit -m "fix: stabilize attack pipeline verification"
```

If no fixes were needed, do not create an empty commit.

## Self-Review Checklist

- Spec coverage: Implements analyzer/validator split, state model, candidate schema, validation schema, promotion rules, linting gates, downstream validation status behavior, skills, and Python helpers.
- Placeholders: No implementation step uses unresolved placeholders or "add tests" without concrete test content.
- Type consistency: Candidate IDs use `cap-*`; final path IDs use `ap-*`; validation statuses use `validated|conditional|rejected`; final validation statuses use `validated|conditional`.
- Scope control: AWS IAM Policy Simulator remains out of default implementation.
- Compatibility: `steps` remains in `config/schemas/audit.schema.json` during migration so old downstream consumers do not break before Task 12 lands.
