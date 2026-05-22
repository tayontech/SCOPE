from __future__ import annotations

import json
from pathlib import Path

from scope.attack.lint import _parse_args, lint_results_file


EDGE_ID = "edge:invokes:gateway:apigw:api->compute:lambda:handler"


def _hop(hop_id: str = "cap-001-hop-001") -> dict[str, object]:
    return {
        "id": hop_id,
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
                "id": EDGE_ID,
                "source_path": "modules/apigateway/us-east-1.json",
            }
        ],
        "assumptions": [],
    }


def _candidate(candidate_id: str = "cap-001") -> dict[str, object]:
    return {
        "id": candidate_id,
        "name": "Public API reaches Lambda role",
        "category": "data_exposure",
        "severity": "high",
        "starting_position": {
            "type": "public_endpoint",
            "id": "gateway:apigw:api",
            "arn": None,
        },
        "initial_context": {"principal": None, "capabilities": ["invoke_public_api"]},
        "hops": [_hop()],
        "impact": {
            "type": "data_access",
            "resource": "arn:aws:s3:::sensitive/*",
            "action": "s3:GetObject",
        },
        "affected_resources": ["arn:aws:s3:::sensitive"],
        "detection_opportunities": ["Invoke", "GetObject"],
        "mitre_techniques": ["T1078.004"],
        "remediation": ["Restrict the public API or remove role S3 access"],
    }


def _validation(candidate_id: str = "cap-001") -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "status": "validated",
        "promotion_decision": "promote",
        "reason": "Graph and IAM checks validate the candidate.",
        "validated_hops": ["cap-001-hop-001"],
        "conditional_hops": [],
        "failed_hops": [],
        "untested_hops": [],
        "runtime_assumptions": [],
        "coverage_caveats": [],
        "final_context": "compute:lambda:handler",
        "validated_impact": {
            "type": "data_access",
            "resource": "arn:aws:s3:::sensitive/*",
            "action": "s3:GetObject",
        },
    }


def _final_path(candidate_id: str = "cap-001") -> dict[str, object]:
    return {
        "id": "ap-001",
        "source_candidate_id": candidate_id,
        "validation_status": "validated",
        "name": "Public API reaches Lambda role",
        "severity": "high",
        "category": "data_exposure",
        "description": "A public API can invoke Lambda and reach sensitive data.",
        "hops": [_hop()],
        "runtime_assumptions": [],
        "coverage_caveats": [],
        "affected_resources": ["arn:aws:s3:::sensitive"],
        "detection_opportunities": ["Invoke", "GetObject"],
        "mitre_techniques": ["T1078.004"],
        "remediation": ["Restrict the public API or remove role S3 access"],
    }


def _results(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "graph": {"nodes": [], "edges": [{"id": EDGE_ID}]},
        "public_entrypoints": [
            {
                "id": "gateway:apigw:api",
                "attack_path_seed": True,
            }
        ],
        "candidate_attack_paths": [],
        "attack_validation": [],
        "attack_paths": [],
        "security_observations": [],
    }
    payload.update(overrides)
    return payload


def _write_results(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "results.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_candidates_stage_rejects_non_empty_final_attack_paths(
    tmp_path: Path,
) -> None:
    path = _write_results(
        tmp_path,
        _results(candidate_attack_paths=[_candidate()], attack_paths=[_final_path()]),
    )

    errors = lint_results_file(path, stage="candidates")

    assert any("candidates stage requires attack_paths to be empty" in e for e in errors)


def test_candidates_stage_accepts_valid_candidate_with_graph_edge_evidence(
    tmp_path: Path,
) -> None:
    path = _write_results(tmp_path, _results(candidate_attack_paths=[_candidate()]))

    assert lint_results_file(path, stage="candidates") == []


def test_candidates_stage_rejects_public_endpoint_without_seed(
    tmp_path: Path,
) -> None:
    path = _write_results(
        tmp_path,
        _results(
            public_entrypoints=[
                {
                    "id": "gateway:apigw:api",
                    "attack_path_seed": False,
                }
            ],
            candidate_attack_paths=[_candidate()],
        ),
    )

    errors = lint_results_file(path, stage="candidates")

    assert any("public_entrypoints[] item with attack_path_seed true" in e for e in errors)


def test_candidates_stage_allows_non_public_start_without_public_seed(
    tmp_path: Path,
) -> None:
    candidate = _candidate()
    candidate["starting_position"] = {
        "type": "principal",
        "id": "arn:aws:iam::123456789012:role/AppRole",
        "arn": "arn:aws:iam::123456789012:role/AppRole",
    }
    path = _write_results(
        tmp_path,
        _results(public_entrypoints=[], candidate_attack_paths=[candidate]),
    )

    assert lint_results_file(path, stage="candidates") == []


def test_validation_stage_rejects_final_path_without_promoted_validation(
    tmp_path: Path,
) -> None:
    path = _write_results(
        tmp_path,
        _results(
            candidate_attack_paths=[_candidate()],
            attack_validation=[_validation(candidate_id="cap-002")],
            attack_paths=[_final_path()],
        ),
    )

    errors = lint_results_file(path, stage="validation")

    assert any("unknown candidate cap-002" in e for e in errors)
    assert any("unknown promoted validation cap-001" in e for e in errors)


def test_missing_attack_pipeline_arrays_rejected(tmp_path: Path) -> None:
    path = _write_results(tmp_path, {"graph": {"nodes": [], "edges": []}})

    errors = lint_results_file(path, stage="candidates")

    assert "candidate_attack_paths is required" in errors
    assert "attack_validation is required" in errors
    assert "attack_paths is required" in errors
    assert "security_observations is required" in errors


def test_duplicate_attack_validation_candidate_id_rejected(tmp_path: Path) -> None:
    path = _write_results(
        tmp_path,
        _results(
            candidate_attack_paths=[_candidate()],
            attack_validation=[_validation(), _validation()],
        ),
    )

    errors = lint_results_file(path, stage="validation")

    assert any("duplicate attack_validation candidate_id cap-001" in e for e in errors)


def test_duplicate_attack_paths_id_rejected(tmp_path: Path) -> None:
    path = _write_results(
        tmp_path,
        _results(
            candidate_attack_paths=[_candidate()],
            attack_validation=[_validation()],
            attack_paths=[_final_path(), _final_path()],
        ),
    )

    errors = lint_results_file(path, stage="validation")

    assert any("duplicate attack_paths id ap-001" in e for e in errors)


def test_cli_help_uses_module_command_name(capsys) -> None:
    try:
        _parse_args(["--help"])
    except SystemExit as exc:
        assert exc.code == 0

    captured = capsys.readouterr()
    assert "python -m scope.attack.lint" in captured.out
