from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Literal, TypeVar

from pydantic import ValidationError

from scope.attack.schema import (
    AttackCandidate,
    AttackValidation,
    FinalAttackPath,
    SecurityObservation,
)


Stage = Literal["auto", "candidates", "validation"]
ModelT = TypeVar(
    "ModelT", AttackCandidate, AttackValidation, FinalAttackPath, SecurityObservation
)
REQUIRED_ARRAY_FIELDS = (
    "candidate_attack_paths",
    "attack_validation",
    "attack_paths",
    "security_observations",
)


def lint_results_file(path: Path, *, stage: Stage = "auto") -> list[str]:
    errors: list[str] = []
    payload = _load_payload(path, errors)
    if payload is None:
        return errors

    candidate_payloads = _required_array(payload, "candidate_attack_paths", errors)
    validation_payloads = _required_array(payload, "attack_validation", errors)
    final_path_payloads = _required_array(payload, "attack_paths", errors)
    observation_payloads = _required_array(payload, "security_observations", errors)

    graph_edge_ids = _graph_edge_ids(payload)
    candidates = _validate_items(
        "candidate_attack_paths", candidate_payloads, AttackCandidate, errors
    )
    validations = _validate_items(
        "attack_validation", validation_payloads, AttackValidation, errors
    )
    final_paths = _validate_items(
        "attack_paths", final_path_payloads, FinalAttackPath, errors
    )
    observations = _validate_items(
        "security_observations", observation_payloads, SecurityObservation, errors
    )

    _check_duplicate_candidate_ids(candidates, errors)
    _check_duplicate_validation_candidate_ids(validations, errors)
    _check_duplicate_final_path_ids(final_paths, errors)
    _check_duplicate_hop_ids("candidate_attack_paths", candidates, errors)
    _check_duplicate_hop_ids("attack_paths", final_paths, errors)
    _check_graph_edge_evidence(
        "candidate_attack_paths", candidates, graph_edge_ids, errors
    )
    _check_graph_edge_evidence("attack_paths", final_paths, graph_edge_ids, errors)
    _check_graph_edge_evidence(
        "security_observations", observations, graph_edge_ids, errors
    )

    resolved_stage = _resolve_stage(stage, validation_payloads, final_path_payloads)
    if resolved_stage == "candidates":
        _check_candidates_stage(final_path_payloads, errors)
    if resolved_stage == "validation":
        _check_validation_stage(candidates, validations, final_paths, errors)

    return errors


def _load_payload(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        with path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
    except OSError as exc:
        errors.append(f"{path}: failed to read results file: {exc}")
        return None
    except json.JSONDecodeError as exc:
        errors.append(f"{path}: invalid JSON: {exc.msg}")
        return None

    if not isinstance(payload, dict):
        errors.append("results payload must be a JSON object")
        return None
    return payload


def _required_array(payload: dict[str, Any], field: str, errors: list[str]) -> list[Any]:
    if field not in payload:
        errors.append(f"{field} is required")
        return []
    value = payload.get(field, [])
    if isinstance(value, list):
        return value
    errors.append(f"{field} must be an array")
    return []


def _validate_items(
    field: str,
    values: list[Any],
    model: type[ModelT],
    errors: list[str],
) -> list[ModelT]:
    valid: list[ModelT] = []
    for index, value in enumerate(values):
        try:
            valid.append(model.model_validate(value))
        except ValidationError as exc:
            for error in exc.errors():
                location = ".".join(str(part) for part in error["loc"])
                suffix = f".{location}" if location else ""
                errors.append(f"{field}[{index}]{suffix}: {error['msg']}")
    return valid


def _graph_edge_ids(payload: dict[str, Any]) -> set[str]:
    graph = payload.get("graph", {})
    if not isinstance(graph, dict):
        return set()
    edges = graph.get("edges", [])
    if not isinstance(edges, list):
        return set()
    return {edge["id"] for edge in edges if isinstance(edge, dict) and edge.get("id")}


def _check_duplicate_candidate_ids(
    candidates: list[AttackCandidate], errors: list[str]
) -> None:
    seen: set[str] = set()
    for candidate in candidates:
        if candidate.id in seen:
            errors.append(f"duplicate candidate id {candidate.id}")
        seen.add(candidate.id)


def _check_duplicate_validation_candidate_ids(
    validations: list[AttackValidation], errors: list[str]
) -> None:
    seen: set[str] = set()
    for validation in validations:
        if validation.candidate_id in seen:
            errors.append(
                f"duplicate attack_validation candidate_id {validation.candidate_id}"
            )
        seen.add(validation.candidate_id)


def _check_duplicate_final_path_ids(
    final_paths: list[FinalAttackPath], errors: list[str]
) -> None:
    seen: set[str] = set()
    for final_path in final_paths:
        if final_path.id in seen:
            errors.append(f"duplicate attack_paths id {final_path.id}")
        seen.add(final_path.id)


def _check_duplicate_hop_ids(
    field: str,
    paths: list[AttackCandidate] | list[FinalAttackPath],
    errors: list[str],
) -> None:
    seen: set[str] = set()
    for path in paths:
        for hop in path.hops:
            if hop.id in seen:
                errors.append(f"{field}: duplicate hop id {hop.id}")
            seen.add(hop.id)


def _check_graph_edge_evidence(
    field: str,
    values: list[AttackCandidate] | list[FinalAttackPath] | list[SecurityObservation],
    graph_edge_ids: set[str],
    errors: list[str],
) -> None:
    for value in values:
        for evidence_id in _graph_edge_evidence_ids(value, field, errors):
            if evidence_id not in graph_edge_ids:
                errors.append(
                    f"{field}: graph_edge evidence id {evidence_id} is not in graph.edges"
                )


def _graph_edge_evidence_ids(
    value: AttackCandidate | FinalAttackPath | SecurityObservation,
    field: str,
    errors: list[str],
) -> list[str]:
    ids: list[str] = []
    if isinstance(value, SecurityObservation):
        evidence_refs = value.evidence
    else:
        evidence_refs = [
            evidence for hop in value.hops for evidence in hop.evidence
        ]

    for evidence in evidence_refs:
        if evidence.type != "graph_edge":
            continue
        if evidence.id is None:
            errors.append(f"{field}: graph_edge evidence requires id")
            continue
        if evidence.id:
            ids.append(evidence.id)
    return ids


def _resolve_stage(
    stage: Stage, validations: list[Any], final_paths: list[Any]
) -> Literal["candidates", "validation"]:
    if stage != "auto":
        return stage
    if validations or final_paths:
        return "validation"
    return "candidates"


def _check_candidates_stage(final_path_payloads: list[Any], errors: list[str]) -> None:
    if final_path_payloads:
        errors.append("candidates stage requires attack_paths to be empty")


def _check_validation_stage(
    candidates: list[AttackCandidate],
    validations: list[AttackValidation],
    final_paths: list[FinalAttackPath],
    errors: list[str],
) -> None:
    candidate_ids = {candidate.id for candidate in candidates}
    for validation in validations:
        if validation.candidate_id not in candidate_ids:
            errors.append(f"attack_validation: unknown candidate {validation.candidate_id}")

    promoted_validations = {
        validation.candidate_id: validation
        for validation in validations
        if validation.promotion_decision == "promote"
        and validation.status in {"validated", "conditional"}
    }
    for final_path in final_paths:
        validation = promoted_validations.get(final_path.source_candidate_id)
        if validation is None:
            errors.append(
                "attack_paths: unknown promoted validation "
                f"{final_path.source_candidate_id}"
            )
            continue
        if final_path.validation_status != validation.status:
            errors.append(
                "attack_paths: validation_status mismatch for "
                f"{final_path.source_candidate_id}: final path is "
                f"{final_path.validation_status}, validation is {validation.status}"
            )


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m scope.attack.lint",
        description="Lint SCOPE attack pipeline results.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--results", type=Path, help="Path to results.json")
    source.add_argument("--run-dir", type=Path, help="Run directory containing results.json")
    parser.add_argument(
        "--stage",
        choices=("auto", "candidates", "validation"),
        default="auto",
        help="Attack pipeline stage to validate",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    path = args.results if args.results is not None else args.run_dir / "results.json"
    errors = lint_results_file(path, stage=args.stage)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
