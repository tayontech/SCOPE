from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scope.runtime.post_processing import build_results
from scope.runtime.run_context import AccountContext


ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = ROOT / "config/schemas/audit.schema.json"


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text())


def load_named_schema(name: str) -> dict[str, Any]:
    return json.loads((ROOT / "config" / "schemas" / name).read_text())


def resolve_ref(schema: dict[str, Any], value: dict[str, Any]) -> dict[str, Any]:
    ref = value.get("$ref")
    if not ref:
        return value
    current: Any = schema
    for part in ref.removeprefix("#/").split("/"):
        current = current[part]
    return current


def allows_null(schema: dict[str, Any], value: dict[str, Any]) -> bool:
    resolved = resolve_ref(schema, value)
    schema_type = resolved.get("type")
    if schema_type == "null":
        return True
    if isinstance(schema_type, list) and "null" in schema_type:
        return True
    return any(
        allows_null(schema, option)
        for key in ["anyOf", "oneOf"]
        for option in resolved.get(key, [])
    )


def test_audit_schema_allows_graph_node_types_emitted_by_python_graph_builder() -> None:
    schema = load_schema()
    node_types = schema["properties"]["graph"]["properties"]["nodes"]["items"]["properties"]["type"]["enum"]
    emitted_types = [
        "user",
        "role",
        "group",
        "external",
        "data",
        "compute",
        "gateway",
        "messaging",
        "ai",
        "idp",
        "oidc",
    ]

    missing = [node_type for node_type in emitted_types if node_type not in node_types]
    assert missing == []


def test_audit_schema_allows_graph_edge_types_emitted_by_python_graph_builder() -> None:
    schema = load_schema()
    edge_types = schema["properties"]["graph"]["properties"]["edges"]["items"]["properties"]["edge_type"]["enum"]
    emitted_types = [
        "trust",
        "service",
        "network",
        "public_access",
        "membership",
        "executes_as",
        "invokes",
        "network",
        "public_access",
        "authenticates_to",
        "resource_policy_allows",
        "resource_policy_statement",
        "event_source",
        "encrypted_by",
    ]

    missing = [edge_type for edge_type in emitted_types if edge_type not in edge_types]
    assert missing == []


def test_audit_schema_documents_graph_v2_metadata_and_evidence_fields() -> None:
    schema = load_schema()
    graph_props = schema["properties"]["graph"]["properties"]
    node_props = graph_props["nodes"]["items"]["properties"]
    edge_props = graph_props["edges"]["items"]["properties"]

    for field in ["schema_version", "metadata"]:
        assert field in graph_props
    for field in ["resource_type", "arn", "service", "region", "account_id", "source_path", "_source"]:
        assert field in node_props
    for field in ["id", "relationship", "service", "region", "account_id", "evidence", "_source"]:
        assert field in edge_props


def test_audit_schema_documents_attack_pipeline_fields() -> None:
    schema = load_schema()
    for field in ["candidate_attack_paths", "attack_validation", "attack_path_groups", "security_observations"]:
        assert schema["properties"][field]["type"] == "array"

    attack_path_props = schema["properties"]["attack_paths"]["items"]["properties"]
    for field in [
        "id",
        "source_candidate_id",
        "validation_status",
        "hops",
        "runtime_assumptions",
        "coverage_caveats",
    ]:
        assert field in attack_path_props

    assert schema["properties"]["candidate_attack_paths"]["items"]["additionalProperties"] is False
    assert schema["properties"]["attack_validation"]["items"]["additionalProperties"] is False
    assert schema["properties"]["security_observations"]["items"]["additionalProperties"] is False
    assert schema["$defs"]["attackPathGroup"]["additionalProperties"] is False
    assert schema["$defs"]["attackPathGroup"]["properties"]["member_count"]["minimum"] == 1
    assert schema["$defs"]["attackPathGroup"]["properties"]["representative_path_id"]["$ref"] == "#/$defs/nonEmptyString"
    assert "leveraging_assets" in schema["$defs"]["attackPathGroup"]["required"]
    asset_schema = schema["$defs"]["attackPathGroupLeveragingAsset"]
    assert asset_schema["additionalProperties"] is False
    assert asset_schema["properties"]["type"]["enum"] == ["user", "role", "external", "resource", "unknown"]

    required = schema["properties"]["attack_paths"]["items"]["required"]
    for field in ["id", "source_candidate_id", "validation_status", "hops"]:
        assert field in required

    hop = schema["$defs"]["hop"]
    assert "assume_role" in hop["properties"]["transition"]["enum"]
    assert "data_access" in hop["properties"]["transition"]["enum"]
    assert "authenticate" in hop["properties"]["transition"]["enum"]
    assert schema["properties"]["candidate_attack_paths"]["items"]["properties"]["hops"]["minItems"] == 1
    assert schema["properties"]["attack_paths"]["items"]["properties"]["hops"]["minItems"] == 1

    hop_json = json.dumps(hop, separators=(",", ":"))
    assert '"runtime_assumption"' in hop_json
    assert '"assumptions":{"minItems":1' in hop_json
    assert '"evidence":{"minItems":1' in hop_json

    evidence_ref = schema["$defs"]["evidenceRef"]
    assert "graph_edge" in evidence_ref["properties"]["type"]["enum"]
    assert allows_null(schema, evidence_ref["properties"]["id"])
    assert allows_null(schema, schema["$defs"]["attackContext"]["properties"]["principal"])
    assert allows_null(schema, schema["$defs"]["startingPosition"]["properties"]["arn"])
    assert allows_null(schema, schema["properties"]["attack_validation"]["items"]["properties"]["validated_impact"])


def test_audit_schema_allows_review_only_aws_cli_commands() -> None:
    schema = load_schema()
    props = schema["properties"]["attack_paths"]["items"]["properties"]

    assert "aws_cli_commands" in props
    assert "aws_cli_command_warnings" in props
    command_schema = props["aws_cli_commands"]["items"]
    for field in [
        "step",
        "description",
        "command",
        "requires_operator_approval",
        "mutates_aws",
        "prerequisites",
        "cleanup",
        "source_basis",
    ]:
        assert field in command_schema["required"]
    assert command_schema["properties"]["command"]["pattern"] == "^aws\\s+"
    assert command_schema["additionalProperties"] is False


def test_audit_schema_documents_public_entrypoint_fields() -> None:
    schema = load_schema()

    entrypoints = schema["properties"]["public_entrypoints"]
    entrypoint = schema["$defs"]["publicEntrypoint"]
    props = entrypoint["properties"]

    assert entrypoints["items"]["$ref"] == "#/$defs/publicEntrypoint"
    for field in [
        "id",
        "service",
        "resource",
        "public_access",
        "auth_type",
        "starting_position",
        "attack_path_seed",
        "risk",
        "evidence",
    ]:
        assert field in entrypoint["required"]
    for field in ["invokes", "execution_roles", "reachable_resources", "seed_reason", "exposure_type"]:
        assert field in props

    assert "external_unauthenticated" in props["starting_position"]["enum"]
    assert "external_cross_account" in props["starting_position"]["enum"]
    assert "NONE" in props["auth_type"]["enum"]
    assert "RESOURCE_POLICY" in props["auth_type"]["enum"]
    assert "public_endpoint" in props["exposure_type"]["enum"]
    assert entrypoint["additionalProperties"] is False


def test_audit_schema_documents_public_exposure_finding_fields() -> None:
    schema = load_schema()

    findings = schema["properties"]["public_exposure_findings"]
    finding = schema["$defs"]["publicExposureFinding"]
    props = finding["properties"]

    assert findings["items"]["$ref"] == "#/$defs/publicExposureFinding"
    for field in [
        "id",
        "source_entrypoint_id",
        "severity",
        "category",
        "resource",
        "title",
        "assessment",
        "security_relevance",
        "attack_path_seed",
        "reason_not_attack_path",
        "coverage_needed",
        "evidence",
    ]:
        assert field in finding["required"]

    assert resolve_ref(schema, props["severity"])["enum"] == ["critical", "high", "medium", "low"]
    assert props["attack_path_seed"]["type"] == "boolean"
    assert props["promoted_attack_path_ids"]["items"]["$ref"] == "#/$defs/nonEmptyString"
    assert props["coverage_needed"]["items"]["$ref"] == "#/$defs/nonEmptyString"
    assert props["evidence"]["items"]["$ref"] == "#/$defs/evidenceRef"
    assert finding["additionalProperties"] is False


def test_base_audit_results_default_public_exposure_findings_without_public_entrypoints(
    tmp_path: Path,
) -> None:
    results = build_results(
        run_dir=tmp_path,
        run_id="run-1",
        account=AccountContext("123456789012", "prod", True, "config/accounts.json"),
        summary={"status": "complete", "modules": []},
        graph={"nodes": [], "edges": []},
        timestamp="2026-05-24T00:00:00Z",
        post_processing_errors=[],
    )

    assert results["public_exposure_findings"] == []
    assert "public_entrypoints" not in results
    assert results["attack_paths"] == []


def test_exploit_schema_uses_downstream_attack_paths_contract() -> None:
    schema = load_named_schema("exploit.schema.json")

    assert "attack_paths" in schema["required"]
    assert "paths" not in schema["required"]
    assert "paths" not in schema["properties"]

    path_schema = schema["properties"]["attack_paths"]["items"]
    required = path_schema["required"]
    for field in [
        "name",
        "severity",
        "category",
        "description",
        "steps",
        "validation_status",
        "runtime_assumptions",
        "coverage_caveats",
    ]:
        assert field in required

    props = path_schema["properties"]
    assert props["validation_status"]["enum"] == ["validated", "conditional"]
    assert props["severity"]["enum"] == ["critical", "high", "medium", "low"]
    assert "aws_cli_commands" in props
    assert "aws_cli_command_warnings" in props
    command_schema = props["aws_cli_commands"]["items"]
    for field in [
        "step",
        "description",
        "command",
        "requires_operator_approval",
        "mutates_aws",
        "prerequisites",
        "cleanup",
        "source_basis",
    ]:
        assert field in command_schema["required"]
    assert command_schema["properties"]["command"]["pattern"] == "^aws\\s+"


def test_controls_schema_allows_dashboard_ideas() -> None:
    schema = load_named_schema("controls.schema.json")
    assert "dashboards" in schema["required"]
    assert "dashboards" in schema["properties"]["summary"]["required"]

    dashboards = schema["properties"]["dashboards"]["items"]
    required = set(dashboards["required"])
    expected = {
        "name",
        "type",
        "objective",
        "why_dashboard_not_detection",
        "severity",
        "category",
        "source_attack_paths",
        "source_public_exposure_findings",
        "source_run_ids",
        "suggested_panels",
        "required_data_sources",
        "useful_fields",
        "refresh_cadence",
        "owner",
        "coverage_caveats",
        "promotion_triggers",
    }
    assert expected <= required
    assert dashboards["properties"]["type"]["enum"] == [
        "monitoring_dashboard",
        "review_dashboard",
        "coverage_dashboard",
        "trend_dashboard",
    ]
