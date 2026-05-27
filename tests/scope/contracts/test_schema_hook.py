from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
HOOK = ROOT / "config/hooks/scope-schema-validate.sh"


def valid_envelope(module_name: str) -> dict[str, Any]:
    return {
        "module": module_name,
        "account_id": "123456789012",
        "region": "us-east-1",
        "timestamp": "2026-05-17T12:00:00Z",
        "status": "complete",
        "resources": [],
    }


def valid_dashboard_idea() -> dict[str, Any]:
    return {
        "name": "Privileged Role Usage Review",
        "type": "review_dashboard",
        "objective": "Track usage of high-privilege roles involved in validated attack paths.",
        "why_dashboard_not_detection": "Role usage may be legitimate and needs trend review before alert thresholds exist.",
        "severity": "high",
        "category": "privilege_escalation",
        "source_attack_paths": ["Validated policy mutation path"],
        "source_run_ids": ["audit-20260517-120000-all"],
        "suggested_panels": [
            {
                "title": "Top principals assuming privileged roles",
                "visualization": "table",
                "question": "Which principals assume privileged roles most often?",
                "fields": ["userIdentity.arn", "requestParameters.roleArn", "sourceIPAddress", "awsRegion", "count"],
            }
        ],
        "required_data_sources": ["aws_api"],
        "useful_fields": ["eventName", "userIdentity.arn", "requestParameters.roleArn", "sourceIPAddress", "awsRegion"],
        "refresh_cadence": "daily",
        "owner": "cloud security",
        "coverage_caveats": [],
        "promotion_triggers": ["new principal assumes role"],
    }


def valid_controls_results() -> dict[str, Any]:
    return {
        "account_id": "123456789012",
        "source": "controls",
        "region": "global",
        "timestamp": "2026-05-17T12:00:00Z",
        "audit_runs_analyzed": ["audit-20260517-120000-all"],
        "summary": {
            "org_wide_issues": 0,
            "detections": 1,
            "dashboards": 1,
            "policy_replacements": 0,
            "remediation_items": 0,
            "validation_status": "pass",
            "severity": "high",
        },
        "org_wide_issues": [],
        "detections": [
            {
                "name": "Policy Mutation Sequence",
                "type": "composite",
                "objective": "Detect attacker-controlled IAM policy activation.",
                "spl": "index=cloudtrail earliest=-24h latest=now eventName=SetDefaultPolicyVersion | stats count by userIdentity.arn",
                "severity": "high",
                "category": "privilege_escalation",
                "mitre_technique": "T1548",
                "source_attack_paths": ["Validated policy mutation path"],
                "source_run_ids": ["audit-20260517-120000-all"],
                "promotion_decision": "alert",
                "fidelity_rationale": "Specific policy mutation against a path-identified policy produces high signal.",
                "noise_controls": ["scope to affected policy ARN from the attack path"],
                "expected_volume": "low",
                "validation_status": "not_validated",
            }
        ],
        "dashboards": [valid_dashboard_idea()],
        "policy_replacements": [],
        "remediation": {"file": "remediation-plan.md", "items": 0},
        "validation": {"status": "pass", "blocks": 0, "warns": 0},
    }


def valid_audit_results() -> dict[str, Any]:
    return {
        "account_id": "123456789012",
        "source": "audit",
        "timestamp": "2026-05-17T12:00:00Z",
        "summary": {"severity": "low"},
        "graph": {"nodes": [], "edges": []},
        "attack_paths": [],
        "principals": [],
        "trust_relationships": [],
    }


def valid_exploit_results() -> dict[str, Any]:
    return {
        "account_id": "123456789012",
        "source": "exploit",
        "timestamp": "2026-05-17T12:00:00Z",
        "target_arn": "arn:aws:iam::123456789012:role/target-role",
        "discovery_mode": "standalone",
        "summary": {"paths_found": 1, "severity": "high"},
        "attack_paths": [
            {
                "name": "Validated role policy escalation",
                "severity": "high",
                "category": "privilege_escalation",
                "description": "The target role can activate an existing policy version.",
                "validation_status": "validated",
                "runtime_assumptions": [],
                "coverage_caveats": [],
                "research_sources": [],
                "steps": [
                    {
                        "description": "Set the default policy version.",
                        "action": "aws iam set-default-policy-version --policy-arn arn:aws:iam::123456789012:policy/example --version-id v2",
                    }
                ],
                "aws_cli_commands": [
                    {
                        "step": 1,
                        "description": "Set the default policy version.",
                        "command": "aws iam set-default-policy-version --policy-arn arn:aws:iam::123456789012:policy/example --version-id v2",
                        "requires_operator_approval": True,
                        "mutates_aws": True,
                        "prerequisites": [],
                        "cleanup": [],
                        "source_basis": ["validated role policy escalation"],
                    }
                ],
                "iam_policy": {"Version": "2012-10-17", "Statement": []},
            }
        ],
    }


def valid_public_entrypoint(**overrides: Any) -> dict[str, Any]:
    entrypoint = {
        "id": "entry-public-api",
        "service": "apigateway",
        "resource": "api-id/stage",
        "arn": "arn:aws:execute-api:us-east-1:123456789012:api-id/prod/GET/payments",
        "public_access": True,
        "auth_type": "NONE",
        "starting_position": "external_unauthenticated",
        "exposure_type": "public_endpoint",
        "invokes": ["arn:aws:lambda:us-east-1:123456789012:function:payments"],
        "execution_roles": [],
        "reachable_resources": [],
        "attack_path_seed": True,
        "seed_reason": "Public API invokes the payments Lambda function.",
        "risk": "high",
        "evidence": [
            {
                "type": "module_resource",
                "source_path": "modules/apigateway/us-east-1.json",
                "arn": "arn:aws:execute-api:us-east-1:123456789012:api-id/prod/GET/payments",
            }
        ],
    }
    entrypoint.update(overrides)
    return entrypoint


def run_hook(tmp_path: Path, envelope_body: dict[str, Any], filename: str) -> subprocess.CompletedProcess[str]:
    file_path = tmp_path / filename
    file_path.write_text(json.dumps(envelope_body, indent=2))
    hook_input = json.dumps(
        {
            "tool_name": "Write",
            "tool_input": {"file_path": str(file_path)},
        }
    )
    return subprocess.run(
        ["bash", str(HOOK)],
        input=hook_input,
        text=True,
        capture_output=True,
        check=False,
    )


def parse_decision(stdout: str) -> dict[str, Any] | None:
    if not stdout.strip():
        return None
    return json.loads(stdout)


def assert_accepted(result: subprocess.CompletedProcess[str], label: str) -> None:
    decision = parse_decision(result.stdout)
    if decision is None:
        return
    assert decision.get("decision") != "block", f"hook blocked {label}: {decision.get('reason', '(no reason)')}"


def assert_blocked(result: subprocess.CompletedProcess[str], label: str) -> None:
    decision = parse_decision(result.stdout)
    assert decision is not None, f"expected block decision for {label}, got empty stdout"
    assert decision["decision"] == "block", f"expected decision:block for {label}, got {decision.get('decision')}"


def test_hook_recognizes_new_module_envelopes(tmp_path: Path) -> None:
    for module_name in ["bedrock", "cognito", "dynamodb", "ecs", "ssm"]:
        envelope = valid_envelope(module_name)
        del envelope["resources"]
        result = run_hook(tmp_path, envelope, f"{module_name}.json")
        assert_blocked(result, f"{module_name} missing resources")


def test_hook_accepts_unknown_account_id_when_status_is_error(tmp_path: Path) -> None:
    envelope = valid_envelope("iam")
    envelope["account_id"] = "unknown"
    envelope["status"] = "error"
    result = run_hook(tmp_path, envelope, "iam.json")
    assert_accepted(result, "unknown account_id with status=error")


def test_hook_blocks_unknown_account_id_when_status_is_complete(tmp_path: Path) -> None:
    envelope = valid_envelope("iam")
    envelope["account_id"] = "unknown"
    result = run_hook(tmp_path, envelope, "iam.json")
    assert_blocked(result, "unknown account_id with status=complete")


def test_hook_blocks_unknown_account_id_when_status_is_partial(tmp_path: Path) -> None:
    envelope = valid_envelope("iam")
    envelope["account_id"] = "unknown"
    envelope["status"] = "partial"
    result = run_hook(tmp_path, envelope, "iam.json")
    assert_blocked(result, "unknown account_id with status=partial")


def test_hook_blocks_unknown_account_id_when_status_is_absent(tmp_path: Path) -> None:
    envelope = valid_envelope("iam")
    envelope["account_id"] = "unknown"
    del envelope["status"]
    result = run_hook(tmp_path, envelope, "iam.json")
    assert_blocked(result, "unknown account_id with no status field")


def test_hook_accepts_empty_coverage_and_errors(tmp_path: Path) -> None:
    envelope = valid_envelope("iam")
    envelope["coverage"] = []
    envelope["errors"] = []
    result = run_hook(tmp_path, envelope, "iam.json")
    assert_accepted(result, "envelope with empty coverage/errors")


def test_hook_accepts_populated_coverage_and_errors(tmp_path: Path) -> None:
    envelope = valid_envelope("iam")
    envelope["coverage"] = [
        {
            "check": "list_users",
            "scope": "module_wide",
            "status": "complete",
            "succeeded": 1,
            "failed": 0,
            "skipped": 0,
            "reasons": [],
        }
    ]
    envelope["errors"] = []
    result = run_hook(tmp_path, envelope, "iam.json")
    assert_accepted(result, "envelope with populated coverage")


def test_hook_accepts_envelope_without_coverage_and_errors(tmp_path: Path) -> None:
    result = run_hook(tmp_path, valid_envelope("iam"), "iam.json")
    assert_accepted(result, "envelope without optional coverage/errors")


def test_audit_hook_rejects_malformed_aws_cli_commands(tmp_path: Path) -> None:
    payload = valid_audit_results()
    payload["attack_paths"] = [
        {
            "id": "path-1",
            "source_candidate_id": "candidate-1",
            "validation_status": "validated",
            "name": "Validated PassRole path",
            "severity": "critical",
            "category": "privilege_escalation",
            "description": "Validated path with replay commands.",
            "hops": [
                {
                    "id": "hop-1",
                    "transition": "permission_escalation",
                    "from_context": {"principal": "arn:aws:iam::123456789012:user/example"},
                    "action": "iam:PassRole",
                    "target": "arn:aws:iam::123456789012:role/Admin",
                    "resulting_context": {"principal": "arn:aws:iam::123456789012:user/example"},
                    "capability_gained": "Can pass role",
                    "required": ["iam:PassRole"],
                    "validation_type": "graph_edge",
                    "evidence": [{"type": "graph_edge", "id": "edge-1"}],
                    "assumptions": [],
                }
            ],
            "runtime_assumptions": [],
            "coverage_caveats": [],
            "aws_cli_commands": [
                {
                    "step": 1,
                    "description": "Bad command",
                    "command": "python replay.py",
                    "requires_operator_approval": True,
                    "mutates_aws": True,
                    "prerequisites": [],
                    "cleanup": [],
                    "source_basis": ["hop-1"],
                }
            ],
        }
    ]

    result = run_hook(tmp_path, payload, "results.json")

    assert_blocked(result, "malformed audit aws_cli_commands should fail")
    reason = parse_decision(result.stdout)["reason"]
    assert "aws_cli_commands" in reason
    assert "must start with 'aws '" in reason


def test_exploit_hook_accepts_attack_paths_contract(tmp_path: Path) -> None:
    result = run_hook(tmp_path, valid_exploit_results(), "results.json")
    assert_accepted(result, "exploit attack_paths contract should pass")


def test_exploit_hook_rejects_legacy_paths_contract(tmp_path: Path) -> None:
    payload = valid_exploit_results()
    payload["paths"] = payload.pop("attack_paths")

    result = run_hook(tmp_path, payload, "results.json")

    assert_blocked(result, "legacy exploit paths contract should fail")
    reason = parse_decision(result.stdout)["reason"]
    assert "attack_paths" in reason
    assert "legacy 'paths'" in reason


def test_exploit_hook_rejects_malformed_aws_cli_commands(tmp_path: Path) -> None:
    payload = valid_exploit_results()
    payload["attack_paths"][0]["aws_cli_commands"][0]["command"] = "python exploit.py"

    result = run_hook(tmp_path, payload, "results.json")

    assert_blocked(result, "malformed aws_cli_commands should fail")
    assert "aws_cli_commands" in parse_decision(result.stdout)["reason"]
    assert "must start with 'aws '" in parse_decision(result.stdout)["reason"]


def test_audit_hook_blocks_malformed_public_entrypoints(tmp_path: Path) -> None:
    payload = valid_audit_results()
    payload["public_entrypoints"] = [
        {
            "id": "entry-public-api",
            "service": "apigateway",
            "resource": "api-id/stage",
            "public_access": True,
        }
    ]

    result = run_hook(tmp_path, payload, "results.json")

    assert_blocked(result, "malformed public_entrypoints")
    assert "public_entrypoints" in parse_decision(result.stdout)["reason"]


def test_audit_hook_blocks_public_entrypoint_seed_without_transition(
    tmp_path: Path,
) -> None:
    payload = valid_audit_results()
    payload["public_entrypoints"] = [
        valid_public_entrypoint(
            invokes=[],
            execution_roles=[],
            reachable_resources=[],
        )
    ]

    result = run_hook(tmp_path, payload, "results.json")

    assert_blocked(result, "public entrypoint seed without transition")
    assert "attack_path_seed true without invokes" in parse_decision(result.stdout)["reason"]


def test_audit_hook_blocks_public_entrypoint_seed_without_reason(
    tmp_path: Path,
) -> None:
    payload = valid_audit_results()
    payload["public_entrypoints"] = [valid_public_entrypoint(seed_reason=" ")]

    result = run_hook(tmp_path, payload, "results.json")

    assert_blocked(result, "public entrypoint seed without reason")
    assert "attack_path_seed true without non-empty seed_reason" in parse_decision(result.stdout)["reason"]


def test_audit_hook_accepts_public_entrypoint_seed_with_transition(
    tmp_path: Path,
) -> None:
    payload = valid_audit_results()
    payload["public_entrypoints"] = [valid_public_entrypoint()]

    result = run_hook(tmp_path, payload, "results.json")

    assert_accepted(result, "public entrypoint seed with transition")


def test_audit_hook_accepts_public_entrypoint_observation_without_transition(
    tmp_path: Path,
) -> None:
    payload = valid_audit_results()
    payload["public_entrypoints"] = [
        valid_public_entrypoint(
            invokes=[],
            execution_roles=[],
            reachable_resources=[],
            attack_path_seed=False,
            seed_reason="Public endpoint has no observed internal transition.",
            risk="medium",
        )
    ]

    result = run_hook(tmp_path, payload, "results.json")

    assert_accepted(result, "public entrypoint observation without transition")


def test_audit_hook_accepts_all_schema_graph_edge_types(tmp_path: Path) -> None:
    payload = valid_audit_results()
    edge_types = [
        "priv_esc",
        "trust",
        "data_access",
        "network",
        "service",
        "public_access",
        "cross_account",
        "membership",
        "executes_as",
        "invokes",
        "authenticates_to",
        "resource_policy_allows",
        "resource_policy_statement",
        "event_source",
        "encrypted_by",
    ]
    payload["graph"] = {
        "nodes": [
            {"id": "node-a", "label": "node-a", "type": "role"},
            {"id": "node-b", "label": "node-b", "type": "data"},
        ],
        "edges": [
            {"source": "node-a", "target": "node-b", "edge_type": edge_type}
            for edge_type in edge_types
        ],
    }

    result = run_hook(tmp_path, payload, "results.json")

    assert_accepted(result, "audit graph edge types allowed by schema")


def test_schema_hook_reads_graph_edge_types_from_audit_schema() -> None:
    body = HOOK.read_text()

    assert "audit_schema_edge_types_json" in body
    assert ".properties.graph.properties.edges.items.properties.edge_type.enum" in body
    assert "--argjson valid \"$ALLOWED_EDGE_TYPES_JSON\"" in body


def test_controls_hook_rejects_malformed_dashboard_ideas(tmp_path: Path) -> None:
    controls = valid_controls_results()
    controls["dashboards"][0].pop("why_dashboard_not_detection")
    result = run_hook(tmp_path, controls, "controls-results.json")
    assert_blocked(result, "controls malformed dashboards")
    assert "dashboards" in result.stdout
    assert "why_dashboard_not_detection" in result.stdout


def test_controls_hook_rejects_dashboards_when_not_array(tmp_path: Path) -> None:
    controls = valid_controls_results()
    controls["dashboards"] = {}
    controls["summary"]["dashboards"] = 0

    result = run_hook(tmp_path, controls, "controls-results.json")

    assert_blocked(result, "controls dashboards must be array")
    assert "'dashboards' must be an array" in parse_decision(result.stdout)["reason"]


def test_controls_hook_rejects_dashboard_panel_visualization_enum(tmp_path: Path) -> None:
    controls = valid_controls_results()
    controls["dashboards"][0]["suggested_panels"][0]["visualization"] = "pie"

    result = run_hook(tmp_path, controls, "controls-results.json")

    assert_blocked(result, "controls dashboard panel visualization enum")
    assert "suggested_panels[].visualization" in parse_decision(result.stdout)["reason"]


def test_controls_hook_rejects_dashboard_panel_missing_required_fields(tmp_path: Path) -> None:
    for field in ["title", "visualization", "question", "fields"]:
        controls = valid_controls_results()
        controls["dashboards"][0]["suggested_panels"][0].pop(field)

        result = run_hook(tmp_path, controls, "controls-results.json")

        assert_blocked(result, f"controls dashboard panel missing {field}")
        assert "suggested_panels[] entries must include title, visualization, question, and fields" in parse_decision(result.stdout)["reason"]


def test_controls_hook_requires_detection_production_fields(tmp_path: Path) -> None:
    payload = valid_controls_results()
    del payload["detections"][0]["promotion_decision"]

    result = run_hook(tmp_path, payload, "results.json")

    assert_blocked(result, "controls detection missing promotion_decision")
    assert "promotion_decision" in parse_decision(result.stdout)["reason"]


def test_controls_hook_blocks_unknown_volume_alerts(tmp_path: Path) -> None:
    payload = valid_controls_results()
    payload["detections"][0]["expected_volume"] = "unknown"

    result = run_hook(tmp_path, payload, "results.json")

    assert_blocked(result, "controls alert with unknown expected volume")
    assert "expected_volume unknown/high cannot be promoted to alert" in parse_decision(result.stdout)["reason"]


def test_controls_hook_blocks_weak_atomic_alerts(tmp_path: Path) -> None:
    payload = valid_controls_results()
    payload["detections"][0]["type"] = "atomic"
    payload["detections"][0]["fidelity_rationale"] = "generic"
    payload["detections"][0]["noise_controls"] = []

    result = run_hook(tmp_path, payload, "results.json")

    assert_blocked(result, "weak atomic controls alert")
    assert "atomic alert detections require non-empty noise_controls" in parse_decision(result.stdout)["reason"]


def test_hook_accepts_valid_iam_envelope(tmp_path: Path) -> None:
    result = run_hook(tmp_path, valid_envelope("iam"), "iam.json")
    assert_accepted(result, "iam")


def test_hook_blocks_unknown_module_value(tmp_path: Path) -> None:
    envelope = valid_envelope("iam")
    envelope["module"] = "invalidmod"
    result = run_hook(tmp_path, envelope, "iam.json")
    assert_blocked(result, "invalidmod")
