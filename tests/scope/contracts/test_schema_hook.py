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
    for module_name in ["bedrock", "cognito", "dynamodb", "ssm"]:
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


def test_hook_accepts_valid_iam_envelope(tmp_path: Path) -> None:
    result = run_hook(tmp_path, valid_envelope("iam"), "iam.json")
    assert_accepted(result, "iam")


def test_hook_blocks_unknown_module_value(tmp_path: Path) -> None:
    envelope = valid_envelope("iam")
    envelope["module"] = "invalidmod"
    result = run_hook(tmp_path, envelope, "iam.json")
    assert_blocked(result, "invalidmod")
