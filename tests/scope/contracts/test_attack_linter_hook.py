from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
HOOK = ROOT / "config/hooks/scope-schema-validate.sh"


def valid_audit_results(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "account_id": "123456789012",
        "source": "audit",
        "timestamp": "2026-05-21T12:00:00Z",
        "summary": {"severity": "low"},
        "graph": {"nodes": [], "edges": []},
        "attack_paths": [],
        "principals": [],
        "trust_relationships": [],
    }
    payload.update(overrides)
    return payload


def run_hook(tmp_path: Path, payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps(payload, indent=2))
    hook_input = json.dumps(
        {
            "tool_name": "Write",
            "tool_input": {"file_path": str(results_path)},
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


def test_schema_validation_hook_invokes_attack_linter() -> None:
    body = HOOK.read_text()
    assert "python -m scope.attack.lint" in body
    assert "--stage auto" in body


def test_schema_validation_hook_blocks_invalid_attack_results(tmp_path: Path) -> None:
    result = run_hook(
        tmp_path,
        valid_audit_results(
            candidate_attack_paths=[{"name": "candidate missing required fields"}],
            attack_validation=[],
            security_observations=[],
        ),
    )

    assert result.returncode == 0, result.stderr
    decision = parse_decision(result.stdout)
    assert decision is not None
    assert decision["decision"] == "block"
    assert "attack linter failed" in decision["reason"] or "candidate_attack_paths[0]" in decision["reason"]


def test_schema_validation_hook_skips_legacy_audit_results(tmp_path: Path) -> None:
    result = run_hook(tmp_path, valid_audit_results())

    assert result.returncode == 0, result.stderr
    decision = parse_decision(result.stdout)
    if decision is None:
        return
    assert decision.get("decision") != "block"
    assert "attack linter failed" not in decision.get("reason", "")
    assert "candidate_attack_paths" not in decision.get("reason", "")
