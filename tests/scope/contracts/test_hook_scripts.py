from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
ARTIFACT_HOOK = ROOT / "config/hooks/scope-artifact-check.sh"
OUTPUT_INJECT_HOOK = ROOT / "config/hooks/scope-aws-output-inject.sh"
LOGGER_HOOK = ROOT / "config/hooks/scope-agent-logger.sh"
SAFETY_HOOK = ROOT / "config/hooks/scope-safety-guard.sh"
SCHEMA_HOOK = ROOT / "config/hooks/scope-schema-validate.sh"


def run_hook(hook: Path, payload: dict[str, object]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(hook)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )


def write_controls_file(run_dir: Path, name: str, body: str = "{}") -> None:
    path = run_dir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)


def test_safety_guard_blocks_shell_c_aws_wrapper() -> None:
    result = run_hook(
        SAFETY_HOOK,
        {"tool_input": {"command": 'bash -c "aws iam delete-user --user-name example"'}},
    )

    assert result.returncode == 2
    assert "shell -c with AWS CLI" in result.stderr


def test_safety_guard_blocks_aws_destructive_command_after_global_options() -> None:
    result = run_hook(
        SAFETY_HOOK,
        {
            "tool_input": {
                "command": "aws --profile prod --region us-east-1 iam create-user --user-name bad"
            }
        },
    )

    assert result.returncode == 2
    assert "aws iam create-" in result.stderr


def test_safety_guard_blocks_antigravity_run_command_payload() -> None:
    result = run_hook(
        SAFETY_HOOK,
        {
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": "aws iam create-user --user-name bad"},
            }
        },
    )

    assert result.returncode == 0
    decision = json.loads(result.stdout)
    assert decision["decision"] == "deny"
    assert "aws iam create-" in decision["reason"]


def test_safety_guard_blocks_iac_without_aws_token() -> None:
    result = run_hook(
        SAFETY_HOOK,
        {"tool_input": {"command": "terraform apply -auto-approve"}},
    )

    assert result.returncode == 2
    assert "terraform apply" in result.stderr


def test_aws_output_inject_respects_equals_form_output() -> None:
    result = run_hook(
        OUTPUT_INJECT_HOOK,
        {
            "tool_name": "run_shell_command",
            "tool_input": {"command": "aws sts get-caller-identity --output=yaml"},
        },
    )

    assert result.returncode == 0
    decision = json.loads(result.stdout)
    assert decision == {"decision": "allow"}


def test_schema_hook_validates_recent_shell_written_results(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs/audit-20260523-120000-all"
    run_dir.mkdir(parents=True)
    (run_dir / "results.json").write_text(
        json.dumps(
            {
                "account_id": "123456789012",
                "source": "audit",
                "timestamp": "2026-05-23T12:00:00Z",
                "summary": {"severity": "low"},
            }
        )
    )

    result = run_hook(
        SCHEMA_HOOK,
        {
            "cwd": str(tmp_path),
            "tool_name": "Bash",
            "tool_input": {"command": 'cat > "$RUN_DIR/results.json"'},
        },
    )

    assert result.returncode == 0
    decision = json.loads(result.stdout)
    assert decision["decision"] == "block"
    assert "graph" in decision["reason"]


def test_schema_hook_reads_antigravity_file_payload(tmp_path: Path) -> None:
    results_path = tmp_path / "runs/audit-20260523-120000-all/results.json"
    results_path.parent.mkdir(parents=True)
    results_path.write_text(
        json.dumps(
            {
                "account_id": "123456789012",
                "source": "audit",
                "timestamp": "2026-05-23T12:00:00Z",
                "summary": {"severity": "low"},
            }
        )
    )

    result = run_hook(
        SCHEMA_HOOK,
        {
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(results_path)},
            }
        },
    )

    assert result.returncode == 0
    decision = json.loads(result.stdout)
    assert decision["decision"] == "block"
    assert "graph" in decision["reason"]


def test_agent_logger_matches_env_prefixed_aws_commands(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs/audit-20260523-120000-all"
    run_dir.mkdir(parents=True)

    result = run_hook(
        LOGGER_HOOK,
        {
            "cwd": str(tmp_path),
            "tool_input": {"command": "AWS_PROFILE=scope aws iam list-users --output json"},
            "tool_response": "{}",
        },
    )

    assert result.returncode == 0
    for _ in range(20):
        if (run_dir / "agent-log.jsonl").exists():
            break
        subprocess.run(["sleep", "0.05"], check=False)

    log = (run_dir / "agent-log.jsonl").read_text()
    entry = json.loads(log.splitlines()[0])
    assert entry["service"] == "iam"
    assert entry["action"] == "list-users"


def test_agent_logger_reads_antigravity_run_command_payload(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs/audit-20260523-120000-all"
    run_dir.mkdir(parents=True)

    result = run_hook(
        LOGGER_HOOK,
        {
            "toolCall": {
                "name": "run_command",
                "args": {
                    "CommandLine": "aws iam list-users --output json",
                    "Cwd": str(tmp_path),
                },
            },
            "error": "",
        },
    )

    assert result.returncode == 0
    for _ in range(20):
        if (run_dir / "agent-log.jsonl").exists():
            break
        subprocess.run(["sleep", "0.05"], check=False)

    log = (run_dir / "agent-log.jsonl").read_text()
    entry = json.loads(log.splitlines()[0])
    assert entry["service"] == "iam"
    assert entry["action"] == "list-users"


def test_agent_logger_classifies_access_denied(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs/audit-20260523-120000-all"
    run_dir.mkdir(parents=True)

    result = run_hook(
        LOGGER_HOOK,
        {
            "cwd": str(tmp_path),
            "tool_input": {"command": "aws iam list-users --output json"},
            "tool_response": "An error occurred (AccessDenied) when calling the ListUsers operation",
        },
    )

    assert result.returncode == 0
    for _ in range(20):
        if (run_dir / "agent-log.jsonl").exists():
            break
        subprocess.run(["sleep", "0.05"], check=False)

    log = (run_dir / "agent-log.jsonl").read_text()
    entry = json.loads(log.splitlines()[0])
    assert entry["response_status"] == "access_denied"


def test_artifact_check_allows_org_wide_controls_without_policies_dir(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs/audit-20260523-120000-all/controls/controls-20260523-120500"
    run_dir.mkdir(parents=True)
    for name in [
        "results.json",
        "org-wide-issues.md",
        "detections.md",
        "detections.json",
        "dashboards.md",
        "dashboards.json",
        "policy-replacements.md",
        "policy-replacements.json",
        "remediation-plan.md",
        "validation-report.md",
        "agent-log.jsonl",
    ]:
        write_controls_file(run_dir, name)
    write_controls_file(run_dir, "org-wide-issues.json", "[]")

    result = run_hook(ARTIFACT_HOOK, {"cwd": str(tmp_path)})

    assert result.returncode == 0


def test_artifact_check_requires_dashboard_controls_artifacts(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs/audit-20260523-120000-all/controls/controls-20260523-120500"
    run_dir.mkdir(parents=True)
    for name in [
        "results.json",
        "org-wide-issues.md",
        "org-wide-issues.json",
        "detections.md",
        "detections.json",
        "policy-replacements.md",
        "policy-replacements.json",
        "remediation-plan.md",
        "validation-report.md",
        "agent-log.jsonl",
    ]:
        write_controls_file(run_dir, name)

    result = run_hook(ARTIFACT_HOOK, {"cwd": str(tmp_path)})

    assert result.returncode == 2
    assert "dashboards.md" in result.stderr
    assert "dashboards.json" in result.stderr


def test_artifact_check_defers_audit_dashboard_until_findings_exist(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs/audit-20260523-120000-all"
    run_dir.mkdir(parents=True)
    (run_dir / "results.json").write_text(
        json.dumps(
            {
                "account_id": "123456789012",
                "source": "audit",
                "timestamp": "2026-05-23T12:00:00Z",
                "summary": {},
                "graph": {"nodes": [], "edges": []},
                "attack_paths": [],
                "principals": [],
                "trust_relationships": [],
            }
        )
    )

    result = run_hook(ARTIFACT_HOOK, {"cwd": str(tmp_path)})

    assert result.returncode == 0
    decision = json.loads(result.stdout)
    assert "final dashboard export check deferred" in decision["systemMessage"]


def test_artifact_check_requires_audit_dashboard_after_findings_exist(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs/audit-20260523-120000-all"
    run_dir.mkdir(parents=True)
    (run_dir / "results.json").write_text(
        json.dumps(
            {
                "account_id": "123456789012",
                "source": "audit",
                "timestamp": "2026-05-23T12:00:00Z",
                "summary": {},
                "graph": {"nodes": [], "edges": []},
                "attack_paths": [],
                "principals": [],
                "trust_relationships": [],
            }
        )
    )
    (run_dir / "findings.md").write_text("# Findings\n")

    result = run_hook(ARTIFACT_HOOK, {"cwd": str(tmp_path)})

    assert result.returncode == 2
    assert "dashboard/public/audit-20260523-120000-all.json" in result.stderr
    assert "Warnings:\nWARNING" in result.stderr
    assert "Warnings:\\nWARNING" not in result.stderr


def test_artifact_check_does_not_sigpipe_with_many_recent_module_files(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs/audit-20260523-120000-all"
    modules_dir = run_dir / "modules/iam"
    modules_dir.mkdir(parents=True)
    (run_dir / "results.json").write_text(
        json.dumps(
            {
                "account_id": "123456789012",
                "source": "audit",
                "timestamp": "2026-05-23T12:00:00Z",
                "summary": {},
                "graph": {"nodes": [], "edges": []},
                "attack_paths": [],
                "principals": [],
                "trust_relationships": [],
            }
        )
    )
    (run_dir / "findings.md").write_text("# Findings\n")
    (run_dir / "agent-log.jsonl").write_text("")
    public_dir = tmp_path / "dashboard/public"
    public_dir.mkdir(parents=True)
    (public_dir / "audit-20260523-120000-all.json").write_text("{}")
    for index in range(300):
        (modules_dir / f"region-{index}.json").write_text(
            json.dumps({"module": "iam", "status": "complete"})
        )

    result = run_hook(ARTIFACT_HOOK, {"cwd": str(tmp_path)})

    assert result.returncode == 0
