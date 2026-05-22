from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def read_repo_file(relative_path: str) -> str:
    return (ROOT / relative_path).read_text()


def assert_contains(relative_path: str, needle: str) -> None:
    body = read_repo_file(relative_path)
    assert needle in body, f"{relative_path} should contain {needle!r}"


def assert_not_contains(relative_path: str, needle: str) -> None:
    body = read_repo_file(relative_path)
    assert needle not in body, f"{relative_path} should not contain {needle!r}"


def test_runtime_path_contracts_use_runs_directory() -> None:
    assert_contains("README.md", "scope/core/")
    assert_not_contains("README.md", "scope.core/")
    assert_contains("README.md", "config/project-docs/PROJECT.md")
    assert_not_contains("README.md", "blob/main/PROJECT.md")
    assert_contains("agents/scope-defend.md", "/runs/audit-*")
    assert_not_contains("agents/scope-defend.md", "/audit/audit-*")
    assert_contains("agents/scope-hunt.md", "`runs/`")
    assert_not_contains("agents/scope-hunt.md", "`audit/`")
    assert_contains("agents/subagents/scope-synthesizer.md", "./runs/audit-20260301-143022-all/")
    assert_not_contains("agents/subagents/scope-synthesizer.md", "./audit/audit-20260301-143022-all/")
    assert_not_contains("config/scps/README.md", "./audit/audit-*")
    assert_contains("config/scps/README.md", "./runs/audit-*/defend/defend-*/policies/scp-deny-root.json")
    assert_contains("config/hooks/scope-agent-logger.sh", '"$CWD/runs/audit-"*')
    assert_not_contains("config/hooks/scope-agent-logger.sh", '"$CWD/audit/audit-"*')
    assert_contains("config/hooks/scope-artifact-check.sh", 'find "$CWD/runs" -maxdepth 1 -type d -name "audit-*"')
    assert_not_contains("config/hooks/scope-artifact-check.sh", 'find "$CWD/audit"')
    assert_contains("config/hooks/scope-safety-guard.sh", "'./runs/'")
    assert_not_contains("config/hooks/scope-safety-guard.sh", "'./audit/'")
    assert_not_contains("config/hooks/scope-safety-guard.sh", "'./data/'")
    assert_contains("bin/generate-report.js", 'join(projectRoot, "runs", run.run_id)')
    assert_not_contains("bin/generate-report.js", 'join(dashboardDir, "..", "audit", run.run_id)')
