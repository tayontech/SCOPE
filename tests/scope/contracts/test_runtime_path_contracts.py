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


def test_controls_naming_is_canonical() -> None:
    expected_paths = [
        "agents/scope-controls.md",
        "agents/subagents/scope-controls-guardrails.md",
        "agents/subagents/scope-controls-policy.md",
        "agents/subagents/scope-controls-remediation.md",
        "agents/subagents/scope-controls-detections.md",
        "agents/subagents/scope-controls-validate.md",
        "config/schemas/controls.schema.json",
    ]
    removed_paths = [
        "agents/scope-defend.md",
        "agents/subagents/scope-defend-guardrails.md",
        "agents/subagents/scope-defend-policy.md",
        "agents/subagents/scope-defend-remediation.md",
        "agents/subagents/scope-defend-splunk.md",
        "agents/subagents/scope-defend-validate.md",
        "config/schemas/defend.schema.json",
    ]
    for relative_path in expected_paths:
        assert (ROOT / relative_path).exists(), f"{relative_path} should exist"
    for relative_path in removed_paths:
        assert not (ROOT / relative_path).exists(), f"{relative_path} should be removed"

    assert_contains("agents/scope-controls.md", "name: scope-controls")
    assert_contains("agents/scope-audit.md", "scope-controls")
    assert_contains("config/schemas/controls.schema.json", '"const": "controls"')

    stale_needles = [
        "scope-defend",
        "/scope:defend",
        "defend.schema",
        "defend/defend",
        "DEFEND_RUN_DIR",
        "defend_run_dir",
        "defend_auto_chain",
        "splunk-detections.md",
        '"source": "defend"',
        "source: 'defend'",
        'source === "defend"',
    ]
    scan_roots = [
        ROOT / "agents",
        ROOT / "bin",
        ROOT / "config",
        ROOT / "tests",
        ROOT / "dashboard" / "src",
        ROOT / "dashboard" / "package.json",
        ROOT / "dashboard" / "vite.config.js",
        ROOT / "README.md",
        ROOT / "ARCHITECTURE.md",
    ]
    files = []
    for scan_root in scan_roots:
        if scan_root.is_file():
            files.append(scan_root)
        else:
            files.extend(
                path
                for path in scan_root.rglob("*")
                if path.is_file()
                and "__pycache__" not in path.parts
                and path.suffix in {".md", ".py", ".js", ".jsx", ".json", ".sh"}
            )

    for path in files:
        if path == Path(__file__).resolve():
            continue
        body = path.read_text(errors="ignore")
        for needle in stale_needles:
            assert needle not in body, f"{path.relative_to(ROOT)} contains stale {needle!r}"


def test_runtime_path_contracts_use_runs_directory() -> None:
    assert_contains("README.md", "scope/core/")
    assert_not_contains("README.md", "scope.core/")
    assert_contains("README.md", "config/project-docs/PROJECT.md")
    assert_not_contains("README.md", "blob/main/PROJECT.md")
    assert_contains("agents/scope-controls.md", "/runs/audit-*")
    assert_not_contains("agents/scope-controls.md", "/audit/audit-*")
    assert_contains("agents/scope-hunt.md", "`runs/`")
    assert_not_contains("agents/scope-hunt.md", "`audit/`")
    assert_contains("agents/subagents/scope-synthesizer.md", "./runs/audit-20260301-143022-all/")
    assert_not_contains("agents/subagents/scope-synthesizer.md", "./audit/audit-20260301-143022-all/")
    assert_not_contains("config/scps/README.md", "./audit/audit-*")
    assert_contains("config/scps/README.md", "./runs/audit-*/controls/controls-*/policies/scp-deny-root.json")
    assert_contains("config/hooks/scope-agent-logger.sh", '"$CWD/runs/audit-"*')
    assert_not_contains("config/hooks/scope-agent-logger.sh", '"$CWD/audit/audit-"*')
    assert_contains("config/hooks/scope-artifact-check.sh", 'find "$CWD/runs" -maxdepth 1 -type d -name "audit-*"')
    assert_not_contains("config/hooks/scope-artifact-check.sh", 'find "$CWD/audit"')
    assert_contains("config/hooks/scope-safety-guard.sh", "'./runs/'")
    assert_not_contains("config/hooks/scope-safety-guard.sh", "'./audit/'")
    assert_not_contains("config/hooks/scope-safety-guard.sh", "'./data/'")
    assert_contains("bin/generate-report.js", 'join(projectRoot, "runs", run.run_id)')
    assert_not_contains("bin/generate-report.js", 'join(dashboardDir, "..", "audit", run.run_id)')
