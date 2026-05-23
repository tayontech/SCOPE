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
    assert_contains("agents/scope-investigate.md", "`runs/`")
    assert_not_contains("agents/scope-investigate.md", "`audit/`")
    assert_not_contains("config/scps/README.md", "./audit/audit-*")
    assert_contains("config/scps/README.md", "./runs/audit-*/controls/controls-*/policies/scp-deny-root.json")
    assert_contains("config/hooks/scope-agent-logger.sh", '"$CWD/runs/audit-"*')
    assert_not_contains("config/hooks/scope-agent-logger.sh", '"$CWD/audit/audit-"*')
    assert_contains("config/hooks/scope-artifact-check.sh", 'find "$CWD/runs" -maxdepth 1 -type d -name "audit-*"')
    assert_not_contains("config/hooks/scope-artifact-check.sh", 'find "$CWD/audit"')
    assert_contains("config/hooks/scope-safety-guard.sh", "'./runs/'")
    assert_contains("config/hooks/scope-safety-guard.sh", "'./investigations/'")
    assert_not_contains("config/hooks/scope-safety-guard.sh", "'./audit/'")
    assert_not_contains("config/hooks/scope-safety-guard.sh", "'./hunt/'")
    assert_not_contains("config/hooks/scope-safety-guard.sh", "'./data/'")
    assert_contains("config/hooks/scope-agent-logger.sh", '"$CWD/investigations/investigate-"*')
    assert_contains("bin/generate-report.js", 'join(projectRoot, "runs", run.run_id)')
    assert_not_contains("bin/generate-report.js", 'join(dashboardDir, "..", "audit", run.run_id)')


def test_controls_prompts_reject_legacy_audit_module_paths() -> None:
    controls_prompts = [
        "agents/scope-controls.md",
        "agents/subagents/scope-controls-guardrails.md",
        "agents/subagents/scope-controls-remediation.md",
        "agents/subagents/scope-controls-policy.md",
        "agents/subagents/scope-controls-validate.md",
    ]
    stale_needles = [
        "AUDIT_RUN_DIR/{service}.json",
        "$AUDIT_RUN_DIR/{service}.json",
        "AUDIT_RUN_DIR/iam.json",
        "$AUDIT_RUN_DIR/iam.json",
        "$AUDIT_RUN_DIR/$SVC.json",
    ]

    for relative_path in controls_prompts:
        body = read_repo_file(relative_path)
        for needle in stale_needles:
            assert needle not in body, f"{relative_path} contains legacy handoff path {needle!r}"

    assert_contains("agents/scope-controls.md", "$AUDIT_RUN_DIR/modules/$SVC")
    assert_contains("agents/subagents/scope-controls-guardrails.md", "$AUDIT_RUN_DIR/modules/<service>/<region>.json")
    assert_contains("agents/subagents/scope-controls-remediation.md", "AUDIT_RUN_DIR/modules/<service>/<region>.json")
    assert_contains("agents/subagents/scope-controls-policy.md", "$AUDIT_RUN_DIR/modules/iam/global.json")
    assert_contains("agents/subagents/scope-controls-validate.md", "$AUDIT_RUN_DIR/modules/iam/global.json")


def test_exploit_and_investigate_use_runtime_module_paths() -> None:
    for relative_path in [
        "agents/scope-exploit.md",
        "agents/subagents/scope-investigate-run.md",
    ]:
        body = read_repo_file(relative_path)
        assert "$AUDIT_RUN_DIR/iam.json" not in body
        assert "$SOURCE_RUN_DIR/iam.json" not in body
        assert '"$AUDIT_RUN_DIR"/*.json' not in body
        assert '"$SOURCE_RUN_DIR"/*.json' not in body

    assert_contains("agents/scope-exploit.md", "$AUDIT_RUN_DIR/modules/iam/global.json")
    assert_contains("agents/scope-exploit.md", "$AUDIT_RUN_DIR/modules/<service>/<region>.json")
    assert_contains("agents/subagents/scope-investigate-run.md", "$SOURCE_RUN_DIR/modules/<service>/<region>.json")


def test_investigate_command_replaces_scope_hunt() -> None:
    expected_paths = [
        "agents/scope-investigate.md",
        "agents/subagents/scope-investigate-alert.md",
        "agents/subagents/scope-investigate-intel.md",
        "agents/subagents/scope-investigate-run.md",
        "skills/scope-investigation-report/SKILL.md",
    ]
    removed_paths = [
        "agents/scope-hunt.md",
        "agents/subagents/scope-hunt-investigate.md",
        "agents/subagents/scope-hunt-intel.md",
        "agents/subagents/scope-hunt-audit.md",
    ]
    for relative_path in expected_paths:
        assert (ROOT / relative_path).exists(), f"{relative_path} should exist"
    for relative_path in removed_paths:
        assert not (ROOT / relative_path).exists(), f"{relative_path} should be removed"

    for relative_path in [
        "bin/install.js",
        "README.md",
        "ARCHITECTURE.md",
        "config/mcp-setup.md",
        "config/splunk-patterns.md",
        "agents/scope-investigate.md",
    ]:
        body = read_repo_file(relative_path)
        assert "scope-investigate" in body, f"{relative_path} should use scope-investigate"
        assert "scope-hunt" not in body, f"{relative_path} should not reference scope-hunt"
        assert "scope:hunt" not in body, f"{relative_path} should not expose /scope:hunt"


def test_investigate_handoffs_use_current_state_fields() -> None:
    parent = read_repo_file("agents/scope-investigate.md")
    alert = read_repo_file("agents/subagents/scope-investigate-alert.md")
    run = read_repo_file("agents/subagents/scope-investigate-run.md")
    intel = read_repo_file("agents/subagents/scope-investigate-intel.md")

    assert "KNOWLEDGE_CONTEXT" in alert
    assert "KNOWLEDGE_CONTEXT" in run
    assert "KNOWLEDGE_CONTEXT" in intel
    assert "tools: Read, Bash, search_splunk, search_oneshot, splunk_search, splunk_run_query" in alert
    assert "Load bounded environment knowledge" in parent
    assert "before dispatching any mode subagent" in parent
    assert "api_call, claim records" not in parent
    assert "claims, API calls, coverage" not in parent

    for body in [run, intel]:
        assert "active_hypothesis:" in body
        assert "selected_hypothesis:" not in body

    assert "hunt_run_dir" not in run
    assert "hunt_run_type" not in run
    assert "source_run_dir" in run
    assert "source_run_type" in run
