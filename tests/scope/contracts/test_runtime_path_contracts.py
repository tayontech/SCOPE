from __future__ import annotations

import subprocess
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


def git_ls_files(pathspec: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", pathspec],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def test_controls_naming_is_canonical() -> None:
    expected_paths = [
        "agents/scope-controls.md",
        "agents/subagents/scope-controls-org-wide.md",
        "agents/subagents/scope-controls-policy.md",
        "agents/subagents/scope-controls-remediation.md",
        "agents/subagents/scope-controls-detections.md",
        "agents/subagents/scope-controls-dashboards.md",
        "agents/subagents/scope-controls-validate.md",
        "config/schemas/controls.schema.json",
    ]
    removed_paths = [
        "agents/scope-defend.md",
        "agents/subagents/scope-defend-guardrails.md",
        "agents/subagents/scope-controls-guardrails.md",
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
    assert_contains("README.md", "ARCHITECTURE.md")
    assert_contains("ARCHITECTURE.md", "scope.core")
    assert_not_contains("README.md", "scope.core/")
    assert_contains("README.md", "config/project-docs/PROJECT.md")
    assert_contains("README.md", "docs/LLM-CONTEXT.md")
    assert_not_contains("README.md", "blob/main/PROJECT.md")
    assert_contains("bin/generate-report.js", 'const reportsDir = join(dashboardDir, "reports")')
    assert_contains("bin/generate-report.js", "dashboard/reports/<run-id>-dashboard.html")
    assert_contains(".gitignore", "dashboard/reports/")
    assert_not_contains(".gitignore", "dashboard/*-dashboard.html")
    assert_contains("agents/scope-controls.md", "/runs/audit-*")
    assert_not_contains("agents/scope-controls.md", "/audit/audit-*")
    assert_contains("agents/scope-investigate.md", "`runs/`")
    assert_not_contains("agents/scope-investigate.md", "`audit/`")
    assert not (ROOT / "config/scps").exists(), "config/scps should be removed"
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


def test_project_docs_are_split_by_ownership() -> None:
    project_docs = sorted(path.name for path in (ROOT / "config" / "project-docs").glob("*.md"))

    assert project_docs == ["PROJECT.md"]
    assert (ROOT / "docs" / "LLM-CONTEXT.md").exists()
    assert "docs/architecture/" in read_repo_file(".gitignore")
    assert git_ls_files("docs/architecture") == [], "docs/architecture should remain private and untracked"


def test_architecture_uses_mermaid_and_current_platform_paths() -> None:
    architecture = read_repo_file("ARCHITECTURE.md")

    assert "```mermaid" in architecture
    assert architecture.count("```mermaid") >= 5
    assert "uv run python -m scope audit" in architecture
    assert ".agents/hooks.json" in architecture
    assert ".codex/hooks.json" in architecture
    assert "runs `python -m scope audit`" not in architecture
    assert "install.js" not in architecture
    assert "scope-controls-guardrails" not in architecture
    assert "scope-defend" not in architecture


def test_agent_dashboard_index_contract_uses_reports_manifest() -> None:
    audit = read_repo_file("agents/scope-audit.md")
    exploit = read_repo_file("agents/scope-exploit.md")

    for body in [audit, exploit]:
        assert "dashboard/public/index.json" in body
        assert "reports[]" in body
        assert "Dashboard index | `dashboard/public/index.json` | Updated: upsert this run into `runs[]` array" not in body

    assert 'INDEX_DATA=\'{"reports": []}\'' in exploit
    assert ".reports |=" in exploit


def test_controls_prompts_reject_legacy_audit_module_paths() -> None:
    controls_prompts = [
        "agents/scope-controls.md",
        "agents/subagents/scope-controls-org-wide.md",
        "agents/subagents/scope-controls-remediation.md",
        "agents/subagents/scope-controls-policy.md",
        "agents/subagents/scope-controls-dashboards.md",
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
    assert_contains("agents/subagents/scope-controls-org-wide.md", "$AUDIT_RUN_DIR/modules/<service>/<region>.json")
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
        "scope/install.py",
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


def test_investigate_prompt_uses_investigation_terminology() -> None:
    body = read_repo_file("agents/scope-investigate.md")

    stale_phrases = [
        "<hunt_technique_patterns>",
        "</hunt_technique_patterns>",
        "Hunt Technique Patterns",
        "hunt technique catalogue",
        "active hunt technique pattern",
        "Re-run this hunt session",
    ]
    for phrase in stale_phrases:
        assert phrase not in body, f"scope-investigate should not expose stale phrase: {phrase!r}"

    expected_phrases = [
        "<hypothesis_driven_step_selection>",
        "</hypothesis_driven_step_selection>",
        "Hypothesis-Driven Step Selection",
        "Service-Qualified Events",
        "Data-Event Caveat",
        "Re-run this investigation session",
    ]
    for phrase in expected_phrases:
        assert phrase in body, f"scope-investigate should contain current phrase: {phrase!r}"


def test_investigate_prompt_uses_declared_splunk_tools_for_index_discovery() -> None:
    body = read_repo_file("agents/scope-investigate.md")
    splunk_patterns = read_repo_file("config/splunk-patterns.md")
    mcp_setup = read_repo_file("config/mcp-setup.md")

    assert "splunk_run_query" in body
    assert "splunk_get_info" in body
    assert "splunk_get_indexes" in body
    assert "| rest /services/data/indexes" not in body
    assert "Do not use SPL `rest` commands for index discovery" in body
    assert "Store approved groupings in session memory as `index_catalog`" in body
    assert "config/index.json" not in body
    assert "For RUN and INTEL modes, run this probe after subagent handoff" in body
    assert "splunk_get_indexes" in splunk_patterns
    assert "There is no static index configuration file" in splunk_patterns
    assert "config/index.json" not in splunk_patterns
    assert "| rest /services/data/indexes | fields title" not in splunk_patterns
    assert "Splunk MCP is optional" in mcp_setup
    assert "current Splunk MCP 1.1 uses `splunk_run_query`, `splunk_get_info`, and `splunk_get_indexes`" in mcp_setup
    assert "connected-mode runtime discovery" in mcp_setup


def test_static_splunk_index_config_is_removed() -> None:
    assert not (ROOT / "config/index.example.json").exists()
    gitignore = read_repo_file(".gitignore")
    for relative_path in [
        "skills/scope-knowledge-load/SKILL.md",
        "agents/subagents/scope-controls-detections.md",
        "config/hooks/scope-spl-lint.sh",
        "config/README.md",
        ".gitignore",
    ]:
        assert "config/index.json" not in read_repo_file(relative_path)
    assert "config/scps" not in gitignore
    assert "install.js" not in gitignore
    assert "runs/" in gitignore
    assert "investigations/" in gitignore
    assert "audit/" not in gitignore
    assert "hunt/" not in gitignore
    assert ".agents/mcp_config.json" in gitignore
    assert ".gemini/antigravity-cli/mcp_config.json" in gitignore


def test_splunk_cloud_path_does_not_assume_enterprise_security() -> None:
    for relative_path in [
        "agents/scope-investigate.md",
        "agents/subagents/scope-investigate-alert.md",
        "config/splunk-patterns.md",
        "config/hooks/scope-spl-lint.sh",
    ]:
        body = read_repo_file(relative_path)
        assert "index=notable" not in body
        assert "notable_id" not in body
        assert "Splunk ES" not in body
        assert "Enterprise Security" not in body


def test_splunk_patterns_expose_detection_building_blocks() -> None:
    splunk_patterns = read_repo_file("config/splunk-patterns.md")
    detections = read_repo_file("agents/subagents/scope-controls-detections.md")
    lint_hook = read_repo_file("config/hooks/scope-spl-lint.sh")

    expected_terms = [
        "Detection Building Blocks",
        "`eval` with `case`, `if`, `coalesce`, `lower`, `replace`",
        "`rex field=<field>`",
        "`spath input=<field>`",
        "`json_extract` / `json_extract_exact`",
        "`bin _time span=<window>` + `stats`",
        "`timechart span=<window>`",
        "Expensive correlation or fan-out commands",
        "Side-effect commands",
        "Use environment-dependent commands",
    ]
    for term in expected_terms:
        assert term in splunk_patterns

    assert "Splunk Cloud detection building blocks" in detections
    assert "lookup enrichment" not in detections
    assert "`lookup ... OUTPUTNEW ...`" not in splunk_patterns
    assert "No environment-dependent commands" not in detections
    assert "Environment-dependent command detected" not in lint_hook
    assert "outputlookup" in lint_hook


def test_mcp_docs_do_not_overclaim_generic_siem_support() -> None:
    readme = read_repo_file("README.md")
    mcp_setup = read_repo_file("config/mcp-setup.md")
    installer = read_repo_file("scope/install.py")

    assert "you can use any SIEM" not in readme
    assert "adapts accordingly" not in readme
    assert "SCOPE remains SPL-first" in readme
    assert "Different SIEM MCP" in mcp_setup
    assert "Current limitation: SCOPE controls detections and investigation templates generate SPL" in mcp_setup
    assert "--no-splunk-mcp" in installer
    assert "strip_splunk_mcp_servers" in installer


def test_dashboard_controls_surface_uses_current_policy_language() -> None:
    body = read_repo_file("dashboard/src/App.jsx")

    expected_terms = [
        "PolicyReplacementsList",
        "policy_replacements",
        "Policies",
        "No policy replacements generated.",
    ]
    for term in expected_terms:
        assert term in body

    stale_terms = [
        "Legacy Preventive",
        "Legacy Resource",
        "bundle.scp_names",
        "bundle.rcp_names",
        'category === "scp"',
        'category === "rcp"',
    ]
    for term in stale_terms:
        assert term not in body


def test_investigate_intel_prompt_uses_investigation_terminology() -> None:
    body = read_repo_file("agents/subagents/scope-investigate-intel.md")

    stale_phrases = [
        "Threat Intel Hunt",
        "proactive hunt",
        "intel hunts",
        "Threat intel hunt",
        "hunt hypotheses",
        "hunt for [eventNames]",
        "hunt for all API calls",
    ]
    for phrase in stale_phrases:
        assert phrase not in body, f"scope-investigate-intel should not expose stale phrase: {phrase!r}"

    expected_phrases = [
        "Threat Intel Investigation",
        "proactive investigation",
        "intel investigations",
        "Threat intel investigation",
        "investigation hypotheses",
        "search for [eventNames]",
        "search for all API calls",
    ]
    for phrase in expected_phrases:
        assert phrase in body, f"scope-investigate-intel should contain current phrase: {phrase!r}"


def test_investigate_run_prompt_uses_investigation_terminology() -> None:
    body = read_repo_file("agents/subagents/scope-investigate-run.md")

    stale_phrases = [
        "<hypothesis_engine_hunt>",
        "</hypothesis_engine_hunt>",
        "CloudTrail eventNames to hunt",
        "hunt for these",
        "hunt strategy context",
        "Generated [N] hunt hypotheses",
    ]
    for phrase in stale_phrases:
        assert phrase not in body, f"scope-investigate-run should not expose stale phrase: {phrase!r}"

    expected_phrases = [
        "<hypothesis_engine_run>",
        "</hypothesis_engine_run>",
        "CloudTrail eventNames to investigate",
        "search for these",
        "investigation strategy context",
        "Generated [N] investigation hypotheses",
    ]
    for phrase in expected_phrases:
        assert phrase in body, f"scope-investigate-run should contain current phrase: {phrase!r}"


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
