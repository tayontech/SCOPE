from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def read_repo_file(relative_path: str) -> str:
    return (ROOT / relative_path).read_text()


def test_report_generator_escapes_inline_json_script_data() -> None:
    body = read_repo_file("bin/generate-report.js")

    assert "function jsonForInlineScript(value)" in body
    assert '.replaceAll("<", "\\\\u003c")' in body
    assert '.replaceAll(">", "\\\\u003e")' in body
    assert '.replaceAll("&", "\\\\u0026")' in body
    assert "window.__SCOPE_INLINE_DATA__ = ${jsonForInlineScript(inlineData)}" in body
    assert "window.__SCOPE_INLINE_DATA__ = ${JSON.stringify(inlineData)}" not in body
    assert "function inlineControlsArtifacts(json)" in body
    assert "markdown: readFileSync(remediationPath" in body


def test_report_generator_filters_current_dashboard_sources_only() -> None:
    body = read_repo_file("bin/generate-report.js")

    assert 'new Set(["audit", "exploit", "controls"])' in body
    assert 'explicitSource.startsWith("svc:")' in body
    assert "unsupported source" in body
    assert "function reportsFromIndex(index)" in body
    assert "function migrateRunsToReports(runs)" in body
    assert "function selectReportForInline(reports)" in body
    assert "selectedReport.audit" in body
    assert "selectedReport.exploit" in body
    assert "selectedReport.controls" in body
    assert "selectRunsForInline" not in body
    assert "controlsReferencesAudit" not in body


def test_dashboard_report_manifest_accepts_exploit_reports() -> None:
    app = read_repo_file("dashboard/src/App.jsx")
    generator = read_repo_file("bin/generate-report.js")
    exploit = read_repo_file("agents/scope-exploit.md")

    for body in [app, generator]:
        assert "(!report.audit?.file && !report.exploit?.file)" in body
        assert '["exploit", report.exploit]' in body or '["exploit", selectedReport.exploit]' in body
        assert "report.exploit?.run_id === currentRunId" in body or 'loaded.exploit ? "exploit"' in body

    assert "exploit:{run_id:$run_id, file:$file}" in exploit
    assert ".reports |= (map(select(.report_id != $new_entry.report_id)) + [$new_entry])" in exploit
    assert ".reports |= (map(select(.run_id != $new_entry.run_id))" not in exploit


def test_dashboard_controls_views_match_controls_schema_fields() -> None:
    body = read_repo_file("dashboard/src/App.jsx")

    expected_terms = [
        "OrgWideIssuesList",
        "DetectionRulesList",
        "MonitoringIdeasList",
        "PolicyReplacementsList",
        "ControlsMatrix",
        "MarkdownBlock",
        "MarkdownTable",
        "formatSplForDisplay",
        "SplBlock",
        "StructuredHop",
        "function severityColorFor(severity",
        "Generated SPL Detections",
        "Detection Opportunities",
        "Monitoring Ideas",
        "AWS CLI replay commands are not embedded",
        "remediationPlanMarkdown",
        "summary.org_wide_issues",
        "summary.detections_generated",
        "summary.dashboards",
        "summary.policy_replacements",
        "summary.remediation_items",
        "why_dashboard_not_detection",
        "promotion_triggers",
    ]
    for term in expected_terms:
        assert term in body

    stale_terms = [
        "executive_summary",
        "technical_recommendations",
        "summary.quick_wins",
        "Executive Summary",
        "Tech Recommendations",
    ]
    for term in stale_terms:
        assert term not in body


def test_dashboard_formats_markdown_spl_and_hops_as_structured_content() -> None:
    body = read_repo_file("dashboard/src/App.jsx")

    expected_terms = [
        "parseMarkdownRows",
        "renderInlineMarkdown",
        "line.includes(\"|\")",
        "const stages = spl.split(/\\s+\\|\\s+/)",
        "return stages.map((stage, index) =>",
        "wordBreak: \"break-word\"",
        "whiteSpace: \"pre-wrap\"",
        "Action",
        "Target",
        "Capability",
        "Source",
    ]
    for term in expected_terms:
        assert term in body

    assert "wordBreak: \"break-all\"" not in body


def test_dashboard_normalizes_schema_driven_attack_paths() -> None:
    body = read_repo_file("dashboard/src/App.jsx")

    assert "const stepText = (step)" in body
    assert "const pathSteps = (p)" in body
    assert "steps: pathSteps(p)" in body
    assert "data.summary.risk_score = highestSeverity([" in body
    assert "function derivePrincipalsFromGraph(graph)" in body
    assert "function deriveTrustsFromGraph(graph)" in body
    assert "function fitTransformForNodes(nodes, width, height" in body
    assert "s.critical_priv_esc_risks = data.attack_paths.filter" in body
    assert "sim.tick(80)" in body
    assert "function graphForAttackPaths(data, paths)" in body
    assert "const graphData = useMemo(() => graphForAttackPaths(data, paths), [data, paths])" in body
    assert "No final attack path graph nodes available" in body
    assert "RISK:" not in body


def test_dashboard_renders_attack_path_groups_as_primary_path_list() -> None:
    body = read_repo_file("dashboard/src/App.jsx")

    for term in [
        "function displayAttackPathItems(data)",
        "data.attack_path_groups",
        "representative_path_id",
        "member_path_ids",
        "member_count",
        "source_principals",
        "leveraging_assets",
        "Assets That Can Leverage This",
        "path.group_id",
        "member_path_names",
        "representative_path_name",
        "pathRefs.has(source)",
        "Grouped Paths",
        "representative raw path",
        "const rawAttackPathCount = data.attack_paths?.length || 0",
        "const attackPathGroupCount = data.attack_path_groups?.length || rawAttackPathCount",
    ]:
        assert term in body

    assert "function SeverityFilter" not in body
    assert "function CategoryFilter" not in body
    assert "activeSeverities" not in body
    assert "activeCategories" not in body


def test_dashboard_does_not_count_wildcard_resource_paths_as_trusts() -> None:
    body = read_repo_file("dashboard/src/App.jsx")

    assert 's.wildcard_trust_policies = data.trust_relationships.filter' in body
    assert 'case "wildcards"' in body
    assert 'return { title: "Wildcard Trusts", items: wildcardTrusts }' in body
    assert "const wildcardPaths = data.attack_paths.filter" not in body
    assert 'p.name || "").toLowerCase().includes("wildcard")' not in body


def test_dashboard_renders_public_exposure_findings_separately() -> None:
    body = read_repo_file("dashboard/src/App.jsx")

    expected_terms = [
        "function PublicExposureFindingsSection",
        "data.public_exposure_findings",
        "Public Exposure Findings",
        "Promoted attack path",
        "Not promoted to attack path",
        "promoted_attack_path_ids",
        "promotedPathIdsByEntrypoint",
        "Coverage needed",
        "finding.reason_not_attack_path",
        "finding.coverage_needed",
        "finding.assessment",
        "finding.security_relevance",
        "finding.resource",
    ]
    for term in expected_terms:
        assert term in body

    assert '["graph", "detail", ...(isExploit ? [] : ["public"])]' in body
    assert 't === "graph" ? "Attack Graph" : t === "detail" ? "Path Detail" : "Public Exposure"' in body
    assert "embedded" in body
    assert 'label="Public Exposure"' not in body

    component_body = body.split("function PublicExposureFindingsSection", 1)[1].split("// \u2500\u2500\u2500 Audit/Exploit View", 1)[0]
    assert "JSON.stringify" not in component_body
    assert "source_attack_paths" not in component_body
    assert "Source Public Exposure Findings" in body
    assert "source_public_exposure_findings" in body


def test_dashboard_styles_all_schema_graph_edge_types() -> None:
    body = read_repo_file("dashboard/src/App.jsx")

    for edge_type in ["resource_policy_allows", "resource_policy_statement", "event_source", "encrypted_by"]:
        assert f'case "{edge_type}"' in body
        assert f'"{edge_type}"' in body


def test_dashboard_has_compact_layout_branch() -> None:
    body = read_repo_file("dashboard/src/App.jsx")

    expected_terms = [
        "function useIsNarrowViewport",
        "const isNarrow = useIsNarrowViewport()",
        'flexDirection: isNarrow ? "column" : "row"',
        'overflow: isNarrow ? "auto" : "hidden"',
        'width: isNarrow ? "100%" : 320',
        'padding: isNarrow ? "10px 12px" : "12px 24px"',
    ]
    for term in expected_terms:
        assert term in body


def test_dashboard_ui_copy_and_spacing_avoid_stale_or_fragile_patterns() -> None:
    body = read_repo_file("dashboard/src/App.jsx")

    assert 'aria-label="Copy to clipboard"' in body
    assert "SPL query not embedded." in body
    assert "technical-remediation.md" not in body
    assert 'letterSpacing: "-' not in body
    assert "policies.scp_files" not in body
    assert "function LoadedPhaseSummary" in body
    assert '{" / "}' in body
    assert "!hasInlineData && <div" in body
    assert "auditcontrols" not in body


def test_inline_dashboard_does_not_fetch_dev_index() -> None:
    body = read_repo_file("dashboard/src/App.jsx")
    report_generator = read_repo_file("bin/generate-report.js")

    assert "const hasInlineData = Boolean(window.__SCOPE_INLINE_DATA__)" in body
    assert "if (!hasInlineData)" in body
    assert '<link rel="icon" href="data:," />' in report_generator
    assert "function reportsFromIndex(index)" in body
    assert "function migrateRunsToReports(runs)" in body
    assert "data.dashboard_run_id = data._dashboard_run_id" in body
    assert "setReportIndex(reports)" in body
    assert "loadReport(reports[0])" in body
    assert "json._dashboard_run_id = report.report_id" in body
