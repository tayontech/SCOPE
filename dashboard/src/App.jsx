import { useState, useEffect, useRef, useCallback, useMemo, forwardRef, useImperativeHandle } from "react";
import * as d3 from "d3";

// No sample data — dashboard only shows real audit results

// ─── Theme & Style Constants ───
const COLORS = {
  bg: "#0a0e17",
  bgCard: "#111827",
  bgCardHover: "#1a2235",
  border: "#1e293b",
  borderActive: "#f59e0b",
  text: "#e2e8f0",
  textDim: "#64748b",
  textMuted: "#475569",
  accent: "#f59e0b",
  accentDim: "#b45309",
  critical: "#ef4444",
  criticalBg: "rgba(239,68,68,0.12)",
  high: "#f59e0b",
  highBg: "rgba(245,158,11,0.12)",
  medium: "#3b82f6",
  mediumBg: "rgba(59,130,246,0.12)",
  low: "#22c55e",
  lowBg: "rgba(34,197,94,0.12)",
  nodeUser: "#8b5cf6",
  nodeRole: "#06b6d4",
  detection: "#06b6d4",
  nodeEsc: "#ef4444",
  nodeData: "#22c55e",
  nodeGroup: "#ec4899",
  nodeExternal: "#f59e0b",
  edgeNormal: "#334155",
  edgePrivEsc: "#ef4444",
  edgeCrossAccount: "#f59e0b",
  edgeDataAccess: "#22c55e",
  edgeTrust: "#64748b",
  edgeService: "#a78bfa",
  edgeNetwork: "#f97316",
  edgePublicAccess: "#ef4444",
};

const SEVERITY_CONFIG = {
  critical: { color: COLORS.critical, bg: COLORS.criticalBg, icon: "\u25C6" },
  high: { color: COLORS.high, bg: COLORS.highBg, icon: "\u25B2" },
  medium: { color: COLORS.medium, bg: COLORS.mediumBg, icon: "\u25CF" },
  low: { color: COLORS.low, bg: COLORS.lowBg, icon: "\u25CB" },
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const VALID_PHASES = ["audit", "exploit", "controls"];

const CATEGORY_CONFIG = {
  privilege_escalation: { label: "Priv Esc", color: "#ef4444" },
  trust_misconfiguration: { label: "Trust", color: "#f59e0b" },
  data_exposure: { label: "Data", color: "#22c55e" },
  credential_risk: { label: "Creds", color: "#a78bfa" },
  excessive_permission: { label: "Perms", color: "#3b82f6" },
  network_exposure: { label: "Network", color: "#f472b6" },
  persistence: { label: "Persist", color: "#fb923c" },
  post_exploitation: { label: "Post-Ex", color: "#e879f9" },
  lateral_movement: { label: "Lateral", color: "#a3e635" },
};

// ─── Phase Configuration ───
const PHASE_CONFIG = {
  audit:       { label: "Audit",       color: "#f59e0b" },
  exploit:     { label: "Exploit",     color: "#ef4444" },
  controls:      { label: "Controls",      color: "#22c55e" },
};

function reportDateValue(report) {
  const parsed = Date.parse(report?.created_at || report?.date || "");
  return Number.isNaN(parsed) ? 0 : parsed;
}

function migrateRunsToReports(runs) {
  const byId = new Map();
  for (const run of Array.isArray(runs) ? runs : []) {
    if (!run || typeof run !== "object") continue;
    if (run.source !== "audit") continue;
    if (!run.run_id) continue;
    if (byId.has(run.run_id)) continue;
    byId.set(run.run_id, {
      report_id: run.run_id,
      created_at: run.date || "",
      account_id: run.account_id,
      target: run.target || "",
      risk: run.risk || "low",
      status: run.status || "complete",
      audit: {
        run_id: run.run_id,
        file: run.file || `${run.run_id}.json`,
      },
    });
  }
  return [...byId.values()];
}

function normalizeReports(reports) {
  const clean = [];
  for (const report of Array.isArray(reports) ? reports : []) {
    if (!report || typeof report !== "object") continue;
    if (!report.report_id || (!report.audit?.file && !report.exploit?.file)) continue;
    clean.push(report);
  }
  return clean.sort((a, b) => reportDateValue(b) - reportDateValue(a));
}

function reportsFromIndex(index) {
  const reports = normalizeReports(index?.reports);
  if (reports.length > 0) return reports;
  return normalizeReports(migrateRunsToReports(index?.runs || []));
}

function reportStatusLabel(status) {
  if (status === "partial") return " \u26A0 partial";
  if (status === "failed") return " \u26A0 failed";
  return " \u2714";
}

function reportDisplayLabel(report) {
  const reportId = report?.report_id || "report";
  const target = report?.target ? ` ${report.target}` : "";
  return `${reportId}${target}${reportStatusLabel(report?.status)}`;
}

function displayNameFromNodeId(id = "") {
  return id.includes(":") ? id.split(":").pop() : id;
}

function derivePrincipalsFromGraph(graph) {
  if (!Array.isArray(graph?.nodes)) return [];
  return graph.nodes
    .filter((node) => node.type === "user" || node.type === "role")
    .map((node) => ({
      ...node,
      type: node.type,
      id: node.label || displayNameFromNodeId(node.id),
      node_id: node.id,
      arn: node.arn || "",
      mfa_enabled: node.mfa_enabled ?? node.mfa ?? false,
      console_access: node.console_access ?? false,
      access_keys: node.access_keys ?? 0,
    }));
}

function deriveTrustsFromGraph(graph) {
  if (!Array.isArray(graph?.edges)) return [];
  const nodeById = new Map((graph?.nodes || []).map((node) => [node.id, node]));
  return graph.edges
    .filter((edge) => edge.edge_type === "trust")
    .map((edge) => {
      const roleNode = nodeById.get(edge.target) || {};
      const principalNode = nodeById.get(edge.source) || {};
      const principal = principalNode.arn || principalNode.label || edge.source;
      const roleName = roleNode.label || displayNameFromNodeId(edge.target);
      const trustType = edge.trust_type || "same-account";
      const isWildcard = trustType === "wildcard" || principal === "*" || principal === "anonymous" || String(principal).includes(":anonymous");
      return {
        role_id: edge.target,
        role_name: roleName,
        role_arn: roleNode.arn || "",
        principal,
        trust_principal: principal,
        trust_type: trustType,
        is_wildcard: isWildcard,
        risk: isWildcard ? "critical" : (trustType === "cross-account" ? "high" : "low"),
      };
    });
}

function detectionMatchesPath(detection, path) {
  const pathRefs = new Set([
    path?.name,
    path?.id,
    path?.source_candidate_id,
    path?.group_id,
    path?.representative_path_id,
    path?.representative_path_name,
    ...(path?.member_path_ids || []),
    ...(path?.member_path_names || []),
  ].filter(Boolean));
  return (detection?.source_attack_paths || []).some((source) => pathRefs.has(source));
}

function commandsFromPath(path) {
  const values = [];
  const collect = (value) => {
    if (!value) return;
    if (Array.isArray(value)) {
      value.forEach(collect);
    } else if (typeof value === "string") {
      values.push(value);
    } else if (typeof value === "object") {
      collect(value.command || value.aws_cli || value.awscli || value.cli || value.shell);
    }
  };
  collect(path?.commands);
  collect(path?.aws_cli_commands);
  collect(path?.exploit_commands);
  collect(path?.steps?.map((step) => (typeof step === "object" ? step.command : null)));
  return values.filter(Boolean);
}

function displayAttackPathItems(data) {
  const rawPaths = Array.isArray(data?.attack_paths) ? data.attack_paths : [];
  const groups = Array.isArray(data?.attack_path_groups) ? data.attack_path_groups : [];
  if (groups.length === 0) return rawPaths;
  const byId = new Map(rawPaths.map((path) => [path.id, path]));
  return groups.map((group) => {
    const representative = byId.get(group.representative_path_id) || byId.get(group.member_path_ids?.[0]) || {};
    const memberPathIds = group.member_path_ids || [];
    const memberPaths = memberPathIds.map((id) => byId.get(id)).filter(Boolean);
    return {
      ...representative,
      id: group.representative_path_id || representative.id || group.id,
      group_id: group.id,
      group_name: group.name,
      group_description: group.description,
      member_path_ids: memberPathIds,
      member_path_names: memberPaths.map((path) => path.name).filter(Boolean),
      member_count: group.member_count || memberPathIds.length || 1,
      source_principals: group.source_principals || [],
      leveraging_assets: group.leveraging_assets || [],
      primitive: group.primitive,
      validation_statuses: group.validation_statuses || [],
      name: group.name || representative.name,
      description: group.description || representative.description || "Grouped attack paths with a shared primitive and impact.",
      severity: group.severity || representative.severity,
      category: group.category || representative.category,
      affected_resources: group.affected_resources || representative.affected_resources || [],
      representative_path_id: group.representative_path_id,
      representative_path_name: representative.name,
    };
  });
}

function formatSplForDisplay(spl = "") {
  const stages = spl.split(/\s+\|\s+/).map((stage) => stage.trim()).filter(Boolean);
  if (stages.length <= 1) return [spl.trim()].filter(Boolean);
  return stages.map((stage, index) => (index === 0 ? stage : `| ${stage}`));
}

function hopPartsFromStep(step) {
  if (step && typeof step === "object") {
    return {
      action: step.action || step.permission || step.event_name || "",
      target: step.target || step.resource || step.to || "",
      capability: step.capability_gained || step.result || step.description || "",
      source: step.source || step.from || "",
    };
  }
  const text = String(step || "");
  const parts = text.split(/\s*(?:→|->)\s*/).filter(Boolean);
  return {
    action: parts[0] || text,
    target: parts[1] || "",
    capability: parts.slice(2).join(" → "),
    source: "",
  };
}

function fitTransformForNodes(nodes, width, height, padding = 120) {
  const usableHeight = Math.max(height - 90, 200);
  const positioned = nodes.filter((node) => Number.isFinite(node.x) && Number.isFinite(node.y));
  if (positioned.length === 0 || width <= 0 || height <= 0) {
    return d3.zoomIdentity.translate(0, 0).scale(0.85);
  }
  const xs = positioned.map((node) => node.x);
  const ys = positioned.map((node) => node.y);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  const spanX = Math.max(maxX - minX, 240);
  const spanY = Math.max(maxY - minY, 240);
  const scale = Math.min(
    Math.max((width - padding * 2) / spanX, 0.2),
    Math.max((usableHeight - padding * 2) / spanY, 0.2),
    1.1
  );
  const centerX = (minX + maxX) / 2;
  const centerY = (minY + maxY) / 2;
  return d3.zoomIdentity.translate(width / 2 - centerX * scale, usableHeight / 2 - centerY * scale).scale(scale);
}

function useIsNarrowViewport(breakpoint = 900) {
  const [isNarrow, setIsNarrow] = useState(() => (
    typeof window !== "undefined" ? window.innerWidth < breakpoint : false
  ));

  useEffect(() => {
    if (typeof window === "undefined") return undefined;
    const mediaQuery = window.matchMedia(`(max-width: ${breakpoint - 1}px)`);
    const sync = () => setIsNarrow(mediaQuery.matches);
    sync();
    mediaQuery.addEventListener("change", sync);
    return () => mediaQuery.removeEventListener("change", sync);
  }, [breakpoint]);

  return isNarrow;
}

// ─── Data Normalization ───
// Handles multiple controls data formats produced by different agents:
//   1. Rich results.json (per spec: has org_wide_issues[], detections[] with severity/spl, etc.)
//   2. Thin results.json (summary counts + basic detections without spl)
//   3. Data layer format (fields nested under payload, from data/controls/*.json)
//   4. Controls org_wide_issues[] advisory format
// Also fixes audit source field: json.source may be service-specific (e.g., "svc:ec2.amazonaws.com")
function normalizeForDashboard(json, indexSource) {
  let data = { ...json };
  if (data._dashboard_run_id && !data.dashboard_run_id) {
    data.dashboard_run_id = data._dashboard_run_id;
  }

  // Unwrap data layer payload format (data/<phase>/*.json nests fields under payload)
  if (data.payload && typeof data.payload === "object") {
    const { payload, ...meta } = data;
    data = { ...meta, ...payload };
  }

  // Resolve canonical phase key: prefer index.json source over json.source when
  // json.source is not a recognized phase (e.g., "svc:ec2.amazonaws.com" for audit)
  const source = (indexSource && VALID_PHASES.includes(indexSource))
    ? indexSource
    : (VALID_PHASES.includes(data.source) ? data.source : "audit");
  data.source = source;

  // Audit-specific normalization
  if (source === "audit") {
    if (!data.summary) data.summary = {};
    const s = data.summary;
    if (s.total_attack_paths == null && s.attack_paths != null) s.total_attack_paths = s.attack_paths;
    if (s.total_attack_paths == null) s.total_attack_paths = data.attack_paths?.length ?? 0;

    if ((!Array.isArray(data.principals) || data.principals.length === 0) && data.graph?.nodes?.length > 0) {
      data.principals = derivePrincipalsFromGraph(data.graph);
    }
    if ((!Array.isArray(data.trust_relationships) || data.trust_relationships.length === 0) && data.graph?.edges?.length > 0) {
      data.trust_relationships = deriveTrustsFromGraph(data.graph);
    }

    // Array-first KPI derivation: principals[] wins over summary when present and non-empty
    if (data.principals?.length > 0) {
      const derivedUsers = data.principals.filter((p) => p.type === "user").length;
      const derivedRoles = data.principals.filter((p) => p.type === "role").length;
      if (s.total_users != null && s.total_users !== derivedUsers && s.total_users > 0) {
        console.warn(`[SCOPE] Derived total_users from principals array (summary was ${s.total_users})`);
      }
      s.total_users = derivedUsers;
      if (s.total_roles != null && s.total_roles !== derivedRoles && s.total_roles > 0) {
        console.warn(`[SCOPE] Derived total_roles from principals array (summary was ${s.total_roles})`);
      }
      s.total_roles = derivedRoles;
    } else {
      // Fall back to summary field variants when principals array is absent or empty
      if (s.total_users == null) s.total_users = s.users ?? 0;
      if (s.total_roles == null) s.total_roles = s.roles ?? 0;
    }

    // DASH-04: Canonicalize is_wildcard field and normalize risk to lowercase BEFORE KPI derivation
    // This must run before the filter() calls below so is_wildcard is consistent
    if (Array.isArray(data.trust_relationships)) {
      data.trust_relationships = data.trust_relationships.map((t) => ({
        ...t,
        is_wildcard: t.is_wildcard ?? t.wildcard ?? false,
        risk: t.risk?.toLowerCase() ?? "low",
      }));
    }

    // Derive trust relationship KPIs from array when available (DASH-02: extended breakdown)
    if (Array.isArray(data.trust_relationships)) {
      s.total_trust_relationships = data.trust_relationships.length;
      s.cross_account_trusts = data.trust_relationships.filter(
        (t) => t.trust_type === "cross-account"
      ).length;
      // NEW: breakdown counts for Trust KPI subtext
      s.service_trusts = data.trust_relationships.filter(
        (t) => t.trust_type === "service"
      ).length;
      s.same_account_trusts = data.trust_relationships.filter(
        (t) => t.trust_type === "same-account"
      ).length;
      s.wildcard_trust_policies = data.trust_relationships.filter(
        (t) => t.is_wildcard
      ).length;
    }

    if (Array.isArray(data.attack_paths)) {
      s.critical_priv_esc_risks = data.attack_paths.filter((p) =>
        p.severity === "critical" && (p.category === "privilege_escalation" || !p.category)
      ).length;
    }
  }

  // Exploit-specific normalization
  if (source === "exploit") {
    if (!data.summary) data.summary = {};
    const s = data.summary;
    if (s.total_attack_paths == null) s.total_attack_paths = s.paths_found ?? data.attack_paths?.length ?? 0;
    if (s.persistence_techniques == null) s.persistence_techniques = 0;
    if (s.exfiltration_vectors == null) s.exfiltration_vectors = 0;
  }

  // Controls-specific normalization
  if (source === "controls") {
    // Map summary field variants to dashboard-expected names
    if (!data.summary) data.summary = {};
    const s = data.summary;

    // Normalize audit_run (string) → audit_runs_analyzed (array)
    if (!data.audit_runs_analyzed && data.audit_run) {
      data.audit_runs_analyzed = [data.audit_run];
    }

    // Normalize remediation: new schema uses remediation.items count; legacy used prioritization[]
    if (!data.prioritization && data.remediation?.file) {
      // New schema: expose file path and item count for the Remediation tab
      data.remediationPlanFile = data.remediation.file;
      data.remediationItemCount = data.remediation.items ?? 0;
      data.remediationPlanMarkdown = data.remediation.markdown || data.remediation.content || "";
    }

    if (!Array.isArray(data.org_wide_issues)) data.org_wide_issues = [];
    if (!Array.isArray(data.dashboards)) data.dashboards = [];
    s.org_wide_issues = data.org_wide_issues.length ?? s.org_wide_issues ?? 0;
    s.detections_generated = data.detections?.length ?? s.detections ?? 0;
    s.dashboards = s.dashboards ?? data.dashboards.length ?? 0;
    s.remediation_items = s.remediation_items ?? data.remediation?.items ?? 0;
    // controls_recommended: new schema has no security_controls[] — map to remediation_items
    s.controls_recommended = s.remediation_items;
  }

  // Severity canonicalization: normalize aliases to canonical values
  // Canonical enum: critical, high, medium, low, info
  const SEVERITY_ALIASES = { informational: "info" };
  const canonicalizeSeverity = (s, fallback = "medium") => {
    const lower = s?.toLowerCase() ?? fallback;
    return SEVERITY_ALIASES[lower] ?? lower;
  };
  const highestSeverity = (values, fallback = "low") => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return values
      .map((value) => canonicalizeSeverity(value, fallback))
      .filter((value) => order[value] != null)
      .sort((a, b) => order[a] - order[b])[0] || fallback;
  };

  // Normalize severity fields to lowercase across all phases
  // Guarantees SEVERITY_CONFIG lowercase keys always match regardless of agent casing
  // Coerce attack_path array fields that agents may emit as strings (e.g. Gemini remediation)
  const ensureArray = (v) => Array.isArray(v) ? v : (typeof v === "string" && v ? [v] : []);
  const stepText = (step) => {
    if (typeof step === "string") return step;
    if (step && typeof step === "object") {
      return [step.description, step.action].filter(Boolean).join(" — ");
    }
    return "";
  };
  const pathSteps = (p) => {
    const directSteps = ensureArray(p.steps || p.exploit_steps).map(stepText).filter(Boolean);
    if (directSteps.length > 0) return directSteps;
    return ensureArray(p.hops).map((hop) => {
      if (!hop || typeof hop !== "object") return stepText(hop);
      return [hop.action, hop.target, hop.capability_gained].filter(Boolean).join(" → ");
    }).filter(Boolean);
  };
  if (Array.isArray(data.attack_paths)) {
    data.attack_paths = data.attack_paths.map((p) => ({
      ...p,
      severity: canonicalizeSeverity(p.severity),
      steps: pathSteps(p),
      remediation: ensureArray(p.remediation),
      detection_opportunities: ensureArray(p.detection_opportunities),
      mitre_techniques: ensureArray(p.mitre_techniques),
      affected_resources: ensureArray(p.affected_resources),
    }));
  }
  const candidateById = new Map(
    (data.candidate_attack_paths || [])
      .filter((candidate) => candidate?.id)
      .map((candidate) => [candidate.id, candidate])
  );
  const promotedPathIdsByEntrypoint = new Map();
  (data.attack_paths || []).forEach((path) => {
    const candidate = candidateById.get(path.source_candidate_id);
    const startingPosition = candidate?.starting_position;
    if (startingPosition?.type !== "public_endpoint" || !startingPosition.id) return;
    const current = promotedPathIdsByEntrypoint.get(startingPosition.id) || [];
    current.push(path.id);
    promotedPathIdsByEntrypoint.set(startingPosition.id, current);
  });
  if (Array.isArray(data.public_exposure_findings)) {
    data.public_exposure_findings = data.public_exposure_findings.map((finding) => {
      const inferredPromotedIds = promotedPathIdsByEntrypoint.get(finding.source_entrypoint_id) || [];
      return {
        ...finding,
        severity: canonicalizeSeverity(finding.severity, "low"),
        coverage_needed: ensureArray(finding.coverage_needed),
        promoted_attack_path_ids: [
          ...new Set([
            ...ensureArray(finding.promoted_attack_path_ids),
            ...inferredPromotedIds,
          ]),
        ],
      };
    });
  }
  if (Array.isArray(data.detections)) {
    data.detections = data.detections.map((d) => ({
      ...d,
      severity: canonicalizeSeverity(d.severity),
    }));
  }
  if (Array.isArray(data.trust_relationships)) {
    data.trust_relationships = data.trust_relationships.map((t) => ({
      ...t,
      is_wildcard: t.is_wildcard ?? t.wildcard ?? false,
      risk: t.risk?.toLowerCase() ?? "low",
    }));
  }
  if (data.summary?.risk_score && typeof data.summary.risk_score === "string") {
    data.summary.risk_score = data.summary.risk_score.toLowerCase();
  }
  if (data.summary && (source === "audit" || source === "exploit")) {
    data.summary.risk_score = highestSeverity([
      data.summary.risk_score,
      data.summary.severity,
      ...(data.attack_paths || []).map((path) => path.severity),
      ...(data.public_exposure_findings || []).map((finding) => finding.severity),
    ]);
    data.summary.severity = data.summary.risk_score;
  }

  // DASH-06: Deduplicate graph nodes and edges.
  // scope-attack-paths builds nodes in two phases (Phase A: identity from raw IAM lists;
  // Phase B: analysis nodes from attack path reasoning) and may also merge nodes from a
  // pre-built graph in iam.json. Without explicit dedup, the same node id can appear
  // multiple times, causing D3 to render duplicate SVG circles for the same resource.
  // Dedup nodes by id (first occurrence wins — preserves Phase A identity data).
  // Dedup edges by composite key source+"|"+target+"|"+edge_type (first occurrence wins).
  if (data.graph) {
    if (Array.isArray(data.graph.nodes)) {
      const seenNodeIds = new Set();
      data.graph.nodes = data.graph.nodes.filter((n) => {
        if (!n.id || seenNodeIds.has(n.id)) return false;
        seenNodeIds.add(n.id);
        return true;
      });
    }
    if (Array.isArray(data.graph.edges)) {
      const seenEdgeKeys = new Set();
      data.graph.edges = data.graph.edges.filter((e) => {
        const key = `${e.source}|${e.target}|${e.edge_type ?? ""}`;
        if (seenEdgeKeys.has(key)) return false;
        seenEdgeKeys.add(key);
        return true;
      });
    }
  }

  // Remove escalation nodes (permission actions like iam:CreatePolicyVersion) from the graph.
  // These are dead-end leaf nodes that clutter the visualization. The escalation capability is
  // preserved as metadata on the source principal's priv_esc edges are converted to self-annotations.
  if (data.graph && Array.isArray(data.graph.nodes)) {
    const escNodeIds = new Set(
      data.graph.nodes.filter((n) => n.type === "escalation").map((n) => n.id)
    );
    if (escNodeIds.size > 0) {
      // Collect escalation capabilities per source principal before removing edges
      const escCapabilities = {};
      if (Array.isArray(data.graph.edges)) {
        data.graph.edges.forEach((e) => {
          if (escNodeIds.has(e.target)) {
            if (!escCapabilities[e.source]) escCapabilities[e.source] = [];
            escCapabilities[e.source].push(e.label || e.target.replace("esc:", ""));
          }
        });
      }
      // Annotate source principals with their escalation capabilities
      data.graph.nodes.forEach((n) => {
        if (escCapabilities[n.id]) {
          n.escalation_capabilities = escCapabilities[n.id];
        }
      });
      // Filter out escalation nodes and edges pointing to them
      data.graph.nodes = data.graph.nodes.filter((n) => n.type !== "escalation");
      if (Array.isArray(data.graph.edges)) {
        data.graph.edges = data.graph.edges.filter((e) => !escNodeIds.has(e.target) && !escNodeIds.has(e.source));
      }
    }
  }

  // Propagate run status from _run_status field (set by generate-report.js for inline HTML)
  // Absent/undefined = "complete" — backward compat with old runs that predate status support
  data.runStatus = data._run_status || "complete";

  return { data, source };
}

// ─── Copy Button ───
function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback((e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [text]);

  return (
    <button
      onClick={handleCopy}
      title="Copy to clipboard"
      aria-label="Copy to clipboard"
      style={{
        background: "none", border: `1px solid ${COLORS.border}`, borderRadius: 4,
        color: copied ? COLORS.low : COLORS.textDim, cursor: "pointer",
        padding: "2px 6px", fontSize: 10, marginLeft: 6, flexShrink: 0,
        transition: "all 0.2s",
      }}
    >
      {copied ? "\u2713 Copied" : "\u2398 Copy"}
    </button>
  );
}

// ─── Trust Display Name Helper (DASH-05) ───
// Extracts a human-readable display name from a trust principal.
// Service principals: "lambda.amazonaws.com" → "lambda"
// ARN principals: arn:aws:iam::123456789012:role/MyRole → "Account 123456789012 / MyRole"
function extractTrustDisplayName(trustPrincipal, trustType) {
  if (!trustPrincipal) return "Unknown";
  if (trustType === "service") {
    return trustPrincipal.split(".")[0];
  }
  if (trustPrincipal.startsWith("arn:")) {
    const parts = trustPrincipal.split(":");
    const accountId = parts[4] || "";
    const resourcePart = (parts[5] || "").replace(/^(role|user|assumed-role)\//, "");
    if (resourcePart && resourcePart !== "root") {
      return `Account ${accountId} / ${resourcePart}`;
    }
    return `Account ${accountId}`;
  }
  return trustPrincipal;
}

// ─── Edge Style Helper ───
// Centralizes all edge color/strokeWidth/dashArray logic.
// PITFALL: trust edges with trust_type==="cross-account" must return cross_account style.
function getEdgeStyle(edge_type, trust_type) {
  if (edge_type === "trust" && trust_type === "cross-account") {
    return { color: COLORS.edgeCrossAccount, strokeWidth: 2, dashArray: "5,3" };
  }
  switch (edge_type) {
    case "priv_esc":     return { color: COLORS.edgePrivEsc,      strokeWidth: 2.5, dashArray: "6,3" };
    case "cross_account":return { color: COLORS.edgeCrossAccount,  strokeWidth: 2,   dashArray: "5,3" };
    case "data_access":  return { color: COLORS.edgeDataAccess,    strokeWidth: 1.5, dashArray: "none" };
    case "trust":        return { color: COLORS.edgeTrust,         strokeWidth: 1.5, dashArray: "none" };
    case "network":      return { color: COLORS.edgeNetwork,       strokeWidth: 2.5, dashArray: "none" };
    case "public_access":return { color: COLORS.edgePublicAccess,  strokeWidth: 3,   dashArray: "none" };
    case "service":      return { color: COLORS.edgeService,       strokeWidth: 1.5, dashArray: "4,2" };
    case "membership":   return { color: COLORS.nodeGroup,         strokeWidth: 1.2, dashArray: "3,2" };
    case "resource_policy_allows": return { color: COLORS.edgePublicAccess, strokeWidth: 2.5, dashArray: "5,2" };
    case "resource_policy_statement": return { color: COLORS.edgePublicAccess, strokeWidth: 1.5, dashArray: "2,4" };
    case "event_source": return { color: COLORS.edgeService,       strokeWidth: 1.5, dashArray: "2,3" };
    case "encrypted_by": return { color: COLORS.edgeDataAccess,    strokeWidth: 1.5, dashArray: "2,2" };
    default:             return { color: COLORS.edgeNormal,        strokeWidth: 1.5, dashArray: "none" };
  }
}

function pathValueCandidates(value) {
  const raw = String(value || "");
  if (!raw) return [];
  const values = new Set([raw]);
  const normalized = raw.replace(/^principal:/, "");
  values.add(normalized);

  const iamMatch = normalized.match(/^arn:aws:iam::\d+:(role|user)\/(.+)$/);
  if (iamMatch) {
    values.add(`${iamMatch[1]}:${iamMatch[2]}`);
    values.add(iamMatch[2]);
  }

  if (normalized.includes("/")) {
    const parts = normalized.split("/").filter(Boolean);
    values.add(parts[parts.length - 1]);
    if (parts[0]?.endsWith(":loadbalancer") && parts.length >= 3) values.add(parts[2]);
    if (parts[0]?.endsWith(":targetgroup") && parts.length >= 2) values.add(parts[1]);
  }

  const colonTail = normalized.split(":").filter(Boolean).pop();
  if (colonTail) values.add(colonTail);

  return [...values].filter(Boolean);
}

function resolvePathNodeIds(value, nodes) {
  const candidates = pathValueCandidates(value);
  if (candidates.length === 0) return [];
  return nodes
    .filter((node) => candidates.some((candidate) =>
      node.id === candidate ||
      node.label === candidate ||
      node.id?.endsWith(`:${candidate}`)
    ))
    .map((node) => node.id);
}

function evidenceEdgeIdsFromPath(path) {
  const ids = new Set();
  const collect = (items) => {
    if (!Array.isArray(items)) return;
    items.forEach((item) => {
      if (item?.id && String(item.id).startsWith("edge:")) ids.add(item.id);
    });
  };
  collect(path.evidence);
  (path.hops || []).forEach((hop) => collect(hop.evidence));
  return ids;
}

function graphForAttackPaths(data, paths) {
  const graph = data?.graph || {};
  const allNodes = graph.nodes || [];
  const allEdges = graph.edges || [];
  if (!Array.isArray(paths) || paths.length === 0) return { nodes: [], edges: [] };

  const evidenceEdgeIds = new Set();
  const nodeIds = new Set();
  const addNodeValue = (value) => resolvePathNodeIds(value, allNodes).forEach((id) => nodeIds.add(id));

  paths.forEach((path) => {
    evidenceEdgeIdsFromPath(path).forEach((id) => evidenceEdgeIds.add(id));
    (path.affected_resources || []).forEach(addNodeValue);
    (path.hops || []).forEach((hop) => {
      addNodeValue(hop.from_context);
      addNodeValue(hop.resulting_context);
      addNodeValue(hop.target);
      (hop.evidence || []).forEach((item) => addNodeValue(item?.id));
    });
  });

  const evidenceEdges = allEdges.filter((edge) => evidenceEdgeIds.has(edge.id));
  evidenceEdges.forEach((edge) => {
    nodeIds.add(edge.source);
    nodeIds.add(edge.target);
  });

  const nodes = allNodes.filter((node) => nodeIds.has(node.id));
  const scopedNodeIds = new Set(nodes.map((node) => node.id));
  const edges = allEdges.filter((edge) =>
    evidenceEdgeIds.has(edge.id) ||
    (scopedNodeIds.has(edge.source) && scopedNodeIds.has(edge.target))
  );

  return { ...graph, nodes, edges };
}

// ─── Attack Graph Visualization (D3) ───
const AttackGraph = forwardRef(function AttackGraph({ data, paths, selectedPath, onNodeClick, onDeselect }, ref) {
  const svgRef = useRef(null);
  const simRef = useRef(null);
  const zoomRef = useRef(null);
  const nodesRef = useRef([]);
  const [disconnectedNodes, setDisconnectedNodes] = useState([]);
  const [showDisconnectedSidebar, setShowDisconnectedSidebar] = useState(false);
  const [edgeTooltip, setEdgeTooltip] = useState(null); // { x, y, edge_type, source, target }
  const graphData = useMemo(() => graphForAttackPaths(data, paths), [data, paths]);

  useImperativeHandle(ref, () => ({
    panToNode(nodeId) {
      const target = nodesRef.current.find((n) => n.id === nodeId);
      if (!target || !svgRef.current || !zoomRef.current) return;
      const svg = d3.select(svgRef.current);
      const w = svgRef.current.clientWidth;
      const h = svgRef.current.clientHeight;
      const scale = 1.2;
      const tx = w / 2 - (target.x ?? 0) * scale;
      const ty = h / 2 - (target.y ?? 0) * scale;
      svg.transition().duration(400).call(
        zoomRef.current.transform,
        d3.zoomIdentity.translate(tx, ty).scale(scale)
      );
    },
    fitNodes(nodeIds) {
      if (!svgRef.current || !zoomRef.current || !nodeIds?.length) return;
      const targets = nodesRef.current.filter((n) => nodeIds.includes(n.id));
      if (targets.length === 0) return;
      const xs = targets.map((n) => n.x ?? 0);
      const ys = targets.map((n) => n.y ?? 0);
      const minX = Math.min(...xs), maxX = Math.max(...xs);
      const minY = Math.min(...ys), maxY = Math.max(...ys);
      const cx = (minX + maxX) / 2;
      const cy = (minY + maxY) / 2;
      const w = svgRef.current.clientWidth;
      const h = svgRef.current.clientHeight;
      const pad = 200;
      const spanX = Math.max(maxX - minX, 300) + pad * 2;
      const spanY = Math.max(maxY - minY, 300) + pad * 2;
      const scale = Math.min(w / spanX, h / spanY, 1.0);
      const tx = w / 2 - cx * scale;
      const ty = h / 2 - cy * scale;
      d3.select(svgRef.current).transition().duration(400).call(
        zoomRef.current.transform,
        d3.zoomIdentity.translate(tx, ty).scale(scale)
      );
    },
    resetView() {
      if (!svgRef.current || !zoomRef.current) return;
      const transform = fitTransformForNodes(nodesRef.current, svgRef.current.clientWidth, svgRef.current.clientHeight);
      d3.select(svgRef.current)
        .transition().duration(300)
        .call(zoomRef.current.transform, transform);
    },
  }), []);

  // Resolve affected_resources (ARNs) to graph node IDs for highlighting
  const highlightedNodes = useMemo(() => {
    if (!selectedPath || !graphData?.nodes) return new Set();
    const resources = selectedPath.affected_resources || [];
    const matched = new Set();
    const nodes = graphData.nodes;
    for (const r of resources) {
      // Direct match
      if (nodes.some((n) => n.id === r)) { matched.add(r); continue; }
      // ARN → node label/id match
      const resName = r.includes("/") ? r.split("/").pop() : r.split(":").pop();
      const node = nodes.find((n) => n.label === resName || n.id.endsWith(":" + resName));
      if (node) matched.add(node.id);
    }
    return matched;
  }, [selectedPath, graphData]);

  const highlightedEdges = useMemo(() => {
    if (!selectedPath || highlightedNodes.size === 0) return new Set();
    const edgeKeys = new Set();
    const ids = [...highlightedNodes];
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        edgeKeys.add(`${ids[i]}|${ids[j]}`);
        edgeKeys.add(`${ids[j]}|${ids[i]}`);
      }
    }
    return edgeKeys;
  }, [selectedPath, highlightedNodes]);

  useEffect(() => {
    if (!svgRef.current || !graphData) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;

    const g = svg.append("g");

    const zoom = d3.zoom().scaleExtent([0.2, 4]).on("zoom", (e) => g.attr("transform", e.transform));
    svg.call(zoom);
    zoomRef.current = zoom;

    // Background click deselect (DASH-03)
    svg.on("click", (e) => {
      if (e.target === svgRef.current) {
        onDeselect?.();
      }
    });

    const defs = svg.append("defs");

    ["normal", "trust", "priv_esc", "cross_account", "data_access", "service", "network", "public_access", "resource_policy_allows", "resource_policy_statement", "event_source", "encrypted_by"].forEach((type) => {
      const { color } = getEdgeStyle(type === "public_access" ? "public_access" : type, undefined);
      defs.append("marker")
        .attr("id", `arrow-${type}`)
        .attr("viewBox", "0 -5 10 10")
        .attr("refX", 28).attr("refY", 0)
        .attr("markerWidth", 6).attr("markerHeight", 6)
        .attr("orient", "auto")
        .append("path").attr("d", "M0,-5L10,0L0,5")
        .attr("fill", color);
    });

    const filter = defs.append("filter").attr("id", "glow");
    filter.append("feGaussianBlur").attr("stdDeviation", "3").attr("result", "blur");
    const feMerge = filter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "blur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    const nodes = (graphData.nodes || []).map((d) => ({ ...d }));
    nodesRef.current = nodes;
    const nodeMap = new Map(nodes.map((n) => [n.id, n]));
    const links = (graphData.edges || [])
      .filter((e) => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map((d) => ({ ...d }));

    if (nodes.length === 0) {
      setDisconnectedNodes([]);
      g.append("text")
        .attr("x", width / 2)
        .attr("y", height / 2)
        .attr("text-anchor", "middle")
        .attr("fill", COLORS.textDim)
        .attr("font-size", 13)
        .text("No final attack path graph nodes available");
      return undefined;
    }

    // Disconnected node detection — compute BEFORE simulation starts
    const connectedNodeIds = new Set();
    links.forEach((l) => {
      const srcId = typeof l.source === "object" ? l.source.id : l.source;
      const tgtId = typeof l.target === "object" ? l.target.id : l.target;
      connectedNodeIds.add(srcId);
      connectedNodeIds.add(tgtId);
    });
    const disconnected = nodes.filter((n) => !connectedNodeIds.has(n.id));
    const disconnectedSet = new Set(disconnected.map((n) => n.id));
    setDisconnectedNodes(disconnected);

    const sim = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d) => d.id).distance(120))
      .force("charge", d3.forceManyBody().strength(-400))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(40));
    simRef.current = sim;

    const hasHighlight = highlightedNodes.size > 0;

    const isEdgeHighlighted = (d) => {
      const srcId = typeof d.source === "object" ? d.source.id : d.source;
      const tgtId = typeof d.target === "object" ? d.target.id : d.target;
      return highlightedEdges.has(`${srcId}|${tgtId}`);
    };

    const link = g.append("g").selectAll("line")
      .data(links).enter().append("line")
      .attr("stroke", (d) => getEdgeStyle(d.edge_type, d.trust_type).color)
      .attr("stroke-width", (d) => {
        if (hasHighlight && isEdgeHighlighted(d)) return 4;
        return getEdgeStyle(d.edge_type, d.trust_type).strokeWidth;
      })
      .attr("stroke-dasharray", (d) => getEdgeStyle(d.edge_type, d.trust_type).dashArray)
      .attr("stroke-opacity", (d) => {
        if (!hasHighlight) return 0.6;
        return isEdgeHighlighted(d) ? 1 : 0.08;
      })
      .attr("marker-end", (d) => {
        const t = d.edge_type === "priv_esc" ? "priv_esc"
          : (d.edge_type === "trust" && d.trust_type === "cross-account") ? "cross_account"
          : d.edge_type === "cross_account" ? "cross_account"
          : d.edge_type || "normal";
        return `url(#arrow-${t})`;
      })
      .style("cursor", "pointer")
      .on("mousemove", (event, d) => {
        const srcId = typeof d.source === "object" ? d.source.id : d.source;
        const tgtId = typeof d.target === "object" ? d.target.id : d.target;
        const srcLabel = typeof d.source === "object" ? (d.source.label || srcId) : srcId;
        const tgtLabel = typeof d.target === "object" ? (d.target.label || tgtId) : tgtId;
        setEdgeTooltip({ x: event.clientX, y: event.clientY, edge_type: d.edge_type || "normal", source: srcLabel, target: tgtLabel });
      })
      .on("mouseout", () => setEdgeTooltip(null));

    const node = g.append("g").selectAll("g")
      .data(nodes).enter().append("g")
      .style("cursor", "pointer")
      .call(d3.drag()
        .on("start", (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on("drag", (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on("end", (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
      )
      .on("click", (e, d) => onNodeClick?.(d));

    node.append("circle")
      .attr("r", (d) => d.type === "escalation" ? 14 : d.type === "data" ? 12 : 16)
      .attr("fill", (d) => {
        const c = { user: COLORS.nodeUser, role: COLORS.nodeRole, group: COLORS.nodeGroup, escalation: COLORS.nodeEsc, data: COLORS.nodeData, external: COLORS.nodeExternal }[d.type] || "#666";
        return c;
      })
      .attr("stroke", (d) => disconnectedSet.has(d.id) ? COLORS.high : highlightedNodes.has(d.id) ? COLORS.accent : "transparent")
      .attr("stroke-width", (d) => disconnectedSet.has(d.id) ? 2 : 3)
      .attr("stroke-dasharray", (d) => disconnectedSet.has(d.id) ? "4,2" : "none")
      .attr("opacity", (d) => disconnectedSet.has(d.id) ? 0.45 : (!hasHighlight || highlightedNodes.has(d.id) ? 1 : 0.08))
      .attr("filter", (d) => highlightedNodes.has(d.id) ? "url(#glow)" : "none");

    node.append("text")
      .attr("text-anchor", "middle").attr("dominant-baseline", "central")
      .attr("font-size", "10px").attr("fill", "#fff").attr("pointer-events", "none")
      .attr("opacity", (d) => !hasHighlight || highlightedNodes.has(d.id) ? 1 : 0.08)
      .text((d) => ({ user: "\uD83D\uDC64", role: "\uD83D\uDD11", group: "\uD83D\uDC65", escalation: "\u26A1", data: "\uD83D\uDCBE", external: "\uD83C\uDF10" }[d.type] || "?"));

    node.append("title").text((d) => d.label);

    node.append("text")
      .attr("dy", 28).attr("text-anchor", "middle")
      .attr("font-size", "10px")
      .attr("fill", (d) => !hasHighlight || highlightedNodes.has(d.id) ? COLORS.text : COLORS.textMuted)
      .attr("pointer-events", "none")
      .attr("opacity", (d) => !hasHighlight || highlightedNodes.has(d.id) ? 1 : 0.08)
      .text((d) => d.label.length > 24 ? d.label.slice(0, 22) + "\u2026" : d.label);

    const syncPositions = () => {
      link.attr("x1", (d) => d.source.x).attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x).attr("y2", (d) => d.target.y);
      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    };

    sim.on("tick", syncPositions);
    sim.tick(80);
    syncPositions();

    svg.call(zoom.transform, fitTransformForNodes(nodes, width, height));

    return () => sim.stop();
  }, [graphData, highlightedNodes, highlightedEdges, onNodeClick]);

  return (
    <div style={{ position: "relative", width: "100%", height: "100%" }}>
      <svg ref={svgRef} style={{ width: "100%", height: "100%", background: COLORS.bg, borderRadius: "8px" }} />

      {/* Disconnected node warning badge */}
      {disconnectedNodes.length > 0 && (
        <div
          onClick={() => setShowDisconnectedSidebar((v) => !v)}
          style={{
            position: "absolute", top: 12, right: 12,
            background: COLORS.highBg, border: `1px solid ${COLORS.high}`,
            borderRadius: 6, padding: "4px 10px", cursor: "pointer",
            fontSize: 11, color: COLORS.high, fontWeight: 600,
            display: "flex", alignItems: "center", gap: 5, zIndex: 10,
          }}
          title="Click to see disconnected nodes"
        >
          <span style={{ fontSize: 13 }}>&#9888;</span>
          {disconnectedNodes.length} disconnected
        </div>
      )}

      {/* Disconnected node sidebar */}
      {showDisconnectedSidebar && disconnectedNodes.length > 0 && (
        <div style={{
          position: "absolute", top: 0, right: 0, width: 240, height: "100%",
          background: "rgba(17,24,39,0.97)", borderLeft: `1px solid ${COLORS.high}`,
          overflowY: "auto", zIndex: 20, padding: 14,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: COLORS.high }}>
              Disconnected Nodes ({disconnectedNodes.length})
            </span>
            <button
              onClick={() => setShowDisconnectedSidebar(false)}
              style={{ background: "none", border: "none", color: COLORS.textDim, cursor: "pointer", fontSize: 14 }}
            >&#215;</button>
          </div>
          <div style={{ fontSize: 11, color: COLORS.textDim, marginBottom: 10, lineHeight: 1.5 }}>
            These nodes have no edges in the graph. They may be incomplete attack path data or isolated resources requiring investigation.
          </div>
          {disconnectedNodes.map((n, i) => (
            <div key={i} style={{
              marginBottom: 6, padding: "7px 10px", borderRadius: 5,
              background: COLORS.bgCard, border: `1px solid ${COLORS.high}33`,
            }}>
              <div style={{ fontWeight: 600, color: COLORS.text, fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                title={n.label}>{n.label}</div>
              <div style={{ fontSize: 10, color: COLORS.textDim, marginTop: 2 }}>
                {n.type || "unknown"}{n.id && n.id !== n.label ? ` \u2014 ${n.id}` : ""}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Edge hover tooltip */}
      {edgeTooltip && (
        <div style={{
          position: "fixed", left: edgeTooltip.x + 12, top: edgeTooltip.y - 10,
          background: "rgba(17,24,39,0.95)", border: `1px solid ${COLORS.border}`,
          borderRadius: 6, padding: "6px 10px", fontSize: 11, color: COLORS.text,
          pointerEvents: "none", zIndex: 1000, maxWidth: 260,
        }}>
          <div style={{ fontWeight: 700, color: getEdgeStyle(edgeTooltip.edge_type).color, marginBottom: 3 }}>
            {edgeTooltip.edge_type}
          </div>
          <div style={{ color: COLORS.textDim, fontSize: 10 }}>
            <span style={{ color: COLORS.text }}>{edgeTooltip.source}</span>
            <span style={{ margin: "0 4px" }}>{"\u2192"}</span>
            <span style={{ color: COLORS.text }}>{edgeTooltip.target}</span>
          </div>
        </div>
      )}
    </div>
  );
});

// ─── Stat Card ───
function StatCard({ label, value, color, subtext, active, onClick }) {
  return (
    <div
      onClick={onClick}
      style={{
        background: active ? COLORS.bgCardHover : COLORS.bgCard,
        border: `1px solid ${active ? COLORS.accent : COLORS.border}`,
        borderRadius: 8, padding: "16px 20px", flex: 1, minWidth: 140,
        cursor: onClick ? "pointer" : "default",
        transition: "all 0.2s",
      }}
    >
      <div style={{ fontSize: 11, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color: color || COLORS.text, fontFamily: "'JetBrains Mono', monospace" }}>{value}</div>
      {subtext && <div style={{ fontSize: 11, color: COLORS.textDim, marginTop: 2 }}>{subtext}</div>}
    </div>
  );
}

// ─── Attack Path Card ───
function AttackPathCard({ path, isSelected, onClick }) {
  const sev = SEVERITY_CONFIG[path.severity] || SEVERITY_CONFIG.medium;
  const isGrouped = Boolean(path.group_id);
  return (
    <div
      onClick={onClick}
      style={{
        background: isSelected ? COLORS.bgCardHover : COLORS.bgCard,
        borderStyle: "solid",
        borderWidth: 1,
        borderColor: isSelected ? sev.color : COLORS.border,
        borderRadius: 8, padding: 16, cursor: "pointer",
        transition: "all 0.2s", marginBottom: 10,
        borderLeftWidth: 3,
        borderLeftColor: sev.color,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <span style={{ fontWeight: 600, color: COLORS.text, fontSize: 14, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }} title={path.name}>{path.name}</span>
        <span style={{
          background: sev.bg, color: sev.color, padding: "2px 10px", borderRadius: 12,
          fontSize: 11, fontWeight: 600, textTransform: "uppercase",
        }}>
          {sev.icon} {path.severity}
        </span>
      </div>
      <p style={{ color: COLORS.textDim, fontSize: 12, margin: 0, lineHeight: 1.5 }}>{path.description}</p>
      <div style={{ display: "flex", gap: 4, marginTop: 8, flexWrap: "wrap", alignItems: "center" }}>
        {isGrouped && (
          <span style={{
            background: COLORS.accent + "1f",
            color: COLORS.accent,
            padding: "1px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700,
          }}>{path.member_count} paths</span>
        )}
        {path.category && CATEGORY_CONFIG[path.category] && (
          <span style={{
            background: CATEGORY_CONFIG[path.category].color + "1f",
            color: CATEGORY_CONFIG[path.category].color,
            padding: "1px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600,
          }}>{CATEGORY_CONFIG[path.category].label}</span>
        )}
        {path.mitre_techniques?.map((t) => (
          <span key={t} style={{
            background: "rgba(139,92,246,0.15)", color: "#a78bfa", padding: "1px 8px",
            borderRadius: 4, fontSize: 10, fontFamily: "monospace",
          }}>{t}</span>
        ))}
      </div>
    </div>
  );
}

// ─── Attack Path Detail Panel ───
function StructuredHop({ step, index, isLast, severity }) {
  const parts = hopPartsFromStep(step);
  const fields = [
    ["Action", parts.action],
    ["Target", parts.target],
    ["Capability", parts.capability],
    ["Source", parts.source],
  ].filter(([, value]) => value);

  return (
    <div style={{ display: "flex", gap: 0, marginBottom: 0, alignItems: "stretch" }}>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", minWidth: 32 }}>
        <div style={{
          minWidth: 26, height: 26, borderRadius: "50%",
          background: index === 0 ? severity.color : severity.bg,
          color: index === 0 ? "#fff" : severity.color,
          border: `2px solid ${severity.color}`,
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 11, fontWeight: 700, flexShrink: 0, zIndex: 1,
        }}>{index + 1}</div>
        {!isLast && (
          <div style={{
            width: 2, flex: 1, minHeight: 12,
            background: `linear-gradient(to bottom, ${severity.color}66, ${severity.color}22)`,
          }} />
        )}
      </div>
      <div style={{
        flex: 1,
        marginLeft: 12,
        marginBottom: isLast ? 0 : 8,
        padding: "10px 14px",
        background: COLORS.bgCard,
        border: `1px solid ${COLORS.border}`,
        borderLeft: `3px solid ${index === 0 ? severity.color : severity.color + "66"}`,
        borderRadius: 6,
      }}>
        {fields.length > 0 ? (
          <div style={{ display: "grid", gridTemplateColumns: "minmax(72px, 110px) 1fr", gap: "6px 10px" }}>
            {fields.map(([label, value]) => (
              <div key={label} style={{ display: "contents" }}>
                <div style={{ color: COLORS.textDim, fontSize: 10, textTransform: "uppercase", fontWeight: 700 }}>{label}</div>
                <div style={{
                  color: label === "Capability" ? COLORS.text : "#cbd5e1",
                  fontSize: 12,
                  lineHeight: 1.45,
                  fontFamily: label === "Action" || label === "Target" || label === "Source" ? "'JetBrains Mono', monospace" : "inherit",
                  wordBreak: "break-word",
                }}>{value}</div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ color: COLORS.text, fontSize: 13, lineHeight: 1.6, wordBreak: "break-word" }}>{String(step || "")}</div>
        )}
      </div>
    </div>
  );
}

function PathDetail({ path, controlsData }) {
  const detailRef = useRef(null);
  const detailKey = `${path?.group_id || ""}:${path?.id || ""}:${path?.representative_path_id || ""}:${path?.name || ""}`;

  useEffect(() => {
    detailRef.current?.scrollTo({ top: 0, left: 0 });
  }, [detailKey]);

  if (!path) return (
    <div style={{ color: COLORS.textDim, textAlign: "center", padding: 40, fontSize: 13 }}>
      Select an attack path to see details
    </div>
  );

  const sev = SEVERITY_CONFIG[path.severity] || SEVERITY_CONFIG.medium;
  const matchingDetections = (controlsData?.detections || []).filter((d) => detectionMatchesPath(d, path));
  const commandLines = commandsFromPath(path);
  const visibleSteps = commandLines.length > 0 ? commandLines : (path.hops?.length > 0 ? path.hops : path.steps);
  const isGrouped = Boolean(path.group_id);

  return (
    <div ref={detailRef} style={{ padding: 20, overflowY: "auto", height: "100%" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
        <span style={{
          background: sev.bg, color: sev.color, padding: "3px 12px", borderRadius: 12,
          fontSize: 12, fontWeight: 700, textTransform: "uppercase",
        }}>{path.severity}</span>
        <h2 style={{ margin: 0, color: COLORS.text, fontSize: 18, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }} title={path.name}>{path.name}</h2>
      </div>
      <p style={{ color: COLORS.textDim, lineHeight: 1.6, fontSize: 13 }}>{path.description}</p>
      {isGrouped && (
        <div style={{
          background: COLORS.bgCard,
          border: `1px solid ${COLORS.border}`,
          borderLeft: `3px solid ${COLORS.accent}`,
          borderRadius: 8,
          padding: 12,
          marginBottom: 16,
        }}>
          <div style={{ color: COLORS.text, fontSize: 12, fontWeight: 700, marginBottom: 8 }}>
            Grouped Paths
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(130px, 170px) 1fr", gap: "6px 10px", fontSize: 12 }}>
            <div style={{ color: COLORS.textDim, textTransform: "uppercase", fontSize: 10, fontWeight: 700 }}>Members</div>
            <div style={{ color: COLORS.text }}>{path.member_count} final attack paths</div>
            <div style={{ color: COLORS.textDim, textTransform: "uppercase", fontSize: 10, fontWeight: 700 }}>Primitive</div>
            <div style={{ color: COLORS.text, fontFamily: "'JetBrains Mono', monospace" }}>{path.primitive}</div>
            <div style={{ color: COLORS.textDim, textTransform: "uppercase", fontSize: 10, fontWeight: 700 }}>Representative</div>
            <div style={{ color: COLORS.text, fontFamily: "'JetBrains Mono', monospace" }}>{path.representative_path_id} representative raw path</div>
            {path.source_principals?.length > 0 && (
              <>
                <div style={{ color: COLORS.textDim, textTransform: "uppercase", fontSize: 10, fontWeight: 700 }}>Starting Principals</div>
                <div style={{ color: COLORS.text, fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-word" }}>
                  {path.source_principals.slice(0, 8).join(", ")}
                  {path.source_principals.length > 8 ? `, +${path.source_principals.length - 8} more` : ""}
                </div>
              </>
            )}
          </div>
        </div>
      )}
      {isGrouped && path.leveraging_assets?.length > 0 && (
        <>
          <SectionHeader title="Assets That Can Leverage This" icon={"\u25C9"} />
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 10, marginBottom: 14 }}>
            {path.leveraging_assets.map((asset) => (
              <div key={asset.id} style={{
                background: COLORS.bgCard,
                border: `1px solid ${COLORS.border}`,
                borderRadius: 8,
                padding: 10,
                borderLeft: `3px solid ${COLORS.accent}`,
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 6 }}>
                  <span style={{ color: COLORS.text, fontSize: 12, fontWeight: 700, wordBreak: "break-word" }}>{asset.id}</span>
                  <span style={{ color: COLORS.accent, background: COLORS.accent + "18", borderRadius: 6, padding: "1px 6px", fontSize: 10, textTransform: "uppercase", height: 18 }}>{asset.type}</span>
                </div>
                {asset.arn && (
                  <div style={{ color: COLORS.textDim, fontFamily: "'JetBrains Mono', monospace", fontSize: 10, wordBreak: "break-word", marginBottom: 6 }}>{asset.arn}</div>
                )}
                <div style={{ color: COLORS.textDim, fontSize: 10 }}>
                  Paths: {(asset.path_ids || []).join(", ")}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Steps */}
      <SectionHeader title={commandLines.length > 0 ? "AWS CLI Replay Commands" : "Validated Attack Hops"} icon={"\u2694"} />
      <div style={{ marginLeft: 4, position: "relative" }}>
        {visibleSteps?.map((step, i) => {
          const isLast = i === visibleSteps.length - 1;
          if (commandLines.length === 0) {
            return <StructuredHop key={i} step={step} index={i} isLast={isLast} severity={sev} />;
          }
          return (
            <div key={i} style={{ display: "flex", gap: 0, marginBottom: 0, alignItems: "stretch" }}>
              {/* Timeline column */}
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", minWidth: 32 }}>
                <div style={{
                  minWidth: 26, height: 26, borderRadius: "50%",
                  background: i === 0 ? sev.color : sev.bg,
                  color: i === 0 ? "#fff" : sev.color,
                  border: `2px solid ${sev.color}`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 11, fontWeight: 700, flexShrink: 0, zIndex: 1,
                }}>{i + 1}</div>
                {!isLast && (
                  <div style={{
                    width: 2, flex: 1, minHeight: 12,
                    background: `linear-gradient(to bottom, ${sev.color}66, ${sev.color}22)`,
                  }} />
                )}
              </div>
              {/* Step content card */}
              <div style={{
                flex: 1, marginLeft: 12, marginBottom: isLast ? 0 : 6, padding: "10px 14px",
                background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
                borderLeft: `3px solid ${i === 0 ? sev.color : sev.color + "66"}`,
                borderRadius: 6, transition: "border-color 0.2s",
              }}>
                <span style={{
                  color: COLORS.text,
                  fontSize: 13,
                  lineHeight: 1.6,
                  wordBreak: "break-word",
                  fontFamily: commandLines.length > 0 ? "'JetBrains Mono', monospace" : "inherit",
                  flex: 1,
                }}>{step}</span>
                {commandLines.length > 0 && <CopyButton text={step} />}
              </div>
            </div>
          );
        })}
      </div>
      {commandLines.length === 0 && (
        <div style={{
          marginTop: 10,
          padding: "10px 12px",
          borderRadius: 6,
          border: `1px solid ${COLORS.border}`,
          background: "#0d1117",
          color: COLORS.textDim,
          fontSize: 12,
          lineHeight: 1.5,
        }}>
          AWS CLI replay commands are not embedded in this audit result. Generate an exploit playbook to display executable reproduction commands.
        </div>
      )}

      {/* MITRE */}
      {path.mitre_techniques?.length > 0 && (
        <>
          <SectionHeader title="MITRE ATT&CK" icon={"\uD83D\uDDFA"} />
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {path.mitre_techniques.map((t) => (
              <a key={t} href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}/`}
                target="_blank" rel="noreferrer"
                style={{
                  background: "rgba(139,92,246,0.15)", color: "#a78bfa", padding: "4px 12px",
                  borderRadius: 6, fontSize: 12, fontFamily: "monospace", textDecoration: "none",
                }}>{t}</a>
            ))}
          </div>
        </>
      )}

      {/* Detection */}
      {matchingDetections.length > 0 ? (
        <>
          <SectionHeader title="Generated SPL Detections" icon={"\uD83D\uDD0D"} />
          {matchingDetections.map((d, i) => (
            <div key={i} style={{
              background: COLORS.bgCard,
              border: `1px solid ${COLORS.border}`,
              borderRadius: 8,
              padding: 12,
              marginBottom: 10,
            }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
                <span style={{ color: COLORS.text, fontWeight: 600, fontSize: 13 }}>{d.name}</span>
                <span style={{
                  fontSize: 10,
                  fontWeight: 700,
                  color: severityColorFor(d.severity),
                  background: severityColorFor(d.severity) + "18",
                  borderRadius: 6,
                  padding: "2px 8px",
                  textTransform: "uppercase",
                }}>{d.severity}</span>
              </div>
              {d.spl ? (
                <SplBlock spl={d.spl} />
              ) : (
                <div style={{ color: COLORS.textDim, fontSize: 12 }}>SPL query not embedded.</div>
              )}
              <DetectionMetadata rule={d} />
            </div>
          ))}
        </>
      ) : path.detection_opportunities?.length > 0 && (
        <>
          <SectionHeader title="Detection Opportunities" icon={"\uD83D\uDD0D"} />
          {path.detection_opportunities.map((d, i) => (
            <div key={i} style={{
              display: "flex", alignItems: "flex-start", gap: 4, marginBottom: 6,
            }}>
              <div style={{
                flex: 1, background: "rgba(6,182,212,0.08)", border: `1px solid rgba(6,182,212,0.2)`,
                borderRadius: 6, padding: "8px 12px", fontSize: 12,
                color: "#67e8f9", wordBreak: "break-word",
              }}>{d}</div>
            </div>
          ))}
        </>
      )}

      {/* Remediation */}
      {path.remediation?.length > 0 && (
        <>
          <SectionHeader title="Remediation" icon={"\uD83D\uDEE1"} />
          {path.remediation.map((r, i) => (
            <div key={i} style={{
              display: "flex", gap: 8, alignItems: "flex-start", marginBottom: 8,
            }}>
              <span style={{ color: COLORS.low, fontSize: 14 }}>{"\u2713"}</span>
              <span style={{ color: COLORS.text, fontSize: 13, flex: 1 }}>{r}</span>
              <CopyButton text={r} />
            </div>
          ))}
        </>
      )}

      {/* Exploit: Lateral Movement */}
      {path.lateral_movement_chain?.length > 0 && (
        <>
          <SectionHeader title="Lateral Movement Chain" icon={"\u21C4"} />
          {path.lateral_movement_chain.map((hop, i) => (
            <div key={i} style={{
              display: "flex", gap: 8, alignItems: "center", marginBottom: 6,
              background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
              borderRadius: 6, padding: "8px 12px",
            }}>
              <span style={{ color: COLORS.nodeUser, fontFamily: "monospace", fontSize: 11, wordBreak: "break-word" }}>{hop.from}</span>
              <span style={{ color: COLORS.edgeCrossAccount }}>{"\u2192"}</span>
              <span style={{ color: COLORS.nodeRole, fontFamily: "monospace", fontSize: 11, wordBreak: "break-word" }}>{hop.to}</span>
              <span style={{ color: COLORS.textDim, fontSize: 10, marginLeft: "auto" }}>{hop.mechanism}</span>
            </div>
          ))}
        </>
      )}

      {/* Exploit: Persistence */}
      {path.persistence_techniques?.length > 0 && (
        <>
          <SectionHeader title="Persistence Techniques" icon={"\uD83D\uDD12"} />
          {path.persistence_techniques.map((t, i) => (
            <div key={i} style={{
              display: "flex", justifyContent: "space-between", alignItems: "center",
              marginBottom: 6, padding: "6px 10px", borderRadius: 6,
              background: t.available ? COLORS.criticalBg : COLORS.bgCard,
              border: `1px solid ${t.available ? COLORS.critical + "33" : COLORS.border}`,
            }}>
              <span style={{ fontSize: 12, color: COLORS.text }}>{t.technique}</span>
              <span style={{
                fontSize: 10, fontWeight: 700, padding: "1px 8px", borderRadius: 4,
                color: t.available ? COLORS.critical : COLORS.low,
                background: t.available ? COLORS.criticalBg : COLORS.lowBg,
              }}>{t.available ? "AVAILABLE" : "BLOCKED"}</span>
            </div>
          ))}
        </>
      )}

      {/* Exploit: Exfiltration */}
      {path.exfiltration_vectors?.length > 0 && (
        <>
          <SectionHeader title="Exfiltration Vectors" icon={"\uD83D\uDCE4"} />
          {path.exfiltration_vectors.map((v, i) => (
            <div key={i} style={{
              marginBottom: 6, padding: "8px 10px", borderRadius: 6,
              background: v.available ? COLORS.highBg : COLORS.bgCard,
              border: `1px solid ${v.available ? COLORS.high + "33" : COLORS.border}`,
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 12, color: COLORS.text }}>{v.vector}</span>
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: "1px 8px", borderRadius: 4,
                  color: v.available ? COLORS.high : COLORS.low,
                  background: v.available ? COLORS.highBg : COLORS.lowBg,
                }}>{v.available ? "REACHABLE" : "BLOCKED"}</span>
              </div>
              {v.scope_estimate && (
                <div style={{ fontSize: 10, color: COLORS.textDim, marginTop: 4 }}>Scope: {v.scope_estimate}</div>
              )}
            </div>
          ))}
        </>
      )}
    </div>
  );
}

function SectionHeader({ title, icon }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 8, marginTop: 24, marginBottom: 12,
      borderBottom: `1px solid ${COLORS.border}`, paddingBottom: 8,
    }}>
      <span style={{ fontSize: 14 }}>{icon}</span>
      <span style={{ color: COLORS.text, fontWeight: 600, fontSize: 13, textTransform: "uppercase", letterSpacing: "0.05em" }}>{title}</span>
    </div>
  );
}

// ─── Legend ───
function GraphLegend() {
  const items = [
    { color: COLORS.nodeUser, label: "User", shape: "circle" },
    { color: COLORS.nodeRole, label: "Role", shape: "circle" },
    { color: COLORS.nodeEsc, label: "Escalation", shape: "circle" },
    { color: COLORS.nodeData, label: "Data Store", shape: "circle" },
    { color: COLORS.nodeExternal, label: "External", shape: "circle" },
    { color: COLORS.edgeTrust, label: "Trust", shape: "line" },
    { color: COLORS.edgePrivEsc, label: "Priv Esc", shape: "line-dashed" },
    { color: COLORS.edgeCrossAccount, label: "Cross-Acct", shape: "line-dashed" },
    { color: COLORS.edgeDataAccess, label: "Data Access", shape: "line" },
    { color: COLORS.edgeService, label: "Service", shape: "line-dashed" },
    { color: COLORS.edgeNetwork, label: "Network", shape: "line" },
    { color: COLORS.edgePublicAccess, label: "Public Access", shape: "line" },
    { color: COLORS.edgePublicAccess, label: "Resource Policy", shape: "line-dashed" },
    { color: COLORS.edgeDataAccess, label: "Encrypted By", shape: "line-dashed" },
  ];
  return (
    <div style={{
      position: "absolute", bottom: 12, left: 12, background: "rgba(17,24,39,0.92)",
      border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: "10px 14px",
      display: "flex", gap: 12, flexWrap: "wrap",
    }}>
      {items.map((item) => (
        <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {item.shape === "circle" ? (
            <div style={{ width: 10, height: 10, borderRadius: "50%", background: item.color }} />
          ) : (
            <div style={{
              width: 18, height: 0, borderTop: `2px ${item.shape === "line-dashed" ? "dashed" : "solid"} ${item.color}`,
            }} />
          )}
          <span style={{ fontSize: 10, color: COLORS.textDim }}>{item.label}</span>
        </div>
      ))}
    </div>
  );
}

// ─── File Upload ───
function FileUpload({ onDataLoad }) {
  const handleFile = useCallback((e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const json = JSON.parse(ev.target.result);
        onDataLoad(json);
      } catch { console.error("[SCOPE] Invalid JSON file uploaded"); }
    };
    reader.readAsText(file);
  }, [onDataLoad]);

  return (
    <label style={{
      display: "inline-flex", alignItems: "center", gap: 6, padding: "6px 14px",
      background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 6,
      cursor: "pointer", fontSize: 12, color: COLORS.textDim,
      transition: "border-color 0.2s",
    }}>
      Load Results JSON
      <input type="file" accept=".json" onChange={handleFile} style={{ display: "none" }} />
    </label>
  );
}

function LoadedPhaseSummary({ allData }) {
  const phases = Object.keys(allData).filter((src) => PHASE_CONFIG[src]);
  if (phases.length === 0) return null;

  return (
    <>
      {" \u2022 "}
      {phases.map((src, index) => (
        <span key={src}>
          {index > 0 && <span style={{ color: COLORS.textDim }}>{" / "}</span>}
          <span style={{ color: PHASE_CONFIG[src]?.color || COLORS.accent }}>{PHASE_CONFIG[src]?.label || src}</span>
        </span>
      ))}
    </>
  );
}

// ─── Node Detail Panel (slide-out) ───
function NodeDetailPanel({ node, data, graphPaths, selectedPath, onSelectPath, onClose }) {
  if (!node) return null;
  const scopedGraph = useMemo(() => graphForAttackPaths(data, graphPaths), [data, graphPaths]);

  const connectedEdges = useMemo(() => {
    if (!scopedGraph?.edges) return [];
    return scopedGraph.edges.filter(
      (e) => e.source === node.id || e.target === node.id
    );
  }, [scopedGraph, node]);

  const associatedPaths = useMemo(() => {
    if (!data?.attack_paths) return [];
    const nodeId = node.id || "";
    const nodeLabel = node.label || "";
    return data.attack_paths.filter((p) => {
      const resources = p.affected_resources || [];
      return resources.some((r) => {
        if (r === nodeId) return true;
        const resName = r.includes("/") ? r.split("/").pop() : r.split(":").pop();
        return resName === nodeLabel || nodeId.endsWith(":" + resName);
      });
    });
  }, [data, node]);

  return (
    <div style={{
      position: "absolute", top: 0, right: 0, width: 280, height: "100%",
      background: "rgba(17,24,39,0.97)", borderLeft: `1px solid ${COLORS.border}`,
      overflowY: "auto", zIndex: 10,
    }}>
      <div style={{ padding: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: COLORS.text, marginBottom: 4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={node.label}>{node.label}</div>
            <div style={{
              fontSize: 10, color: COLORS.textDim, background: COLORS.bgCard,
              padding: "2px 8px", borderRadius: 4, display: "inline-block",
            }}>{node.type}</div>
          </div>
          <button onClick={onClose}
            style={{ background: "none", border: "none", color: COLORS.textDim, cursor: "pointer", fontSize: 14 }}>
            {"\u2715"}
          </button>
        </div>

        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 10, color: COLORS.textDim, textTransform: "uppercase", marginBottom: 4 }}>Node ID</div>
          <div style={{
            fontSize: 11, color: COLORS.text, fontFamily: "monospace", wordBreak: "break-word",
            background: COLORS.bgCard, padding: "6px 8px", borderRadius: 4,
          }}>{node.id}</div>
        </div>

        {node.mfa !== undefined && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 10, color: COLORS.textDim, textTransform: "uppercase", marginBottom: 4 }}>MFA Status</div>
            <div style={{
              fontSize: 12, fontWeight: 600,
              color: node.mfa ? COLORS.low : COLORS.critical,
            }}>
              {node.mfa ? "\u2713 Enabled" : "\u2717 Disabled"}
            </div>
          </div>
        )}

        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 10, color: COLORS.textDim, textTransform: "uppercase", marginBottom: 8 }}>
            Connected Edges ({connectedEdges.length})
          </div>
          {connectedEdges.slice(0, 20).map((e, i) => {
            const isSource = e.source === node.id;
            const otherId = isSource ? e.target : e.source;
            const direction = isSource ? "\u2192" : "\u2190";
            const edgeColor = getEdgeStyle(e.edge_type, e.trust_type).color;
            const edgeLabel = e.label || e.edge_type || e.trust_type || "";
            return (
              <div key={i} style={{
                fontSize: 11, color: COLORS.text, marginBottom: 6,
                background: COLORS.bgCard, borderRadius: 4, padding: "4px 8px",
                borderLeft: `2px solid ${edgeColor}`,
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <span style={{ color: edgeColor, fontWeight: 600 }}>{direction}</span>
                  <span style={{ fontFamily: "monospace", fontSize: 10, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={otherId}>{otherId}</span>
                </div>
                {edgeLabel && (
                  <div style={{ fontSize: 9, color: edgeColor, marginTop: 2, paddingLeft: 16 }}>{edgeLabel}{e.trust_type && e.trust_type !== edgeLabel ? ` (${e.trust_type})` : ""}</div>
                )}
              </div>
            );
          })}
          {connectedEdges.length > 20 && (
            <div style={{ fontSize: 10, color: COLORS.textDim }}>...and {connectedEdges.length - 20} more</div>
          )}
        </div>

        {associatedPaths.length > 0 && (
          <div>
            <div style={{ fontSize: 10, color: COLORS.textDim, textTransform: "uppercase", marginBottom: 8 }}>
              Attack Paths ({associatedPaths.length})
            </div>
            {associatedPaths.map((p, i) => {
              const sev = SEVERITY_CONFIG[p.severity] || SEVERITY_CONFIG.medium;
              return (
                <div key={i}
                  onClick={() => onSelectPath(p)}
                  style={{
                    fontSize: 12, color: COLORS.text, cursor: "pointer", marginBottom: 6,
                    padding: "6px 8px", borderRadius: 4, background: COLORS.bgCard,
                    borderLeft: `2px solid ${sev.color}`,
                  }}
                >
                  <span style={{ color: sev.color, fontSize: 10, marginRight: 6 }}>{sev.icon}</span>
                  {p.name}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Stat Detail Panel (slide-out) ───
function StatDetailPanel({ statKey, data, onClose, onSelectPath, onHighlightNode }) {
  const principals = data?.principals || [];
  const trusts = data?.trust_relationships || [];
  const paths = data?.attack_paths || [];

  const content = useMemo(() => {
    switch (statKey) {
      case "users":
        return { title: "Users", items: principals.filter((p) => p.type === "user") };
      case "roles":
        return { title: "Roles", items: principals.filter((p) => p.type === "role") };
      case "trusts": {
        const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
        const TRUST_TYPE_ORDER = { "cross-account": 0, service: 1, "same-account": 2 };
        if (trusts.length === 0) return { title: "Trust Relationships", items: paths.filter((p) => p.category === "trust_misconfiguration") };
        // Group by role_id — collapse multiple service trusts into one entry with a principals array
        const grouped = {};
        for (const t of trusts) {
          const key = t.role_id || t.role_arn || JSON.stringify(t);
          if (!grouped[key]) {
            grouped[key] = { ...t, all_principals: [t.principal || t.trust_principal || ""] };
          } else {
            grouped[key].all_principals.push(t.principal || t.trust_principal || "");
            // Keep highest risk
            if ((RISK_ORDER[t.risk] ?? 4) < (RISK_ORDER[grouped[key].risk] ?? 4)) grouped[key].risk = t.risk;
            // Keep most specific trust_type
            if ((TRUST_TYPE_ORDER[t.trust_type] ?? 3) < (TRUST_TYPE_ORDER[grouped[key].trust_type] ?? 3)) grouped[key].trust_type = t.trust_type;
            if (t.is_wildcard) grouped[key].is_wildcard = true;
          }
        }
        const trustItems = Object.values(grouped).sort((a, b) => {
          const riskDiff = (RISK_ORDER[a.risk] ?? 4) - (RISK_ORDER[b.risk] ?? 4);
          if (riskDiff !== 0) return riskDiff;
          const typeDiff = (TRUST_TYPE_ORDER[a.trust_type] ?? 3) - (TRUST_TYPE_ORDER[b.trust_type] ?? 3);
          if (typeDiff !== 0) return typeDiff;
          return (a.role_id || "").localeCompare(b.role_id || "");
        });
        return { title: "Trust Relationships", items: trustItems };
      }
      case "wildcards": {
        const wildcardTrusts = trusts.filter((t) => t.is_wildcard);
        return { title: "Wildcard Trusts", items: wildcardTrusts };
      }
      case "privesc": {
        // Include all critical paths that are privilege escalation or have no category
        const privescPaths = paths.filter((p) =>
          p.severity === "critical" && (
            p.category === "privilege_escalation" ||
            !p.category ||
            (p.name || "").toLowerCase().includes("priv") ||
            (p.name || "").toLowerCase().includes("escalat")
          )
        );
        return { title: "Critical PrivEsc", items: privescPaths };
      }
      case "paths":
        return { title: "All Attack Paths", items: paths };
      default:
        return { title: "", items: [] };
    }
  }, [statKey, principals, trusts, paths]);

  return (
    <div style={{
      position: "fixed", top: 0, right: 0, width: 360, height: "100vh",
      background: COLORS.bg, borderLeft: `1px solid ${COLORS.border}`,
      zIndex: 100, overflowY: "auto", boxShadow: "-4px 0 24px rgba(0,0,0,0.4)",
    }}>
      <div style={{ padding: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: COLORS.text }}>{content.title}</h2>
          <button onClick={onClose}
            style={{ background: "none", border: "none", color: COLORS.textDim, cursor: "pointer", fontSize: 16 }}>
            {"\u2715"}
          </button>
        </div>
        {content.items.length === 0 ? (
          <div style={{ color: COLORS.textDim, fontSize: 13 }}>No data available.</div>
        ) : (
          content.items.map((item, i) => (
            <StatDetailItem
              key={i}
              item={item}
              statKey={statKey}
              onSelectPath={onSelectPath}
              onHighlightNode={onHighlightNode}
            />
          ))
        )}
      </div>
    </div>
  );
}

function StatDetailItem({ item, statKey, onSelectPath, onHighlightNode }) {
  if (statKey === "users") {
    return (
      <div
        onClick={() => onHighlightNode?.(item.node_id || item.id)}
        style={{
          background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
          borderRadius: 8, padding: 14, marginBottom: 10, cursor: "pointer",
          transition: "border-color 0.2s",
        }}
      >
        <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, marginBottom: 6 }}>{item.id}</div>
        <div style={{ fontSize: 11, color: COLORS.textDim, fontFamily: "monospace", wordBreak: "break-word", marginBottom: 8 }}>{item.arn}</div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", fontSize: 11 }}>
          <span style={{ color: item.mfa_enabled ? COLORS.low : COLORS.critical }}>
            MFA: {item.mfa_enabled ? "Yes" : "No"}
          </span>
          <span style={{ color: COLORS.textDim }}>Console: {item.console_access ? "Yes" : "No"}</span>
          <span style={{ color: COLORS.textDim }}>Keys: {Array.isArray(item.access_keys) ? item.access_keys.length : (item.access_keys ?? 0)}</span>
        </div>
        {item.groups?.length > 0 && (
          <div style={{ fontSize: 10, color: COLORS.textDim, marginTop: 6 }}>Groups: {item.groups.join(", ")}</div>
        )}
        {item.risk_flags?.length > 0 && (
          <div style={{ display: "flex", gap: 4, marginTop: 6, flexWrap: "wrap" }}>
            {item.risk_flags.map((f) => (
              <span key={f} style={{
                background: COLORS.criticalBg, color: COLORS.critical, padding: "1px 6px",
                borderRadius: 4, fontSize: 9,
              }}>{f}</span>
            ))}
          </div>
        )}
      </div>
    );
  }

  if (statKey === "roles") {
    return (
      <div
        onClick={() => onHighlightNode?.(item.node_id || item.id)}
        style={{
          background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
          borderRadius: 8, padding: 14, marginBottom: 10, cursor: "pointer",
          transition: "border-color 0.2s",
        }}
      >
        <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, marginBottom: 6 }}>{item.id}</div>
        <div style={{ fontSize: 11, color: COLORS.textDim, fontFamily: "monospace", wordBreak: "break-word", marginBottom: 8 }}>{item.arn}</div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", fontSize: 11 }}>
          {item.is_wildcard_trust && <span style={{ color: COLORS.critical }}>Wildcard Trust</span>}
          <span style={{ color: item.has_boundary ? COLORS.low : COLORS.textDim }}>
            Boundary: {item.has_boundary ? "Yes" : "No"}
          </span>
        </div>
        {item.trust_principal && (
          <div style={{ fontSize: 10, color: COLORS.textDim, marginTop: 6, fontFamily: "monospace" }}>
            Trust: {item.trust_principal}
          </div>
        )}
        {(item.attached_policies?.length > 0 || item.policies?.length > 0) && (
          <div style={{ fontSize: 10, color: COLORS.textDim, marginTop: 4 }}>Policies: {(item.attached_policies || item.policies).join(", ")}</div>
        )}
        {item.risk_flags?.length > 0 && (
          <div style={{ display: "flex", gap: 4, marginTop: 6, flexWrap: "wrap" }}>
            {item.risk_flags.map((f) => (
              <span key={f} style={{
                background: COLORS.criticalBg, color: COLORS.critical, padding: "1px 6px",
                borderRadius: 4, fontSize: 9,
              }}>{f}</span>
            ))}
          </div>
        )}
      </div>
    );
  }

  if ((statKey === "trusts" || statKey === "wildcards") && (item.role_id || item.role_arn)) {
    const riskColor = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low }[item.risk] || COLORS.textDim;
    // Trust entity (role_name) is the focus; trusted principal is secondary
    const principal = item.trust_principal || item.principal || "";
    const trustedByName = extractTrustDisplayName(principal, item.trust_type);
    return (
      <div
        onClick={() => onHighlightNode?.(item.role_id)}
        style={{
          background: COLORS.bgCard,
          border: `1px solid ${item.is_wildcard ? COLORS.critical + "66" : COLORS.border}`,
          borderRadius: 8, padding: 14, marginBottom: 10, cursor: "pointer",
          borderLeft: `3px solid ${riskColor}`,
          transition: "border-color 0.2s",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, flex: 1, minWidth: 0 }}>
            {item.is_wildcard && (
              <span style={{
                fontSize: 10, fontWeight: 700, color: COLORS.critical,
                background: COLORS.criticalBg, padding: "1px 6px", borderRadius: 4, flexShrink: 0,
              }}>
                {"\u26A0"} WILDCARD
              </span>
            )}
            <span style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={item.role_name || item.role_arn}>{item.role_name || item.role_id || "Unknown Role"}</span>
          </div>
          <span style={{ fontSize: 10, fontWeight: 700, color: riskColor, background: riskColor + "18", padding: "1px 8px", borderRadius: 8, flexShrink: 0 }}>{item.risk}</span>
        </div>
        {/* Trusted-by line: show all principals if grouped, otherwise single */}
        {item.all_principals?.length > 1 ? (
          <div style={{ marginBottom: 6 }}>
            <div style={{ fontSize: 11, color: COLORS.textDim, marginBottom: 4 }}>Trusted by {item.all_principals.length} principals:</div>
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {item.all_principals.map((p, idx) => (
                <span key={idx} style={{
                  fontSize: 10, fontFamily: "monospace", background: COLORS.bgCardHover,
                  color: COLORS.text, padding: "2px 6px", borderRadius: 4,
                }}>{p.replace(".amazonaws.com", "")}</span>
              ))}
            </div>
          </div>
        ) : (
          <>
            <div style={{ fontSize: 11, color: COLORS.textDim, marginBottom: 4 }}>
              Trusted by: <span style={{ color: COLORS.text, fontWeight: 500 }}>{trustedByName}</span>
            </div>
            {principal && (
              <div style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: "monospace", wordBreak: "break-word", marginBottom: 6 }}>{principal}</div>
            )}
          </>
        )}
        {item.is_internal != null && (
          <div style={{ marginBottom: 6 }}>
            <span style={{
              display: "inline-block", fontSize: 10, fontWeight: 700,
              padding: "2px 8px", borderRadius: 4,
              background: item.is_internal ? "#10b98118" : "#f9731618",
              color: item.is_internal ? "#10b981" : "#f97316",
            }}>
              {item.is_internal ? `INTERNAL${item.account_name ? ` — ${item.account_name}` : ""}` : "EXTERNAL"}
            </span>
          </div>
        )}
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", fontSize: 10 }}>
          <span style={{ color: COLORS.textDim }}>{item.trust_type}</span>
          <span style={{ color: item.has_external_id ? COLORS.low : COLORS.high }}>
            ExtID: {item.has_external_id ? "Yes" : "No"}
          </span>
          <span style={{ color: item.has_mfa_condition ? COLORS.low : COLORS.textDim }}>
            MFA: {item.has_mfa_condition ? "Yes" : "No"}
          </span>
        </div>
      </div>
    );
  }

  const sev = SEVERITY_CONFIG[item.severity] || SEVERITY_CONFIG.medium;
  const catCfg = CATEGORY_CONFIG[item.category];
  return (
    <div
      onClick={() => onSelectPath?.(item)}
      style={{
        background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
        borderRadius: 8, padding: 14, marginBottom: 10, cursor: "pointer",
        borderLeft: `3px solid ${sev.color}`,
        transition: "border-color 0.2s",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }} title={item.name}>{item.name}</span>
        <span style={{
          background: sev.bg, color: sev.color, padding: "2px 8px", borderRadius: 12,
          fontSize: 10, fontWeight: 600, textTransform: "uppercase",
        }}>
          {sev.icon} {item.severity}
        </span>
      </div>
      <p style={{ color: COLORS.textDim, fontSize: 11, margin: 0, lineHeight: 1.4 }}>{item.description}</p>
      {catCfg && (
        <span style={{
          display: "inline-block", marginTop: 6, fontSize: 9, fontWeight: 600,
          color: catCfg.color, background: catCfg.color + "1f",
          padding: "1px 8px", borderRadius: 4,
        }}>{catCfg.label}</span>
      )}
    </div>
  );
}

function publicExposureDisplayValue(value, fallback = "Unknown") {
  if (value == null || value === "") return fallback;
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    const values = value.map((item) => publicExposureDisplayValue(item, "")).filter(Boolean);
    return values.length ? values.join(", ") : fallback;
  }
  if (typeof value === "object") {
    return value.name || value.id || value.resource || value.arn || value.type || fallback;
  }
  return fallback;
}

function PublicExposureFindingsSection({ findings = [], isNarrow, embedded = false }) {
  if (!findings.length) return null;

  const sortedFindings = [...findings].sort((a, b) => (
    (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4)
  ));

  return (
    <section style={{
      padding: embedded ? 16 : (isNarrow ? "0 12px 12px" : "0 24px 16px"),
      height: embedded ? "100%" : "auto",
      overflowY: embedded ? "auto" : "visible",
      boxSizing: "border-box",
    }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 10 }}>
        <h2 style={{
          margin: 0,
          fontSize: 13,
          fontWeight: 700,
          color: COLORS.text,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}>
          Public Exposure Findings
        </h2>
        <span style={{ fontSize: 11, color: COLORS.textDim }}>
          Public reachability assessment, separate from validated attack paths
        </span>
      </div>
      <div style={{
        display: "grid",
        gridTemplateColumns: isNarrow ? "1fr" : "repeat(auto-fit, minmax(280px, 1fr))",
        gap: 12,
      }}>
        {sortedFindings.map((finding, index) => {
          const severityKey = finding.severity || "low";
          const sev = SEVERITY_CONFIG[severityKey] || SEVERITY_CONFIG.low;
          const coverageNeeded = Array.isArray(finding.coverage_needed) ? finding.coverage_needed : [];
          const promotedPathIds = Array.isArray(finding.promoted_attack_path_ids) ? finding.promoted_attack_path_ids : [];
          const resource = publicExposureDisplayValue(finding.resource);

          return (
            <article
              key={finding.id || finding.source_entrypoint_id || index}
              style={{
                background: COLORS.bgCard,
                border: `1px solid ${COLORS.border}`,
                borderLeft: `3px solid ${sev.color}`,
                borderRadius: 8,
                padding: 14,
                minWidth: 0,
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "flex-start", marginBottom: 8 }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: COLORS.text, lineHeight: 1.35 }}>
                    {finding.title || finding.category || "Public exposure"}
                  </div>
                  <div style={{
                    marginTop: 4,
                    fontSize: 11,
                    color: COLORS.textDim,
                    fontFamily: "'JetBrains Mono', monospace",
                    wordBreak: "break-word",
                    lineHeight: 1.35,
                  }}>
                    {resource}
                  </div>
                </div>
                <span style={{
                  background: sev.bg,
                  color: sev.color,
                  padding: "2px 8px",
                  borderRadius: 12,
                  fontSize: 10,
                  fontWeight: 700,
                  textTransform: "uppercase",
                  flexShrink: 0,
                }}>
                  {sev.icon} {severityKey}
                </span>
              </div>

              {finding.assessment && (
                <p style={{ color: COLORS.text, fontSize: 12, lineHeight: 1.5, margin: "0 0 8px" }}>
                  {finding.assessment}
                </p>
              )}
              {finding.security_relevance && (
                <p style={{ color: COLORS.textDim, fontSize: 12, lineHeight: 1.5, margin: "0 0 10px" }}>
                  {finding.security_relevance}
                </p>
              )}

              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 10, color: COLORS.textMuted, textTransform: "uppercase", fontWeight: 700, marginBottom: 4 }}>
                  {promotedPathIds.length > 0 ? "Promoted attack path" : "Not promoted to attack path"}
                </div>
                {promotedPathIds.length > 0 ? (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {promotedPathIds.map((pathId) => (
                      <span
                        key={`${finding.id || index}-promoted-${pathId}`}
                        style={{
                          color: COLORS.high,
                          background: COLORS.highBg,
                          border: `1px solid ${COLORS.high}33`,
                          borderRadius: 4,
                          padding: "2px 6px",
                          fontSize: 11,
                          lineHeight: 1.35,
                          wordBreak: "break-word",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {pathId}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div style={{ color: COLORS.textDim, fontSize: 12, lineHeight: 1.45 }}>
                    {finding.reason_not_attack_path || "No internal transition was validated from this public entrypoint."}
                  </div>
                )}
              </div>

              <div>
                <div style={{ fontSize: 10, color: COLORS.textMuted, textTransform: "uppercase", fontWeight: 700, marginBottom: 6 }}>
                  Coverage needed
                </div>
                {coverageNeeded.length > 0 ? (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {coverageNeeded.map((item, itemIndex) => (
                      <span
                        key={`${finding.id || index}-coverage-${itemIndex}`}
                        style={{
                          color: COLORS.medium,
                          background: COLORS.mediumBg,
                          border: `1px solid ${COLORS.medium}33`,
                          borderRadius: 4,
                          padding: "2px 6px",
                          fontSize: 11,
                          lineHeight: 1.35,
                          wordBreak: "break-word",
                        }}
                      >
                        {publicExposureDisplayValue(item, "coverage item")}
                      </span>
                    ))}
                  </div>
                ) : (
                  <div style={{ color: COLORS.textMuted, fontSize: 12 }}>No additional coverage listed.</div>
                )}
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}

// ═══════════════════════════════════════════════════════════════════
// ─── Phase Views ───
// ═══════════════════════════════════════════════════════════════════

// ─── Audit/Exploit View (extracted from original App) ───
function AuditExploitView({ data, controlsData, filteredPaths, selectedPath, setSelectedPath, tab, setTab, selectedNode, setSelectedNode, searchQuery, setSearchQuery, sortMode, setSortMode, activeStatPanel, handleStatClick, isNarrow }) {
  const summary = data?.summary || {};
  const isExploit = data?.source === "exploit";
  const rawAttackPathCount = data.attack_paths?.length || 0;
  const attackPathGroupCount = data.attack_path_groups?.length || rawAttackPathCount;
  // Run status: absent/undefined treated as "complete" — backward compat with pre-status runs
  const runStatus = data?.runStatus || "complete";
  const isIncomplete = runStatus === "partial" || runStatus === "failed";

  // DASH-03: ref for graph navigation
  const graphRef = useRef(null);

  // DASH-03: deselect handler — clears path and node selection, called on SVG background click
  const handleDeselect = useCallback(() => {
    setSelectedPath(null);
    setSelectedNode(null);
  }, [setSelectedPath, setSelectedNode]);

  // DASH-03: node-click filtering — when a node is selected, filter paths to those involving that node
  // Node IDs are "user:name" / "role:name" / "data:s3:name" but affected_resources are ARNs
  // Match by: exact ID, node label in resource name, or resource name in node ID
  const displayedPaths = useMemo(() => {
    if (!selectedNode) return filteredPaths;
    const nodeId = selectedNode.id || "";
    const nodeLabel = selectedNode.label || "";
    return filteredPaths.filter((p) => {
      const resources = p.affected_resources || [];
      return resources.some((r) => {
        if (r === nodeId) return true;
        // Extract resource name from ARN (last segment after : or /)
        const resName = r.includes("/") ? r.split("/").pop() : r.split(":").pop();
        return resName === nodeLabel || nodeId.endsWith(":" + resName);
      });
    });
  }, [filteredPaths, selectedNode]);

  return (
    <>
      {/* Stats Row */}
      <div style={{ display: "flex", gap: 12, padding: isNarrow ? "12px" : "16px 24px", flexWrap: "wrap" }}>
        {isExploit ? (
          <>
            <StatCard label="Attack Paths" value={rawAttackPathCount} color={COLORS.accent} active={activeStatPanel === "paths"} onClick={() => handleStatClick("paths")} />
            <StatCard label="Persistence" value={summary.persistence_techniques ?? 0} color={COLORS.critical} />
            <StatCard label="Exfiltration" value={summary.exfiltration_vectors ?? 0} color={COLORS.high} />
            <StatCard label="Highest Priv" value={summary.highest_priv || "N/A"} color={COLORS.text} />
            <StatCard label="Critical PrivEsc" value={data.attack_paths?.filter((p) => p.severity === "critical" && (p.category === "privilege_escalation" || !p.category)).length || 0} color={COLORS.critical} active={activeStatPanel === "privesc"} onClick={() => handleStatClick("privesc")} />
          </>
        ) : (
          <>
            <StatCard label="Users" value={summary.total_users ?? 0} subtext={`${summary.users_without_mfa || 0} no MFA`} color={summary.users_without_mfa > 0 ? COLORS.high : COLORS.text} active={activeStatPanel === "users"} onClick={() => handleStatClick("users")} />
            <StatCard label="Roles" value={summary.total_roles ?? 0} active={activeStatPanel === "roles"} onClick={() => handleStatClick("roles")} />
            <StatCard label="Trust Relationships" value={summary.total_trust_relationships ?? 0} subtext={`${summary.cross_account_trusts || 0} cross-account / ${summary.service_trusts || 0} service / ${summary.same_account_trusts || 0} same-account`} active={activeStatPanel === "trusts"} onClick={() => handleStatClick("trusts")} />
            <StatCard label="Wildcard Trusts" value={summary.wildcard_trust_policies ?? 0} color={(summary.wildcard_trust_policies ?? 0) > 0 ? COLORS.critical : COLORS.low} active={activeStatPanel === "wildcards"} onClick={() => handleStatClick("wildcards")} />
            <StatCard label="Critical PrivEsc" value={summary.critical_priv_esc_risks ?? 0} color={(summary.critical_priv_esc_risks ?? 0) > 0 ? COLORS.critical : COLORS.low} active={activeStatPanel === "privesc"} onClick={() => handleStatClick("privesc")} />
            <StatCard label="Attack Groups" value={attackPathGroupCount} subtext={`${rawAttackPathCount} raw paths`} color={COLORS.accent} active={activeStatPanel === "paths"} onClick={() => handleStatClick("paths")} />
          </>
        )}
      </div>

      {/* Main Content */}
      <div style={{
        flex: 1,
        display: "flex",
        flexDirection: isNarrow ? "column" : "row",
        padding: isNarrow ? "0 12px 12px" : "0 24px 24px",
        gap: isNarrow ? 12 : 16,
        minHeight: 0,
        overflow: isNarrow ? "auto" : "hidden",
      }}>
        {/* Left: Attack Paths List */}
        <div style={{
          width: isNarrow ? "100%" : 320,
          minWidth: 0,
          maxHeight: isNarrow ? 360 : "none",
          display: "flex",
          flexDirection: "column",
          opacity: (isIncomplete && !data?.attack_paths?.length) ? 0.6 : 1,
        }}>
          <div style={{ marginBottom: 10, fontSize: 13, fontWeight: 600, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "0.05em" }}>
            {data.attack_path_groups?.length ? "Attack Path Groups" : "Attack Paths"}
          </div>

          <div style={{ marginBottom: 8 }}>
            <input
              type="text"
              placeholder="Search paths, techniques..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: "100%", padding: "7px 12px", borderRadius: 6,
                border: `1px solid ${COLORS.border}`, background: COLORS.bgCard,
                color: COLORS.text, fontSize: 12, outline: "none",
                boxSizing: "border-box",
              }}
            />
          </div>
          <div style={{ display: "flex", gap: 4, marginBottom: 10 }}>
            {[
              { key: "severity", label: "Severity" },
              { key: "steps", label: "Steps" },
              { key: "name", label: "Name" },
            ].map((s) => (
              <button
                key={s.key}
                onClick={() => setSortMode(s.key)}
                style={{
                  padding: "2px 8px", borderRadius: 4, cursor: "pointer",
                  fontSize: 10, fontWeight: 600, textTransform: "uppercase",
                  border: `1px solid ${sortMode === s.key ? COLORS.accent : COLORS.border}`,
                  background: sortMode === s.key ? COLORS.accent + "18" : "transparent",
                  color: sortMode === s.key ? COLORS.accent : COLORS.textMuted,
                }}
              >
                {s.label}
              </button>
            ))}
          </div>
          <div style={{ flex: 1, overflowY: "auto" }}>
            {selectedNode && (
              <div style={{ fontSize: 10, color: COLORS.accent, marginBottom: 6, padding: "3px 8px", background: COLORS.accent + "12", borderRadius: 4 }}>
                Showing paths for: {selectedNode.label}
              </div>
            )}
            {displayedPaths.length === 0 ? (
              <div style={{ color: COLORS.textDim, fontSize: 12, textAlign: "center", padding: 20 }}>
                No paths match filters
              </div>
            ) : (
              displayedPaths.map((path, i) => (
                <AttackPathCard
                  key={i}
                  path={path}
                  isSelected={selectedPath === path}
                  onClick={() => {
                    const newPath = selectedPath === path ? null : path;
                    setSelectedPath(newPath);
                    if (newPath && graphRef.current) {
                      const resources = newPath.affected_resources || [];
                      const fitTo = () => {
                        const nodes = data?.graph?.nodes || [];
                        const resolved = resources.map((r) => {
                          if (nodes.some((n) => n.id === r)) return r;
                          const resName = r.includes("/") ? r.split("/").pop() : r.split(":").pop();
                          const match = nodes.find((n) => n.label === resName || n.id.endsWith(":" + resName));
                          return match ? match.id : null;
                        }).filter(Boolean);
                        if (resolved.length) graphRef.current.fitNodes(resolved);
                      };
                      if (tab !== "graph") {
                        setTab("graph");
                        setTimeout(fitTo, 100);
                      } else {
                        setTimeout(fitTo, 50);
                      }
                    }
                  }}
                />
              ))
            )}
          </div>
        </div>

        {/* Center: Graph / Detail toggle */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, minHeight: isNarrow ? 520 : 0 }}>
          <div style={{ display: "flex", gap: 4, marginBottom: 12, alignItems: "center" }}>
            {["graph", "detail", ...(isExploit ? [] : ["public"])].map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                style={{
                  padding: "6px 18px", borderRadius: 6, border: `1px solid ${tab === t ? COLORS.accent : COLORS.border}`,
                  background: tab === t ? COLORS.accent + "18" : "transparent",
                  color: tab === t ? COLORS.accent : COLORS.textDim,
                  cursor: "pointer", fontSize: 12, fontWeight: 600, textTransform: "uppercase",
                }}
              >
                {t === "graph" ? "Attack Graph" : t === "detail" ? "Path Detail" : "Public Exposure"}
              </button>
            ))}
            {/* Amber warning badge — only shown for partial or failed runs */}
            {isIncomplete && (
              <span style={{ color: "#f59e0b", fontWeight: 600, fontSize: 11, marginLeft: 8 }}>
                {runStatus.toUpperCase()}
              </span>
            )}
          </div>
          <div style={{
            flex: 1, background: COLORS.bgCard, borderRadius: 8,
            border: `1px solid ${isIncomplete ? "#f59e0b40" : COLORS.border}`, position: "relative", overflow: "hidden",
          }}>
            {tab === "graph" ? (
              <>
                {/* Attack graph unavailable state for partial/failed runs with no graph data */}
                {isIncomplete && (!data?.graph?.nodes?.length) ? (
                  <div style={{
                    display: "flex", alignItems: "center", justifyContent: "center",
                    height: "100%", opacity: 0.6,
                  }}>
                    <div style={{ textAlign: "center", color: COLORS.textDim, fontSize: 13 }}>
                      <div style={{ fontSize: 24, marginBottom: 8 }}>{"\u26A0"}</div>
                      Attack graph unavailable — run was incomplete
                    </div>
                  </div>
                ) : (
                  <>
                    <AttackGraph
                      ref={graphRef}
                      data={data}
                      paths={displayedPaths}
                      selectedPath={selectedPath}
                      onNodeClick={setSelectedNode}
                      onDeselect={handleDeselect}
                    />
                    <GraphLegend />
                    {/* Reset View button (DASH-03) */}
                    <button
                      onClick={() => { graphRef.current?.resetView(); setSelectedPath(null); setSelectedNode(null); }}
                      style={{
                        position: "absolute", top: 12, right: 12, zIndex: 10,
                        background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
                        color: COLORS.textDim, borderRadius: 6, padding: "4px 10px",
                        fontSize: 11, cursor: "pointer",
                      }}
                    >
                      Reset View
                    </button>
                    {selectedNode && (
                      <NodeDetailPanel
                        node={selectedNode}
                        data={data}
                        graphPaths={displayedPaths}
                        selectedPath={selectedPath}
                        onSelectPath={(p) => { setSelectedPath(p); setTab("detail"); }}
                        onClose={() => setSelectedNode(null)}
                      />
                    )}
                  </>
                )}
              </>
            ) : tab === "detail" ? (
              selectedPath ? <PathDetail path={selectedPath} controlsData={controlsData} /> : <div style={{
                display: "flex", alignItems: "center", justifyContent: "center",
                height: "100%", color: COLORS.textDim, fontSize: 13, opacity: 0.6,
              }}>Select an attack path to view details</div>
            ) : (
              <PublicExposureFindingsSection
                findings={data.public_exposure_findings || []}
                isNarrow={isNarrow}
                embedded
              />
            )}
          </div>
        </div>
      </div>

      {activeStatPanel && (
        <StatDetailPanel
          statKey={activeStatPanel}
          data={data}
          onClose={() => handleStatClick(null)}
          onSelectPath={(p) => { setSelectedPath(p); setTab("detail"); handleStatClick(null); }}
          onHighlightNode={(id) => {
            const node = data?.graph?.nodes?.find((n) => n.id === id);
            if (node) { setSelectedNode(node); setTab("graph"); handleStatClick(null); }
          }}
        />
      )}
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════
// ─── ControlsView ───
// ═══════════════════════════════════════════════════════════════════

function formatJSON(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

function severityColorFor(severity = "medium") {
  const key = String(severity).toLowerCase();
  return {
    critical: COLORS.critical,
    high: COLORS.high,
    medium: COLORS.medium,
    low: COLORS.low,
    info: COLORS.textDim,
  }[key] || COLORS.medium;
}

function renderInlineMarkdown(text = "") {
  const parts = String(text).split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter((part) => part !== "");
  return parts.map((part, index) => {
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code key={index} style={{
          color: "#bfdbfe",
          background: "#0d1117",
          border: `1px solid ${COLORS.border}`,
          borderRadius: 4,
          padding: "1px 4px",
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: "0.92em",
        }}>{part.slice(1, -1)}</code>
      );
    }
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={index} style={{ color: COLORS.text, fontWeight: 700 }}>{part.slice(2, -2)}</strong>;
    }
    return <span key={index}>{part}</span>;
  });
}

function splitMarkdownTableLine(line) {
  return line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim());
}

function isMarkdownTableSeparator(line) {
  return /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(line);
}

function parseMarkdownRows(markdown) {
  const lines = String(markdown || "").split("\n");
  const rows = [];
  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    const trimmed = line.trim();

    if (line.includes("|") && lines[index + 1] && isMarkdownTableSeparator(lines[index + 1])) {
      const headers = splitMarkdownTableLine(line);
      const body = [];
      index += 2;
      while (index < lines.length && lines[index].includes("|")) {
        body.push(splitMarkdownTableLine(lines[index]));
        index += 1;
      }
      rows.push({ type: "table", headers, body });
      continue;
    }

    if (trimmed.startsWith("- ")) {
      const items = [];
      while (index < lines.length && lines[index].trim().startsWith("- ")) {
        items.push(lines[index].trim().slice(2));
        index += 1;
      }
      rows.push({ type: "list", items });
      continue;
    }

    if (!trimmed) rows.push({ type: "space" });
    else if (trimmed === "---") rows.push({ type: "hr" });
    else if (line.startsWith("# ")) rows.push({ type: "h2", text: line.slice(2) });
    else if (line.startsWith("## ")) rows.push({ type: "h3", text: line.slice(3) });
    else if (line.startsWith("### ")) rows.push({ type: "h4", text: line.slice(4) });
    else rows.push({ type: "p", text: line });
    index += 1;
  }
  return rows;
}

function MarkdownTable({ row }) {
  return (
    <div style={{ overflowX: "auto", margin: "10px 0 14px" }}>
      <table style={{
        width: "100%",
        borderCollapse: "collapse",
        fontSize: 12,
        color: COLORS.textDim,
      }}>
        <thead>
          <tr>
            {row.headers.map((header, index) => (
              <th key={index} style={{
                textAlign: "left",
                color: COLORS.text,
                borderBottom: `1px solid ${COLORS.border}`,
                padding: "7px 8px",
                background: "#0d1117",
              }}>{renderInlineMarkdown(header)}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {row.body.map((cells, rowIndex) => (
            <tr key={rowIndex}>
              {row.headers.map((_, cellIndex) => (
                <td key={cellIndex} style={{
                  borderBottom: `1px solid ${COLORS.border}`,
                  padding: "7px 8px",
                  verticalAlign: "top",
                  lineHeight: 1.45,
                  wordBreak: "break-word",
                }}>{renderInlineMarkdown(cells[cellIndex] || "")}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function MarkdownBlock({ markdown }) {
  if (!markdown) return null;
  const rows = parseMarkdownRows(markdown);
  return (
    <div style={{
      background: COLORS.bgCard,
      border: `1px solid ${COLORS.border}`,
      borderRadius: 8,
      padding: 16,
      maxHeight: 520,
      overflow: "auto",
    }}>
      {rows.map((row, index) => {
        if (row.type === "h2") return <h2 key={index} style={{ color: COLORS.text, fontSize: 18, margin: "18px 0 10px" }}>{renderInlineMarkdown(row.text)}</h2>;
        if (row.type === "h3") return <h3 key={index} style={{ color: COLORS.text, fontSize: 15, margin: "16px 0 8px" }}>{renderInlineMarkdown(row.text)}</h3>;
        if (row.type === "h4") return <h4 key={index} style={{ color: COLORS.text, fontSize: 13, margin: "14px 0 6px" }}>{renderInlineMarkdown(row.text)}</h4>;
        if (row.type === "list") {
          return (
            <ul key={index} style={{ margin: "6px 0 10px 18px", padding: 0 }}>
              {row.items.map((item, itemIndex) => (
                <li key={itemIndex} style={{ color: COLORS.textDim, fontSize: 12, lineHeight: 1.55, marginBottom: 4, wordBreak: "break-word" }}>
                  {renderInlineMarkdown(item)}
                </li>
              ))}
            </ul>
          );
        }
        if (row.type === "table") return <MarkdownTable key={index} row={row} />;
        if (row.type === "hr") return <hr key={index} style={{ border: "none", borderTop: `1px solid ${COLORS.border}`, margin: "14px 0" }} />;
        if (row.type === "space") return <div key={index} style={{ height: 8 }} />;
        return <p key={index} style={{ color: COLORS.textDim, fontSize: 12, lineHeight: 1.55, margin: "4px 0", wordBreak: "break-word" }}>{renderInlineMarkdown(row.text)}</p>;
      })}
    </div>
  );
}

function SplBlock({ spl }) {
  const lines = formatSplForDisplay(spl);
  return (
    <div style={{ display: "flex", alignItems: "flex-start", gap: 4 }}>
      <pre style={{
        flex: 1,
        background: "rgba(6,182,212,0.08)",
        border: `1px solid rgba(6,182,212,0.2)`,
        borderRadius: 6,
        padding: "10px 12px",
        fontSize: 11,
        color: "#67e8f9",
        fontFamily: "'JetBrains Mono', monospace",
        margin: 0,
        whiteSpace: "pre-wrap",
        overflow: "auto",
        maxHeight: 240,
        lineHeight: 1.55,
        wordBreak: "break-word",
      }}>{lines.join("\n")}</pre>
      <CopyButton text={spl} />
    </div>
  );
}

function DetectionMetadata({ rule }) {
  const blocks = [
    ["Objective", rule.objective],
    ["Fidelity", rule.fidelity_rationale],
    ["Tuning", rule.tuning_guidance],
    ["Expected Volume", rule.expected_volume],
    ["Validation", rule.validation_status],
  ].filter(([, value]) => value);
  const listBlocks = [
    ["Noise Controls", rule.noise_controls],
    ["Coverage Caveats", rule.coverage_caveats],
    ["Covered Hops", rule.covered_hops],
    ["Source Attack Paths", rule.source_attack_paths],
    ["Source Public Exposure Findings", rule.source_public_exposure_findings],
  ].filter(([, value]) => Array.isArray(value) && value.length > 0);

  if (blocks.length === 0 && listBlocks.length === 0) return null;

  return (
    <div style={{
      marginTop: 10,
      display: "grid",
      gap: 8,
      fontSize: 12,
      lineHeight: 1.5,
    }}>
      {blocks.map(([label, value]) => (
        <div key={label} style={{ background: "#0d1117", border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: "8px 10px" }}>
          <div style={{ color: COLORS.textDim, fontSize: 10, fontWeight: 700, textTransform: "uppercase", marginBottom: 3 }}>{label}</div>
          <div style={{ color: COLORS.text, wordBreak: "break-word" }}>{value}</div>
        </div>
      ))}
      {listBlocks.map(([label, values]) => (
        <div key={label} style={{ background: "#0d1117", border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: "8px 10px" }}>
          <div style={{ color: COLORS.textDim, fontSize: 10, fontWeight: 700, textTransform: "uppercase", marginBottom: 5 }}>{label}</div>
          <ul style={{ margin: "0 0 0 16px", padding: 0 }}>
            {values.map((value, index) => (
              <li key={index} style={{ color: COLORS.text, marginBottom: 3, wordBreak: "break-word" }}>{value}</li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

function OrgWideIssuesList({ issues }) {
  const [expandedIdx, setExpandedIdx] = useState(null);

  if (!issues?.length) {
    return <div style={{ color: COLORS.textDim, fontSize: 13, padding: 20 }}>No org-wide issues identified.</div>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {issues.map((issue, i) => {
        const isExpanded = expandedIdx === i;
        const severityColor = severityColorFor(issue.severity || "medium");

        return (
          <div key={i} style={{
            background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
            borderRadius: 8, overflow: "hidden",
          }}>
            <div
              onClick={() => setExpandedIdx(isExpanded ? null : i)}
              style={{
                padding: "12px 16px", cursor: "pointer", display: "flex",
                justifyContent: "space-between", alignItems: "center",
                gap: 12, minWidth: 0,
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, minWidth: 0 }}>
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4,
                  background: severityColor + "18",
                  color: severityColor,
                }}>{issue.severity || "medium"}</span>
                <span style={{ fontSize: 14, fontWeight: 600, color: COLORS.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0 }} title={issue.name}>{issue.name}</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                <span style={{
                  fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 4,
                  color: COLORS.accent, background: COLORS.accent + "18",
                  textTransform: "uppercase",
                }}>
                  {issue.scope || "unknown"}
                </span>
                <span style={{ color: COLORS.textDim, fontSize: 12 }}>{isExpanded ? "\u25B2" : "\u25BC"}</span>
              </div>
            </div>

            {isExpanded && (
              <div style={{ padding: "0 16px 16px", borderTop: `1px solid ${COLORS.border}` }}>
                {issue.evidence?.length > 0 && (
                  <div style={{ marginTop: 12, marginBottom: 12 }}>
                    <div style={{ fontSize: 10, color: COLORS.textDim, textTransform: "uppercase", marginBottom: 6 }}>Evidence</div>
                    {issue.evidence.map((item, j) => (
                      <div key={j} style={{ fontSize: 12, color: COLORS.text, marginBottom: 4 }}>{item}</div>
                    ))}
                  </div>
                )}

                {issue.source_attack_paths?.length > 0 && (
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontSize: 10, color: COLORS.textDim, textTransform: "uppercase", marginBottom: 4 }}>Source Attack Paths</div>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                      {issue.source_attack_paths.map((p, j) => (
                        <span key={j} style={{
                          fontSize: 10, color: COLORS.critical, background: COLORS.criticalBg,
                          padding: "2px 8px", borderRadius: 4,
                        }}>{p}</span>
                      ))}
                    </div>
                  </div>
                )}

                {issue.source_public_exposure_findings?.length > 0 && (
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontSize: 10, color: COLORS.textDim, textTransform: "uppercase", marginBottom: 4 }}>Source Public Exposure Findings</div>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                      {issue.source_public_exposure_findings.map((findingId, j) => (
                        <span key={j} style={{
                          fontSize: 10, color: COLORS.high, background: COLORS.highBg,
                          padding: "2px 8px", borderRadius: 4,
                        }}>{findingId}</span>
                      ))}
                    </div>
                  </div>
                )}

                {(issue.widespread_rationale || issue.recommended_next_step) && (
                  <div style={{ marginTop: 8, padding: 12, background: "#0d1117", border: `1px solid ${COLORS.border}`, borderRadius: 6, fontSize: 12, color: COLORS.textDim }}>
                    {issue.widespread_rationale && <div style={{ marginBottom: 8 }}><span style={{ color: COLORS.text }}>Rationale: </span>{issue.widespread_rationale}</div>}
                    {issue.recommended_next_step && <div><span style={{ color: COLORS.text }}>Next step: </span>{issue.recommended_next_step}</div>}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function DetectionRulesList({ detections }) {
  if (!detections?.length) {
    return <div style={{ color: COLORS.textDim, fontSize: 13, padding: 20 }}>No detections generated.</div>;
  }

  const grouped = {};
  detections.forEach((d) => {
    const cat = d.category || "uncategorized";
    if (!grouped[cat]) grouped[cat] = [];
    grouped[cat].push(d);
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {Object.entries(grouped).map(([cat, rules]) => {
        const catCfg = CATEGORY_CONFIG[cat];
        return (
          <div key={cat}>
            <div style={{
              fontSize: 11, fontWeight: 700, color: catCfg?.color || COLORS.textDim,
              textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 8,
              display: "flex", alignItems: "center", gap: 6,
            }}>
              {catCfg && <span style={{
                width: 8, height: 8, borderRadius: "50%", background: catCfg.color, display: "inline-block",
              }} />}
              {catCfg?.label || cat}
            </div>
            {rules.map((rule, i) => {
              const sevCfg = SEVERITY_CONFIG[rule.severity] || SEVERITY_CONFIG.medium;
              const detType = rule.type || (/^\[COMPOSITE\]/i.test(rule.name) ? "composite" : /^\[ATOMIC\]/i.test(rule.name) ? "atomic" : null);
              const displayName = rule.name?.replace(/^\[(ATOMIC|COMPOSITE)\]\s*/i, "") || rule.name;
              return (
                <div key={i} style={{
                  background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
                  borderRadius: 8, padding: 14, marginBottom: 8,
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 10, marginBottom: 8, minWidth: 0 }}>
                    <span style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }} title={rule.name}>{displayName}</span>
                    <div style={{ display: "flex", gap: 6, alignItems: "center", justifyContent: "flex-end", flexWrap: "wrap", flexShrink: 0, maxWidth: "45%" }}>
                      {detType && <span style={{
                        fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 8,
                        color: detType === "composite" ? "#c084fc" : "#67e8f9",
                        background: detType === "composite" ? "rgba(192,132,252,0.15)" : "rgba(103,232,249,0.15)",
                        textTransform: "uppercase",
                      }}>{detType}</span>}
                      <span style={{
                        fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 8,
                        color: sevCfg.color, background: sevCfg.bg, textTransform: "uppercase",
                      }}>{rule.severity}</span>
                      {rule.mitre_technique && (
                        <a href={`https://attack.mitre.org/techniques/${rule.mitre_technique.replace(".", "/")}/`}
                          target="_blank" rel="noreferrer"
                          style={{
                            fontSize: 10, fontFamily: "monospace", color: "#a78bfa",
                            background: "rgba(139,92,246,0.15)", padding: "2px 8px", borderRadius: 4,
                            textDecoration: "none",
                          }}>{rule.mitre_technique}</a>
                      )}
                    </div>
                  </div>
                  {rule.spl ? (
                    <SplBlock spl={rule.spl} />
                  ) : (
                    <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
                      {rule.paths_covered != null && (
                        <span style={{ fontSize: 11, color: COLORS.textDim }}>
                          Paths covered: <span style={{ color: COLORS.text, fontWeight: 600 }}>{rule.paths_covered}</span>
                        </span>
                      )}
                      <span style={{ fontSize: 11, color: COLORS.textMuted, fontStyle: "italic" }}>
                        SPL query not embedded.
                      </span>
                    </div>
                  )}
                  <DetectionMetadata rule={rule} />
                </div>
              );
            })}
          </div>
        );
      })}
    </div>
  );
}

function MonitoringIdeasList({ ideas }) {
  if (!ideas?.length) {
    return <div style={{ color: COLORS.textDim, fontSize: 13, padding: 20 }}>No monitoring dashboard ideas generated.</div>;
  }

  const asList = (value) => Array.isArray(value) ? value : [];
  const ideaTypeLabel = (type = "monitoring_dashboard") => String(type).replace(/_/g, " ");

  const renderChips = (values, color = COLORS.textDim) => (
    <div style={{ display: "flex", gap: 4, flexWrap: "wrap", minWidth: 0 }}>
      {values.map((value, index) => (
        <span key={index} style={{
          fontSize: 10,
          color,
          background: color + "18",
          borderRadius: 4,
          padding: "2px 8px",
          wordBreak: "break-word",
        }}>{value}</span>
      ))}
    </div>
  );

  const renderTextBlock = (label, value) => value ? (
    <div style={{ background: "#0d1117", border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: "8px 10px" }}>
      <div style={{ color: COLORS.textDim, fontSize: 10, fontWeight: 700, textTransform: "uppercase", marginBottom: 3 }}>{label}</div>
      <div style={{ color: COLORS.text, fontSize: 12, lineHeight: 1.5, wordBreak: "break-word" }}>{value}</div>
    </div>
  ) : null;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {ideas.map((idea, i) => {
        const sevCfg = SEVERITY_CONFIG[idea.severity] || SEVERITY_CONFIG.medium;
        const requiredSources = asList(idea.required_data_sources);
        const promotionTriggers = asList(idea.promotion_triggers);
        const sourceExposureFindings = asList(idea.source_public_exposure_findings);
        const panels = asList(idea.suggested_panels);

        return (
          <div key={i} style={{
            background: COLORS.bgCard,
            border: `1px solid ${COLORS.border}`,
            borderRadius: 8,
            padding: 14,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, marginBottom: 10 }}>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={idea.name}>
                  {idea.name || "Unnamed monitoring idea"}
                </div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 6 }}>
                  <span style={{
                    fontSize: 10,
                    fontWeight: 700,
                    padding: "2px 8px",
                    borderRadius: 8,
                    color: COLORS.accent,
                    background: COLORS.accent + "18",
                    textTransform: "uppercase",
                  }}>{ideaTypeLabel(idea.type)}</span>
                  <span style={{
                    fontSize: 10,
                    fontWeight: 700,
                    padding: "2px 8px",
                    borderRadius: 8,
                    color: sevCfg.color,
                    background: sevCfg.bg,
                    textTransform: "uppercase",
                  }}>{idea.severity || "medium"}</span>
                </div>
              </div>
              {(idea.refresh_cadence || idea.owner) && (
                <div style={{ display: "grid", gap: 4, justifyItems: "end", flexShrink: 0 }}>
                  {idea.refresh_cadence && <span style={{ fontSize: 10, color: COLORS.medium, background: COLORS.mediumBg, borderRadius: 4, padding: "2px 8px", textTransform: "uppercase" }}>{idea.refresh_cadence}</span>}
                  {idea.owner && <span style={{ fontSize: 10, color: COLORS.textDim, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={idea.owner}>{idea.owner}</span>}
                </div>
              )}
            </div>

            <div style={{ display: "grid", gap: 8 }}>
              {renderTextBlock("Objective", idea.objective)}
              {renderTextBlock("Why Dashboard Not Detection", idea.why_dashboard_not_detection)}

              {requiredSources.length > 0 && (
                <div style={{ background: "#0d1117", border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: "8px 10px" }}>
                  <div style={{ color: COLORS.textDim, fontSize: 10, fontWeight: 700, textTransform: "uppercase", marginBottom: 5 }}>Required Data Sources</div>
                  {renderChips(requiredSources, COLORS.detection)}
                </div>
              )}

              {sourceExposureFindings.length > 0 && (
                <div style={{ background: "#0d1117", border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: "8px 10px" }}>
                  <div style={{ color: COLORS.textDim, fontSize: 10, fontWeight: 700, textTransform: "uppercase", marginBottom: 5 }}>Source Public Exposure Findings</div>
                  {renderChips(sourceExposureFindings, COLORS.high)}
                </div>
              )}

              {panels.length > 0 && (
                <div style={{ background: "#0d1117", border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: "8px 10px" }}>
                  <div style={{ color: COLORS.textDim, fontSize: 10, fontWeight: 700, textTransform: "uppercase", marginBottom: 8 }}>Suggested Panels</div>
                  <div style={{ display: "grid", gap: 8 }}>
                    {panels.map((panel, panelIndex) => (
                      <div key={panelIndex} style={{ border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: "8px 10px", minWidth: 0 }}>
                        <div style={{ display: "flex", gap: 8, alignItems: "baseline", justifyContent: "space-between", marginBottom: 6 }}>
                          <div style={{ color: COLORS.text, fontSize: 12, fontWeight: 600, wordBreak: "break-word", minWidth: 0 }}>{panel.title || "Untitled panel"}</div>
                          {panel.visualization && <span style={{ color: COLORS.textDim, fontSize: 10, textTransform: "uppercase", flexShrink: 0 }}>{panel.visualization}</span>}
                        </div>
                        {panel.question && <div style={{ color: COLORS.textDim, fontSize: 12, lineHeight: 1.45, marginBottom: 6, wordBreak: "break-word" }}>{panel.question}</div>}
                        {asList(panel.fields).length > 0 && renderChips(asList(panel.fields), COLORS.low)}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {promotionTriggers.length > 0 && (
                <div style={{ background: "#0d1117", border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: "8px 10px" }}>
                  <div style={{ color: COLORS.textDim, fontSize: 10, fontWeight: 700, textTransform: "uppercase", marginBottom: 5 }}>Promotion Triggers</div>
                  <ul style={{ margin: "0 0 0 16px", padding: 0 }}>
                    {promotionTriggers.map((trigger, index) => (
                      <li key={index} style={{ color: COLORS.text, fontSize: 12, lineHeight: 1.5, marginBottom: 3, wordBreak: "break-word" }}>{trigger}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function PolicyReplacementsList({ replacements }) {
  if (!replacements?.length) {
    return <div style={{ color: COLORS.textDim, fontSize: 13, padding: 20 }}>No policy replacements generated.</div>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {replacements.map((policy, i) => (
        <div key={i} style={{
          background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
          borderRadius: 8, padding: 14,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, marginBottom: 10 }}>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={policy.role_name}>
                {policy.role_name || "Unknown role"}
              </div>
              {policy.original_policy_arn && (
                <div style={{ fontSize: 10, color: COLORS.textDim, fontFamily: "monospace", wordBreak: "break-word", marginTop: 4 }}>
                  {policy.original_policy_arn}
                </div>
              )}
            </div>
            {policy.file && (
              <span style={{
                fontSize: 10, color: COLORS.accent, background: COLORS.accent + "18",
                borderRadius: 4, padding: "2px 8px", fontFamily: "monospace",
                maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flexShrink: 0,
              }} title={policy.file}>{policy.file}</span>
            )}
          </div>

          {policy.staleness_reasoning && (
            <div style={{ fontSize: 12, color: COLORS.textDim, lineHeight: 1.5, marginBottom: 8 }}>
              <span style={{ color: COLORS.text }}>Reasoning: </span>{policy.staleness_reasoning}
            </div>
          )}
          {policy.boundary_considerations && (
            <div style={{ fontSize: 12, color: COLORS.textDim, lineHeight: 1.5, marginBottom: 8 }}>
              <span style={{ color: COLORS.text }}>Boundary considerations: </span>{policy.boundary_considerations}
            </div>
          )}
          {policy.source_attack_paths?.length > 0 && (
            <div style={{ display: "flex", gap: 4, marginTop: 8, flexWrap: "wrap" }}>
              {policy.source_attack_paths.map((p, j) => (
                <span key={j} style={{
                  fontSize: 9, color: COLORS.critical, background: COLORS.criticalBg,
                  padding: "1px 6px", borderRadius: 4,
                }}>{p}</span>
              ))}
            </div>
          )}
          {policy.replacement_policy_json && (
            <div style={{ display: "flex", alignItems: "flex-start", gap: 4, marginTop: 10 }}>
              <pre style={{
                flex: 1, background: "#0d1117", border: `1px solid ${COLORS.border}`,
                borderRadius: 6, padding: "8px 12px", fontSize: 11,
                color: COLORS.text, fontFamily: "monospace", margin: 0,
                whiteSpace: "pre-wrap", overflow: "auto", maxHeight: 220,
              }}>{formatJSON(policy.replacement_policy_json)}</pre>
              <CopyButton text={formatJSON(policy.replacement_policy_json)} />
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function ControlsMatrix({ controls }) {
  if (!controls?.length) {
    return <div style={{ color: COLORS.textDim, fontSize: 13, padding: 20 }}>No security controls recommended.</div>;
  }

  const priorityColor = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low };
  const effortColor = { low: COLORS.low, medium: COLORS.high, high: COLORS.critical };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 10 }}>
      {controls.map((ctrl, i) => (
        <div key={i} style={{
          background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
          borderRadius: 8, padding: 14,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{
              fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4,
              background: COLORS.mediumBg, color: COLORS.medium,
            }}>{ctrl.service}</span>
            <div style={{ display: "flex", gap: 4 }}>
              {ctrl.priority && (
                <span style={{
                  fontSize: 9, fontWeight: 700, padding: "1px 6px", borderRadius: 4,
                  color: priorityColor[ctrl.priority] || COLORS.textDim,
                  background: (priorityColor[ctrl.priority] || COLORS.textDim) + "18",
                  textTransform: "uppercase",
                }}>{ctrl.priority}</span>
              )}
              {ctrl.effort && (
                <span style={{
                  fontSize: 9, fontWeight: 700, padding: "1px 6px", borderRadius: 4,
                  color: effortColor[ctrl.effort] || COLORS.textDim,
                  background: (effortColor[ctrl.effort] || COLORS.textDim) + "18",
                  textTransform: "uppercase",
                }}>{ctrl.effort} effort</span>
              )}
            </div>
          </div>
          <div style={{ fontSize: 13, color: COLORS.text, lineHeight: 1.5 }}>{ctrl.recommendation}</div>
          {ctrl.source_attack_paths?.length > 0 && (
            <div style={{ display: "flex", gap: 4, marginTop: 8, flexWrap: "wrap" }}>
              {ctrl.source_attack_paths.map((p, j) => (
                <span key={j} style={{
                  fontSize: 9, color: COLORS.textDim, background: COLORS.bgCardHover,
                  padding: "1px 6px", borderRadius: 4,
                }}>{p}</span>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function PrioritizationSidebar({ items, onScrollTo }) {
  if (!items?.length) return null;

  const catColors = {
    policy: COLORS.high,
    policy_replacement: COLORS.high,
    detection: COLORS.detection,
    remediation: COLORS.low,
    control: COLORS.low,
    org_wide: COLORS.accent,
  };
  const riskColors = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low };
  const effortColors = { low: COLORS.low, medium: COLORS.high, high: COLORS.critical };
  const displayCategory = (category) => catColors[category] ? category : "remediation";

  return (
    <div style={{ width: 320, minWidth: 280, overflowY: "auto" }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 12 }}>
        Prioritization
      </div>
      {items.map((item, i) => (
        <div key={i}
          onClick={() => onScrollTo?.(item)}
          style={{
            background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
            borderRadius: 8, padding: 12, marginBottom: 8, cursor: "pointer",
            transition: "border-color 0.2s",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <span style={{
              fontSize: 16, fontWeight: 700, color: COLORS.textDim, fontFamily: "monospace",
              minWidth: 24,
            }}>#{item.rank}</span>
            <span style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={item.action}>{item.action}</span>
          </div>
          <div style={{ display: "flex", gap: 4, paddingLeft: 32 }}>
            <span style={{
              fontSize: 9, fontWeight: 700, padding: "1px 6px", borderRadius: 4,
              color: riskColors[item.risk] || COLORS.textDim,
              background: (riskColors[item.risk] || COLORS.textDim) + "18",
              textTransform: "uppercase",
            }}>{item.risk} risk</span>
            <span style={{
              fontSize: 9, fontWeight: 700, padding: "1px 6px", borderRadius: 4,
              color: effortColors[item.effort] || COLORS.textDim,
              background: (effortColors[item.effort] || COLORS.textDim) + "18",
              textTransform: "uppercase",
            }}>{item.effort} effort</span>
            <span style={{
              fontSize: 9, fontWeight: 700, padding: "1px 6px", borderRadius: 4,
              color: catColors[displayCategory(item.category)] || COLORS.textDim,
              background: (catColors[displayCategory(item.category)] || COLORS.textDim) + "18",
              textTransform: "uppercase",
            }}>{displayCategory(item.category)}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function ControlsView({ data, isNarrow }) {
  const [controlsTab, setControlsTab] = useState("org-wide");
  const summary = data?.summary || {};

  return (
    <>
      {/* Stats Row — cards switch to the corresponding tab */}
      <div style={{ display: "flex", gap: 12, padding: isNarrow ? "12px" : "16px 24px", flexWrap: "wrap" }}>
        <StatCard label="Org-Wide" value={summary.org_wide_issues ?? data.org_wide_issues?.length ?? 0} color={COLORS.high} onClick={() => setControlsTab("org-wide")} active={controlsTab === "org-wide"} />
        <StatCard label="Detections" value={summary.detections_generated ?? data.detections?.length ?? 0} color={COLORS.detection} onClick={() => setControlsTab("detections")} active={controlsTab === "detections"} />
        <StatCard label="Monitoring" value={summary.dashboards ?? data.dashboards?.length ?? 0} color={COLORS.accent} onClick={() => setControlsTab("dashboards")} active={controlsTab === "dashboards"} />
        <StatCard label="Policies" value={summary.policy_replacements ?? data.policy_replacements?.length ?? 0} color={COLORS.medium} onClick={() => setControlsTab("policies")} active={controlsTab === "policies"} />
        <StatCard label="Remediation" value={summary.remediation_items ?? summary.controls_recommended ?? 0} color={COLORS.low} onClick={() => setControlsTab("remediation")} active={controlsTab === "remediation"} />
      </div>

      {/* Main Content: Sidebar + Tabbed Center */}
      <div style={{
        flex: 1,
        display: "flex",
        flexDirection: isNarrow ? "column" : "row",
        padding: isNarrow ? "0 12px 12px" : "0 24px 24px",
        gap: isNarrow ? 12 : 16,
        minHeight: 0,
        overflow: isNarrow ? "auto" : "hidden",
      }}>
        {/* Prioritization Sidebar — uses legacy prioritization[] array when present */}
        <PrioritizationSidebar items={data.prioritization} />

        {/* Center: Tabbed content */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          <div style={{ display: "flex", gap: 4, marginBottom: 12, flexWrap: "wrap" }}>
            {[
              { key: "org-wide", label: "Org-Wide" },
              { key: "detections", label: "Detections" },
              { key: "dashboards", label: "Monitoring Ideas" },
              { key: "policies", label: "Policies" },
              { key: "remediation", label: "Remediation" },
            ].map((t) => (
              <button
                key={t.key}
                onClick={() => setControlsTab(t.key)}
                style={{
                  padding: "6px 14px", borderRadius: 6,
                  border: `1px solid ${controlsTab === t.key ? PHASE_CONFIG.controls.color : COLORS.border}`,
                  background: controlsTab === t.key ? PHASE_CONFIG.controls.color + "18" : "transparent",
                  color: controlsTab === t.key ? PHASE_CONFIG.controls.color : COLORS.textDim,
                  cursor: "pointer", fontSize: 12, fontWeight: 600, textTransform: "uppercase",
                }}
              >
                {t.label}
              </button>
            ))}
          </div>
          <div style={{ flex: 1, overflowY: "auto" }}>
            {controlsTab === "org-wide" && <OrgWideIssuesList issues={data.org_wide_issues} />}
            {controlsTab === "detections" && <DetectionRulesList detections={data.detections} />}
            {controlsTab === "dashboards" && <MonitoringIdeasList ideas={data.dashboards} />}
            {controlsTab === "policies" && <PolicyReplacementsList replacements={data.policy_replacements} />}
            {controlsTab === "remediation" && (
              data.prioritization?.length
                ? <ControlsMatrix controls={data.prioritization} />
                : data.remediationPlanFile
                  ? <div style={{ padding: 20, color: "#c8d0e0" }}>
                      <div style={{ fontWeight: 600, marginBottom: 8 }}>Remediation Plan</div>
                      <div style={{ fontSize: 13, marginBottom: 4 }}>
                        <span style={{ color: "#8899aa" }}>Items: </span>{data.remediationItemCount ?? 0}
                      </div>
                      {data.remediationPlanMarkdown
                        ? <MarkdownBlock markdown={data.remediationPlanMarkdown} />
                        : <div style={{ fontSize: 12, color: "#8899aa", wordBreak: "break-word" }}>{data.remediationPlanFile}</div>}
                    </div>
                  : <div style={{ color: "#8899aa", fontSize: 13, padding: 20 }}>No remediation plan available.</div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════
// ─── Main Dashboard ───
// ═══════════════════════════════════════════════════════════════════
export default function App() {
  const isNarrow = useIsNarrowViewport();
  const [allData, setAllData] = useState({});  // { audit: {...}, controls: {...}, exploit: {...} }
  const [selectedPath, setSelectedPath] = useState(null);
  const [tab, setTab] = useState("graph");
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activePhase, setActivePhase] = useState("audit");
  // Report index state loads from index.json in dev server mode.
  const [reportIndex, setReportIndex] = useState([]);
  const hasInlineData = Boolean(window.__SCOPE_INLINE_DATA__);

  // Interactive state
  const [searchQuery, setSearchQuery] = useState("");
  const [sortMode, setSortMode] = useState("severity");
  const [activeStatPanel, setActiveStatPanel] = useState(null);

  const handleDataLoad = useCallback((json) => {
    const { data: normalized, source } = normalizeForDashboard(json);
    setAllData((prev) => ({ ...prev, [source]: normalized }));
    setActivePhase(source);
    setSelectedPath(null);
    setSelectedNode(null);
    setSearchQuery("");
    setActiveStatPanel(null);
  }, []);

  const loadReport = useCallback(async (report) => {
    if (!report) return;
    const loaded = {};
    const entries = [
      ["audit", report.audit],
      ["exploit", report.exploit],
      ["controls", report.controls],
    ].filter(([, entry]) => entry?.file);

    for (const [fallbackSource, entry] of entries) {
      const response = await fetch(entry.file);
      if (!response.ok) continue;
      const json = await response.json();
      json._run_status = report.status || "complete";
      json._dashboard_run_id = report.report_id;
      const { data: normalized, source } = normalizeForDashboard(json, fallbackSource);
      loaded[source] = normalized;
    }

    if (Object.keys(loaded).length === 0) return;
    setAllData(loaded);
    setActivePhase(loaded.audit ? "audit" : loaded.exploit ? "exploit" : Object.keys(loaded)[0]);
    setSelectedPath(null);
    setSelectedNode(null);
    setSearchQuery("");
    setActiveStatPanel(null);
  }, []);

  // DASH-01: Reset view state when switching between phases to prevent blank pages
  useEffect(() => {
    setTab("graph");
    setSelectedPath(null);
    setSelectedNode(null);
    setActiveStatPanel(null);
  }, [activePhase]);

  // Derive active data from allData + activePhase
  const data = useMemo(() => {
    if (allData[activePhase]) return allData[activePhase];
    // audit/exploit share a view — show whichever is available
    if (activePhase === "audit" && allData["exploit"]) return allData["exploit"];
    if (activePhase === "exploit" && allData["audit"]) return allData["audit"];
    return null;
  }, [allData, activePhase]);

  // Auto-switch to first available phase when data loads
  useEffect(() => {
    const sources = Object.keys(allData);
    if (sources.length > 0 && !allData[activePhase]) {
      // Don't auto-switch if audit/exploit share a view and either exists
      if ((activePhase === "audit" || activePhase === "exploit") && (allData["audit"] || allData["exploit"])) return;
      if (allData["audit"]) setActivePhase("audit");
      else if (allData["exploit"]) setActivePhase("exploit");
      else if (allData["controls"]) setActivePhase("controls");
    }
  }, [allData]); // eslint-disable-line react-hooks/exhaustive-deps

  // Load inline data — dashboard.html has all data embedded via window.__SCOPE_INLINE_DATA__
  useEffect(() => {
    if (window.__SCOPE_INLINE_DATA__) {
      const inline = window.__SCOPE_INLINE_DATA__;
      const loaded = {};
      for (const [src, json] of Object.entries(inline)) {
        const { data: normalized, source } = normalizeForDashboard(json, src);
        loaded[source] = normalized;
      }
      setAllData((prev) => ({ ...prev, ...loaded }));
    }
    // Try to load index.json for report selector and latest report in dev server mode.
    if (!hasInlineData) {
      fetch("index.json").then((r) => r.ok ? r.json() : null).then((idx) => {
        const reports = reportsFromIndex(idx);
        if (reports.length > 0) {
          setReportIndex(reports);
          loadReport(reports[0]).catch(() => {});
        }
      }).catch(() => { /* index.json not available */ });
    }
    setLoading(false);
  }, [loadReport]);

  const handleStatClick = useCallback((key) => {
    setActiveStatPanel((prev) => prev === key ? null : key);
  }, []);

  // Filter and sort attack paths
  const filteredPaths = useMemo(() => {
    if (!data?.attack_paths) return [];
    let paths = displayAttackPathItems(data);

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      paths = paths.filter((p) =>
        (p.name || "").toLowerCase().includes(q) ||
        (p.description || "").toLowerCase().includes(q) ||
        (p.mitre_techniques || []).some((t) => t.toLowerCase().includes(q))
      );
    }

    paths = [...paths];
    if (sortMode === "severity") {
      paths.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));
    } else if (sortMode === "steps") {
      paths.sort((a, b) => (a.steps?.length || 0) - (b.steps?.length || 0));
    } else if (sortMode === "name") {
      paths.sort((a, b) => (a.name || "").localeCompare(b.name || ""));
    }

    return paths;
  }, [data, searchQuery, sortMode]);

  // Empty state
  if (loading) return (
    <div style={{ fontFamily: "'IBM Plex Sans', -apple-system, sans-serif", background: COLORS.bg, color: COLORS.text, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ color: COLORS.textDim, fontSize: 14 }}>Loading...</div>
    </div>
  );

  if (Object.keys(allData).length === 0) return (
    <div style={{ fontFamily: "'IBM Plex Sans', -apple-system, sans-serif", background: COLORS.bg, color: COLORS.text, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ textAlign: "center", maxWidth: 480 }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>{"\uD83D\uDEE1"}</div>
        <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>SCOPE</h1>
        <p style={{ color: COLORS.textDim, fontSize: 14, lineHeight: 1.6, marginBottom: 24 }}>
          No results loaded. Run <span style={{ color: COLORS.accent, fontFamily: "monospace" }}>/scope:audit</span> to generate results, then refresh this page.
        </p>
        <FileUpload onDataLoad={handleDataLoad} />
      </div>
    </div>
  );

  // Get account info from any available data source (for header)
  const anyData = data || Object.values(allData)[0] || {};

  return (
    <div style={{
      fontFamily: "'IBM Plex Sans', -apple-system, sans-serif",
      background: COLORS.bg, color: COLORS.text, height: "100vh",
      display: "flex", flexDirection: "column", overflow: "hidden",
      minWidth: 0,
    }}>
      {/* Header */}
      <div style={{
        padding: isNarrow ? "10px 12px" : "12px 24px", borderBottom: `1px solid ${COLORS.border}`,
        display: "flex", justifyContent: "space-between", alignItems: isNarrow ? "flex-start" : "center",
        gap: 12, flexWrap: isNarrow ? "wrap" : "nowrap",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: 22 }}>{"\uD83D\uDEE1"}</span>
          <div>
            <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, letterSpacing: 0 }}>
              SCOPE
            </h1>
            <span style={{
              fontSize: 11,
              color: COLORS.textDim,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              maxWidth: isNarrow ? "calc(100vw - 88px)" : 400,
              display: "inline-block",
            }} title={`Account ${anyData.account_id} \u2022 ${anyData.region || "N/A"}`}>
              Account {anyData.account_id} {"\u2022"} {anyData.region || "N/A"}
              <LoadedPhaseSummary allData={allData} />
            </span>
          </div>
        </div>
        {!hasInlineData && <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <FileUpload onDataLoad={handleDataLoad} />
        </div>}
      </div>

      {/* Phase Tab Bar + Run Selector */}
      <div style={{
        display: "flex", gap: 0, padding: isNarrow ? "0 12px" : "0 24px",
        borderBottom: `1px solid ${COLORS.border}`,
        justifyContent: "space-between", alignItems: "center",
        overflowX: "auto",
      }}>
        <div style={{ display: "flex" }}>
          {Object.entries(PHASE_CONFIG).map(([key, cfg]) => {
            const isActive = activePhase === key;
            const hasData = !!allData[key] || ((key === "audit" || key === "exploit") && (allData["audit"] || allData["exploit"]));
            // Show amber dot in tab if the loaded run for this phase is partial/failed
            const phaseRunStatus = allData[key]?.runStatus || "complete";
            const isPartialOrFailed = phaseRunStatus === "partial" || phaseRunStatus === "failed";
            return (
              <button
                key={key}
                onClick={() => setActivePhase(key)}
                style={{
                  padding: isNarrow ? "10px 12px" : "10px 20px", cursor: "pointer",
                  fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em",
                  background: "transparent",
                  border: "none",
                  borderBottom: `2px solid ${isActive ? cfg.color : "transparent"}`,
                  color: isActive ? cfg.color : COLORS.textMuted,
                  transition: "all 0.15s",
                  display: "flex", alignItems: "center", gap: 6,
                }}
              >
                {cfg.label}
                {hasData && !isPartialOrFailed && <span style={{ width: 6, height: 6, borderRadius: "50%", background: cfg.color, opacity: isActive ? 1 : 0.5 }} />}
                {hasData && isPartialOrFailed && <span style={{ fontSize: 10, color: "#f59e0b", fontWeight: 700 }}>{"\u26A0"} {phaseRunStatus}</span>}
              </button>
            );
          })}
        </div>
        {/* Report selector dropdown. Controls attach to the selected audit report. */}
        {(() => {
          if (reportIndex.length === 0) return null;
          const currentId = data?.dashboard_run_id || reportIndex[0]?.report_id || "";
          return (
            <select
              value={currentId}
              onChange={(e) => {
                const report = reportIndex.find((item) => item.report_id === e.target.value);
                if (report) loadReport(report).catch(() => {});
              }}
              style={{
                background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
                color: COLORS.text, borderRadius: 6, fontSize: 11,
                padding: "4px 8px", cursor: "pointer", maxWidth: 260,
                marginRight: 0,
              }}
            >
              {reportIndex.map((report) => (
                <option key={report.report_id} value={report.report_id}>
                  {reportDisplayLabel(report)}
                </option>
              ))}
            </select>
          );
        })()}
      </div>

      {/* Phase Content */}
      {!data ? (
        <div style={{
          flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
          padding: "16px 24px",
        }}>
          <div style={{ textAlign: "center", color: COLORS.textDim, fontSize: 14 }}>
            No {activePhase} data loaded. Run <span style={{ color: COLORS.accent, fontFamily: "monospace" }}>/scope:{activePhase}</span> or load a {activePhase} results.json file.
          </div>
        </div>
      ) : (activePhase === "audit" || activePhase === "exploit") ? (
        <AuditExploitView
          data={data}
          controlsData={allData.controls}
          filteredPaths={filteredPaths}
          selectedPath={selectedPath}
          setSelectedPath={setSelectedPath}
          tab={tab}
          setTab={setTab}
          selectedNode={selectedNode}
          setSelectedNode={setSelectedNode}
          searchQuery={searchQuery}
          setSearchQuery={setSearchQuery}
          sortMode={sortMode}
          setSortMode={setSortMode}
          activeStatPanel={activeStatPanel}
          handleStatClick={handleStatClick}
          isNarrow={isNarrow}
        />
      ) : activePhase === "controls" ? (
        <ControlsView data={data} isNarrow={isNarrow} />
      ) : null}

    </div>
  );
}
