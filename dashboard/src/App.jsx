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
  defend:      { label: "Defend",      color: "#22c55e" },
};

// ─── Data Normalization ───
// Handles multiple defend data formats produced by different agents:
//   1. Rich results.json (per spec: has scps[], rcps[], detections[] with severity/spl, etc.)
//   2. Thin results.json (summary counts + policies.scp_files + basic detections without spl)
//   3. Data layer format (fields nested under payload, from data/defend/*.json)
//   4. Flat policies[] format (policies as single array with type: "SCP"/"RCP", no scps[]/rcps[])
// Also fixes audit source field: json.source may be service-specific (e.g., "svc:ec2.amazonaws.com")
function normalizeForDashboard(json, indexSource) {
  let data = { ...json };

  // Unwrap data layer payload format (data/<phase>/*.json nests fields under payload)
  if (data.payload && typeof data.payload === "object") {
    const { payload, ...meta } = data;
    data = { ...meta, ...payload };
  }

  // Resolve canonical phase key: prefer index.json source over json.source when
  // json.source is not a recognized phase (e.g., "svc:ec2.amazonaws.com" for audit)
  const VALID_PHASES = ["audit", "exploit", "defend"];
  const source = (indexSource && VALID_PHASES.includes(indexSource))
    ? indexSource
    : (VALID_PHASES.includes(data.source) ? data.source : (indexSource || "audit"));
  data.source = source;

  // Audit-specific normalization
  if (source === "audit") {
    if (!data.summary) data.summary = {};
    const s = data.summary;
    if (s.total_attack_paths == null && s.attack_paths != null) s.total_attack_paths = s.attack_paths;
    if (s.total_attack_paths == null) s.total_attack_paths = data.attack_paths?.length ?? 0;

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
  }

  // Exploit-specific normalization
  if (source === "exploit") {
    if (!data.summary) data.summary = {};
    const s = data.summary;
    if (s.total_attack_paths == null) s.total_attack_paths = s.paths_found ?? data.attack_paths?.length ?? 0;
    if (s.persistence_techniques == null) s.persistence_techniques = 0;
    if (s.exfiltration_vectors == null) s.exfiltration_vectors = 0;
  }

  // Defend-specific normalization
  if (source === "defend") {
    // Map summary field variants to dashboard-expected names
    if (!data.summary) data.summary = {};
    const s = data.summary;
    // Array lengths ALWAYS win for defend KPIs — summary fields become informational only
    s.detections_generated = data.detections?.length ?? 0;
    s.scps_generated = data.scps?.length ?? s.scps_generated ?? s.scps ?? 0;
    s.rcps_generated = data.rcps?.length ?? s.rcps_generated ?? s.rcps ?? 0;
    s.controls_recommended = data.security_controls?.length ?? 0;

    // Normalize audit_run (string) → audit_runs_analyzed (array)
    if (!data.audit_runs_analyzed && data.audit_run) {
      data.audit_runs_analyzed = [data.audit_run];
    }

    // Split flat policies[] array by type into separate scps[]/rcps[] arrays
    // Some agents produce policies: [{ file, type: "SCP", ... }] instead of scps[]/rcps[]
    if (!data.scps && !data.rcps && Array.isArray(data.policies)) {
      const mapPolicy = (p) => ({
        name: p.name || p.file?.replace(/^policies\//, "").replace(/\.json$/, "") || "Unnamed",
        policy_json: p.policy_json || null,
        source_attack_paths: p.source_attack_paths || [],
        impact_analysis: p.impact_analysis || {
          prevents: [],
          blast_radius: (p.blast_radius || "unknown").toLowerCase(),
          break_glass: "none",
        },
      });
      data.scps = data.policies
        .filter((p) => (p.type || "").toUpperCase() === "SCP")
        .map(mapPolicy);
      data.rcps = data.policies
        .filter((p) => (p.type || "").toUpperCase() === "RCP")
        .map(mapPolicy);
    }
  }

  // Severity canonicalization: normalize aliases to canonical values
  // Canonical enum: critical, high, medium, low, info
  const SEVERITY_ALIASES = { informational: "info" };
  const canonicalizeSeverity = (s, fallback = "medium") => {
    const lower = s?.toLowerCase() ?? fallback;
    return SEVERITY_ALIASES[lower] ?? lower;
  };

  // Normalize severity fields to lowercase across all phases
  // Guarantees SEVERITY_CONFIG lowercase keys always match regardless of agent casing
  // Coerce attack_path array fields that agents may emit as strings (e.g. Gemini remediation)
  const ensureArray = (v) => Array.isArray(v) ? v : (typeof v === "string" && v ? [v] : []);
  if (Array.isArray(data.attack_paths)) {
    data.attack_paths = data.attack_paths.map((p) => ({
      ...p,
      severity: canonicalizeSeverity(p.severity),
      steps: ensureArray(p.steps || p.exploit_steps),
      remediation: ensureArray(p.remediation),
      detection_opportunities: ensureArray(p.detection_opportunities),
      mitre_techniques: ensureArray(p.mitre_techniques),
      affected_resources: ensureArray(p.affected_resources),
    }));
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

  // Map technical_remediation → technical_recommendations (data layer uses former)
  if (data.technical_remediation && !data.technical_recommendations) {
    data.technical_recommendations = data.technical_remediation;
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
    default:             return { color: COLORS.edgeNormal,        strokeWidth: 1.5, dashArray: "none" };
  }
}

// ─── Attack Graph Visualization (D3) ───
const AttackGraph = forwardRef(function AttackGraph({ data, selectedPath, onNodeClick, onDeselect }, ref) {
  const svgRef = useRef(null);
  const simRef = useRef(null);
  const zoomRef = useRef(null);
  const nodesRef = useRef([]);
  const [disconnectedNodes, setDisconnectedNodes] = useState([]);
  const [showDisconnectedSidebar, setShowDisconnectedSidebar] = useState(false);
  const [edgeTooltip, setEdgeTooltip] = useState(null); // { x, y, edge_type, source, target }

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
      d3.select(svgRef.current)
        .transition().duration(300)
        .call(zoomRef.current.transform, d3.zoomIdentity.translate(0, 0).scale(0.85));
    },
  }), []);

  // Resolve affected_resources (ARNs) to graph node IDs for highlighting
  const highlightedNodes = useMemo(() => {
    if (!selectedPath || !data?.graph?.nodes) return new Set();
    const resources = selectedPath.affected_resources || [];
    const matched = new Set();
    const nodes = data.graph.nodes;
    for (const r of resources) {
      // Direct match
      if (nodes.some((n) => n.id === r)) { matched.add(r); continue; }
      // ARN → node label/id match
      const resName = r.includes("/") ? r.split("/").pop() : r.split(":").pop();
      const node = nodes.find((n) => n.label === resName || n.id.endsWith(":" + resName));
      if (node) matched.add(node.id);
    }
    return matched;
  }, [selectedPath, data]);

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
    if (!svgRef.current || !data?.graph) return;
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

    ["normal", "trust", "priv_esc", "cross_account", "data_access", "service", "network", "public_access"].forEach((type) => {
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

    const nodes = (data.graph.nodes || []).map((d) => ({ ...d }));
    nodesRef.current = nodes;
    const nodeMap = new Map(nodes.map((n) => [n.id, n]));
    const links = (data.graph.edges || [])
      .filter((e) => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map((d) => ({ ...d }));

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

    sim.on("tick", () => {
      link.attr("x1", (d) => d.source.x).attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x).attr("y2", (d) => d.target.y);
      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    svg.call(zoom.transform, d3.zoomIdentity.translate(0, 0).scale(0.85));

    return () => sim.stop();
  }, [data, highlightedNodes, highlightedEdges, onNodeClick]);

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
            These nodes have no edges in the graph — they may be incomplete attack path data or isolated resources requiring investigation.
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
  return (
    <div
      onClick={onClick}
      style={{
        background: isSelected ? COLORS.bgCardHover : COLORS.bgCard,
        border: `1px solid ${isSelected ? sev.color : COLORS.border}`,
        borderRadius: 8, padding: 16, cursor: "pointer",
        transition: "all 0.2s", marginBottom: 10,
        borderLeft: `3px solid ${sev.color}`,
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
function PathDetail({ path }) {
  if (!path) return (
    <div style={{ color: COLORS.textDim, textAlign: "center", padding: 40, fontSize: 13 }}>
      Select an attack path to see details
    </div>
  );

  const sev = SEVERITY_CONFIG[path.severity] || SEVERITY_CONFIG.medium;

  return (
    <div style={{ padding: 20, overflowY: "auto", height: "100%" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
        <span style={{
          background: sev.bg, color: sev.color, padding: "3px 12px", borderRadius: 12,
          fontSize: 12, fontWeight: 700, textTransform: "uppercase",
        }}>{path.severity}</span>
        <h2 style={{ margin: 0, color: COLORS.text, fontSize: 18, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }} title={path.name}>{path.name}</h2>
      </div>
      <p style={{ color: COLORS.textDim, lineHeight: 1.6, fontSize: 13 }}>{path.description}</p>

      {/* Steps */}
      <SectionHeader title="Attack Steps" icon={"\u2694"} />
      <div style={{ marginLeft: 4, position: "relative" }}>
        {path.steps?.map((step, i) => {
          const isLast = i === path.steps.length - 1;
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
                <span style={{ color: COLORS.text, fontSize: 13, lineHeight: 1.6 }}>{step}</span>
              </div>
            </div>
          );
        })}
      </div>

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
      {path.detection_opportunities?.length > 0 && (
        <>
          <SectionHeader title="Splunk Detections (CloudTrail)" icon={"\uD83D\uDD0D"} />
          {path.detection_opportunities.map((d, i) => (
            <div key={i} style={{
              display: "flex", alignItems: "flex-start", gap: 4, marginBottom: 6,
            }}>
              <div style={{
                flex: 1, background: "rgba(6,182,212,0.08)", border: `1px solid rgba(6,182,212,0.2)`,
                borderRadius: 6, padding: "8px 12px", fontSize: 12,
                color: "#67e8f9", fontFamily: "monospace",
              }}>{d}</div>
              <CopyButton text={d} />
            </div>
          ))}
        </>
      )}

      {/* Remediation */}
      {path.remediation?.length > 0 && (
        <>
          <SectionHeader title="Remediation (SCP/RCP + IAM)" icon={"\uD83D\uDEE1"} />
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
              <span style={{ color: COLORS.nodeUser, fontFamily: "monospace", fontSize: 11 }}>{hop.from}</span>
              <span style={{ color: COLORS.edgeCrossAccount }}>{"\u2192"}</span>
              <span style={{ color: COLORS.nodeRole, fontFamily: "monospace", fontSize: 11 }}>{hop.to}</span>
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

// ─── Node Detail Panel (slide-out) ───
function NodeDetailPanel({ node, data, selectedPath, onSelectPath, onClose }) {
  if (!node) return null;

  const connectedEdges = useMemo(() => {
    if (!data?.graph?.edges) return [];
    return data.graph.edges.filter(
      (e) => e.source === node.id || e.target === node.id
    );
  }, [data, node]);

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
            fontSize: 11, color: COLORS.text, fontFamily: "monospace", wordBreak: "break-all",
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

// ─── Run History Panel (phase-aware) ───
// ─── Severity Filter Buttons ───
function SeverityFilter({ activeSeverities, onToggle }) {
  return (
    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
      {["critical", "high", "medium", "low"].map((sev) => {
        const config = SEVERITY_CONFIG[sev];
        const active = activeSeverities.has(sev);
        return (
          <button
            key={sev}
            onClick={() => onToggle(sev)}
            style={{
              padding: "3px 10px", borderRadius: 12, cursor: "pointer",
              fontSize: 11, fontWeight: 600, textTransform: "uppercase",
              border: `1px solid ${active ? config.color : COLORS.border}`,
              background: active ? config.bg : "transparent",
              color: active ? config.color : COLORS.textMuted,
              transition: "all 0.15s",
            }}
          >
            {config.icon} {sev}
          </button>
        );
      })}
    </div>
  );
}

// ─── Category Filter Buttons ───
function CategoryFilter({ activeCategories, onToggle }) {
  return (
    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
      {Object.entries(CATEGORY_CONFIG).map(([key, cfg]) => {
        const active = activeCategories.has(key);
        return (
          <button
            key={key}
            onClick={() => onToggle(key)}
            style={{
              padding: "3px 10px", borderRadius: 12, cursor: "pointer",
              fontSize: 10, fontWeight: 600,
              border: `1px solid ${active ? cfg.color : COLORS.border}`,
              background: active ? cfg.color + "1f" : "transparent",
              color: active ? cfg.color : COLORS.textMuted,
              transition: "all 0.15s",
            }}
          >
            {cfg.label}
          </button>
        );
      })}
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
        const trustItems = trusts.length > 0 ? [...trusts].sort((a, b) => {
          // Sort by risk level (critical first), then trust_type (cross-account first), then role_id
          const riskDiff = (RISK_ORDER[a.risk] ?? 4) - (RISK_ORDER[b.risk] ?? 4);
          if (riskDiff !== 0) return riskDiff;
          const typeDiff = (TRUST_TYPE_ORDER[a.trust_type] ?? 3) - (TRUST_TYPE_ORDER[b.trust_type] ?? 3);
          if (typeDiff !== 0) return typeDiff;
          return (a.role_id || "").localeCompare(b.role_id || "");
        }) : paths.filter((p) => p.category === "trust_misconfiguration");
        return { title: "Trust Relationships", items: trustItems };
      }
      case "wildcards": {
        const wildcardTrusts = trusts.filter((t) => t.is_wildcard);
        if (wildcardTrusts.length > 0) return { title: "Wildcard Trusts", items: wildcardTrusts };
        // Fallback: find wildcard-related attack paths or trust paths mentioning wildcard
        const wildcardPaths = paths.filter((p) =>
          (p.name || "").toLowerCase().includes("wildcard") ||
          (p.description || "").toLowerCase().includes("wildcard") ||
          p.category === "trust_misconfiguration"
        );
        return { title: "Wildcard Trusts", items: wildcardPaths };
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
        onClick={() => onHighlightNode?.(item.id)}
        style={{
          background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
          borderRadius: 8, padding: 14, marginBottom: 10, cursor: "pointer",
          transition: "border-color 0.2s",
        }}
      >
        <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, marginBottom: 6 }}>{item.id}</div>
        <div style={{ fontSize: 11, color: COLORS.textDim, fontFamily: "monospace", wordBreak: "break-all", marginBottom: 8 }}>{item.arn}</div>
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
        onClick={() => onHighlightNode?.(item.id)}
        style={{
          background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
          borderRadius: 8, padding: 14, marginBottom: 10, cursor: "pointer",
          transition: "border-color 0.2s",
        }}
      >
        <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, marginBottom: 6 }}>{item.id}</div>
        <div style={{ fontSize: 11, color: COLORS.textDim, fontFamily: "monospace", wordBreak: "break-all", marginBottom: 8 }}>{item.arn}</div>
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
        {item.attached_policies?.length > 0 && (
          <div style={{ fontSize: 10, color: COLORS.textDim, marginTop: 4 }}>Policies: {item.attached_policies.join(", ")}</div>
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

  if (statKey === "trusts" || statKey === "wildcards") {
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
        {/* Trusted-by line: who/what is trusted to assume this role */}
        <div style={{ fontSize: 11, color: COLORS.textDim, marginBottom: 4 }}>
          Trusted by: <span style={{ color: COLORS.text, fontWeight: 500 }}>{trustedByName}</span>
        </div>
        {/* Full principal in monospace below */}
        {principal && (
          <div style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: "monospace", wordBreak: "break-all", marginBottom: 6 }}>{principal}</div>
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

// ═══════════════════════════════════════════════════════════════════
// ─── Phase Views ───
// ═══════════════════════════════════════════════════════════════════

// ─── Audit/Exploit View (extracted from original App) ───
function AuditExploitView({ data, filteredPaths, selectedPath, setSelectedPath, tab, setTab, selectedNode, setSelectedNode, searchQuery, setSearchQuery, activeSeverities, handleToggleSeverity, activeCategories, handleToggleCategory, sortMode, setSortMode, activeStatPanel, handleStatClick }) {
  const summary = data?.summary || {};
  const isExploit = data?.source === "exploit";
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
      <div style={{ display: "flex", gap: 12, padding: "16px 24px", flexWrap: "wrap" }}>
        {isExploit ? (
          <>
            <StatCard label="Attack Paths" value={data.attack_paths?.length || 0} color={COLORS.accent} active={activeStatPanel === "paths"} onClick={() => handleStatClick("paths")} />
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
            <StatCard label="Attack Paths" value={data.attack_paths?.length || 0} color={COLORS.accent} active={activeStatPanel === "paths"} onClick={() => handleStatClick("paths")} />
          </>
        )}
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, display: "flex", padding: "0 24px 24px", gap: 16, minHeight: 0, overflow: "hidden" }}>
        {/* Left: Attack Paths List */}
        <div style={{ width: 320, minWidth: 280, display: "flex", flexDirection: "column", opacity: (isIncomplete && !data?.attack_paths?.length) ? 0.6 : 1 }}>
          <div style={{ marginBottom: 10, fontSize: 13, fontWeight: 600, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Attack Paths
          </div>

          <div style={{ marginBottom: 8 }}>
            <SeverityFilter activeSeverities={activeSeverities} onToggle={handleToggleSeverity} />
          </div>
          <div style={{ marginBottom: 8 }}>
            <CategoryFilter activeCategories={activeCategories} onToggle={handleToggleCategory} />
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
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          <div style={{ display: "flex", gap: 4, marginBottom: 12, alignItems: "center" }}>
            {["graph", "detail"].map((t) => (
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
                {t === "graph" ? "Attack Graph" : "Path Detail"}
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
                        selectedPath={selectedPath}
                        onSelectPath={(p) => { setSelectedPath(p); setTab("detail"); }}
                        onClose={() => setSelectedNode(null)}
                      />
                    )}
                  </>
                )}
              </>
            ) : (
              selectedPath ? <PathDetail path={selectedPath} /> : <div style={{
                display: "flex", alignItems: "center", justifyContent: "center",
                height: "100%", color: COLORS.textDim, fontSize: 13, opacity: 0.6,
              }}>Select an attack path to view details</div>
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
// ─── DefendView ───
// ═══════════════════════════════════════════════════════════════════

function formatJSON(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

function PolicyViewer({ scps, rcps }) {
  const [expandedIdx, setExpandedIdx] = useState(null);
  const allPolicies = [
    ...(scps || []).map((p) => ({ ...p, policyType: "SCP" })),
    ...(rcps || []).map((p) => ({ ...p, policyType: "RCP" })),
  ];

  if (allPolicies.length === 0) {
    return <div style={{ color: COLORS.textDim, fontSize: 13, padding: 20 }}>No policies generated.</div>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {allPolicies.map((policy, i) => {
        const isExpanded = expandedIdx === i;
        const blastColor = policy.impact_analysis?.blast_radius === "high" ? COLORS.critical
          : policy.impact_analysis?.blast_radius === "medium" ? COLORS.high : COLORS.low;

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
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4,
                  background: policy.policyType === "SCP" ? COLORS.highBg : COLORS.mediumBg,
                  color: policy.policyType === "SCP" ? COLORS.high : COLORS.medium,
                }}>{policy.policyType}</span>
                <span style={{ fontSize: 14, fontWeight: 600, color: COLORS.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0 }} title={policy.name}>{policy.name}</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{
                  fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 4,
                  color: blastColor, background: blastColor + "18",
                  textTransform: "uppercase",
                }}>
                  {policy.impact_analysis?.blast_radius || "unknown"} blast
                </span>
                <span style={{ color: COLORS.textDim, fontSize: 12 }}>{isExpanded ? "\u25B2" : "\u25BC"}</span>
              </div>
            </div>

            {isExpanded && (
              <div style={{ padding: "0 16px 16px", borderTop: `1px solid ${COLORS.border}` }}>
                {/* Impact Analysis — only show when it has real data */}
                {policy.impact_analysis && (policy.impact_analysis.prevents?.length > 0 || (policy.impact_analysis.break_glass && policy.impact_analysis.break_glass !== "none")) && (
                  <div style={{ marginTop: 12, marginBottom: 12 }}>
                    <div style={{ fontSize: 10, color: COLORS.textDim, textTransform: "uppercase", marginBottom: 6 }}>Impact Analysis</div>
                    {policy.impact_analysis.prevents?.length > 0 && (
                      <div style={{ fontSize: 12, color: COLORS.text, marginBottom: 4 }}>
                        <span style={{ color: COLORS.textDim }}>Prevents: </span>{policy.impact_analysis.prevents.join(", ")}
                      </div>
                    )}
                    {policy.impact_analysis.break_glass && policy.impact_analysis.break_glass !== "none" && (
                      <div style={{ fontSize: 12, color: COLORS.textDim }}>
                        Break-glass: {policy.impact_analysis.break_glass}
                      </div>
                    )}
                  </div>
                )}

                {/* Source attack paths */}
                {policy.source_attack_paths?.length > 0 && (
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontSize: 10, color: COLORS.textDim, textTransform: "uppercase", marginBottom: 4 }}>Source Attack Paths</div>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                      {policy.source_attack_paths.map((p, j) => (
                        <span key={j} style={{
                          fontSize: 10, color: COLORS.critical, background: COLORS.criticalBg,
                          padding: "2px 8px", borderRadius: 4,
                        }}>{p}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Policy JSON */}
                {policy.policy_json ? (
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 4, marginBottom: 4 }}>
                      <span style={{ fontSize: 10, color: COLORS.textDim, textTransform: "uppercase" }}>Policy JSON</span>
                      <CopyButton text={formatJSON(policy.policy_json)} />
                    </div>
                    <pre style={{
                      background: "#0d1117", border: `1px solid ${COLORS.border}`, borderRadius: 6,
                      padding: 12, fontSize: 11, color: "#7ee787", fontFamily: "monospace",
                      overflow: "auto", maxHeight: 300, margin: 0, whiteSpace: "pre-wrap",
                    }}>{formatJSON(policy.policy_json)}</pre>
                  </div>
                ) : (
                  <div style={{
                    marginTop: 8, padding: 12, background: "#0d1117",
                    border: `1px solid ${COLORS.border}`, borderRadius: 6,
                    fontSize: 12, color: COLORS.textDim,
                  }}>
                    Policy JSON not embedded in results. See <span style={{ color: COLORS.accent, fontFamily: "monospace" }}>{policy.name}.json</span> in the run directory's <span style={{ fontFamily: "monospace" }}>policies/</span> folder.
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
              return (
                <div key={i} style={{
                  background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
                  borderRadius: 8, padding: 14, marginBottom: 8,
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <span style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }} title={rule.name}>{rule.name}</span>
                    <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
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
                    <div style={{ display: "flex", alignItems: "flex-start", gap: 4 }}>
                      <pre style={{
                        flex: 1, background: "rgba(6,182,212,0.08)", border: `1px solid rgba(6,182,212,0.2)`,
                        borderRadius: 6, padding: "8px 12px", fontSize: 11,
                        color: "#67e8f9", fontFamily: "monospace", margin: 0,
                        whiteSpace: "pre-wrap", overflow: "auto", maxHeight: 200,
                      }}>{rule.spl}</pre>
                      <CopyButton text={rule.spl} />
                    </div>
                  ) : (
                    <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
                      {rule.paths_covered != null && (
                        <span style={{ fontSize: 11, color: COLORS.textDim }}>
                          Paths covered: <span style={{ color: COLORS.text, fontWeight: 600 }}>{rule.paths_covered}</span>
                        </span>
                      )}
                      <span style={{ fontSize: 11, color: COLORS.textMuted, fontStyle: "italic" }}>
                        SPL query in technical-remediation.md
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        );
      })}
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

  const catColors = { scp: COLORS.high, rcp: COLORS.medium, detection: COLORS.detection, control: COLORS.low };
  const riskColors = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low };
  const effortColors = { low: COLORS.low, medium: COLORS.high, high: COLORS.critical };

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
              color: catColors[item.category] || COLORS.textDim,
              background: (catColors[item.category] || COLORS.textDim) + "18",
              textTransform: "uppercase",
            }}>{item.category}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Executive Summary View ───
function ExecutiveSummaryView({ data }) {
  const exec = data?.executive_summary;
  const summary = data?.summary || {};
  const riskColor = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low }[summary.risk_score] || COLORS.text;

  if (!exec) {
    return <div style={{ color: COLORS.textDim, fontSize: 13, padding: 20 }}>No executive summary data available. Re-run defend to generate.</div>;
  }

  return (
    <div style={{ padding: 20, maxWidth: 900 }}>
      {/* Risk Posture */}
      <div style={{
        background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 8,
        padding: 20, marginBottom: 16,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
          <span style={{ fontSize: 11, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "0.05em" }}>Risk Posture</span>
          {summary.risk_score && (
            <span style={{
              fontSize: 12, fontWeight: 700, padding: "3px 12px", borderRadius: 6,
              color: riskColor, background: riskColor + "18",
            }}>{summary.risk_score}</span>
          )}
        </div>
        <p style={{ color: COLORS.text, fontSize: 14, lineHeight: 1.6, margin: 0 }}>{exec.risk_posture}</p>
      </div>

      {/* Category Breakdown */}
      {exec.category_breakdown?.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 8 }}>Category Breakdown</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 8 }}>
            {exec.category_breakdown.map((cat, i) => {
              const sevCfg = SEVERITY_CONFIG[cat.severity] || SEVERITY_CONFIG.medium;
              return (
                <div key={i} style={{
                  background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 8,
                  padding: 12, borderLeft: `3px solid ${sevCfg.color}`,
                }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, marginBottom: 4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={cat.category}>{cat.category}</div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: 22, fontWeight: 700, color: sevCfg.color, fontFamily: "monospace" }}>{cat.count}</span>
                    <span style={{ fontSize: 10, color: sevCfg.color, textTransform: "uppercase", fontWeight: 600 }}>{cat.severity}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Quick Wins */}
      {exec.quick_wins?.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 8 }}>Top Quick Wins</div>
          {exec.quick_wins.map((qw, i) => (
            <div key={i} style={{
              background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 8,
              padding: 14, marginBottom: 8, display: "flex", gap: 12, alignItems: "flex-start",
            }}>
              <span style={{
                minWidth: 28, height: 28, borderRadius: "50%", background: COLORS.accent + "18",
                color: COLORS.accent, display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 13, fontWeight: 700,
              }}>{qw.rank}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, marginBottom: 4 }}>{qw.action}</div>
                <div style={{ fontSize: 12, color: COLORS.textDim, lineHeight: 1.4 }}>{qw.impact}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Remediation Timeline */}
      {exec.remediation_timeline && (
        <div>
          <div style={{ fontSize: 11, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 8 }}>Remediation Timeline</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
            {[
              { key: "this_week", label: "This Week", color: COLORS.critical },
              { key: "this_month", label: "This Month", color: COLORS.high },
              { key: "this_quarter", label: "This Quarter", color: COLORS.medium },
            ].map(({ key, label, color }) => (
              <div key={key} style={{
                background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 8,
                padding: 14, borderTop: `3px solid ${color}`,
              }}>
                <div style={{ fontSize: 12, fontWeight: 700, color, marginBottom: 8, textTransform: "uppercase" }}>{label}</div>
                {(exec.remediation_timeline[key] || []).map((item, i) => (
                  <div key={i} style={{ fontSize: 12, color: COLORS.text, marginBottom: 6, lineHeight: 1.4, display: "flex", gap: 6, alignItems: "flex-start" }}>
                    <span style={{ color: COLORS.textDim, flexShrink: 0 }}>{"\u2022"}</span>
                    <span>{item}</span>
                  </div>
                ))}
                {(!exec.remediation_timeline[key] || exec.remediation_timeline[key].length === 0) && (
                  <div style={{ fontSize: 11, color: COLORS.textMuted }}>None</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Technical Recommendations View ───
function TechnicalRecommendationsView({ data }) {
  const tech = data?.technical_recommendations;
  if (!tech?.attack_path_bundles?.length) {
    return <div style={{ color: COLORS.textDim, fontSize: 13, padding: 20 }}>No technical recommendations data available. Re-run defend to generate.</div>;
  }

  return (
    <div style={{ padding: 20, maxWidth: 900 }}>
      <div style={{ fontSize: 11, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 12 }}>
        Attack Path Remediation Bundles
      </div>
      {tech.attack_path_bundles.map((bundle, i) => {
        const sevCfg = SEVERITY_CONFIG[bundle.severity] || SEVERITY_CONFIG.medium;
        return (
          <div key={i} style={{
            background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 8,
            padding: 16, marginBottom: 12, borderLeft: `3px solid ${sevCfg.color}`,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10, flexWrap: "wrap", gap: 8 }}>
              <span style={{ fontSize: 14, fontWeight: 600, color: COLORS.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }} title={bundle.attack_path}>{bundle.attack_path}</span>
              <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 8,
                  color: sevCfg.color, background: sevCfg.bg, textTransform: "uppercase",
                }}>{bundle.severity}</span>
                {bundle.classification && (
                  <span style={{
                    fontSize: 9, fontWeight: 600, padding: "2px 6px", borderRadius: 4,
                    color: bundle.classification === "systemic" ? COLORS.critical : COLORS.textDim,
                    background: bundle.classification === "systemic" ? COLORS.criticalBg : COLORS.bgCardHover,
                    textTransform: "uppercase",
                  }}>{bundle.classification}</span>
                )}
              </div>
            </div>

            {/* Source runs */}
            {bundle.source_run_ids?.length > 0 && (
              <div style={{ fontSize: 10, color: COLORS.textDim, marginBottom: 10, fontFamily: "monospace" }}>
                Source: {bundle.source_run_ids.join(", ")}
              </div>
            )}

            {/* Remediation links */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 8 }}>
              {[
                { items: bundle.scp_names, label: "SCPs", color: COLORS.high },
                { items: bundle.rcp_names, label: "RCPs", color: COLORS.medium },
                { items: bundle.detection_names, label: "Detections", color: COLORS.detection },
                { items: bundle.control_names, label: "Controls", color: COLORS.low },
              ].filter(({ items }) => items?.length > 0).map(({ items, label, color }) => (
                <div key={label}>
                  <div style={{ fontSize: 10, color, textTransform: "uppercase", fontWeight: 700, marginBottom: 4 }}>{label}</div>
                  {items.map((name, j) => (
                    <div key={j} style={{
                      fontSize: 11, color: COLORS.text, background: color + "0d", border: `1px solid ${color}22`,
                      borderRadius: 4, padding: "4px 8px", marginBottom: 4,
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                    }} title={name}>{name}</div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function DefendView({ data }) {
  const [defendTab, setDefendTab] = useState(data?.executive_summary ? "executive" : "policies");
  const summary = data?.summary || {};

  return (
    <>
      {/* Stats Row — cards switch to the corresponding tab */}
      <div style={{ display: "flex", gap: 12, padding: "16px 24px", flexWrap: "wrap" }}>
        <StatCard label="SCPs" value={summary.scps_generated ?? data.scps?.length ?? 0} color={COLORS.high} onClick={() => setDefendTab("policies")} active={defendTab === "policies"} />
        <StatCard label="RCPs" value={summary.rcps_generated ?? data.rcps?.length ?? 0} color={COLORS.medium} onClick={() => setDefendTab("policies")} active={defendTab === "policies"} />
        <StatCard label="Detections" value={summary.detections_generated ?? data.detections?.length ?? 0} color={COLORS.detection} onClick={() => setDefendTab("detections")} active={defendTab === "detections"} />
        <StatCard label="Controls" value={summary.controls_recommended ?? data.security_controls?.length ?? 0} color={COLORS.low} onClick={() => setDefendTab("controls")} active={defendTab === "controls"} />
        <StatCard label="Quick Wins" value={summary.quick_wins ?? 0} color={COLORS.accent} onClick={() => setDefendTab("executive")} active={defendTab === "executive"} />
      </div>

      {/* Main Content: Sidebar + Tabbed Center */}
      <div style={{ flex: 1, display: "flex", padding: "0 24px 24px", gap: 16, minHeight: 0, overflow: "hidden" }}>
        {/* Prioritization Sidebar */}
        <PrioritizationSidebar items={data.prioritization} />

        {/* Center: Tabbed content */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          <div style={{ display: "flex", gap: 4, marginBottom: 12, flexWrap: "wrap" }}>
            {[
              { key: "executive", label: "Executive Summary" },
              { key: "technical", label: "Tech Recommendations" },
              { key: "policies", label: "Policies" },
              { key: "detections", label: "Detections" },
              { key: "controls", label: "Controls" },
            ].map((t) => (
              <button
                key={t.key}
                onClick={() => setDefendTab(t.key)}
                style={{
                  padding: "6px 14px", borderRadius: 6,
                  border: `1px solid ${defendTab === t.key ? PHASE_CONFIG.defend.color : COLORS.border}`,
                  background: defendTab === t.key ? PHASE_CONFIG.defend.color + "18" : "transparent",
                  color: defendTab === t.key ? PHASE_CONFIG.defend.color : COLORS.textDim,
                  cursor: "pointer", fontSize: 12, fontWeight: 600, textTransform: "uppercase",
                }}
              >
                {t.label}
              </button>
            ))}
          </div>
          <div style={{ flex: 1, overflowY: "auto" }}>
            {defendTab === "executive" && <ExecutiveSummaryView data={data} />}
            {defendTab === "technical" && <TechnicalRecommendationsView data={data} />}
            {defendTab === "policies" && <PolicyViewer scps={data.scps} rcps={data.rcps} />}
            {defendTab === "detections" && <DetectionRulesList detections={data.detections} />}
            {defendTab === "controls" && <ControlsMatrix controls={data.security_controls} />}
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
  const [allData, setAllData] = useState({});  // { audit: {...}, defend: {...}, exploit: {...} }
  const [selectedPath, setSelectedPath] = useState(null);
  const [tab, setTab] = useState("graph");
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activePhase, setActivePhase] = useState("audit");
  // Run index state — loaded from index.json when available (enables run selector + status)
  const [runIndex, setRunIndex] = useState([]);  // array of { run_id, source, date, status, file }

  // Interactive state
  const [searchQuery, setSearchQuery] = useState("");
  const [activeSeverities, setActiveSeverities] = useState(new Set(["critical", "high", "medium", "low"]));
  const [activeCategories, setActiveCategories] = useState(new Set(Object.keys(CATEGORY_CONFIG)));
  const [sortMode, setSortMode] = useState("severity");
  const [activeStatPanel, setActiveStatPanel] = useState(null);

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
      else if (allData["defend"]) setActivePhase("defend");
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
    // Try to load index.json for run selector (only works in dev server mode, not inline HTML)
    fetch("index.json").then((r) => r.ok ? r.json() : null).then((idx) => {
      if (idx?.runs?.length) setRunIndex(idx.runs);
    }).catch(() => { /* index.json not available — inline mode */ });
    setLoading(false);
  }, []);

  const handleDataLoad = useCallback((json) => {
    const { data: normalized, source } = normalizeForDashboard(json);
    setAllData((prev) => ({ ...prev, [source]: normalized }));
    setActivePhase(source);
    setSelectedPath(null);
    setSelectedNode(null);
    setSearchQuery("");
    setActiveStatPanel(null);
  }, []);

  const handleToggleCategory = useCallback((cat) => {
    setActiveCategories((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) {
        if (next.size > 1) next.delete(cat);
      } else {
        next.add(cat);
      }
      return next;
    });
  }, []);

  const handleStatClick = useCallback((key) => {
    setActiveStatPanel((prev) => prev === key ? null : key);
  }, []);

  const handleToggleSeverity = useCallback((sev) => {
    setActiveSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) {
        if (next.size > 1) next.delete(sev);
      } else {
        next.add(sev);
      }
      return next;
    });
  }, []);

  // Filter and sort attack paths
  const filteredPaths = useMemo(() => {
    if (!data?.attack_paths) return [];
    let paths = data.attack_paths;

    paths = paths.filter((p) => activeSeverities.has(p.severity));
    paths = paths.filter((p) => {
      const cat = p.category || "privilege_escalation";
      return activeCategories.has(cat);
    });

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
  }, [data, activeSeverities, activeCategories, searchQuery, sortMode]);

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
  const summary = data?.summary || {};
  const riskColor = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low }[summary.risk_score] || COLORS.text;
  const phaseColor = PHASE_CONFIG[activePhase]?.color || COLORS.accent;

  return (
    <div style={{
      fontFamily: "'IBM Plex Sans', -apple-system, sans-serif",
      background: COLORS.bg, color: COLORS.text, height: "100vh",
      display: "flex", flexDirection: "column", overflow: "hidden",
      minWidth: 0,
    }}>
      {/* Header */}
      <div style={{
        padding: "12px 24px", borderBottom: `1px solid ${COLORS.border}`,
        display: "flex", justifyContent: "space-between", alignItems: "center",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: 22 }}>{"\uD83D\uDEE1"}</span>
          <div>
            <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, letterSpacing: "-0.02em" }}>
              SCOPE
            </h1>
            <span style={{ fontSize: 11, color: COLORS.textDim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 400, display: "inline-block" }} title={`Account ${anyData.account_id} \u2022 ${anyData.region || "N/A"}`}>
              Account {anyData.account_id} {"\u2022"} {anyData.region || "N/A"}
              {Object.keys(allData).length > 0 && <> {"\u2022"} {Object.keys(allData).map((src) => (
                <span key={src} style={{ color: PHASE_CONFIG[src]?.color || COLORS.accent, marginLeft: 4 }}>{src}</span>
              ))}</>}
            </span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <FileUpload onDataLoad={handleDataLoad} />
          {(activePhase === "audit" || activePhase === "exploit") && summary.risk_score && (
            <div style={{
              padding: "6px 16px", borderRadius: 6, fontWeight: 700, fontSize: 13,
              background: riskColor + "20", color: riskColor, border: `1px solid ${riskColor}40`,
            }}>
              RISK: {summary.risk_score || "N/A"}
            </div>
          )}
        </div>
      </div>

      {/* Phase Tab Bar + Run Selector */}
      <div style={{
        display: "flex", gap: 0, padding: "0 24px",
        borderBottom: `1px solid ${COLORS.border}`,
        justifyContent: "space-between", alignItems: "center",
      }}>
        <div style={{ display: "flex" }}>
          {Object.entries(PHASE_CONFIG).map(([key, cfg]) => {
            const isActive = activePhase === key;
            const phaseRuns = runIndex.filter((r) => r.source === key || (key === "audit" && r.source === "audit") || (key === "exploit" && r.source === "exploit"));
            const hasData = !!allData[key] || ((key === "audit" || key === "exploit") && (allData["audit"] || allData["exploit"]));
            // Show amber dot in tab if the loaded run for this phase is partial/failed
            const phaseRunStatus = allData[key]?.runStatus || "complete";
            const isPartialOrFailed = phaseRunStatus === "partial" || phaseRunStatus === "failed";
            return (
              <button
                key={key}
                onClick={() => setActivePhase(key)}
                style={{
                  padding: "10px 20px", cursor: "pointer",
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
        {/* Run selector dropdown — only shown when index.json has multiple runs for the active phase */}
        {(() => {
          const phaseRuns = runIndex.filter((r) => {
            const matchPhase = activePhase === "audit" ? (r.source === "audit" || r.source === "exploit") : r.source === activePhase;
            return matchPhase;
          });
          if (phaseRuns.length < 2) return null;
          const runStatusLabel = (s) => s === "partial" ? " \u26A0 partial" : s === "failed" ? " \u26A0 failed" : " \u2714";
          const currentId = data?.run_id || "";
          return (
            <select
              value={currentId}
              onChange={(e) => {
                const run = phaseRuns.find((r) => r.run_id === e.target.value);
                if (run) fetch(run.file || `${run.run_id}.json`).then((r) => r.json()).then((json) => {
                  // Attach status from index before normalizing
                  json._run_status = run.status || "complete";
                  handleDataLoad(json);
                }).catch(() => {});
              }}
              style={{
                background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
                color: COLORS.text, borderRadius: 6, fontSize: 11,
                padding: "4px 8px", cursor: "pointer", maxWidth: 260,
                marginRight: 0,
              }}
            >
              {phaseRuns.map((run) => (
                <option key={run.run_id} value={run.run_id}>
                  {run.run_id}{runStatusLabel(run.status)}
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
          filteredPaths={filteredPaths}
          selectedPath={selectedPath}
          setSelectedPath={setSelectedPath}
          tab={tab}
          setTab={setTab}
          selectedNode={selectedNode}
          setSelectedNode={setSelectedNode}
          searchQuery={searchQuery}
          setSearchQuery={setSearchQuery}
          activeSeverities={activeSeverities}
          handleToggleSeverity={handleToggleSeverity}
          activeCategories={activeCategories}
          handleToggleCategory={handleToggleCategory}
          sortMode={sortMode}
          setSortMode={setSortMode}
          activeStatPanel={activeStatPanel}
          handleStatClick={handleStatClick}
        />
      ) : activePhase === "defend" ? (
        <DefendView data={data} />
      ) : null}

    </div>
  );
}
