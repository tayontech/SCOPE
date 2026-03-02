import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import * as d3 from "d3";

// ─── Sample Data (shown when no results.json is loaded) ───
const SAMPLE_DATA = {
  account_id: "123456789012",
  region: "us-east-1",
  timestamp: "2026-02-28T12:00:00Z",
  summary: {
    total_users: 14,
    total_roles: 38,
    total_policies: 22,
    total_trust_relationships: 47,
    critical_priv_esc_risks: 3,
    wildcard_trust_policies: 1,
    cross_account_trusts: 5,
    users_without_mfa: 6,
    risk_score: "HIGH",
  },
  graph: {
    nodes: [
      { id: "user:dev-intern", label: "dev-intern", type: "user", mfa: false },
      { id: "user:ci-deploy", label: "ci-deploy", type: "user", mfa: false },
      { id: "user:admin-ops", label: "admin-ops", type: "user", mfa: true },
      { id: "user:data-analyst", label: "data-analyst", type: "user", mfa: false },
      { id: "role:LambdaExecRole", label: "LambdaExecRole", type: "role", service_role: true },
      { id: "role:AdminRole", label: "AdminRole", type: "role", service_role: false },
      { id: "role:S3ReadRole", label: "S3ReadRole", type: "role", service_role: false },
      { id: "role:CrossAccountAudit", label: "CrossAccountAudit", type: "role", service_role: false },
      { id: "role:GlueServiceRole", label: "GlueServiceRole", type: "role", service_role: true },
      { id: "role:EC2InstanceRole", label: "EC2InstanceRole", type: "role", service_role: true },
      { id: "ext:arn:aws:iam::999888777666:root", label: "External Acct", type: "external" },
      { id: "esc:iam:CreatePolicyVersion", label: "CreatePolicyVersion", type: "escalation" },
      { id: "esc:iam:PassRole", label: "PassRole", type: "escalation" },
      { id: "esc:iam:AttachUserPolicy", label: "AttachUserPolicy", type: "escalation" },
      { id: "data:s3:prod-data-bucket", label: "prod-data-bucket", type: "data" },
      { id: "data:secrets:db-credentials", label: "db-credentials", type: "data" },
    ],
    edges: [
      { source: "user:dev-intern", target: "role:LambdaExecRole", trust_type: "same-account" },
      { source: "user:dev-intern", target: "esc:iam:PassRole", edge_type: "priv_esc", severity: "high" },
      { source: "user:ci-deploy", target: "role:AdminRole", trust_type: "same-account" },
      { source: "user:ci-deploy", target: "esc:iam:CreatePolicyVersion", edge_type: "priv_esc", severity: "critical" },
      { source: "user:ci-deploy", target: "esc:iam:AttachUserPolicy", edge_type: "priv_esc", severity: "critical" },
      { source: "user:data-analyst", target: "role:S3ReadRole", trust_type: "same-account" },
      { source: "role:LambdaExecRole", target: "role:AdminRole", trust_type: "service" },
      { source: "role:LambdaExecRole", target: "data:secrets:db-credentials", edge_type: "data_access" },
      { source: "role:AdminRole", target: "data:s3:prod-data-bucket", edge_type: "data_access" },
      { source: "role:AdminRole", target: "data:secrets:db-credentials", edge_type: "data_access" },
      { source: "role:S3ReadRole", target: "data:s3:prod-data-bucket", edge_type: "data_access" },
      { source: "ext:arn:aws:iam::999888777666:root", target: "role:CrossAccountAudit", trust_type: "cross-account" },
      { source: "role:CrossAccountAudit", target: "role:S3ReadRole", trust_type: "same-account" },
      { source: "role:GlueServiceRole", target: "role:AdminRole", trust_type: "service" },
      { source: "role:EC2InstanceRole", target: "data:s3:prod-data-bucket", edge_type: "data_access" },
    ],
  },
  attack_paths: [
    {
      name: "CI/CD Pipeline to Full Admin",
      severity: "critical",
      description: "The ci-deploy user has CreatePolicyVersion and AttachUserPolicy permissions, allowing direct escalation to AdministratorAccess without MFA.",
      steps: [
        "Compromise ci-deploy credentials (no MFA required)",
        "Use iam:CreatePolicyVersion to create a new version of an attached policy with Action:* Resource:*",
        "Set the new version as default using iam:SetDefaultPolicyVersion",
        "Now has full admin access to the account",
      ],
      mitre_techniques: ["T1078.004", "T1548", "T1098"],
      affected_resources: ["user:ci-deploy", "role:AdminRole"],
      detection_opportunities: [
        "index=cloudtrail eventName=CreatePolicyVersion | where match(requestParameters, \"Effect.*Allow.*Action.*\\*\")",
        "index=cloudtrail eventName=AttachUserPolicy | where match(requestParameters, \"AdministratorAccess\")",
        "index=cloudtrail eventName=ConsoleLogin | where mfaAuthenticated=\"false\"",
      ],
      remediation: [
        "SCP: Deny iam:CreatePolicyVersion except from admin OU",
        "Remove iam:CreatePolicyVersion from ci-deploy",
        "Enforce MFA via IAM policy condition",
        "Use OIDC federation instead of long-lived keys",
      ],
    },
    {
      name: "Intern to Admin via Lambda Role Chain",
      severity: "high",
      description: "dev-intern can pass roles to Lambda, which has access to AdminRole trust. Chain: dev-intern -> PassRole -> Lambda -> AdminRole.",
      steps: [
        "Compromise dev-intern credentials (no MFA)",
        "Use iam:PassRole to assign AdminRole to a new Lambda function",
        "Invoke the Lambda function which now runs with AdminRole permissions",
        "Use admin permissions to access any resource",
      ],
      mitre_techniques: ["T1078.004", "T1548", "T1098.003"],
      affected_resources: ["user:dev-intern", "role:LambdaExecRole", "role:AdminRole"],
      detection_opportunities: [
        "index=cloudtrail eventName=CreateFunction* | where match(requestParameters, \"AdminRole\")",
        "index=cloudtrail eventName=PassRole | where match(requestParameters, \"lambda\")",
      ],
      remediation: [
        "SCP: Restrict iam:PassRole to specific non-admin roles",
        "Add conditions limiting which roles can be passed",
        "Enable MFA for dev-intern",
      ],
    },
    {
      name: "Cross-Account Pivot to Production Data",
      severity: "high",
      description: "External account 999888777666 can assume CrossAccountAudit, which chains to S3ReadRole accessing production data.",
      steps: [
        "Attacker compromises external account 999888777666",
        "Assume CrossAccountAudit role in target account",
        "Pivot to S3ReadRole via trust relationship",
        "Exfiltrate data from prod-data-bucket",
      ],
      mitre_techniques: ["T1550.001", "T1078.004", "T1530"],
      affected_resources: ["role:CrossAccountAudit", "role:S3ReadRole", "data:s3:prod-data-bucket"],
      detection_opportunities: [
        "index=cloudtrail eventName=AssumeRole | where userIdentity.accountId!=\"123456789012\"",
        "index=cloudtrail eventName=AssumeRole | transaction requestParameters.roleArn maxspan=5m | where eventcount>1",
        "index=cloudtrail eventName=GetObject | where bucket=\"prod-data-bucket\" | stats count by userIdentity.arn",
      ],
      remediation: [
        "SCP: Require sts:ExternalId on cross-account trust",
        "Restrict CrossAccountAudit to read-only specific resources",
        "Remove trust chain from CrossAccountAudit to S3ReadRole",
      ],
    },
    {
      name: "Data Analyst Direct Data Access",
      severity: "medium",
      description: "data-analyst user without MFA can assume S3ReadRole and access production data bucket directly.",
      steps: [
        "Compromise data-analyst credentials (no MFA)",
        "Assume S3ReadRole",
        "Access and exfiltrate prod-data-bucket contents",
      ],
      mitre_techniques: ["T1078.004", "T1530"],
      affected_resources: ["user:data-analyst", "role:S3ReadRole", "data:s3:prod-data-bucket"],
      detection_opportunities: [
        "index=cloudtrail eventName=ConsoleLogin | where mfaAuthenticated=\"false\" AND userIdentity.userName=\"data-analyst\"",
        "index=cloudtrail eventName=GetObject | where bucket=\"prod-data-bucket\" | stats count by sourceIPAddress",
      ],
      remediation: [
        "Enable MFA for data-analyst",
        "Add MFA condition on S3ReadRole trust policy",
        "SCP: Deny s3:GetObject without MFA for non-service principals",
      ],
    },
  ],
};

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
  nodeEsc: "#ef4444",
  nodeData: "#22c55e",
  nodeExternal: "#f59e0b",
  edgeNormal: "#334155",
  edgePrivEsc: "#ef4444",
  edgeCrossAccount: "#f59e0b",
  edgeDataAccess: "#22c55e",
};

const SEVERITY_CONFIG = {
  critical: { color: COLORS.critical, bg: COLORS.criticalBg, icon: "\u25C6" },
  high: { color: COLORS.high, bg: COLORS.highBg, icon: "\u25B2" },
  medium: { color: COLORS.medium, bg: COLORS.mediumBg, icon: "\u25CF" },
  low: { color: COLORS.low, bg: COLORS.lowBg, icon: "\u25CB" },
};

// ─── Attack Graph Visualization (D3) ───
function AttackGraph({ data, selectedPath, onNodeClick }) {
  const svgRef = useRef(null);
  const simRef = useRef(null);

  const highlightedNodes = useMemo(() => {
    if (!selectedPath) return new Set();
    return new Set(selectedPath.affected_resources || []);
  }, [selectedPath]);

  useEffect(() => {
    if (!svgRef.current || !data?.graph) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;

    const g = svg.append("g");

    // Zoom
    const zoom = d3.zoom().scaleExtent([0.2, 4]).on("zoom", (e) => g.attr("transform", e.transform));
    svg.call(zoom);

    // Defs for arrowheads and glow
    const defs = svg.append("defs");

    ["normal", "priv_esc", "cross_account", "data_access"].forEach((type) => {
      const color = type === "priv_esc" ? COLORS.edgePrivEsc
        : type === "cross_account" ? COLORS.edgeCrossAccount
        : type === "data_access" ? COLORS.edgeDataAccess
        : COLORS.edgeNormal;
      defs.append("marker")
        .attr("id", `arrow-${type}`)
        .attr("viewBox", "0 -5 10 10")
        .attr("refX", 28).attr("refY", 0)
        .attr("markerWidth", 6).attr("markerHeight", 6)
        .attr("orient", "auto")
        .append("path").attr("d", "M0,-5L10,0L0,5")
        .attr("fill", color);
    });

    // Glow filter
    const filter = defs.append("filter").attr("id", "glow");
    filter.append("feGaussianBlur").attr("stdDeviation", "3").attr("result", "blur");
    const feMerge = filter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "blur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    // Prepare data
    const nodes = data.graph.nodes.map((d) => ({ ...d }));
    const nodeMap = new Map(nodes.map((n) => [n.id, n]));
    const links = data.graph.edges
      .filter((e) => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map((d) => ({ ...d }));

    // Force simulation
    const sim = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d) => d.id).distance(120))
      .force("charge", d3.forceManyBody().strength(-400))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(40));
    simRef.current = sim;

    // Links
    const link = g.append("g").selectAll("line")
      .data(links).enter().append("line")
      .attr("stroke", (d) => {
        if (d.edge_type === "priv_esc") return COLORS.edgePrivEsc;
        if (d.trust_type === "cross-account") return COLORS.edgeCrossAccount;
        if (d.edge_type === "data_access") return COLORS.edgeDataAccess;
        return COLORS.edgeNormal;
      })
      .attr("stroke-width", (d) => d.edge_type === "priv_esc" ? 2.5 : 1.5)
      .attr("stroke-dasharray", (d) => d.edge_type === "priv_esc" ? "6,3" : "none")
      .attr("stroke-opacity", 0.6)
      .attr("marker-end", (d) => {
        if (d.edge_type === "priv_esc") return "url(#arrow-priv_esc)";
        if (d.trust_type === "cross-account") return "url(#arrow-cross_account)";
        if (d.edge_type === "data_access") return "url(#arrow-data_access)";
        return "url(#arrow-normal)";
      });

    // Node groups
    const node = g.append("g").selectAll("g")
      .data(nodes).enter().append("g")
      .style("cursor", "pointer")
      .call(d3.drag()
        .on("start", (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on("drag", (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on("end", (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
      )
      .on("click", (e, d) => onNodeClick?.(d));

    // Node circles
    node.append("circle")
      .attr("r", (d) => d.type === "escalation" ? 14 : d.type === "data" ? 12 : 16)
      .attr("fill", (d) => {
        const c = { user: COLORS.nodeUser, role: COLORS.nodeRole, escalation: COLORS.nodeEsc, data: COLORS.nodeData, external: COLORS.nodeExternal }[d.type] || "#666";
        return c;
      })
      .attr("stroke", (d) => highlightedNodes.has(d.id) ? COLORS.accent : "transparent")
      .attr("stroke-width", 3)
      .attr("opacity", (d) => highlightedNodes.size === 0 || highlightedNodes.has(d.id) ? 1 : 0.3)
      .attr("filter", (d) => highlightedNodes.has(d.id) ? "url(#glow)" : "none");

    // Node icons
    node.append("text")
      .attr("text-anchor", "middle").attr("dominant-baseline", "central")
      .attr("font-size", "10px").attr("fill", "#fff").attr("pointer-events", "none")
      .text((d) => ({ user: "\uD83D\uDC64", role: "\uD83D\uDD11", escalation: "\u26A1", data: "\uD83D\uDCBE", external: "\uD83C\uDF10" }[d.type] || "?"));

    // Labels
    node.append("text")
      .attr("dy", 28).attr("text-anchor", "middle")
      .attr("font-size", "10px")
      .attr("fill", (d) => highlightedNodes.size === 0 || highlightedNodes.has(d.id) ? COLORS.text : COLORS.textMuted)
      .attr("pointer-events", "none")
      .text((d) => d.label.length > 18 ? d.label.slice(0, 16) + "\u2026" : d.label);

    // Tick
    sim.on("tick", () => {
      link.attr("x1", (d) => d.source.x).attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x).attr("y2", (d) => d.target.y);
      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    // Center on load
    svg.call(zoom.transform, d3.zoomIdentity.translate(0, 0).scale(0.85));

    return () => sim.stop();
  }, [data, highlightedNodes, onNodeClick]);

  return (
    <svg ref={svgRef} style={{ width: "100%", height: "100%", background: COLORS.bg, borderRadius: "8px" }} />
  );
}

// ─── Stat Card ───
function StatCard({ label, value, color, subtext }) {
  return (
    <div style={{
      background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 8,
      padding: "16px 20px", flex: 1, minWidth: 140,
    }}>
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
        <span style={{ fontWeight: 600, color: COLORS.text, fontSize: 14 }}>{path.name}</span>
        <span style={{
          background: sev.bg, color: sev.color, padding: "2px 10px", borderRadius: 12,
          fontSize: 11, fontWeight: 600, textTransform: "uppercase",
        }}>
          {sev.icon} {path.severity}
        </span>
      </div>
      <p style={{ color: COLORS.textDim, fontSize: 12, margin: 0, lineHeight: 1.5 }}>{path.description}</p>
      {path.mitre_techniques?.length > 0 && (
        <div style={{ display: "flex", gap: 4, marginTop: 8, flexWrap: "wrap" }}>
          {path.mitre_techniques.map((t) => (
            <span key={t} style={{
              background: "rgba(139,92,246,0.15)", color: "#a78bfa", padding: "1px 8px",
              borderRadius: 4, fontSize: 10, fontFamily: "monospace",
            }}>{t}</span>
          ))}
        </div>
      )}
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
        <h2 style={{ margin: 0, color: COLORS.text, fontSize: 18 }}>{path.name}</h2>
      </div>
      <p style={{ color: COLORS.textDim, lineHeight: 1.6, fontSize: 13 }}>{path.description}</p>

      {/* Steps */}
      <SectionHeader title="Attack Steps" icon={"\u2694"} />
      <div style={{ marginLeft: 8 }}>
        {path.steps?.map((step, i) => (
          <div key={i} style={{ display: "flex", gap: 12, marginBottom: 12, alignItems: "flex-start" }}>
            <div style={{
              minWidth: 24, height: 24, borderRadius: "50%", background: sev.bg,
              color: sev.color, display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 11, fontWeight: 700,
            }}>{i + 1}</div>
            <span style={{ color: COLORS.text, fontSize: 13, lineHeight: 1.5 }}>{step}</span>
          </div>
        ))}
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
              background: "rgba(6,182,212,0.08)", border: `1px solid rgba(6,182,212,0.2)`,
              borderRadius: 6, padding: "8px 12px", marginBottom: 6, fontSize: 12,
              color: "#67e8f9", fontFamily: "monospace",
            }}>{d}</div>
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
              <span style={{ color: COLORS.text, fontSize: 13 }}>{r}</span>
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
    { color: COLORS.edgePrivEsc, label: "Priv Esc", shape: "line-dashed" },
    { color: COLORS.edgeCrossAccount, label: "Cross-Account", shape: "line" },
    { color: COLORS.edgeDataAccess, label: "Data Access", shape: "line" },
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
      } catch { alert("Invalid JSON file"); }
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

// ─── Main Dashboard ───
export default function App() {
  const [data, setData] = useState(SAMPLE_DATA);
  const [selectedPath, setSelectedPath] = useState(null);
  const [tab, setTab] = useState("graph");
  const [selectedNode, setSelectedNode] = useState(null);
  const [dataSource, setDataSource] = useState("sample");

  // Auto-load results.json from public/ on mount
  useEffect(() => {
    fetch("/results.json")
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((json) => { setData(json); setDataSource("live"); })
      .catch(() => { /* no results.json, keep sample data */ });
  }, []);

  const handleDataLoad = useCallback((json) => {
    setData(json);
    setDataSource("file");
    setSelectedPath(null);
    setSelectedNode(null);
  }, []);

  const summary = data?.summary || {};
  const riskColor = { CRITICAL: COLORS.critical, HIGH: COLORS.high, MEDIUM: COLORS.medium, LOW: COLORS.low }[summary.risk_score] || COLORS.text;

  return (
    <div style={{
      fontFamily: "'IBM Plex Sans', -apple-system, sans-serif",
      background: COLORS.bg, color: COLORS.text, minHeight: "100vh",
      display: "flex", flexDirection: "column",
    }}>
      {/* Header */}
      <div style={{
        padding: "16px 24px", borderBottom: `1px solid ${COLORS.border}`,
        display: "flex", justifyContent: "space-between", alignItems: "center",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: 22 }}>{"\uD83D\uDEE1"}</span>
          <div>
            <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, letterSpacing: "-0.02em" }}>
              SCOPE
            </h1>
            <span style={{ fontSize: 11, color: COLORS.textDim }}>
              Attack Graph — Account {data.account_id} {"\u2022"} {data.region}
              {dataSource === "sample" && " \u2022 Sample Data"}
            </span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <FileUpload onDataLoad={handleDataLoad} />
          <div style={{
            padding: "6px 16px", borderRadius: 6, fontWeight: 700, fontSize: 13,
            background: riskColor + "20", color: riskColor, border: `1px solid ${riskColor}40`,
          }}>
            RISK: {summary.risk_score || "N/A"}
          </div>
        </div>
      </div>

      {/* Stats Row */}
      <div style={{ display: "flex", gap: 12, padding: "16px 24px", flexWrap: "wrap" }}>
        <StatCard label="Users" value={summary.total_users} subtext={`${summary.users_without_mfa} no MFA`} color={summary.users_without_mfa > 0 ? COLORS.high : COLORS.text} />
        <StatCard label="Roles" value={summary.total_roles} />
        <StatCard label="Trust Relationships" value={summary.total_trust_relationships} subtext={`${summary.cross_account_trusts} cross-account`} />
        <StatCard label="Wildcard Trusts" value={summary.wildcard_trust_policies} color={summary.wildcard_trust_policies > 0 ? COLORS.critical : COLORS.low} />
        <StatCard label="Critical PrivEsc" value={summary.critical_priv_esc_risks} color={summary.critical_priv_esc_risks > 0 ? COLORS.critical : COLORS.low} />
        <StatCard label="Attack Paths" value={data.attack_paths?.length || 0} color={COLORS.accent} />
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, display: "flex", padding: "0 24px 24px", gap: 16, minHeight: 0 }}>
        {/* Left: Attack Paths List */}
        <div style={{ width: 320, minWidth: 280, display: "flex", flexDirection: "column" }}>
          <div style={{ marginBottom: 12, fontSize: 13, fontWeight: 600, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Attack Paths
          </div>
          <div style={{ flex: 1, overflowY: "auto" }}>
            {(data.attack_paths || []).map((path, i) => (
              <AttackPathCard
                key={i}
                path={path}
                isSelected={selectedPath === path}
                onClick={() => setSelectedPath(selectedPath === path ? null : path)}
              />
            ))}
          </div>
        </div>

        {/* Center: Graph / Detail toggle */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          <div style={{ display: "flex", gap: 4, marginBottom: 12 }}>
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
          </div>
          <div style={{
            flex: 1, background: COLORS.bgCard, borderRadius: 8,
            border: `1px solid ${COLORS.border}`, position: "relative", overflow: "hidden",
          }}>
            {tab === "graph" ? (
              <>
                <AttackGraph data={data} selectedPath={selectedPath} onNodeClick={setSelectedNode} />
                <GraphLegend />
                {selectedNode && (
                  <div style={{
                    position: "absolute", top: 12, right: 12, background: "rgba(17,24,39,0.95)",
                    border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 14, maxWidth: 220,
                  }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: COLORS.text, marginBottom: 4 }}>{selectedNode.label}</div>
                    <div style={{ fontSize: 11, color: COLORS.textDim }}>Type: {selectedNode.type}</div>
                    {selectedNode.mfa !== undefined && (
                      <div style={{ fontSize: 11, color: selectedNode.mfa ? COLORS.low : COLORS.critical }}>
                        MFA: {selectedNode.mfa ? "Enabled" : "Disabled"}
                      </div>
                    )}
                    <button onClick={() => setSelectedNode(null)}
                      style={{ marginTop: 8, fontSize: 10, color: COLORS.textDim, background: "none", border: "none", cursor: "pointer" }}>
                      {"\u2715"} close
                    </button>
                  </div>
                )}
              </>
            ) : (
              <PathDetail path={selectedPath} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
