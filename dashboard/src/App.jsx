import { useState, useEffect, useRef, useCallback, useMemo } from "react";
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

// ─── Attack Graph Visualization (D3) ───
function AttackGraph({ data, selectedPath, onNodeClick }) {
  const svgRef = useRef(null);
  const simRef = useRef(null);

  const highlightedNodes = useMemo(() => {
    if (!selectedPath) return new Set();
    return new Set(selectedPath.affected_resources || []);
  }, [selectedPath]);

  const highlightedEdges = useMemo(() => {
    if (!selectedPath || !selectedPath.affected_resources) return new Set();
    const resources = selectedPath.affected_resources || [];
    const edgeKeys = new Set();
    for (let i = 0; i < resources.length; i++) {
      for (let j = i + 1; j < resources.length; j++) {
        edgeKeys.add(`${resources[i]}|${resources[j]}`);
        edgeKeys.add(`${resources[j]}|${resources[i]}`);
      }
    }
    return edgeKeys;
  }, [selectedPath]);

  useEffect(() => {
    if (!svgRef.current || !data?.graph) return;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;

    const g = svg.append("g");

    const zoom = d3.zoom().scaleExtent([0.2, 4]).on("zoom", (e) => g.attr("transform", e.transform));
    svg.call(zoom);

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

    const filter = defs.append("filter").attr("id", "glow");
    filter.append("feGaussianBlur").attr("stdDeviation", "3").attr("result", "blur");
    const feMerge = filter.append("feMerge");
    feMerge.append("feMergeNode").attr("in", "blur");
    feMerge.append("feMergeNode").attr("in", "SourceGraphic");

    const nodes = data.graph.nodes.map((d) => ({ ...d }));
    const nodeMap = new Map(nodes.map((n) => [n.id, n]));
    const links = data.graph.edges
      .filter((e) => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map((d) => ({ ...d }));

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
      .attr("stroke", (d) => {
        if (d.edge_type === "priv_esc") return COLORS.edgePrivEsc;
        if (d.trust_type === "cross-account") return COLORS.edgeCrossAccount;
        if (d.edge_type === "data_access") return COLORS.edgeDataAccess;
        return COLORS.edgeNormal;
      })
      .attr("stroke-width", (d) => {
        if (hasHighlight && isEdgeHighlighted(d)) return 4;
        return d.edge_type === "priv_esc" ? 2.5 : 1.5;
      })
      .attr("stroke-dasharray", (d) => d.edge_type === "priv_esc" ? "6,3" : "none")
      .attr("stroke-opacity", (d) => {
        if (!hasHighlight) return 0.6;
        return isEdgeHighlighted(d) ? 1 : 0.08;
      })
      .attr("marker-end", (d) => {
        if (d.edge_type === "priv_esc") return "url(#arrow-priv_esc)";
        if (d.trust_type === "cross-account") return "url(#arrow-cross_account)";
        if (d.edge_type === "data_access") return "url(#arrow-data_access)";
        return "url(#arrow-normal)";
      });

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
        const c = { user: COLORS.nodeUser, role: COLORS.nodeRole, escalation: COLORS.nodeEsc, data: COLORS.nodeData, external: COLORS.nodeExternal }[d.type] || "#666";
        return c;
      })
      .attr("stroke", (d) => highlightedNodes.has(d.id) ? COLORS.accent : "transparent")
      .attr("stroke-width", 3)
      .attr("opacity", (d) => !hasHighlight || highlightedNodes.has(d.id) ? 1 : 0.08)
      .attr("filter", (d) => highlightedNodes.has(d.id) ? "url(#glow)" : "none");

    node.append("text")
      .attr("text-anchor", "middle").attr("dominant-baseline", "central")
      .attr("font-size", "10px").attr("fill", "#fff").attr("pointer-events", "none")
      .attr("opacity", (d) => !hasHighlight || highlightedNodes.has(d.id) ? 1 : 0.08)
      .text((d) => ({ user: "\uD83D\uDC64", role: "\uD83D\uDD11", escalation: "\u26A1", data: "\uD83D\uDCBE", external: "\uD83C\uDF10" }[d.type] || "?"));

    node.append("text")
      .attr("dy", 28).attr("text-anchor", "middle")
      .attr("font-size", "10px")
      .attr("fill", (d) => !hasHighlight || highlightedNodes.has(d.id) ? COLORS.text : COLORS.textMuted)
      .attr("pointer-events", "none")
      .attr("opacity", (d) => !hasHighlight || highlightedNodes.has(d.id) ? 1 : 0.08)
      .text((d) => d.label.length > 18 ? d.label.slice(0, 16) + "\u2026" : d.label);

    sim.on("tick", () => {
      link.attr("x1", (d) => d.source.x).attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x).attr("y2", (d) => d.target.y);
      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    svg.call(zoom.transform, d3.zoomIdentity.translate(0, 0).scale(0.85));

    return () => sim.stop();
  }, [data, highlightedNodes, highlightedEdges, onNodeClick]);

  return (
    <svg ref={svgRef} style={{ width: "100%", height: "100%", background: COLORS.bg, borderRadius: "8px" }} />
  );
}

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
        <span style={{ fontWeight: 600, color: COLORS.text, fontSize: 14 }}>{path.name}</span>
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
    return data.attack_paths.filter(
      (p) => p.affected_resources?.includes(node.id)
    );
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
            <div style={{ fontSize: 15, fontWeight: 700, color: COLORS.text, marginBottom: 4 }}>{node.label}</div>
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
            const edgeColor = e.edge_type === "priv_esc" ? COLORS.edgePrivEsc
              : e.trust_type === "cross-account" ? COLORS.edgeCrossAccount
              : e.edge_type === "data_access" ? COLORS.edgeDataAccess
              : COLORS.textDim;
            return (
              <div key={i} style={{
                fontSize: 11, color: COLORS.text, marginBottom: 4,
                display: "flex", alignItems: "center", gap: 4,
              }}>
                <span style={{ color: edgeColor }}>{direction}</span>
                <span style={{ fontFamily: "monospace", fontSize: 10 }}>{otherId}</span>
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
function RunHistoryPanel({ runs, onSelectRun, onClose }) {
  return (
    <div style={{
      position: "fixed", top: 0, right: 0, width: 320, height: "100vh",
      background: COLORS.bg, borderLeft: `1px solid ${COLORS.border}`,
      zIndex: 100, overflowY: "auto", boxShadow: "-4px 0 24px rgba(0,0,0,0.4)",
    }}>
      <div style={{ padding: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: COLORS.text }}>Run History</h2>
          <button onClick={onClose}
            style={{ background: "none", border: "none", color: COLORS.textDim, cursor: "pointer", fontSize: 16 }}>
            {"\u2715"}
          </button>
        </div>
        {runs.length === 0 ? (
          <div style={{ color: COLORS.textDim, fontSize: 13 }}>No previous runs found.</div>
        ) : (
          runs.map((run) => {
            const riskColor = { CRITICAL: COLORS.critical, HIGH: COLORS.high, MEDIUM: COLORS.medium, LOW: COLORS.low }[run.risk] || COLORS.textDim;
            const phaseSource = run.source || "audit";
            const phaseColor = PHASE_CONFIG[phaseSource]?.color || COLORS.textDim;
            return (
              <div key={run.run_id}
                onClick={() => onSelectRun(run)}
                style={{
                  background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
                  borderRadius: 8, padding: 14, marginBottom: 10, cursor: "pointer",
                  transition: "border-color 0.2s",
                  borderLeft: `3px solid ${phaseColor}`,
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: "monospace" }}>
                    {run.run_id}
                  </span>
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <span style={{
                      fontSize: 9, fontWeight: 700, color: phaseColor,
                      background: phaseColor + "18", padding: "1px 6px", borderRadius: 6,
                      textTransform: "uppercase", letterSpacing: "0.05em",
                    }}>{phaseSource}</span>
                    {run.risk && (
                      <span style={{
                        fontSize: 10, fontWeight: 700, color: riskColor,
                        background: riskColor + "18", padding: "1px 8px", borderRadius: 8,
                      }}>{run.risk}</span>
                    )}
                  </div>
                </div>
                <div style={{ fontSize: 11, color: COLORS.textDim }}>
                  {run.date ? new Date(run.date).toLocaleString() : "Unknown date"}
                </div>
                <div style={{ fontSize: 11, color: COLORS.textDim, marginTop: 2 }}>
                  {run.target || "Unknown target"}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

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
      case "trusts":
        return { title: "Trust Relationships", items: trusts };
      case "wildcards":
        return { title: "Wildcard Trusts", items: trusts.filter((t) => t.is_wildcard) };
      case "privesc":
        return { title: "Critical PrivEsc", items: paths.filter((p) => p.severity === "critical" && (p.category === "privilege_escalation" || !p.category)) };
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
          <span style={{ color: COLORS.textDim }}>Keys: {item.access_keys ?? 0}</span>
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
    const riskColor = { CRITICAL: COLORS.critical, HIGH: COLORS.high, MEDIUM: COLORS.medium, LOW: COLORS.low }[item.risk] || COLORS.textDim;
    return (
      <div
        onClick={() => onHighlightNode?.(item.role_id)}
        style={{
          background: COLORS.bgCard, border: `1px solid ${COLORS.border}`,
          borderRadius: 8, padding: 14, marginBottom: 10, cursor: "pointer",
          borderLeft: `3px solid ${riskColor}`,
          transition: "border-color 0.2s",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: COLORS.text }}>{item.role_id}</span>
          <span style={{ fontSize: 10, fontWeight: 700, color: riskColor, background: riskColor + "18", padding: "1px 8px", borderRadius: 8 }}>{item.risk}</span>
        </div>
        <div style={{ fontSize: 11, color: COLORS.textDim, fontFamily: "monospace", wordBreak: "break-all", marginBottom: 6 }}>{item.principal}</div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", fontSize: 10 }}>
          <span style={{ color: COLORS.textDim }}>{item.trust_type}</span>
          {item.is_wildcard && <span style={{ color: COLORS.critical }}>Wildcard</span>}
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
        <span style={{ fontSize: 13, fontWeight: 600, color: COLORS.text }}>{item.name}</span>
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

  return (
    <>
      {/* Stats Row */}
      <div style={{ display: "flex", gap: 12, padding: "16px 24px", flexWrap: "wrap" }}>
        <StatCard label="Users" value={summary.total_users} subtext={`${summary.users_without_mfa || 0} no MFA`} color={summary.users_without_mfa > 0 ? COLORS.high : COLORS.text} active={activeStatPanel === "users"} onClick={() => handleStatClick("users")} />
        <StatCard label="Roles" value={summary.total_roles} active={activeStatPanel === "roles"} onClick={() => handleStatClick("roles")} />
        <StatCard label="Trust Relationships" value={summary.total_trust_relationships} subtext={`${summary.cross_account_trusts || 0} cross-account`} active={activeStatPanel === "trusts"} onClick={() => handleStatClick("trusts")} />
        <StatCard label="Wildcard Trusts" value={summary.wildcard_trust_policies} color={summary.wildcard_trust_policies > 0 ? COLORS.critical : COLORS.low} active={activeStatPanel === "wildcards"} onClick={() => handleStatClick("wildcards")} />
        <StatCard label="Critical PrivEsc" value={summary.critical_priv_esc_risks} color={summary.critical_priv_esc_risks > 0 ? COLORS.critical : COLORS.low} active={activeStatPanel === "privesc"} onClick={() => handleStatClick("privesc")} />
        <StatCard label="Attack Paths" value={data.attack_paths?.length || 0} color={COLORS.accent} active={activeStatPanel === "paths"} onClick={() => handleStatClick("paths")} />
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, display: "flex", padding: "0 24px 24px", gap: 16, minHeight: 0 }}>
        {/* Left: Attack Paths List */}
        <div style={{ width: 320, minWidth: 280, display: "flex", flexDirection: "column" }}>
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
            {filteredPaths.length === 0 ? (
              <div style={{ color: COLORS.textDim, fontSize: 12, textAlign: "center", padding: 20 }}>
                No paths match filters
              </div>
            ) : (
              filteredPaths.map((path, i) => (
                <AttackPathCard
                  key={i}
                  path={path}
                  isSelected={selectedPath === path}
                  onClick={() => setSelectedPath(selectedPath === path ? null : path)}
                />
              ))
            )}
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
                  <NodeDetailPanel
                    node={selectedNode}
                    data={data}
                    selectedPath={selectedPath}
                    onSelectPath={(p) => { setSelectedPath(p); setTab("detail"); }}
                    onClose={() => setSelectedNode(null)}
                  />
                )}
              </>
            ) : (
              <PathDetail path={selectedPath} />
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
                <span style={{ fontSize: 14, fontWeight: 600, color: COLORS.text }}>{policy.name}</span>
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
                {/* Impact Analysis */}
                {policy.impact_analysis && (
                  <div style={{ marginTop: 12, marginBottom: 12 }}>
                    <div style={{ fontSize: 10, color: COLORS.textDim, textTransform: "uppercase", marginBottom: 6 }}>Impact Analysis</div>
                    {policy.impact_analysis.prevents?.length > 0 && (
                      <div style={{ fontSize: 12, color: COLORS.text, marginBottom: 4 }}>
                        Prevents: {policy.impact_analysis.prevents.join(", ")}
                      </div>
                    )}
                    {policy.impact_analysis.break_glass && (
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
                {policy.policy_json && (
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
                    <span style={{ fontSize: 13, fontWeight: 600, color: COLORS.text }}>{rule.name}</span>
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
                  <div style={{ display: "flex", alignItems: "flex-start", gap: 4 }}>
                    <pre style={{
                      flex: 1, background: "rgba(6,182,212,0.08)", border: `1px solid rgba(6,182,212,0.2)`,
                      borderRadius: 6, padding: "8px 12px", fontSize: 11,
                      color: "#67e8f9", fontFamily: "monospace", margin: 0,
                      whiteSpace: "pre-wrap", overflow: "auto", maxHeight: 200,
                    }}>{rule.spl}</pre>
                    <CopyButton text={rule.spl} />
                  </div>
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

  const catColors = { scp: COLORS.high, rcp: COLORS.medium, detection: "#06b6d4", control: COLORS.low };
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
            <span style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, flex: 1 }}>{item.action}</span>
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

function DefendView({ data }) {
  const [defendTab, setDefendTab] = useState("policies");
  const summary = data?.summary || {};

  return (
    <>
      {/* Stats Row */}
      <div style={{ display: "flex", gap: 12, padding: "16px 24px", flexWrap: "wrap" }}>
        <StatCard label="SCPs" value={summary.scps_generated ?? data.scps?.length ?? 0} color={COLORS.high} />
        <StatCard label="RCPs" value={summary.rcps_generated ?? data.rcps?.length ?? 0} color={COLORS.medium} />
        <StatCard label="Detections" value={summary.detections_generated ?? data.detections?.length ?? 0} color="#06b6d4" />
        <StatCard label="Controls" value={summary.controls_recommended ?? data.security_controls?.length ?? 0} color={COLORS.low} />
        <StatCard label="Quick Wins" value={summary.quick_wins ?? 0} color={COLORS.accent} />
      </div>

      {/* Main Content: Sidebar + Tabbed Center */}
      <div style={{ flex: 1, display: "flex", padding: "0 24px 24px", gap: 16, minHeight: 0 }}>
        {/* Prioritization Sidebar */}
        <PrioritizationSidebar items={data.prioritization} />

        {/* Center: Tabbed content */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          <div style={{ display: "flex", gap: 4, marginBottom: 12 }}>
            {[
              { key: "policies", label: "Policies" },
              { key: "detections", label: "Detections" },
              { key: "controls", label: "Controls" },
            ].map((t) => (
              <button
                key={t.key}
                onClick={() => setDefendTab(t.key)}
                style={{
                  padding: "6px 18px", borderRadius: 6,
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
            {defendTab === "policies" && <PolicyViewer scps={data.scps} rcps={data.rcps} />}
            {defendTab === "detections" && <DetectionRulesList detections={data.detections} />}
            {defendTab === "controls" && <ControlsMatrix controls={data.security_controls} />}
          </div>
        </div>
      </div>
    </>
  );
}

// ─── Phase Mismatch Banner ───
function PhaseMismatchBanner({ activePhase, dataSource, onSwitchPhase }) {
  const sourceLabel = PHASE_CONFIG[dataSource]?.label || dataSource;
  const activeLabel = PHASE_CONFIG[activePhase]?.label || activePhase;
  return (
    <div style={{
      padding: "16px 24px", background: "rgba(245,158,11,0.08)",
      border: `1px solid rgba(245,158,11,0.2)`, margin: "16px 24px",
      borderRadius: 8, textAlign: "center",
    }}>
      <div style={{ fontSize: 14, color: COLORS.text, marginBottom: 8 }}>
        This run does not contain <strong>{activeLabel}</strong> data.
      </div>
      <div style={{ fontSize: 12, color: COLORS.textDim, marginBottom: 12 }}>
        The loaded data is from a <strong style={{ color: PHASE_CONFIG[dataSource]?.color }}>{sourceLabel}</strong> run.
      </div>
      <button
        onClick={() => onSwitchPhase(dataSource)}
        style={{
          padding: "6px 18px", borderRadius: 6, cursor: "pointer",
          background: PHASE_CONFIG[dataSource]?.color + "18",
          border: `1px solid ${PHASE_CONFIG[dataSource]?.color}`,
          color: PHASE_CONFIG[dataSource]?.color,
          fontSize: 12, fontWeight: 600,
        }}
      >
        Switch to {sourceLabel} tab
      </button>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// ─── Main Dashboard ───
// ═══════════════════════════════════════════════════════════════════
export default function App() {
  const [data, setData] = useState(null);
  const [selectedPath, setSelectedPath] = useState(null);
  const [tab, setTab] = useState("graph");
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activePhase, setActivePhase] = useState("audit");

  // Interactive state
  const [searchQuery, setSearchQuery] = useState("");
  const [activeSeverities, setActiveSeverities] = useState(new Set(["critical", "high", "medium", "low"]));
  const [activeCategories, setActiveCategories] = useState(new Set(Object.keys(CATEGORY_CONFIG)));
  const [sortMode, setSortMode] = useState("severity");
  const [showHistory, setShowHistory] = useState(false);
  const [runIndex, setRunIndex] = useState(null);
  const [activeStatPanel, setActiveStatPanel] = useState(null);

  // Detect phase from data source
  const dataSource = useMemo(() => {
    if (!data) return "audit";
    return data.source || "audit";
  }, [data]);

  // Auto-switch phase when data source changes
  useEffect(() => {
    if (dataSource === "audit" || dataSource === "exploit") {
      setActivePhase((prev) => (prev === "audit" || prev === "exploit") ? prev : dataSource);
    } else {
      setActivePhase(dataSource);
    }
  }, [dataSource]);

  // Check if current phase matches loaded data
  const isPhaseMatch = useMemo(() => {
    if (activePhase === "audit" || activePhase === "exploit") {
      return dataSource === "audit" || dataSource === "exploit";
    }
    return activePhase === dataSource;
  }, [activePhase, dataSource]);

  // Auto-load latest results
  useEffect(() => {
    fetch("/index.json")
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((index) => {
        setRunIndex(index);
        if (index && index.latest) {
          return fetch(`/${index.latest}.json`).then((r) => {
            if (!r.ok) throw new Error();
            return r.json();
          });
        }
        throw new Error("no latest");
      })
      .then((json) => {
        if (json && json.account_id) setData(json);
        setLoading(false);
      })
      .catch(() => {
        fetch("/results.json")
          .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
          .then((json) => {
            if (json && json.account_id) setData(json);
            setLoading(false);
          })
          .catch(() => { setLoading(false); });
      });
  }, []);

  const handleDataLoad = useCallback((json) => {
    setData(json);
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

  const handleSelectRun = useCallback((run) => {
    const file = run.file || `${run.run_id}.json`;
    fetch(`/${file}`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((json) => {
        if (json && json.account_id) {
          setData(json);
          setSelectedPath(null);
          setSelectedNode(null);
          setSearchQuery("");
          setShowHistory(false);
          setActiveStatPanel(null);
          // Auto-switch phase based on loaded run
          const source = json.source || run.source || "audit";
          if (source === "audit" || source === "exploit") {
            setActivePhase(source);
          } else {
            setActivePhase(source);
          }
        }
      })
      .catch(() => { alert(`Failed to load run: ${run.run_id}`); });
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

  if (!data) return (
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

  const summary = data?.summary || {};
  const riskColor = { CRITICAL: COLORS.critical, HIGH: COLORS.high, MEDIUM: COLORS.medium, LOW: COLORS.low }[summary.risk_score] || COLORS.text;
  const historyRuns = runIndex?.runs || [];
  const phaseColor = PHASE_CONFIG[activePhase]?.color || COLORS.accent;

  return (
    <div style={{
      fontFamily: "'IBM Plex Sans', -apple-system, sans-serif",
      background: COLORS.bg, color: COLORS.text, minHeight: "100vh",
      display: "flex", flexDirection: "column",
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
            <span style={{ fontSize: 11, color: COLORS.textDim }}>
              Account {data.account_id} {"\u2022"} {data.region || "N/A"}
              {data.source && <> {"\u2022"} <span style={{ color: PHASE_CONFIG[data.source]?.color || COLORS.accent }}>{data.source}</span></>}
            </span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          {historyRuns.length > 0 && (
            <button
              onClick={() => setShowHistory(!showHistory)}
              style={{
                padding: "6px 14px", borderRadius: 6, cursor: "pointer",
                background: showHistory ? COLORS.accent + "18" : COLORS.bgCard,
                border: `1px solid ${showHistory ? COLORS.accent : COLORS.border}`,
                color: showHistory ? COLORS.accent : COLORS.textDim,
                fontSize: 12, fontWeight: 600,
              }}
            >
              History
            </button>
          )}
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

      {/* Phase Tab Bar */}
      <div style={{
        display: "flex", gap: 0, padding: "0 24px",
        borderBottom: `1px solid ${COLORS.border}`,
      }}>
        {Object.entries(PHASE_CONFIG).map(([key, cfg]) => {
          const isActive = activePhase === key;
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
              }}
            >
              {cfg.label}
            </button>
          );
        })}
      </div>

      {/* Phase Content */}
      {!isPhaseMatch ? (
        <PhaseMismatchBanner
          activePhase={activePhase}
          dataSource={dataSource}
          onSwitchPhase={setActivePhase}
        />
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

      {/* Run History Sidebar */}
      {showHistory && (
        <RunHistoryPanel
          runs={historyRuns}
          onSelectRun={handleSelectRun}
          onClose={() => setShowHistory(false)}
        />
      )}
    </div>
  );
}
