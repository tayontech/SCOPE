---
name: scope-render
description: Dashboard rendering middleware — reads normalized JSON from ./data/, writes self-contained HTML dashboards to run directories. Auto-called by other agents after scope-data. Not a slash command.
compatibility: No external dependencies. Reads local files only.
allowed-tools: Read, Write, Bash, Glob
color: gray
---

<role>
You are SCOPE's dashboard rendering layer. Your mission: read normalized JSON data from `./data/` and produce self-contained HTML dashboards in agent run directories.

**You are middleware, not a user-facing agent.** You are invoked automatically by other SCOPE agents as the last step of the post-processing pipeline (after scope-data and scope-evidence). You do not have operator gates, slash commands, or credential checks.

**Input:** A PHASE name and a RUN_DIR path, passed by the calling agent.
**Output:** A self-contained HTML dashboard file in the run directory.

**Behavior:**
1. Extract RUN_ID from the RUN_DIR path (basename)
2. Read the normalized data from `./data/<phase>/<run-id>.json`
3. Extract the `payload` object and envelope metadata
4. Route to the phase-specific renderer
5. Construct the DATA_JSON object for the template
6. Write the HTML file with embedded data to the run directory
7. Verify the file was written

**On failure:** Log a warning and return. Do not stop the calling agent's run. The raw artifacts and normalized data already exist — dashboard rendering is a visualization layer, not a gating requirement.

**No operator interaction.** Do not ask for approval, display gates, or pause for input. Run silently.
</role>

<dispatch>
## Dispatch — Phase-Specific Rendering

When invoked, the calling agent provides two values:

- **PHASE**: one of `audit`, `remediate`, `exploit`, `investigate`
- **RUN_DIR**: path to the run directory

### Dispatch Steps

1. Extract the RUN_ID:
   ```bash
   RUN_ID=$(basename "$RUN_DIR")
   ```

2. Read the normalized data file:
   ```
   DATA_FILE="./data/$PHASE/$RUN_ID.json"
   ```
   If this file does not exist, log a warning and return without generating a dashboard.

3. Parse the JSON file. Extract the `payload` object and envelope fields (`run_id`, `timestamp`, `account_id`, `region`).

4. Route to the phase-specific renderer:
   - `audit` → `<audit_renderer>` → writes `$RUN_DIR/attack-graph.html`
   - `remediate` → `<remediate_renderer>` → writes `$RUN_DIR/dashboard.html`
   - `exploit` → `<exploit_renderer>` → writes `$RUN_DIR/dashboard.html`
   - `investigate` → `<investigate_renderer>` → writes `$RUN_DIR/dashboard.html`

5. Verify the output file was written:
   ```bash
   test -f "$RUN_DIR/<filename>" && echo "Dashboard generated" || echo "WARNING: Dashboard not created"
   ```

### DATA_JSON Construction

Each renderer constructs a DATA_JSON object from the normalized payload. The DATA_JSON is embedded directly as a JavaScript object literal in the HTML template — replace `{{DATA_JSON}}` with the serialized object. Use proper JSON serialization: double quotes, escape special characters, no trailing commas.

### Cross-Contamination Prevention

- DATA_JSON is built from the normalized data file only — no reads from other run directories
- HTML is written to `$RUN_DIR/` — scoped to this session
- Data is embedded as a JS literal — no runtime data loading
- No shared state with other dashboard files
</dispatch>


<audit_renderer>
## Audit Renderer — Interactive D3 Attack Graph

**Output file:** `$RUN_DIR/attack-graph.html`

### Data Source

Read `./data/audit/<RUN_ID>.json`. Extract the `payload` object — this contains `summary`, `graph`, `attack_paths`, and `principals`. Add `account_id`, `region`, and `timestamp` from the envelope.

The DATA_JSON object passed to the template must follow this structure:

```json
{
  "account_id": "string — from envelope",
  "region": "string — from envelope",
  "timestamp": "string — ISO8601 from envelope",
  "summary": { ... },
  "graph": { "nodes": [...], "edges": [...] },
  "attack_paths": [...]
}
```

### Node ID Conventions

- Users: `user:<username>` (e.g., `user:alice`)
- Roles: `role:<rolename>` (e.g., `role:AdminRole`)
- Escalation vectors: `esc:<action>` (e.g., `esc:iam:CreatePolicyVersion`)
- Data resources: `data:<service>:<name>` (e.g., `data:s3:prod-bucket`)
- External accounts: `ext:<arn>` (e.g., `ext:arn:aws:iam::999888777666:root`)

### Edge Construction Rules

- User/role to role trust: `edge_type: "normal"`, `trust_type: "same-account"` or `"cross-account"`
- Privilege escalation: `edge_type: "priv_esc"`, set `severity` to the attack path severity
- Data access: `edge_type: "data_access"`
- Cross-account trust: `edge_type: "cross_account"`, `trust_type: "cross-account"`

### Complete HTML Template

Copy this template exactly, then replace `{{DATA_JSON}}` with the constructed data object:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SCOPE Attack Graph</title>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg: #0a0e17;
      --surface: #111827;
      --surface-alt: #1a2332;
      --border: #1f2937;
      --text: #e5e7eb;
      --text-dim: #9ca3af;
      --text-muted: #6b7280;
      --purple: #a78bfa;
      --cyan: #22d3ee;
      --red: #ef4444;
      --green: #34d399;
      --amber: #f59e0b;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #3b82f6;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      overflow: hidden;
      height: 100vh;
      width: 100vw;
    }

    /* ── Header ── */
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.75rem 1.25rem;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      z-index: 100;
      position: relative;
    }
    .header-left {
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .header-title {
      font-size: 1rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      color: var(--cyan);
    }
    .header-account {
      font-size: 0.8rem;
      color: var(--text-dim);
    }
    .header-account span {
      color: var(--text);
      font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    }
    .risk-badge {
      padding: 0.25rem 0.75rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .risk-badge.critical { background: rgba(239,68,68,0.2); color: var(--critical); border: 1px solid var(--critical); }
    .risk-badge.high { background: rgba(249,115,22,0.2); color: var(--high); border: 1px solid var(--high); }
    .risk-badge.medium { background: rgba(245,158,11,0.2); color: var(--medium); border: 1px solid var(--medium); }
    .risk-badge.low { background: rgba(59,130,246,0.2); color: var(--low); border: 1px solid var(--low); }

    /* ── Stats Row ── */
    .stats-row {
      display: flex;
      gap: 0;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      z-index: 99;
      position: relative;
    }
    .stat-card {
      flex: 1;
      text-align: center;
      padding: 0.6rem 0.5rem;
      border-right: 1px solid var(--border);
    }
    .stat-card:last-child { border-right: none; }
    .stat-value {
      font-size: 1.3rem;
      font-weight: 700;
      color: var(--text);
      font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    }
    .stat-value.critical-val { color: var(--critical); }
    .stat-label {
      font-size: 0.65rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      margin-top: 0.15rem;
    }

    /* ── Main Layout ── */
    .main-layout {
      display: flex;
      height: calc(100vh - 105px);
    }

    /* ── Sidebar ── */
    .sidebar {
      width: 320px;
      min-width: 320px;
      background: var(--surface);
      border-right: 1px solid var(--border);
      overflow-y: auto;
      padding: 0.75rem;
    }
    .sidebar-title {
      font-size: 0.7rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 0.75rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }
    .attack-card {
      background: var(--surface-alt);
      border-radius: 6px;
      padding: 0.75rem;
      margin-bottom: 0.5rem;
      cursor: pointer;
      border-left: 3px solid transparent;
      transition: background 0.15s, border-color 0.15s;
    }
    .attack-card:hover { background: #1e293b; }
    .attack-card.selected { background: #1e293b; }
    .attack-card.critical { border-left-color: var(--critical); }
    .attack-card.high { border-left-color: var(--high); }
    .attack-card.medium { border-left-color: var(--medium); }
    .attack-card.low { border-left-color: var(--low); }
    .attack-card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.35rem;
    }
    .attack-card-name {
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--text);
      flex: 1;
      margin-right: 0.5rem;
    }
    .severity-pill {
      font-size: 0.6rem;
      font-weight: 700;
      padding: 0.15rem 0.4rem;
      border-radius: 3px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      white-space: nowrap;
    }
    .severity-pill.critical { background: rgba(239,68,68,0.2); color: var(--critical); }
    .severity-pill.high { background: rgba(249,115,22,0.2); color: var(--high); }
    .severity-pill.medium { background: rgba(245,158,11,0.2); color: var(--medium); }
    .severity-pill.low { background: rgba(59,130,246,0.2); color: var(--low); }
    .attack-card-desc {
      font-size: 0.72rem;
      color: var(--text-dim);
      line-height: 1.4;
      margin-bottom: 0.4rem;
    }
    .mitre-tags {
      display: flex;
      flex-wrap: wrap;
      gap: 0.3rem;
    }
    .mitre-tag {
      font-size: 0.6rem;
      font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
      background: rgba(34,211,238,0.1);
      color: var(--cyan);
      padding: 0.1rem 0.35rem;
      border-radius: 3px;
      border: 1px solid rgba(34,211,238,0.2);
    }
    .attack-detail {
      display: none;
      margin-top: 0.5rem;
      padding-top: 0.5rem;
      border-top: 1px solid var(--border);
    }
    .attack-card.selected .attack-detail { display: block; }
    .detail-section-label {
      font-size: 0.6rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      margin-top: 0.4rem;
      margin-bottom: 0.2rem;
    }
    .detail-list {
      list-style: none;
      padding: 0;
    }
    .detail-list li {
      font-size: 0.7rem;
      color: var(--text-dim);
      padding: 0.15rem 0;
      padding-left: 0.75rem;
      position: relative;
    }
    .detail-list li::before {
      content: "\25B8";
      position: absolute;
      left: 0;
      color: var(--text-muted);
    }

    /* ── Graph Panel ── */
    .graph-panel {
      flex: 1;
      position: relative;
      overflow: hidden;
    }

    /* Filter Buttons */
    .filter-bar {
      position: absolute;
      top: 0.75rem;
      left: 50%;
      transform: translateX(-50%);
      display: flex;
      gap: 0.35rem;
      z-index: 20;
      background: rgba(17,24,39,0.85);
      padding: 0.35rem 0.5rem;
      border-radius: 6px;
      border: 1px solid var(--border);
      backdrop-filter: blur(8px);
    }
    .filter-btn {
      font-size: 0.68rem;
      font-weight: 600;
      padding: 0.3rem 0.65rem;
      border-radius: 4px;
      border: 1px solid var(--border);
      background: transparent;
      color: var(--text-dim);
      cursor: pointer;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      transition: all 0.15s;
    }
    .filter-btn:hover { border-color: var(--text-muted); color: var(--text); }
    .filter-btn.active { background: rgba(34,211,238,0.15); border-color: var(--cyan); color: var(--cyan); }
    .filter-btn.active-critical { background: rgba(239,68,68,0.15); border-color: var(--critical); color: var(--critical); }
    .filter-btn.active-high { background: rgba(249,115,22,0.15); border-color: var(--high); color: var(--high); }
    .filter-btn.active-medium { background: rgba(245,158,11,0.15); border-color: var(--medium); color: var(--medium); }
    .filter-btn.active-low { background: rgba(59,130,246,0.15); border-color: var(--low); color: var(--low); }

    /* SVG graph */
    .graph-svg {
      width: 100%;
      height: 100%;
      display: block;
    }

    /* Node info overlay */
    .node-info {
      display: none;
      position: absolute;
      bottom: 1rem;
      right: 1rem;
      width: 280px;
      background: rgba(17,24,39,0.95);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      z-index: 30;
      backdrop-filter: blur(8px);
    }
    .node-info.visible { display: block; }
    .node-info-title {
      font-size: 0.85rem;
      font-weight: 700;
      color: var(--text);
      margin-bottom: 0.25rem;
      word-break: break-all;
    }
    .node-info-type {
      font-size: 0.7rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      margin-bottom: 0.5rem;
    }
    .node-info-edges {
      font-size: 0.72rem;
      color: var(--text-dim);
    }
    .node-info-edges div {
      padding: 0.15rem 0;
    }
    .node-info-close {
      position: absolute;
      top: 0.5rem;
      right: 0.5rem;
      background: none;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 1rem;
      line-height: 1;
    }
    .node-info-close:hover { color: var(--text); }

    /* ── Legend ── */
    .legend {
      position: absolute;
      bottom: 0.75rem;
      left: 50%;
      transform: translateX(-50%);
      display: flex;
      gap: 1.25rem;
      background: rgba(17,24,39,0.85);
      padding: 0.5rem 1rem;
      border-radius: 6px;
      border: 1px solid var(--border);
      z-index: 20;
      backdrop-filter: blur(8px);
    }
    .legend-item {
      display: flex;
      align-items: center;
      gap: 0.35rem;
      font-size: 0.65rem;
      color: var(--text-dim);
    }
    .legend-icon {
      width: 12px;
      height: 12px;
    }

    /* Scrollbar */
    .sidebar::-webkit-scrollbar { width: 6px; }
    .sidebar::-webkit-scrollbar-track { background: transparent; }
    .sidebar::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  </style>
</head>
<body>

  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <div class="header-title">SCOPE ATTACK GRAPH</div>
      <div class="header-account">
        Account <span id="hdr-account"></span>
        &nbsp;&middot;&nbsp;
        <span id="hdr-region"></span>
        &nbsp;&middot;&nbsp;
        <span id="hdr-timestamp"></span>
      </div>
    </div>
    <div id="hdr-risk-badge" class="risk-badge"></div>
  </div>

  <!-- Stats Row -->
  <div class="stats-row">
    <div class="stat-card"><div class="stat-value" id="stat-users">0</div><div class="stat-label">Users</div></div>
    <div class="stat-card"><div class="stat-value" id="stat-roles">0</div><div class="stat-label">Roles</div></div>
    <div class="stat-card"><div class="stat-value" id="stat-trusts">0</div><div class="stat-label">Trusts</div></div>
    <div class="stat-card"><div class="stat-value critical-val" id="stat-critical">0</div><div class="stat-label">Critical Paths</div></div>
    <div class="stat-card">
      <div class="stat-value" id="stat-risk-score">--</div>
      <div class="stat-label">Risk Score</div>
    </div>
  </div>

  <!-- Main Layout -->
  <div class="main-layout">

    <!-- Sidebar: Attack Paths -->
    <div class="sidebar">
      <div class="sidebar-title">Attack Paths</div>
      <div id="attack-path-list"></div>
    </div>

    <!-- Graph Panel -->
    <div class="graph-panel">
      <!-- Filter buttons -->
      <div class="filter-bar">
        <button class="filter-btn active" data-filter="all">All</button>
        <button class="filter-btn" data-filter="critical">Critical</button>
        <button class="filter-btn" data-filter="high">High</button>
        <button class="filter-btn" data-filter="medium">Medium</button>
        <button class="filter-btn" data-filter="low">Low</button>
      </div>

      <svg class="graph-svg" id="graph-svg"></svg>

      <!-- Node info overlay -->
      <div class="node-info" id="node-info">
        <button class="node-info-close" id="node-info-close">&times;</button>
        <div class="node-info-title" id="ni-title"></div>
        <div class="node-info-type" id="ni-type"></div>
        <div class="node-info-edges" id="ni-edges"></div>
      </div>

      <!-- Legend -->
      <div class="legend">
        <div class="legend-item">
          <svg class="legend-icon" viewBox="0 0 12 12"><circle cx="6" cy="6" r="5" fill="#a78bfa"/></svg>
          User
        </div>
        <div class="legend-item">
          <svg class="legend-icon" viewBox="0 0 12 12"><circle cx="6" cy="6" r="5" fill="#22d3ee"/></svg>
          Role
        </div>
        <div class="legend-item">
          <svg class="legend-icon" viewBox="0 0 12 12"><polygon points="6,1 11,6 6,11 1,6" fill="#ef4444"/></svg>
          Escalation
        </div>
        <div class="legend-item">
          <svg class="legend-icon" viewBox="0 0 12 12"><rect x="1" y="1" width="10" height="10" rx="1" fill="#34d399"/></svg>
          Data
        </div>
        <div class="legend-item">
          <svg class="legend-icon" viewBox="0 0 12 12"><polygon points="6,1 11,11 1,11" fill="#f59e0b"/></svg>
          External
        </div>
        <div class="legend-item">
          <svg class="legend-icon" viewBox="0 0 14 6"><line x1="0" y1="3" x2="14" y2="3" stroke="#9ca3af" stroke-width="2"/></svg>
          Normal
        </div>
        <div class="legend-item">
          <svg class="legend-icon" viewBox="0 0 14 6"><line x1="0" y1="3" x2="14" y2="3" stroke="#ef4444" stroke-width="2" stroke-dasharray="3,2"/></svg>
          Priv Esc
        </div>
      </div>
    </div>
  </div>

  <script>
    /* ── Embedded Data ── */
    const data = {{DATA_JSON}};

    /* ── Severity helpers ── */
    const sevColor = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6' };
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };

    /* ── Populate Header ── */
    document.getElementById('hdr-account').textContent = data.account_id || '';
    document.getElementById('hdr-region').textContent = data.region || '';
    document.getElementById('hdr-timestamp').textContent = data.timestamp ? new Date(data.timestamp).toLocaleString() : '';
    const riskBadge = document.getElementById('hdr-risk-badge');
    const riskLevel = (data.summary && data.summary.risk_score) ? data.summary.risk_score.toLowerCase() : 'low';
    riskBadge.textContent = riskLevel.toUpperCase();
    riskBadge.classList.add(riskLevel);

    /* ── Populate Stats ── */
    const s = data.summary || {};
    document.getElementById('stat-users').textContent = s.total_users || 0;
    document.getElementById('stat-roles').textContent = s.total_roles || 0;
    document.getElementById('stat-trusts').textContent = s.total_trust_relationships || 0;
    document.getElementById('stat-critical').textContent = s.critical_priv_esc_risks || 0;
    const riskScoreEl = document.getElementById('stat-risk-score');
    riskScoreEl.textContent = (s.risk_score || '--').toUpperCase();
    if (s.risk_score) {
      riskScoreEl.style.color = sevColor[s.risk_score.toLowerCase()] || '#e5e7eb';
    }

    /* ── Build Attack Path Cards ── */
    const pathList = document.getElementById('attack-path-list');
    const paths = (data.attack_paths || []).sort((a, b) => (sevOrder[a.severity] || 3) - (sevOrder[b.severity] || 3));
    let selectedPathIdx = null;

    paths.forEach((ap, idx) => {
      const sev = (ap.severity || 'low').toLowerCase();
      const card = document.createElement('div');
      card.className = `attack-card ${sev}`;
      card.dataset.index = idx;

      let mitreHtml = '';
      if (ap.mitre_techniques && ap.mitre_techniques.length) {
        mitreHtml = '<div class="mitre-tags">' +
          ap.mitre_techniques.map(t => `<span class="mitre-tag">${escHtml(t)}</span>`).join('') +
          '</div>';
      }

      let stepsHtml = '';
      if (ap.steps && ap.steps.length) {
        stepsHtml = '<div class="detail-section-label">Steps</div><ol style="padding-left:1.1rem;margin:0;">' +
          ap.steps.map(st => `<li style="font-size:0.7rem;color:#9ca3af;padding:0.1rem 0;">${escHtml(st)}</li>`).join('') +
          '</ol>';
      }

      let remediationHtml = '';
      if (ap.remediation && ap.remediation.length) {
        remediationHtml = '<div class="detail-section-label">Remediation</div><ul class="detail-list">' +
          ap.remediation.map(r => `<li>${escHtml(r)}</li>`).join('') + '</ul>';
      }

      let detectionHtml = '';
      if (ap.detection_opportunities && ap.detection_opportunities.length) {
        detectionHtml = '<div class="detail-section-label">Detection</div><ul class="detail-list">' +
          ap.detection_opportunities.map(d => `<li>${escHtml(d)}</li>`).join('') + '</ul>';
      }

      let affectedHtml = '';
      if (ap.affected_resources && ap.affected_resources.length) {
        affectedHtml = '<div class="detail-section-label">Affected Resources</div><ul class="detail-list">' +
          ap.affected_resources.map(r => `<li>${escHtml(r)}</li>`).join('') + '</ul>';
      }

      card.innerHTML =
        '<div class="attack-card-header">' +
          `<div class="attack-card-name">${escHtml(ap.name)}</div>` +
          `<span class="severity-pill ${sev}">${sev}</span>` +
        '</div>' +
        `<div class="attack-card-desc">${escHtml(ap.description || '')}</div>` +
        mitreHtml +
        '<div class="attack-detail">' + stepsHtml + affectedHtml + detectionHtml + remediationHtml + '</div>';

      card.addEventListener('click', () => togglePath(idx));
      pathList.appendChild(card);
    });

    function escHtml(str) {
      const d = document.createElement('div');
      d.textContent = str;
      return d.innerHTML;
    }

    function togglePath(idx) {
      const cards = pathList.querySelectorAll('.attack-card');
      if (selectedPathIdx === idx) {
        selectedPathIdx = null;
        cards[idx].classList.remove('selected');
        highlightPath(null);
      } else {
        if (selectedPathIdx !== null && cards[selectedPathIdx]) {
          cards[selectedPathIdx].classList.remove('selected');
        }
        selectedPathIdx = idx;
        cards[idx].classList.add('selected');
        highlightPath(paths[idx]);
      }
    }

    /* ── D3 Graph Setup ── */
    const svg = d3.select('#graph-svg');
    const graphPanel = document.querySelector('.graph-panel');
    const width = graphPanel.clientWidth;
    const height = graphPanel.clientHeight;

    svg.attr('viewBox', [0, 0, width, height]);

    const defs = svg.append('defs');

    /* Arrowhead markers per edge type */
    ['normal', 'priv_esc', 'data_access', 'cross_account'].forEach(et => {
      const col = et === 'priv_esc' ? '#ef4444' : et === 'data_access' ? '#34d399' : et === 'cross_account' ? '#f59e0b' : '#4b5563';
      defs.append('marker')
        .attr('id', `arrow-${et}`)
        .attr('viewBox', '0 -4 8 8')
        .attr('refX', 20)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-4L8,0L0,4Z')
        .attr('fill', col);
    });

    /* Container group for zoom/pan */
    const g = svg.append('g');

    /* Zoom behavior */
    const zoom = d3.zoom()
      .scaleExtent([0.15, 5])
      .on('zoom', (event) => g.attr('transform', event.transform));
    svg.call(zoom);

    /* Prepare data */
    const nodes = (data.graph && data.graph.nodes) ? data.graph.nodes.map(d => ({ ...d })) : [];
    const edges = (data.graph && data.graph.edges) ? data.graph.edges.map(d => ({ ...d })) : [];

    /* Build adjacency for node info */
    const nodeMap = {};
    nodes.forEach(n => { nodeMap[n.id] = n; });

    /* Edge color and dash */
    function edgeColor(e) {
      if (e.edge_type === 'priv_esc') return sevColor[e.severity] || '#ef4444';
      if (e.edge_type === 'data_access') return '#34d399';
      if (e.edge_type === 'cross_account') return '#f59e0b';
      return '#4b5563';
    }
    function edgeDash(e) {
      return e.edge_type === 'priv_esc' ? '6,3' : 'none';
    }
    function edgeMarker(e) {
      if (e.edge_type === 'priv_esc') return 'url(#arrow-priv_esc)';
      if (e.edge_type === 'data_access') return 'url(#arrow-data_access)';
      if (e.edge_type === 'cross_account') return 'url(#arrow-cross_account)';
      return 'url(#arrow-normal)';
    }

    /* Node color and shape */
    const nodeColor = { user: '#a78bfa', role: '#22d3ee', escalation: '#ef4444', data: '#34d399', external: '#f59e0b' };
    const nodeRadius = 10;

    function drawNodeShape(sel) {
      sel.each(function(d) {
        const el = d3.select(this);
        el.selectAll('*').remove();
        const t = d.type || 'user';
        if (t === 'user' || t === 'role') {
          el.append('circle')
            .attr('r', nodeRadius)
            .attr('fill', nodeColor[t])
            .attr('stroke', '#0a0e17')
            .attr('stroke-width', 1.5);
        } else if (t === 'escalation') {
          el.append('polygon')
            .attr('points', `0,${-nodeRadius} ${nodeRadius},0 0,${nodeRadius} ${-nodeRadius},0`)
            .attr('fill', nodeColor.escalation)
            .attr('stroke', '#0a0e17')
            .attr('stroke-width', 1.5);
        } else if (t === 'data') {
          const sz = nodeRadius * 1.4;
          el.append('rect')
            .attr('x', -sz/2).attr('y', -sz/2)
            .attr('width', sz).attr('height', sz)
            .attr('rx', 2)
            .attr('fill', nodeColor.data)
            .attr('stroke', '#0a0e17')
            .attr('stroke-width', 1.5);
        } else if (t === 'external') {
          el.append('polygon')
            .attr('points', `0,${-nodeRadius} ${nodeRadius * 0.9},${nodeRadius * 0.6} ${-nodeRadius * 0.9},${nodeRadius * 0.6}`)
            .attr('fill', nodeColor.external)
            .attr('stroke', '#0a0e17')
            .attr('stroke-width', 1.5);
        } else {
          el.append('circle')
            .attr('r', nodeRadius)
            .attr('fill', '#6b7280')
            .attr('stroke', '#0a0e17')
            .attr('stroke-width', 1.5);
        }
      });
    }

    /* Draw edges */
    const linkGroup = g.append('g').attr('class', 'links');
    const link = linkGroup.selectAll('line')
      .data(edges)
      .join('line')
      .attr('stroke', d => edgeColor(d))
      .attr('stroke-width', d => d.edge_type === 'priv_esc' ? 2 : 1.5)
      .attr('stroke-dasharray', d => edgeDash(d))
      .attr('marker-end', d => edgeMarker(d))
      .attr('opacity', 0.7);

    /* Edge labels */
    const edgeLabelGroup = g.append('g').attr('class', 'edge-labels');
    const edgeLabel = edgeLabelGroup.selectAll('text')
      .data(edges.filter(e => e.label))
      .join('text')
      .attr('font-size', '8px')
      .attr('fill', '#6b7280')
      .attr('text-anchor', 'middle')
      .attr('dy', -4)
      .text(d => d.label);

    /* Draw nodes */
    const nodeGroup = g.append('g').attr('class', 'nodes');
    const node = nodeGroup.selectAll('g')
      .data(nodes)
      .join('g')
      .attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', dragStarted)
        .on('drag', dragged)
        .on('end', dragEnded));

    node.each(function(d) { drawNodeShape(d3.select(this)); });

    /* Node labels */
    node.append('text')
      .attr('dy', nodeRadius + 12)
      .attr('text-anchor', 'middle')
      .attr('font-size', '9px')
      .attr('fill', '#9ca3af')
      .text(d => d.label || d.id);

    /* Node click — show info */
    node.on('click', (event, d) => {
      event.stopPropagation();
      showNodeInfo(d);
    });

    /* Click on background to dismiss */
    svg.on('click', () => {
      document.getElementById('node-info').classList.remove('visible');
    });

    document.getElementById('node-info-close').addEventListener('click', () => {
      document.getElementById('node-info').classList.remove('visible');
    });

    function showNodeInfo(d) {
      const ni = document.getElementById('node-info');
      document.getElementById('ni-title').textContent = d.label || d.id;
      document.getElementById('ni-type').textContent = (d.type || 'unknown').toUpperCase();
      const related = edges.filter(e => e.source.id === d.id || e.target.id === d.id || e.source === d.id || e.target === d.id);
      const edgesEl = document.getElementById('ni-edges');
      if (related.length === 0) {
        edgesEl.innerHTML = '<div style="color:#6b7280;">No connections</div>';
      } else {
        edgesEl.innerHTML = related.map(e => {
          const src = typeof e.source === 'object' ? e.source.id : e.source;
          const tgt = typeof e.target === 'object' ? e.target.id : e.target;
          const dir = src === d.id ? `&#8594; ${escHtml(tgt)}` : `&#8592; ${escHtml(src)}`;
          const eType = e.edge_type || 'normal';
          return `<div>${dir} <span style="color:${edgeColor(e)};font-size:0.65rem;">[${eType}]</span></div>`;
        }).join('');
      }
      ni.classList.add('visible');
    }

    /* ── Force Simulation ── */
    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(edges).id(d => d.id).distance(100))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(nodeRadius + 8))
      .force('x', d3.forceX(width / 2).strength(0.05))
      .force('y', d3.forceY(height / 2).strength(0.05))
      .on('tick', ticked);

    function ticked() {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

      edgeLabel
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2);

      node.attr('transform', d => `translate(${d.x},${d.y})`);
    }

    function dragStarted(event) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
    }
    function dragged(event) {
      event.subject.fx = event.x;
      event.subject.fy = event.y;
    }
    function dragEnded(event) {
      if (!event.active) simulation.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    }

    /* ── Filters ── */
    let activeFilter = 'all';
    const filterBtns = document.querySelectorAll('.filter-btn');

    filterBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        filterBtns.forEach(b => { b.className = 'filter-btn'; });
        const f = btn.dataset.filter;
        activeFilter = f;
        if (f === 'all') {
          btn.classList.add('active');
        } else {
          btn.classList.add(`active-${f}`);
        }
        applyFilter();
      });
    });

    function applyFilter() {
      if (activeFilter === 'all') {
        link.attr('opacity', 0.7);
        node.attr('opacity', 1);
        edgeLabel.attr('opacity', 1);
      } else {
        /* Find edges matching the filter severity */
        const matchEdgeSet = new Set();
        const matchNodeSet = new Set();
        edges.forEach((e, i) => {
          if ((e.severity || '').toLowerCase() === activeFilter) {
            matchEdgeSet.add(i);
            const src = typeof e.source === 'object' ? e.source.id : e.source;
            const tgt = typeof e.target === 'object' ? e.target.id : e.target;
            matchNodeSet.add(src);
            matchNodeSet.add(tgt);
          }
        });
        /* Also include nodes from attack paths with this severity */
        paths.forEach(ap => {
          if ((ap.severity || '').toLowerCase() === activeFilter && ap.affected_resources) {
            ap.affected_resources.forEach(r => matchNodeSet.add(r));
          }
        });

        link.attr('opacity', (d, i) => matchEdgeSet.has(i) ? 0.85 : 0.08);
        node.attr('opacity', d => matchNodeSet.has(d.id) ? 1 : 0.12);
        edgeLabel.attr('opacity', (d, i) => {
          const edgeIdx = edges.indexOf(d);
          return matchEdgeSet.has(edgeIdx) ? 1 : 0.08;
        });
      }
    }

    /* ── Attack Path Highlighting ── */
    function highlightPath(ap) {
      if (!ap) {
        /* Reset all */
        link.attr('opacity', 0.7).attr('stroke-width', d => d.edge_type === 'priv_esc' ? 2 : 1.5);
        node.attr('opacity', 1);
        edgeLabel.attr('opacity', 1);
        return;
      }
      const affected = new Set(ap.affected_resources || []);
      /* Find edges that connect affected resources */
      const pathEdges = new Set();
      edges.forEach((e, i) => {
        const src = typeof e.source === 'object' ? e.source.id : e.source;
        const tgt = typeof e.target === 'object' ? e.target.id : e.target;
        if (affected.has(src) || affected.has(tgt)) {
          pathEdges.add(i);
          affected.add(src);
          affected.add(tgt);
        }
      });

      link.attr('opacity', (d, i) => pathEdges.has(i) ? 1 : 0.06)
        .attr('stroke-width', (d, i) => pathEdges.has(i) ? 3 : (d.edge_type === 'priv_esc' ? 2 : 1.5));
      node.attr('opacity', d => affected.has(d.id) ? 1 : 0.1);
      edgeLabel.attr('opacity', (d) => {
        const idx = edges.indexOf(d);
        return pathEdges.has(idx) ? 1 : 0.06;
      });
    }

    /* ── Initial zoom to fit ── */
    simulation.on('end', () => {
      const bounds = g.node().getBBox();
      if (bounds.width > 0 && bounds.height > 0) {
        const padding = 60;
        const fullWidth = width;
        const fullHeight = height;
        const scale = Math.min(
          (fullWidth - padding * 2) / bounds.width,
          (fullHeight - padding * 2) / bounds.height,
          1.5
        );
        const tx = fullWidth / 2 - scale * (bounds.x + bounds.width / 2);
        const ty = fullHeight / 2 - scale * (bounds.y + bounds.height / 2);
        svg.transition().duration(750).call(
          zoom.transform,
          d3.zoomIdentity.translate(tx, ty).scale(scale)
        );
      }
    });
  </script>
</body>
</html>
```

### Rendering Steps

1. Read `./data/audit/<RUN_ID>.json`
2. Parse the JSON -- extract `payload`, `run_id`, `timestamp`, `account_id`, `region`
3. Construct the DATA_JSON object:
   - `account_id` from envelope
   - `region` from envelope
   - `timestamp` from envelope
   - `summary` from `payload.summary`
   - `graph` from `payload.graph` (with `nodes` and `edges` arrays)
   - `attack_paths` from `payload.attack_paths`
4. Serialize DATA_JSON with `JSON.stringify` -- ensure valid JSON, double quotes, no trailing commas, escape `</script>` as `<\/script>` if present in any string values
5. Copy the HTML template above
6. Replace the literal `{{DATA_JSON}}` with the serialized object
7. Write the resulting HTML to `$RUN_DIR/attack-graph.html`
8. Verify: `test -f "$RUN_DIR/attack-graph.html"`

### Template Contract

- The template is self-contained -- D3 v7 is loaded from CDN
- `const data = {{DATA_JSON}};` is the single injection point
- No other template variables exist
- The HTML requires no server -- open directly in a browser
- All styles are inlined -- no external CSS dependencies
</audit_renderer>


<remediate_renderer>
## Remediate Renderer — Interactive Risk & Policy Dashboard

**Output file:** `$RUN_DIR/dashboard.html`

### Data Source

Read `./data/remediate/<RUN_ID>.json`. Extract the `payload` object — this contains `attack_paths_aggregated`, `scps`, `rcps`, `detections`, `security_controls`, `prioritization`, and `audit_runs_analyzed`. Add `account_id`, `region`, and `timestamp` from the envelope.

The DATA_JSON object passed to the template must follow this structure:

```json
{
  "account_id": "string — from envelope",
  "region": "string — from envelope",
  "timestamp": "string — ISO8601 from envelope",
  "run_id": "string — from envelope",
  "audit_runs_analyzed": ["string"],
  "attack_paths_aggregated": {
    "total": "int",
    "systemic": "int",
    "oneoff": "int",
    "by_severity": { "critical": "int", "high": "int", "medium": "int", "low": "int" }
  },
  "scps": [...],
  "rcps": [...],
  "detections": [...],
  "security_controls": [...],
  "prioritization": [...]
}
```

### Complete HTML Template

Copy this template exactly, then replace `{{DATA_JSON}}` with the constructed data object:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SCOPE Remediation Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #0a0e17;
    color: #e2e8f0;
    font-family: 'Inter', 'Segoe UI', -apple-system, sans-serif;
    overflow-x: hidden;
    min-height: 100vh;
  }

  .header {
    padding: 14px 24px;
    border-bottom: 1px solid #1e293b;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .header-title { font-size: 18px; font-weight: 700; letter-spacing: -0.02em; }
  .header-sub { font-size: 11px; color: #64748b; margin-top: 2px; }
  .risk-badge {
    padding: 4px 14px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 13px;
    text-transform: uppercase;
  }

  .stats-row {
    display: flex;
    gap: 10px;
    padding: 14px 24px;
    flex-wrap: wrap;
  }
  .stat-card {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 12px 16px;
    flex: 1;
    min-width: 130px;
  }
  .stat-label { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px; }
  .stat-value { font-size: 24px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }

  .main { padding: 0 24px 24px; display: flex; gap: 14px; min-height: calc(100vh - 160px); }

  .sidebar {
    width: 320px;
    min-width: 260px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
  }
  .sidebar-title {
    font-size: 12px;
    font-weight: 600;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 10px;
  }
  .filter-bar { display: flex; gap: 4px; margin-bottom: 10px; flex-wrap: wrap; }
  .filter-btn {
    padding: 5px 12px;
    border-radius: 6px;
    border: 1px solid #1e293b;
    background: transparent;
    color: #64748b;
    cursor: pointer;
    font-size: 11px;
    font-weight: 600;
    transition: all 0.2s;
  }
  .filter-btn.active { border-color: #f59e0b; background: rgba(245,158,11,0.1); color: #f59e0b; }
  .filter-btn:hover { border-color: #475569; color: #e2e8f0; }

  .sidebar-list { flex: 1; overflow-y: auto; padding-right: 4px; }
  .sidebar-list::-webkit-scrollbar { width: 4px; }
  .sidebar-list::-webkit-scrollbar-track { background: transparent; }
  .sidebar-list::-webkit-scrollbar-thumb { background: #334155; border-radius: 2px; }

  .prio-card {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 12px 14px;
    margin-bottom: 8px;
    cursor: pointer;
    transition: all 0.2s;
    border-left: 3px solid #334155;
  }
  .prio-card:hover { background: #1a2235; }
  .prio-card.selected { background: #1a2235; border-color: #f59e0b; }
  .prio-rank {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: #1e293b;
    color: #e2e8f0;
    font-size: 11px;
    font-weight: 700;
    font-family: monospace;
    margin-right: 8px;
  }
  .prio-action { font-weight: 600; font-size: 13px; }
  .prio-meta { display: flex; gap: 6px; margin-top: 6px; flex-wrap: wrap; }

  .badge { padding: 2px 9px; border-radius: 12px; font-size: 10px; font-weight: 600; text-transform: uppercase; white-space: nowrap; }
  .badge-critical { background: rgba(239,68,68,0.15); color: #ef4444; }
  .badge-high { background: rgba(245,158,11,0.15); color: #f59e0b; }
  .badge-medium { background: rgba(59,130,246,0.15); color: #3b82f6; }
  .badge-low { background: rgba(34,197,94,0.15); color: #22c55e; }
  .badge-scp { background: rgba(139,92,246,0.15); color: #a78bfa; }
  .badge-rcp { background: rgba(6,182,212,0.15); color: #22d3ee; }
  .badge-detection { background: rgba(245,158,11,0.15); color: #f59e0b; }
  .badge-control { background: rgba(34,197,94,0.15); color: #22c55e; }
  .badge-config { background: rgba(100,116,139,0.15); color: #94a3b8; }
  .badge-effort-low { background: rgba(34,197,94,0.15); color: #22c55e; }
  .badge-effort-medium { background: rgba(245,158,11,0.15); color: #f59e0b; }
  .badge-effort-high { background: rgba(239,68,68,0.15); color: #ef4444; }

  .content-panel { flex: 1; min-width: 0; display: flex; flex-direction: column; }

  .tabs { display: flex; gap: 2px; margin-bottom: 14px; }
  .tab {
    padding: 8px 18px;
    border-radius: 6px 6px 0 0;
    border: 1px solid #1e293b;
    border-bottom: none;
    background: transparent;
    color: #64748b;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
    transition: all 0.2s;
  }
  .tab.active { background: #111827; color: #e2e8f0; border-color: #334155; }
  .tab:hover { color: #e2e8f0; }

  .tab-content {
    flex: 1;
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 0 8px 8px 8px;
    padding: 20px;
    overflow-y: auto;
    display: none;
  }
  .tab-content.active { display: block; }

  .policy-card {
    background: #0f1729;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 12px;
  }
  .policy-name { font-weight: 700; font-size: 14px; margin-bottom: 6px; }
  .policy-meta { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
  .policy-paths { font-size: 11px; color: #64748b; margin-bottom: 8px; }
  .policy-impact { font-size: 11px; color: #94a3b8; }
  .policy-impact strong { color: #e2e8f0; }

  .detection-card {
    background: #0f1729;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 12px;
  }
  .detection-name { font-weight: 700; font-size: 14px; margin-bottom: 6px; }
  .spl-block {
    background: #0a0e17;
    border: 1px solid #1e293b;
    border-radius: 6px;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: #a78bfa;
    white-space: pre-wrap;
    word-break: break-all;
    position: relative;
    margin-top: 8px;
  }
  .copy-btn {
    position: absolute;
    top: 8px;
    right: 8px;
    padding: 3px 10px;
    border-radius: 4px;
    border: 1px solid #334155;
    background: #1e293b;
    color: #94a3b8;
    cursor: pointer;
    font-size: 10px;
    transition: all 0.2s;
  }
  .copy-btn:hover { background: #334155; color: #e2e8f0; }

  .control-card {
    background: #0f1729;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 12px;
  }
  .control-service { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px; }
  .control-rec { font-size: 13px; line-height: 1.5; }

  .matrix-container { width: 100%; height: 400px; position: relative; }

  .severity-bar { display: flex; gap: 2px; height: 24px; border-radius: 4px; overflow: hidden; margin-top: 8px; }
  .severity-segment { height: 100%; transition: width 0.3s; }
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="header-title">SCOPE Remediation Dashboard</div>
    <div class="header-sub" id="header-sub"></div>
  </div>
  <div id="summary-badge"></div>
</div>

<div class="stats-row" id="stats-row"></div>

<div class="main">
  <div class="sidebar">
    <div class="sidebar-title">Prioritized Actions</div>
    <div class="filter-bar" id="filter-bar"></div>
    <div class="sidebar-list" id="prio-list"></div>
  </div>

  <div class="content-panel">
    <div class="tabs" id="tabs"></div>
    <div class="tab-content active" id="tab-policies"></div>
    <div class="tab-content" id="tab-detections"></div>
    <div class="tab-content" id="tab-controls"></div>
    <div class="tab-content" id="tab-matrix"></div>
  </div>
</div>

<script>
const data = {{DATA_JSON}};

const SEVERITY_COLORS = { critical: "#ef4444", high: "#f59e0b", medium: "#3b82f6", low: "#22c55e" };
const CATEGORY_COLORS = { scp: "#a78bfa", rcp: "#22d3ee", detection: "#f59e0b", control: "#22c55e", config: "#94a3b8" };

function escapeHtml(t) { var d = document.createElement("div"); d.appendChild(document.createTextNode(t)); return d.innerHTML; }

// Header
document.getElementById("header-sub").textContent =
  data.run_id + " \u2022 Account " + data.account_id + " \u2022 " + data.region + " \u2022 " + data.timestamp;

var ap = data.attack_paths_aggregated;
var topSev = ap.by_severity.critical > 0 ? "critical" : ap.by_severity.high > 0 ? "high" : ap.by_severity.medium > 0 ? "medium" : "low";
var badge = document.getElementById("summary-badge");
badge.className = "risk-badge";
badge.textContent = ap.total + " Attack Paths";
badge.style.background = SEVERITY_COLORS[topSev] + "20";
badge.style.color = SEVERITY_COLORS[topSev];
badge.style.border = "1px solid " + SEVERITY_COLORS[topSev] + "40";

// Stats
var statsRow = document.getElementById("stats-row");
function addStat(label, value, color) {
  var c = document.createElement("div");
  c.className = "stat-card";
  c.innerHTML = '<div class="stat-label">' + label + '</div><div class="stat-value" style="color:' + (color || "#e2e8f0") + '">' + value + '</div>';
  statsRow.appendChild(c);
}
addStat("Attack Paths", ap.total, SEVERITY_COLORS[topSev]);
addStat("Systemic", ap.systemic, ap.systemic > 0 ? "#ef4444" : "#22c55e");
addStat("SCPs", data.scps.length, "#a78bfa");
addStat("RCPs", data.rcps.length, "#22d3ee");
addStat("Detections", data.detections.length, "#f59e0b");
addStat("Controls", data.security_controls.length, "#22c55e");
addStat("Audits Analyzed", data.audit_runs_analyzed.length);

// Severity bar
var total = ap.total || 1;
var bar = document.createElement("div");
bar.className = "severity-bar";
bar.style.margin = "0 24px 14px";
["critical","high","medium","low"].forEach(function(s) {
  var seg = document.createElement("div");
  seg.className = "severity-segment";
  seg.style.width = ((ap.by_severity[s] / total) * 100) + "%";
  seg.style.background = SEVERITY_COLORS[s];
  seg.title = s.toUpperCase() + ": " + ap.by_severity[s];
  bar.appendChild(seg);
});
document.querySelector(".main").before(bar);

// Sidebar filters
var activeFilter = "all";
var filterBar = document.getElementById("filter-bar");
["all","scp","rcp","detection","control"].forEach(function(f) {
  var btn = document.createElement("button");
  btn.className = "filter-btn" + (f === "all" ? " active" : "");
  btn.dataset.filter = f;
  btn.textContent = f === "all" ? "All" : f.toUpperCase();
  btn.onclick = function() {
    activeFilter = f;
    document.querySelectorAll(".filter-btn").forEach(function(b) { b.classList.toggle("active", b.dataset.filter === f); });
    renderPrioList();
  };
  filterBar.appendChild(btn);
});

// Prioritized actions sidebar
function renderPrioList() {
  var list = document.getElementById("prio-list");
  list.innerHTML = "";
  var items = data.prioritization.filter(function(p) { return activeFilter === "all" || p.category === activeFilter; });
  items.forEach(function(p) {
    var card = document.createElement("div");
    card.className = "prio-card";
    card.style.borderLeftColor = SEVERITY_COLORS[p.risk] || "#334155";
    card.innerHTML =
      '<div><span class="prio-rank">' + p.rank + '</span><span class="prio-action">' + escapeHtml(p.action) + '</span></div>' +
      '<div class="prio-meta">' +
        '<span class="badge badge-' + p.risk + '">' + p.risk.toUpperCase() + '</span>' +
        '<span class="badge badge-effort-' + p.effort + '">Effort: ' + p.effort.toUpperCase() + '</span>' +
        '<span class="badge badge-' + p.category + '">' + p.category.toUpperCase() + '</span>' +
      '</div>';
    list.appendChild(card);
  });
}
renderPrioList();

// Tabs
var tabDefs = [
  { id: "tab-policies", label: "Policies (" + (data.scps.length + data.rcps.length) + ")" },
  { id: "tab-detections", label: "Detections (" + data.detections.length + ")" },
  { id: "tab-controls", label: "Controls (" + data.security_controls.length + ")" },
  { id: "tab-matrix", label: "Risk Matrix" }
];
var tabsEl = document.getElementById("tabs");
tabDefs.forEach(function(t, i) {
  var btn = document.createElement("button");
  btn.className = "tab" + (i === 0 ? " active" : "");
  btn.textContent = t.label;
  btn.onclick = function() {
    document.querySelectorAll(".tab").forEach(function(b) { b.classList.remove("active"); });
    document.querySelectorAll(".tab-content").forEach(function(c) { c.classList.remove("active"); });
    btn.classList.add("active");
    document.getElementById(t.id).classList.add("active");
  };
  tabsEl.appendChild(btn);
});

// Policies tab
var policiesTab = document.getElementById("tab-policies");
function renderPolicies(items, type) {
  items.forEach(function(p) {
    var card = document.createElement("div");
    card.className = "policy-card";
    var impactHtml = "";
    if (p.impact_analysis) {
      var ia = p.impact_analysis;
      impactHtml = '<div class="policy-impact">' +
        '<strong>Prevents:</strong> ' + (ia.prevents || []).join(", ") + '<br>' +
        '<strong>Blast radius:</strong> ' + (ia.blast_radius || "unknown") +
        ' &bull; <strong>Services:</strong> ' + (ia.affected_services || []).join(", ") +
        (ia.break_glass && ia.break_glass !== "none" ? '<br><strong>Break glass:</strong> ' + escapeHtml(ia.break_glass) : '') +
      '</div>';
    }
    card.innerHTML =
      '<div class="policy-name">' + escapeHtml(p.name) + '</div>' +
      '<div class="policy-meta">' +
        '<span class="badge badge-' + type + '">' + type.toUpperCase() + '</span>' +
        (p.source_attack_paths || []).map(function(ap) {
          return '<span class="badge badge-medium">' + escapeHtml(ap) + '</span>';
        }).join("") +
      '</div>' +
      '<div class="policy-paths">File: ' + escapeHtml(p.file || "N/A") + '</div>' +
      impactHtml;
    policiesTab.appendChild(card);
  });
}
renderPolicies(data.scps, "scp");
renderPolicies(data.rcps, "rcp");
if (data.scps.length === 0 && data.rcps.length === 0) {
  policiesTab.innerHTML = '<div style="color:#64748b;text-align:center;padding:40px">No policy recommendations generated</div>';
}

// Detections tab
var detectionsTab = document.getElementById("tab-detections");
data.detections.forEach(function(d) {
  var card = document.createElement("div");
  card.className = "detection-card";
  var splId = "spl-" + Math.random().toString(36).slice(2, 9);
  card.innerHTML =
    '<div class="detection-name">' + escapeHtml(d.name) + '</div>' +
    '<div class="policy-meta">' +
      '<span class="badge badge-' + d.severity + '">' + d.severity.toUpperCase() + '</span>' +
      '<span class="badge" style="background:rgba(139,92,246,0.15);color:#a78bfa;font-family:monospace">' + escapeHtml(d.mitre_technique) + '</span>' +
    '</div>' +
    '<div class="spl-block" id="' + splId + '">' +
      '<button class="copy-btn" onclick="copyToClipboard(\'' + splId + '\')">COPY</button>' +
      escapeHtml(d.spl) +
    '</div>';
  detectionsTab.appendChild(card);
});
if (data.detections.length === 0) {
  detectionsTab.innerHTML = '<div style="color:#64748b;text-align:center;padding:40px">No detection suggestions generated</div>';
}

function copyToClipboard(id) {
  var el = document.getElementById(id);
  var text = el.textContent.replace("COPY", "").trim();
  navigator.clipboard.writeText(text).then(function() {
    var btn = el.querySelector(".copy-btn");
    btn.textContent = "COPIED";
    setTimeout(function() { btn.textContent = "COPY"; }, 1500);
  });
}

// Controls tab
var controlsTab = document.getElementById("tab-controls");
var byService = {};
data.security_controls.forEach(function(c) {
  if (!byService[c.service]) byService[c.service] = [];
  byService[c.service].push(c);
});
Object.keys(byService).sort().forEach(function(svc) {
  byService[svc].forEach(function(c) {
    var card = document.createElement("div");
    card.className = "control-card";
    card.innerHTML =
      '<div class="control-service">' + escapeHtml(svc) + '</div>' +
      '<div class="control-rec">' + escapeHtml(c.recommendation) + '</div>' +
      '<div class="policy-paths" style="margin-top:6px">Attack paths: ' +
        (c.source_attack_paths || []).map(function(p) { return escapeHtml(p); }).join(", ") +
      '</div>';
    controlsTab.appendChild(card);
  });
});
if (data.security_controls.length === 0) {
  controlsTab.innerHTML = '<div style="color:#64748b;text-align:center;padding:40px">No security control recommendations</div>';
}

// Risk Matrix tab — scatter plot
var matrixTab = document.getElementById("tab-matrix");
matrixTab.innerHTML = '<div class="matrix-container" id="matrix-chart"></div>';
(function() {
  var container = document.getElementById("matrix-chart");
  var margin = { top: 30, right: 30, bottom: 50, left: 60 };
  var width = container.clientWidth - margin.left - margin.right;
  var height = 360 - margin.top - margin.bottom;

  var svg = d3.select("#matrix-chart").append("svg")
    .attr("width", width + margin.left + margin.right)
    .attr("height", height + margin.top + margin.bottom)
    .append("g")
    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

  var riskScale = { critical: 4, high: 3, medium: 2, low: 1 };
  var effortScale = { low: 1, medium: 2, high: 3 };

  var x = d3.scaleLinear().domain([0.5, 3.5]).range([0, width]);
  var y = d3.scaleLinear().domain([0.5, 4.5]).range([height, 0]);

  // Quick win zone
  svg.append("rect")
    .attr("x", x(0.5)).attr("y", y(4.5))
    .attr("width", x(1.8) - x(0.5)).attr("height", y(2.5) - y(4.5))
    .attr("fill", "rgba(34,197,94,0.06)")
    .attr("stroke", "#22c55e").attr("stroke-width", 1).attr("stroke-dasharray", "4,4");
  svg.append("text").attr("x", x(0.7)).attr("y", y(4.3))
    .attr("fill", "#22c55e").attr("font-size", "10px").attr("opacity", 0.6).text("QUICK WINS");

  // Axes
  svg.append("g").attr("transform", "translate(0," + height + ")")
    .call(d3.axisBottom(x).tickValues([1, 2, 3]).tickFormat(function(d) { return ["","Low","Medium","High"][d]; }))
    .selectAll("text,line,path").attr("stroke", "#334155").attr("fill", "#64748b");
  svg.append("g")
    .call(d3.axisLeft(y).tickValues([1, 2, 3, 4]).tickFormat(function(d) { return ["","Low","Medium","High","Critical"][d]; }))
    .selectAll("text,line,path").attr("stroke", "#334155").attr("fill", "#64748b");

  svg.append("text").attr("x", width / 2).attr("y", height + 40)
    .attr("text-anchor", "middle").attr("fill", "#64748b").attr("font-size", "11px").text("Effort");
  svg.append("text").attr("transform", "rotate(-90)")
    .attr("x", -height / 2).attr("y", -45)
    .attr("text-anchor", "middle").attr("fill", "#64748b").attr("font-size", "11px").text("Risk");

  // Plot items
  data.prioritization.forEach(function(p, i) {
    var cx = x(effortScale[p.effort] || 2) + (Math.random() - 0.5) * 20;
    var cy = y(riskScale[p.risk] || 2) + (Math.random() - 0.5) * 20;
    var color = CATEGORY_COLORS[p.category] || "#94a3b8";

    var g = svg.append("g").style("cursor", "pointer");
    g.append("circle").attr("cx", cx).attr("cy", cy).attr("r", 8)
      .attr("fill", color).attr("fill-opacity", 0.7).attr("stroke", color).attr("stroke-width", 1.5);
    g.append("text").attr("x", cx).attr("y", cy + 3.5)
      .attr("text-anchor", "middle").attr("fill", "#fff").attr("font-size", "9px").attr("font-weight", "700")
      .text(p.rank);

    g.append("title").text("#" + p.rank + " " + p.action + "\nRisk: " + p.risk + " | Effort: " + p.effort + " | " + p.category);
  });
})();
</script>
</body>
</html>
```

### Rendering Steps

1. Read `./data/remediate/<RUN_ID>.json`
2. Verify `payload` exists and contains expected fields
3. Construct DATA_JSON:
   - `account_id`, `region`, `timestamp`, `run_id` from envelope
   - All fields from `payload`
4. Serialize DATA_JSON — valid JSON, escape `</script>` as `<\/script>`
5. Copy the HTML template, replace `{{DATA_JSON}}`
6. Write to `$RUN_DIR/dashboard.html`
7. Verify: `test -f "$RUN_DIR/dashboard.html"`

### Template Contract

- Self-contained — D3 v7 loaded from CDN
- `const data = {{DATA_JSON}};` is the single injection point
- No other template variables
- No server required — open directly in browser
- All styles inlined — no external CSS
</remediate_renderer>


<exploit_renderer>
## Exploit Renderer — Escalation Path & Playbook Dashboard

**Output file:** `$RUN_DIR/dashboard.html`

### Data Source

Read `./data/exploit/<RUN_ID>.json`. Extract the `payload` object — this contains `target_arn`, `intake_mode`, `paths_found`, `highest_priv`, `escalation_paths`, `circumvention_analysis`, and `lateral_movement`. Add `account_id`, `region`, and `timestamp` from the envelope.

The DATA_JSON object passed to the template must follow this structure:

```json
{
  "account_id": "string — from envelope",
  "region": "string — from envelope",
  "timestamp": "string — ISO8601 from envelope",
  "run_id": "string — from envelope",
  "source_audit_run": "string | null",
  "target_arn": "string",
  "intake_mode": "audit-data | fresh-enumeration",
  "paths_found": "int",
  "highest_priv": "string",
  "escalation_paths": [...],
  "circumvention_analysis": { "scp_bypass": [...], "boundary_bypass": [...], "session_policy": [...] },
  "lateral_movement": { "cross_account": [...], "service_linked": [...], "trust_chain": [...] }
}
```

### Complete HTML Template

Copy this template exactly, then replace `{{DATA_JSON}}` with the constructed data object:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SCOPE Exploit Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #0a0e17;
    color: #e2e8f0;
    font-family: 'Inter', 'Segoe UI', -apple-system, sans-serif;
    overflow-x: hidden;
    min-height: 100vh;
  }

  .header {
    padding: 14px 24px;
    border-bottom: 1px solid #1e293b;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .header-title { font-size: 18px; font-weight: 700; letter-spacing: -0.02em; }
  .header-sub { font-size: 11px; color: #64748b; margin-top: 2px; }
  .priv-badge {
    padding: 4px 14px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 13px;
    text-transform: uppercase;
  }

  .stats-row { display: flex; gap: 10px; padding: 14px 24px; flex-wrap: wrap; }
  .stat-card {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 12px 16px;
    flex: 1;
    min-width: 130px;
  }
  .stat-label { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px; }
  .stat-value { font-size: 24px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
  .stat-sub { font-size: 10px; color: #64748b; margin-top: 2px; }

  .main { padding: 0 24px 24px; display: flex; gap: 14px; min-height: calc(100vh - 160px); }

  .sidebar {
    width: 320px;
    min-width: 260px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
  }
  .sidebar-title { font-size: 12px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 10px; }
  .sidebar-list { flex: 1; overflow-y: auto; padding-right: 4px; }
  .sidebar-list::-webkit-scrollbar { width: 4px; }
  .sidebar-list::-webkit-scrollbar-thumb { background: #334155; border-radius: 2px; }

  .path-card {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 14px;
    margin-bottom: 8px;
    cursor: pointer;
    transition: all 0.2s;
    border-left: 3px solid #334155;
  }
  .path-card:hover { background: #1a2235; }
  .path-card.selected { background: #1a2235; border-color: #ef4444; }
  .path-rank {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    font-size: 12px;
    font-weight: 700;
    font-family: monospace;
    margin-right: 8px;
  }
  .path-name { font-weight: 600; font-size: 13px; }
  .path-meta { display: flex; gap: 6px; margin-top: 8px; flex-wrap: wrap; }
  .step-count { font-size: 10px; color: #475569; }

  .mitre-tag { background: rgba(139,92,246,0.15); color: #a78bfa; padding: 1px 7px; border-radius: 4px; font-size: 10px; font-family: monospace; }
  .badge { padding: 2px 9px; border-radius: 12px; font-size: 10px; font-weight: 600; text-transform: uppercase; white-space: nowrap; }
  .badge-critical { background: rgba(239,68,68,0.15); color: #ef4444; }
  .badge-high { background: rgba(245,158,11,0.15); color: #f59e0b; }
  .badge-medium { background: rgba(59,130,246,0.15); color: #3b82f6; }

  .section-title {
    font-size: 11px;
    font-weight: 600;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 16px;
    margin-bottom: 8px;
    padding-top: 12px;
    border-top: 1px solid #1e293b;
  }
  .summary-item {
    font-size: 12px;
    color: #94a3b8;
    padding: 4px 0;
    line-height: 1.5;
  }
  .summary-count { color: #e2e8f0; font-weight: 600; font-family: monospace; }

  .content-panel { flex: 1; min-width: 0; display: flex; flex-direction: column; }

  .tabs { display: flex; gap: 2px; margin-bottom: 14px; }
  .tab {
    padding: 8px 18px;
    border-radius: 6px 6px 0 0;
    border: 1px solid #1e293b;
    border-bottom: none;
    background: transparent;
    color: #64748b;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
    transition: all 0.2s;
  }
  .tab.active { background: #111827; color: #e2e8f0; border-color: #334155; }
  .tab:hover { color: #e2e8f0; }
  .tab-content {
    flex: 1;
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 0 8px 8px 8px;
    padding: 20px;
    overflow-y: auto;
    display: none;
  }
  .tab-content.active { display: block; }

  .timeline { position: relative; padding-left: 36px; }
  .timeline::before {
    content: "";
    position: absolute;
    left: 14px;
    top: 0;
    bottom: 0;
    width: 2px;
    background: #1e293b;
  }
  .step-item { position: relative; margin-bottom: 20px; }
  .step-num {
    position: absolute;
    left: -36px;
    width: 28px;
    height: 28px;
    border-radius: 50%;
    background: #ef4444;
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: 700;
    font-family: monospace;
    z-index: 1;
  }
  .step-desc { font-size: 13px; line-height: 1.6; margin-bottom: 8px; }

  .cli-block {
    background: #0a0e17;
    border: 1px solid #1e293b;
    border-radius: 6px;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: #22d3ee;
    white-space: pre-wrap;
    word-break: break-all;
    position: relative;
    margin-bottom: 8px;
  }
  .policy-block {
    background: #0a0e17;
    border: 1px solid #1e293b;
    border-radius: 6px;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: #a78bfa;
    white-space: pre-wrap;
    word-break: break-all;
    position: relative;
    margin-bottom: 8px;
  }
  .copy-btn {
    position: absolute;
    top: 8px;
    right: 8px;
    padding: 3px 10px;
    border-radius: 4px;
    border: 1px solid #334155;
    background: #1e293b;
    color: #94a3b8;
    cursor: pointer;
    font-size: 10px;
    transition: all 0.2s;
  }
  .copy-btn:hover { background: #334155; color: #e2e8f0; }

  .circ-card {
    background: #0f1729;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 12px;
  }
  .circ-title { font-weight: 700; font-size: 14px; margin-bottom: 8px; }
  .circ-item { font-size: 12px; color: #94a3b8; padding: 6px 0; border-bottom: 1px solid #1e293b; line-height: 1.5; }
  .circ-item:last-child { border-bottom: none; }

  .lateral-card {
    background: #0f1729;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 12px;
  }
  .lateral-title { font-weight: 700; font-size: 14px; margin-bottom: 8px; }
  .lateral-item { font-size: 12px; color: #94a3b8; padding: 6px 0; border-bottom: 1px solid #1e293b; line-height: 1.5; }
  .lateral-item:last-child { border-bottom: none; }

  .empty-state { color: #475569; text-align: center; padding: 40px; font-size: 13px; }
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="header-title">SCOPE Exploit Dashboard</div>
    <div class="header-sub" id="header-sub"></div>
  </div>
  <div class="priv-badge" id="priv-badge"></div>
</div>

<div class="stats-row" id="stats-row"></div>

<div class="main">
  <div class="sidebar">
    <div class="sidebar-title">Escalation Paths</div>
    <div class="sidebar-list" id="path-list"></div>
    <div id="sidebar-summary"></div>
  </div>

  <div class="content-panel">
    <div class="tabs" id="tabs"></div>
    <div class="tab-content active" id="tab-path"></div>
    <div class="tab-content" id="tab-circumvent"></div>
    <div class="tab-content" id="tab-lateral"></div>
  </div>
</div>

<script>
const data = {{DATA_JSON}};

function escapeHtml(t) { var d = document.createElement("div"); d.appendChild(document.createTextNode(t)); return d.innerHTML; }

var PRIV_COLORS = { ADMIN: "#ef4444", POWER_USER: "#f59e0b", READ_ONLY: "#3b82f6", NONE: "#64748b" };
var privColor = PRIV_COLORS[data.highest_priv] || "#64748b";

// Header
document.getElementById("header-sub").textContent =
  "Target: " + data.target_arn + " \u2022 " + data.region + " \u2022 " + data.timestamp;

var privBadge = document.getElementById("priv-badge");
privBadge.textContent = data.highest_priv;
privBadge.style.background = privColor + "20";
privBadge.style.color = privColor;
privBadge.style.border = "1px solid " + privColor + "40";

// Stats
var statsRow = document.getElementById("stats-row");
function addStat(label, value, color, sub) {
  var c = document.createElement("div");
  c.className = "stat-card";
  c.innerHTML = '<div class="stat-label">' + label + '</div><div class="stat-value" style="color:' + (color || "#e2e8f0") + '">' + value + '</div>' + (sub ? '<div class="stat-sub">' + sub + '</div>' : '');
  statsRow.appendChild(c);
}
var totalSteps = data.escalation_paths.reduce(function(s, p) { return s + p.steps.length; }, 0);
addStat("Paths Found", data.paths_found, data.paths_found > 0 ? "#ef4444" : "#22c55e");
addStat("Total Steps", totalSteps);
addStat("Highest Priv", data.highest_priv, privColor);
addStat("Intake Mode", data.intake_mode === "audit-data" ? "Audit" : "Fresh",
  null, data.source_audit_run ? "from: " + data.source_audit_run : "");

// Sidebar — path cards
var selectedPath = 0;
function renderPathList() {
  var list = document.getElementById("path-list");
  list.innerHTML = "";
  data.escalation_paths.forEach(function(p, i) {
    var card = document.createElement("div");
    card.className = "path-card" + (selectedPath === i ? " selected" : "");
    if (selectedPath === i) card.style.borderColor = "#ef4444";
    var rankColors = ["#ef4444","#f59e0b","#3b82f6","#22c55e","#64748b"];
    var rc = rankColors[Math.min(i, rankColors.length - 1)];
    card.innerHTML =
      '<div><span class="path-rank" style="background:' + rc + '">' + p.rank + '</span><span class="path-name">' + escapeHtml(p.name) + '</span></div>' +
      '<div class="path-meta">' +
        '<span class="step-count">' + p.steps.length + ' steps</span>' +
        (p.mitre_techniques || []).map(function(t) { return '<span class="mitre-tag">' + t + '</span>'; }).join("") +
      '</div>';
    card.onclick = function() { selectedPath = i; renderPathList(); renderPathDetail(); };
    list.appendChild(card);
  });

  // Sidebar summaries
  var summary = document.getElementById("sidebar-summary");
  var ca = data.circumvention_analysis || {};
  var lm = data.lateral_movement || {};
  summary.innerHTML =
    '<div class="section-title">Circumvention</div>' +
    '<div class="summary-item">SCP Bypass: <span class="summary-count">' + (ca.scp_bypass || []).length + '</span></div>' +
    '<div class="summary-item">Boundary Bypass: <span class="summary-count">' + (ca.boundary_bypass || []).length + '</span></div>' +
    '<div class="summary-item">Session Policy: <span class="summary-count">' + (ca.session_policy || []).length + '</span></div>' +
    '<div class="section-title">Lateral Movement</div>' +
    '<div class="summary-item">Cross-Account: <span class="summary-count">' + (lm.cross_account || []).length + '</span></div>' +
    '<div class="summary-item">Service-Linked: <span class="summary-count">' + (lm.service_linked || []).length + '</span></div>' +
    '<div class="summary-item">Trust Chain: <span class="summary-count">' + (lm.trust_chain || []).length + '</span></div>';
}
renderPathList();

// Tabs
var tabDefs = [
  { id: "tab-path", label: "Path Detail" },
  { id: "tab-circumvent", label: "Circumvention" },
  { id: "tab-lateral", label: "Lateral Movement" }
];
var tabsEl = document.getElementById("tabs");
tabDefs.forEach(function(t, i) {
  var btn = document.createElement("button");
  btn.className = "tab" + (i === 0 ? " active" : "");
  btn.textContent = t.label;
  btn.onclick = function() {
    document.querySelectorAll(".tab").forEach(function(b) { b.classList.remove("active"); });
    document.querySelectorAll(".tab-content").forEach(function(c) { c.classList.remove("active"); });
    btn.classList.add("active");
    document.getElementById(t.id).classList.add("active");
  };
  tabsEl.appendChild(btn);
});

// Path detail tab
function renderPathDetail() {
  var tab = document.getElementById("tab-path");
  if (data.escalation_paths.length === 0) {
    tab.innerHTML = '<div class="empty-state">No escalation paths found</div>';
    return;
  }
  var path = data.escalation_paths[selectedPath] || data.escalation_paths[0];
  var html = '<h3 style="font-size:16px;margin-bottom:16px">' + escapeHtml(path.name) + '</h3><div class="timeline">';
  path.steps.forEach(function(s) {
    var id = "cli-" + selectedPath + "-" + s.step_number;
    var policyId = "pol-" + selectedPath + "-" + s.step_number;
    html += '<div class="step-item">' +
      '<div class="step-num">' + s.step_number + '</div>' +
      '<div class="step-desc">' + escapeHtml(s.description) + '</div>';
    if (s.cli_command) {
      html += '<div class="cli-block" id="' + id + '"><button class="copy-btn" onclick="copyText(\'' + id + '\')">COPY</button>' + escapeHtml(s.cli_command) + '</div>';
    }
    if (s.iam_policy_json) {
      html += '<div class="policy-block" id="' + policyId + '"><button class="copy-btn" onclick="copyText(\'' + policyId + '\')">COPY</button>' + escapeHtml(JSON.stringify(s.iam_policy_json, null, 2)) + '</div>';
    }
    html += '</div>';
  });
  html += '</div>';
  if (path.mitre_techniques && path.mitre_techniques.length) {
    html += '<div style="margin-top:16px;display:flex;gap:6px;flex-wrap:wrap">' +
      path.mitre_techniques.map(function(t) { return '<span class="mitre-tag">' + t + '</span>'; }).join("") +
    '</div>';
  }
  tab.innerHTML = html;
}
renderPathDetail();

function copyText(id) {
  var el = document.getElementById(id);
  var text = el.textContent.replace("COPY", "").trim();
  navigator.clipboard.writeText(text).then(function() {
    var btn = el.querySelector(".copy-btn");
    btn.textContent = "COPIED";
    setTimeout(function() { btn.textContent = "COPY"; }, 1500);
  });
}

// Circumvention tab
(function() {
  var tab = document.getElementById("tab-circumvent");
  var ca = data.circumvention_analysis || {};
  var sections = [
    { title: "SCP Bypass Techniques", items: ca.scp_bypass || [], color: "#a78bfa" },
    { title: "Permission Boundary Bypass", items: ca.boundary_bypass || [], color: "#22d3ee" },
    { title: "Session Policy Considerations", items: ca.session_policy || [], color: "#f59e0b" }
  ];
  var html = "";
  sections.forEach(function(s) {
    html += '<div class="circ-card" style="border-left:3px solid ' + s.color + '">' +
      '<div class="circ-title" style="color:' + s.color + '">' + s.title + ' (' + s.items.length + ')</div>';
    if (s.items.length === 0) {
      html += '<div class="circ-item" style="color:#475569">None identified</div>';
    } else {
      s.items.forEach(function(item) {
        html += '<div class="circ-item">' + escapeHtml(item) + '</div>';
      });
    }
    html += '</div>';
  });
  tab.innerHTML = html;
})();

// Lateral movement tab
(function() {
  var tab = document.getElementById("tab-lateral");
  var lm = data.lateral_movement || {};
  var sections = [
    { title: "Cross-Account Role Assumptions", items: lm.cross_account || [], color: "#f59e0b" },
    { title: "Service-Linked Role Abuse", items: lm.service_linked || [], color: "#22d3ee" },
    { title: "Trust Chain Exploitation", items: lm.trust_chain || [], color: "#ef4444" }
  ];
  var html = "";
  sections.forEach(function(s) {
    html += '<div class="lateral-card" style="border-left:3px solid ' + s.color + '">' +
      '<div class="lateral-title" style="color:' + s.color + '">' + s.title + ' (' + s.items.length + ')</div>';
    if (s.items.length === 0) {
      html += '<div class="lateral-item" style="color:#475569">None identified</div>';
    } else {
      s.items.forEach(function(item) {
        html += '<div class="lateral-item">' + escapeHtml(item) + '</div>';
      });
    }
    html += '</div>';
  });
  tab.innerHTML = html;
})();
</script>
</body>
</html>
```

### Rendering Steps

1. Read `./data/exploit/<RUN_ID>.json`
2. Verify `payload` exists and contains expected fields
3. Construct DATA_JSON:
   - `account_id`, `region`, `timestamp`, `run_id` from envelope
   - All fields from `payload`
4. Serialize DATA_JSON — valid JSON, escape `</script>` as `<\/script>`
5. Copy the HTML template, replace `{{DATA_JSON}}`
6. Write to `$RUN_DIR/dashboard.html`
7. Verify: `test -f "$RUN_DIR/dashboard.html"`

### Template Contract

- Self-contained — no external dependencies (pure CSS/JS)
- `const data = {{DATA_JSON}};` is the single injection point
- No other template variables
- No server required — open directly in browser
- All styles inlined — no external CSS
</exploit_renderer>


<investigate_renderer>
## Investigate Renderer — Alert Investigation Timeline Dashboard

**Output file:** `$RUN_DIR/dashboard.html`

### Data Source

Read `./data/investigate/<RUN_ID>.json`. Extract the `payload` object — this contains `alert_type`, `mcp_mode`, `time_range`, `narrative`, `timeline`, and `queries_run`. Add `account_id`, `region`, and `timestamp` from the envelope.

The DATA_JSON object passed to the template must follow this structure:

```json
{
  "account_id": "string — from envelope",
  "region": "string — from envelope",
  "timestamp": "string — ISO8601 from envelope",
  "run_id": "string — from envelope",
  "alert_type": "string",
  "mcp_mode": "CONNECTED | MANUAL",
  "time_range": { "earliest": "string", "latest": "string" },
  "narrative": "string",
  "timeline": [...],
  "queries_run": [...]
}
```

### Complete HTML Template

Copy this template exactly, then replace `{{DATA_JSON}}` with the constructed data object:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SCOPE Investigation Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #0a0e17;
    color: #e2e8f0;
    font-family: 'Inter', 'Segoe UI', -apple-system, sans-serif;
    overflow-x: hidden;
    min-height: 100vh;
  }

  .header {
    padding: 14px 24px;
    border-bottom: 1px solid #1e293b;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .header-title { font-size: 18px; font-weight: 700; letter-spacing: -0.02em; }
  .header-sub { font-size: 11px; color: #64748b; margin-top: 2px; }
  .mode-badge {
    padding: 4px 14px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 13px;
    text-transform: uppercase;
  }

  .stats-row { display: flex; gap: 10px; padding: 14px 24px; flex-wrap: wrap; }
  .stat-card {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 12px 16px;
    flex: 1;
    min-width: 130px;
  }
  .stat-label { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px; }
  .stat-value { font-size: 24px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
  .stat-sub { font-size: 10px; color: #64748b; margin-top: 2px; }

  .main { padding: 0 24px 24px; display: flex; flex-direction: column; gap: 14px; }

  .tabs { display: flex; gap: 2px; }
  .tab {
    padding: 8px 18px;
    border-radius: 6px 6px 0 0;
    border: 1px solid #1e293b;
    border-bottom: none;
    background: transparent;
    color: #64748b;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
    transition: all 0.2s;
  }
  .tab.active { background: #111827; color: #e2e8f0; border-color: #334155; }
  .tab:hover { color: #e2e8f0; }
  .tab-content {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 0 8px 8px 8px;
    padding: 20px;
    overflow-y: auto;
    display: none;
    min-height: 400px;
  }
  .tab-content.active { display: block; }

  .narrative-text {
    font-size: 14px;
    line-height: 1.8;
    color: #cbd5e1;
    white-space: pre-wrap;
  }

  .timeline-container { position: relative; padding-left: 140px; }
  .timeline-container::before {
    content: "";
    position: absolute;
    left: 130px;
    top: 0;
    bottom: 0;
    width: 2px;
    background: #1e293b;
  }
  .tl-event {
    position: relative;
    margin-bottom: 16px;
    padding: 12px 16px;
    background: #0f1729;
    border: 1px solid #1e293b;
    border-radius: 8px;
    transition: all 0.2s;
  }
  .tl-event:hover { border-color: #334155; }
  .tl-event::before {
    content: "";
    position: absolute;
    left: -18px;
    top: 18px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #3b82f6;
    border: 2px solid #0a0e17;
  }
  .tl-time {
    position: absolute;
    left: -140px;
    top: 12px;
    width: 120px;
    text-align: right;
    font-size: 10px;
    font-family: 'JetBrains Mono', monospace;
    color: #64748b;
  }
  .tl-event-name { font-weight: 600; font-size: 13px; margin-bottom: 4px; }
  .tl-meta { display: flex; gap: 10px; font-size: 11px; color: #64748b; }
  .tl-principal { color: #a78bfa; }
  .tl-ip { color: #22d3ee; }

  .query-card {
    background: #0f1729;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 12px;
  }
  .query-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .query-name { font-weight: 600; font-size: 13px; }
  .query-step { font-size: 10px; color: #64748b; font-family: monospace; }
  .query-status {
    padding: 2px 9px;
    border-radius: 12px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
  }
  .status-executed { background: rgba(34,197,94,0.15); color: #22c55e; }
  .status-skipped { background: rgba(100,116,139,0.15); color: #94a3b8; }
  .status-pivoted { background: rgba(245,158,11,0.15); color: #f59e0b; }
  .spl-block {
    background: #0a0e17;
    border: 1px solid #1e293b;
    border-radius: 6px;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: #a78bfa;
    white-space: pre-wrap;
    word-break: break-all;
    position: relative;
    margin-top: 8px;
  }
  .copy-btn {
    position: absolute;
    top: 8px;
    right: 8px;
    padding: 3px 10px;
    border-radius: 4px;
    border: 1px solid #334155;
    background: #1e293b;
    color: #94a3b8;
    cursor: pointer;
    font-size: 10px;
    transition: all 0.2s;
  }
  .copy-btn:hover { background: #334155; color: #e2e8f0; }

  .ip-table { width: 100%; border-collapse: collapse; }
  .ip-table th {
    text-align: left;
    font-size: 10px;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 8px 12px;
    border-bottom: 1px solid #1e293b;
  }
  .ip-table td {
    font-size: 12px;
    padding: 8px 12px;
    border-bottom: 1px solid #1e293b;
  }
  .ip-table tr:hover td { background: #0f1729; }
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="header-title">SCOPE Investigation Dashboard</div>
    <div class="header-sub" id="header-sub"></div>
  </div>
  <div class="mode-badge" id="mode-badge"></div>
</div>

<div class="stats-row" id="stats-row"></div>

<div class="main">
  <div class="tabs" id="tabs"></div>
  <div class="tab-content active" id="tab-narrative"></div>
  <div class="tab-content" id="tab-timeline"></div>
  <div class="tab-content" id="tab-queries"></div>
  <div class="tab-content" id="tab-iocs"></div>
</div>

<script>
const data = {{DATA_JSON}};

function escapeHtml(t) { var d = document.createElement("div"); d.appendChild(document.createTextNode(t)); return d.innerHTML; }

// Header
document.getElementById("header-sub").textContent =
  "Alert: " + data.alert_type + " \u2022 Account " + data.account_id + " \u2022 " + data.region + " \u2022 " + data.timestamp;

var modeBadge = document.getElementById("mode-badge");
var isConnected = data.mcp_mode === "CONNECTED";
modeBadge.textContent = data.mcp_mode;
modeBadge.style.background = isConnected ? "rgba(34,197,94,0.15)" : "rgba(245,158,11,0.15)";
modeBadge.style.color = isConnected ? "#22c55e" : "#f59e0b";
modeBadge.style.border = "1px solid " + (isConnected ? "#22c55e40" : "#f59e0b40");

// Stats
var statsRow = document.getElementById("stats-row");
function addStat(label, value, color, sub) {
  var c = document.createElement("div");
  c.className = "stat-card";
  c.innerHTML = '<div class="stat-label">' + label + '</div><div class="stat-value" style="color:' + (color || "#e2e8f0") + '">' + value + '</div>' + (sub ? '<div class="stat-sub">' + sub + '</div>' : '');
  statsRow.appendChild(c);
}
addStat("Alert Type", data.alert_type, "#f59e0b");
addStat("Events", data.timeline.length, "#3b82f6");
addStat("Queries", data.queries_run.length, "#a78bfa",
  data.queries_run.filter(function(q) { return q.status === "executed"; }).length + " executed");
addStat("Time Range", data.time_range.earliest ? "Set" : "N/A", "#22d3ee",
  (data.time_range.earliest || "") + " to " + (data.time_range.latest || ""));

// Unique IPs and principals for IOC tab
var uniqueIPs = {};
var uniquePrincipals = {};
data.timeline.forEach(function(e) {
  if (e.source_ip) uniqueIPs[e.source_ip] = (uniqueIPs[e.source_ip] || 0) + 1;
  if (e.principal) uniquePrincipals[e.principal] = (uniquePrincipals[e.principal] || 0) + 1;
});

// Tabs
var tabDefs = [
  { id: "tab-narrative", label: "Narrative" },
  { id: "tab-timeline", label: "Timeline (" + data.timeline.length + ")" },
  { id: "tab-queries", label: "Queries (" + data.queries_run.length + ")" },
  { id: "tab-iocs", label: "IOCs" }
];
var tabsEl = document.getElementById("tabs");
tabDefs.forEach(function(t, i) {
  var btn = document.createElement("button");
  btn.className = "tab" + (i === 0 ? " active" : "");
  btn.textContent = t.label;
  btn.onclick = function() {
    document.querySelectorAll(".tab").forEach(function(b) { b.classList.remove("active"); });
    document.querySelectorAll(".tab-content").forEach(function(c) { c.classList.remove("active"); });
    btn.classList.add("active");
    document.getElementById(t.id).classList.add("active");
  };
  tabsEl.appendChild(btn);
});

// Narrative tab
document.getElementById("tab-narrative").innerHTML =
  '<div class="narrative-text">' + escapeHtml(data.narrative || "No narrative generated.") + '</div>';

// Timeline tab
(function() {
  var tab = document.getElementById("tab-timeline");
  if (data.timeline.length === 0) {
    tab.innerHTML = '<div style="color:#475569;text-align:center;padding:40px">No timeline events recorded</div>';
    return;
  }
  var html = '<div class="timeline-container">';
  data.timeline.forEach(function(e) {
    var timeStr = e.timestamp || "";
    var shortTime = timeStr.length > 19 ? timeStr.substring(11, 19) : timeStr;
    html += '<div class="tl-event">' +
      '<div class="tl-time">' + escapeHtml(shortTime) + '</div>' +
      '<div class="tl-event-name">' + escapeHtml(e.event) + '</div>' +
      '<div class="tl-meta">' +
        '<span class="tl-principal">' + escapeHtml(e.principal || "unknown") + '</span>' +
        '<span class="tl-ip">' + escapeHtml(e.source_ip || "N/A") + '</span>' +
      '</div>' +
    '</div>';
  });
  html += '</div>';
  tab.innerHTML = html;
})();

// Queries tab
(function() {
  var tab = document.getElementById("tab-queries");
  if (data.queries_run.length === 0) {
    tab.innerHTML = '<div style="color:#475569;text-align:center;padding:40px">No queries recorded</div>';
    return;
  }
  var html = "";
  data.queries_run.forEach(function(q) {
    var statusClass = "status-" + q.status;
    var splId = "qspl-" + q.step;
    html += '<div class="query-card">' +
      '<div class="query-header">' +
        '<div><span class="query-step">Step ' + q.step + '</span> <span class="query-name">' + escapeHtml(q.name) + '</span></div>' +
        '<span class="query-status ' + statusClass + '">' + q.status + '</span>' +
      '</div>' +
      '<div class="spl-block" id="' + splId + '">' +
        '<button class="copy-btn" onclick="copyText(\'' + splId + '\')">COPY</button>' +
        escapeHtml(q.spl) +
      '</div>' +
    '</div>';
  });
  tab.innerHTML = html;
})();

function copyText(id) {
  var el = document.getElementById(id);
  var text = el.textContent.replace("COPY", "").trim();
  navigator.clipboard.writeText(text).then(function() {
    var btn = el.querySelector(".copy-btn");
    btn.textContent = "COPIED";
    setTimeout(function() { btn.textContent = "COPY"; }, 1500);
  });
}

// IOC tab — unique IPs and principals
(function() {
  var tab = document.getElementById("tab-iocs");
  var html = '<h3 style="font-size:14px;margin-bottom:12px">Source IPs</h3>';
  var ips = Object.keys(uniqueIPs).sort(function(a, b) { return uniqueIPs[b] - uniqueIPs[a]; });
  if (ips.length > 0) {
    html += '<table class="ip-table"><thead><tr><th>IP Address</th><th>Events</th></tr></thead><tbody>';
    ips.forEach(function(ip) {
      html += '<tr><td style="font-family:monospace;color:#22d3ee">' + escapeHtml(ip) + '</td><td>' + uniqueIPs[ip] + '</td></tr>';
    });
    html += '</tbody></table>';
  } else {
    html += '<div style="color:#475569;padding:12px">No source IPs recorded</div>';
  }
  html += '<h3 style="font-size:14px;margin:20px 0 12px">Principals</h3>';
  var principals = Object.keys(uniquePrincipals).sort(function(a, b) { return uniquePrincipals[b] - uniquePrincipals[a]; });
  if (principals.length > 0) {
    html += '<table class="ip-table"><thead><tr><th>Principal</th><th>Events</th></tr></thead><tbody>';
    principals.forEach(function(p) {
      html += '<tr><td style="font-family:monospace;color:#a78bfa">' + escapeHtml(p) + '</td><td>' + uniquePrincipals[p] + '</td></tr>';
    });
    html += '</tbody></table>';
  } else {
    html += '<div style="color:#475569;padding:12px">No principals recorded</div>';
  }
  tab.innerHTML = html;
})();
</script>
</body>
</html>
```

### Rendering Steps

1. Read `./data/investigate/<RUN_ID>.json`
2. Verify `payload` exists and contains expected fields
3. Construct DATA_JSON:
   - `account_id`, `region`, `timestamp`, `run_id` from envelope
   - All fields from `payload`
4. Serialize DATA_JSON — valid JSON, escape `</script>` as `<\/script>`
5. Copy the HTML template, replace `{{DATA_JSON}}`
6. Write to `$RUN_DIR/dashboard.html`
7. Verify: `test -f "$RUN_DIR/dashboard.html"`

### Template Contract

- Self-contained — no external dependencies (pure CSS/JS)
- `const data = {{DATA_JSON}};` is the single injection point
- No other template variables
- No server required — open directly in browser
- All styles inlined — no external CSS
</investigate_renderer>


<error_handling>
## Error Handling

scope-render is a best-effort visualization layer. Failures must never block the calling agent.

### Normalized Data Not Found

If `./data/<PHASE>/<RUN_ID>.json` does not exist:
- Log: `"Warning: normalized data not found at ./data/<PHASE>/<RUN_ID>.json — skipping dashboard generation"`
- Return without writing any HTML file

### Invalid or Incomplete Data

If the normalized JSON exists but is missing required payload fields:
- Log: `"Warning: payload missing expected fields for <PHASE> dashboard — generating partial dashboard"`
- Proceed with available data — templates handle missing fields gracefully with empty states

### Write Failure

If unable to write to `$RUN_DIR/`:
- Log: `"Error: cannot write dashboard to $RUN_DIR/<filename> — <error>"`
- Return without retrying

### Template Rendering Failure

If an error occurs during DATA_JSON construction or template population:
- Log: `"Warning: dashboard rendering failed for <PHASE>/<RUN_ID> — <error>"`
- Return without writing a partial HTML file

### General Rule

On any unhandled error: log the full error and return. The raw artifacts and normalized data already exist — dashboard rendering is a visualization convenience, not a gating requirement.
</error_handling>
