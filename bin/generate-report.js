#!/usr/bin/env node
// SCOPE Report Generator
// Builds the dashboard and inlines all assets + JSON data into a single
// self-contained HTML file that opens in any browser without a server.
//
// Usage:
//   node bin/generate-report.js [output-path]
//   npm run dashboard                          (from dashboard/)
//   npm run dashboard -- ../dashboard/reports/custom.html     (custom output path)
//
// The script:
//   1. Runs `vite build` to produce dist/
//   2. Reads the built HTML, JS, and CSS from dist/
//   3. Reads all JSON data from dashboard/public/ (via index.json)
//   4. Inlines everything into a single dashboard.html
//   5. Writes to the specified output path (default: $RUN_DIR/dashboard.html or dashboard/reports/<run-id>-dashboard.html)

import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync, readdirSync, renameSync, mkdirSync } from "node:fs";
import { join, dirname, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const dashboardDir = join(__dirname, "..", "dashboard");
const publicDir = join(dashboardDir, "public");
const distDir = join(dashboardDir, "dist");
const reportsDir = join(dashboardDir, "reports");
const validSources = new Set(["audit", "exploit", "controls"]);

function canonicalSource(explicitSource, fallbackSource = "audit") {
  if (validSources.has(explicitSource)) return explicitSource;
  if (typeof explicitSource === "string" && explicitSource.startsWith("svc:")) {
    return validSources.has(fallbackSource) ? fallbackSource : "audit";
  }
  if (explicitSource) return null;
  return validSources.has(fallbackSource) ? fallbackSource : null;
}

function jsonForInlineScript(value) {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}

function readAuditModule(auditRunDir, service) {
  const nestedDir = join(auditRunDir, "modules", service);
  if (existsSync(nestedDir)) {
    const resources = [];
    const files = readdirSync(nestedDir)
      .filter((file) => file.endsWith(".json"))
      .sort();
    for (const file of files) {
      const payload = JSON.parse(readFileSync(join(nestedDir, file), "utf-8"));
      resources.push(...resourcesOf(payload));
    }
    return { resources };
  }

  const legacyPath = join(auditRunDir, `${service}.json`);
  if (!existsSync(legacyPath)) return null;
  return JSON.parse(readFileSync(legacyPath, "utf-8"));
}

function resourcesOf(moduleData) {
  if (Array.isArray(moduleData?.resources)) return moduleData.resources;
  if (Array.isArray(moduleData?.findings)) return moduleData.findings;
  return [];
}

function inlineControlsArtifacts(json) {
  const file = json?.remediation?.file;
  if (json?.source !== "controls" || typeof file !== "string" || json.remediation.markdown) {
    return json;
  }
  const remediationPath = resolve(file);
  if (!existsSync(remediationPath)) {
    return json;
  }
  return {
    ...json,
    remediation: {
      ...json.remediation,
      markdown: readFileSync(remediationPath, "utf-8"),
    },
  };
}

function reportSortValue(report) {
  const parsed = Date.parse(report?.created_at || report?.date || "");
  return Number.isNaN(parsed) ? 0 : parsed;
}

function migrateRunsToReports(runs) {
  const byId = new Map();
  for (const run of Array.isArray(runs) ? runs : []) {
    const source = canonicalSource(run?.source);
    if (source !== "audit" && source !== "exploit") continue;
    const runId = run?.run_id;
    if (!runId) continue;
    if (!byId.has(runId)) {
      const report = {
        report_id: runId,
        created_at: run.date || "",
        account_id: run.account_id,
        target: run.target || "",
        risk: run.risk || "low",
        status: run.status || "complete",
      };
      report[source] = {
        run_id: runId,
        file: run.file || `${runId}.json`,
      };
      byId.set(runId, report);
    }
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
  return clean.sort((a, b) => reportSortValue(b) - reportSortValue(a));
}

function reportsFromIndex(index) {
  const reports = normalizeReports(index?.reports);
  if (reports.length > 0) return reports;
  return migrateRunsToReports(index?.runs || []);
}

function selectReportForInline(reports) {
  if (currentRunId) {
    const selected = reports.find((report) => (
      report.report_id === currentRunId ||
      report.audit?.run_id === currentRunId ||
      report.exploit?.run_id === currentRunId ||
      report.controls?.run_id === currentRunId
    ));
    if (selected) return selected;
  }
  return reports[0] || null;
}

// --- Step 1: Install dependencies if needed, then build the dashboard ---
const nodeModulesDir = join(dashboardDir, "node_modules");
if (!existsSync(nodeModulesDir)) {
  console.log("[SCOPE] node_modules not found — running npm install...");
  try {
    execSync("npm install --prefer-offline --no-audit --no-fund", { cwd: dashboardDir, stdio: "pipe" });
    console.log("[SCOPE] npm install complete.");
  } catch (err) {
    console.error("[SCOPE] npm install failed:", err.stderr?.toString() || err.message);
    process.exit(1);
  }
}

console.log("[SCOPE] Building dashboard...");
try {
  execSync("npm run build", { cwd: dashboardDir, stdio: "pipe" });
} catch (err) {
  console.error("[SCOPE] Build failed:", err.stderr?.toString() || err.message);
  process.exit(1);
}
console.log("[SCOPE] Build complete.");

// --- Step 2: Read built assets ---
const distHtml = readFileSync(join(distDir, "index.html"), "utf-8");
const assetsDir = join(distDir, "assets");
const assetFiles = existsSync(assetsDir) ? readdirSync(assetsDir) : [];

const jsFiles = assetFiles.filter((f) => f.endsWith(".js"));
const cssFiles = assetFiles.filter((f) => f.endsWith(".css"));

let jsContent = "";
for (const f of jsFiles) {
  jsContent += readFileSync(join(assetsDir, f), "utf-8") + "\n";
}

let cssContent = "";
for (const f of cssFiles) {
  cssContent += readFileSync(join(assetsDir, f), "utf-8") + "\n";
}

// --- Step 3: Upsert+cull+atomic-write for dashboard/public/index.json ---
// If the agent set RUN_DIR, we know the current run_id and can propagate status from
// data/index.json into the dashboard index. This is the hardening step for PIPE-03.
const projectRoot = join(__dirname, "..");
const dataIndexPath = join(projectRoot, "data", "index.json");
const dashboardIndexPath = join(publicDir, "index.json");
const dashboardIndexTmpPath = join(publicDir, "index.json.tmp");

const runDir = process.env.RUN_DIR || process.env.AUDIT_RUN_DIR;
const currentRunId = runDir ? basename(runDir) : null;

if (existsSync(dashboardIndexPath)) {
  try {
    let dashIndex = JSON.parse(readFileSync(dashboardIndexPath, "utf-8"));
    const reports = reportsFromIndex(dashIndex);

    // Look up status for the current run from data/index.json (if available)
    let currentRunStatus = "complete";
    if (currentRunId && existsSync(dataIndexPath)) {
      try {
        const dataIndex = JSON.parse(readFileSync(dataIndexPath, "utf-8"));
        const dataEntry = (dataIndex?.runs || []).find((r) => r.run_id === currentRunId);
        if (dataEntry?.status) currentRunStatus = dataEntry.status;
      } catch (e) {
        console.warn("[SCOPE] Could not read data/index.json for status propagation:", e.message);
      }
    }

    // Single-pass filter: cull report entries whose source files are gone.
    const culledReports = [];
    let orphanCount = 0;
    for (const report of reports) {
      const auditFile = report.audit?.file;
      const exploitFile = report.exploit?.file;
      const controlsFile = report.controls?.file;
      if ((auditFile && !existsSync(join(publicDir, auditFile))) || (exploitFile && !existsSync(join(publicDir, exploitFile))) || (controlsFile && !existsSync(join(publicDir, controlsFile)))) {
        orphanCount++;
        console.log(`[SCOPE] Culled orphan dashboard report: ${report.report_id}`);
        continue;
      }
      if (currentRunId && (report.report_id === currentRunId || report.audit?.run_id === currentRunId || report.exploit?.run_id === currentRunId || report.controls?.run_id === currentRunId)) {
        report.status = currentRunStatus || report.status || "complete";
      }
      culledReports.push(report);
    }

    // Write updated index atomically
    const updatedIndex = {
      version: "2.0.0",
      updated: new Date().toISOString(),
      reports: culledReports.sort((a, b) => reportSortValue(b) - reportSortValue(a)),
    };
    writeFileSync(dashboardIndexTmpPath, JSON.stringify(updatedIndex, null, 2), "utf-8");
    renameSync(dashboardIndexTmpPath, dashboardIndexPath);
    if (orphanCount > 0) {
      console.log(`[SCOPE] Dashboard index updated: culled ${orphanCount} orphan(s), version 2.0.0`);
    }
  } catch (err) {
    console.warn("[SCOPE] Dashboard index update failed (non-blocking):", err.message);
  }
}

// --- Step 4: Read JSON data from public/ ---
const inlineData = {};

if (existsSync(join(publicDir, "index.json"))) {
  const index = JSON.parse(readFileSync(join(publicDir, "index.json"), "utf-8"));
  const reports = reportsFromIndex(index);
  const selectedReport = selectReportForInline(reports);
  const selectedFiles = selectedReport ? [
    ["audit", selectedReport.audit],
    ["exploit", selectedReport.exploit],
    ["controls", selectedReport.controls],
  ].filter(([, entry]) => entry?.file) : [];

  for (const [src, entry] of selectedFiles) {
    const file = entry.file;
    const filePath = join(publicDir, file);
    if (existsSync(filePath)) {
      try {
        let json = JSON.parse(readFileSync(filePath, "utf-8"));
        json = inlineControlsArtifacts(json);
        // Note: controls account_id backfill is done in a second pass below
        // (after all sources are loaded) to avoid order-dependence.
        // Edge backfill: derive graph edges from IAM trust policies when edges are empty
        if (src === "audit" && json.graph && Array.isArray(json.graph.edges) && json.graph.edges.length === 0) {
          const edges = [];
          // 1. From trust_relationships[] in results.json (Claude populates this)
          if (Array.isArray(json.trust_relationships)) {
            for (const tr of json.trust_relationships) {
              if (tr.principal && tr.role_arn) {
                const srcLabel = tr.principal.includes(":user/") ? `user:${tr.principal.split("/").pop()}` : tr.principal;
                const tgtLabel = tr.role_id || `role:${tr.role_arn.split("/").pop()}`;
                edges.push({ source: srcLabel, target: tgtLabel, trust_type: tr.trust_type || "same-account", edge_type: "trust", label: "can_assume" });
              }
            }
          }
          // 2. Fallback: parse IAM module data from the audit run directory for role trust policies
          const run = entry;
          if (edges.length === 0 && run.run_id) {
            // Detect format: ARN-based ("arn:aws:...") or short ("user:name")
            const firstId = json.graph.nodes?.[0]?.id || "";
            const useArns = firstId.startsWith("arn:");

            const auditRunDir = run.run_id === currentRunId && runDir
              ? runDir
              : join(projectRoot, "runs", run.run_id);
            try {
              const iam = readAuditModule(auditRunDir, "iam");
              if (iam) {
                const roles = resourcesOf(iam).filter(f => f.resource_type === 'iam_role');
                for (const role of roles) {
                  if (!role.trust_relationships) continue;
                  for (const tr of role.trust_relationships) {
                    if (!tr.principal) continue;
                    const isExternal = tr.trust_type === 'cross_account' || tr.trust_type === 'federated' || tr.trust_type === 'wildcard';
                    const targetId = isExternal
                      ? `external:${tr.principal}`
                      : `role:${tr.principal.split('/').pop()}`;
                    edges.push({
                      source: `role:${role.resource_id}`,
                      target: targetId,
                      edge_type: 'trust',
                      trust_type: tr.trust_type || 'same-account',
                      label: `${tr.trust_type} trust`,
                    });
                  }
                }
                if (edges.length > 0) console.log(`[SCOPE] Derived ${edges.length} trust edges from IAM module data`);
              }
            } catch (e) {
              console.warn(`[SCOPE] Edge backfill: failed to parse IAM module data:`, e.message);
            }
          }
          if (edges.length > 0) {
            json.graph.edges = edges;
            console.log(`[SCOPE] Backfilled ${edges.length} graph edges total`);
          }
        }
        // Propagate status field from index entry into inlined data for dashboard badge rendering
        if (selectedReport?.status && selectedReport.status !== "complete") {
          json._run_status = selectedReport.status;
        }
        json._dashboard_run_id = selectedReport.report_id;
        inlineData[src] = json;
        console.log(`[SCOPE] Inlined ${src} data from ${file}${selectedReport?.status && selectedReport.status !== "complete" ? ` [${selectedReport.status}]` : ""}`);
      } catch (err) {
        console.warn(`[SCOPE] Failed to read ${file}:`, err.message);
      }
    } else {
      console.warn(`[SCOPE] Data file not found: ${filePath}`);
    }
  }
} else {
  // Fallback: scan all JSON files in public/ (no index.json needed)
  if (!existsSync(publicDir)) {
    console.log("No dashboard/public/ directory found — skipping data inlining.");
  }
  const jsonFiles = existsSync(publicDir) ? readdirSync(publicDir).filter(f => f.endsWith(".json") && f !== "index.json") : [];
  if (jsonFiles.length > 0) {
    // Group by source, pick the most recent file per source (by filename timestamp)
    const bySource = {};
    for (const file of jsonFiles.sort().reverse()) {
      try {
        let json = JSON.parse(readFileSync(join(publicDir, file), "utf-8"));
        json = inlineControlsArtifacts(json);
        const src = canonicalSource(json.source, file.startsWith("controls") ? "controls" : "audit");
        if (!src) {
          console.warn(`[SCOPE] Skipping ${file} with unsupported source: ${json.source}`);
          continue;
        }
        if (!bySource[src]) {
          bySource[src] = { json, file };
        }
      } catch (_) { /* skip invalid JSON */ }
    }
    for (const [src, { json, file }] of Object.entries(bySource)) {
      inlineData[src] = json;
      console.log(`[SCOPE] Inlined ${src} data from ${file} (no index.json)`);
    }
  } else {
    // Last resort: try results.json
    const fallback = join(publicDir, "results.json");
    if (existsSync(fallback)) {
      let json = JSON.parse(readFileSync(fallback, "utf-8"));
      json = inlineControlsArtifacts(json);
      const src = canonicalSource(json.source);
      if (src) {
        inlineData[src] = json;
        console.log(`[SCOPE] Inlined ${src} data from results.json`);
      } else {
        console.warn(`[SCOPE] Skipping results.json with unsupported source: ${json.source}`);
      }
    }
  }
}

// Second pass: backfill controls account_id from audit data (order-independent)
if (inlineData["controls"] && !inlineData["controls"].account_id && inlineData["audit"]?.account_id) {
  inlineData["controls"].account_id = inlineData["audit"].account_id;
  console.log(`[SCOPE] Backfilled controls account_id from audit data: ${inlineData["audit"].account_id}`);
}

if (Object.keys(inlineData).length === 0) {
  console.error("[SCOPE] No data files found in dashboard/public/. Run an audit first.");
  process.exit(1);
}

// --- Step 5: Build self-contained HTML ---
const dataScript = `<script>window.__SCOPE_INLINE_DATA__ = ${jsonForInlineScript(inlineData)};</script>`;

// Extract the original <head> content from the built HTML
const headMatch = distHtml.match(/<head>([\s\S]*?)<\/head>/);
const originalHead = headMatch ? headMatch[1] : "";

// Remove existing <script> and <link rel="stylesheet"> tags from head (we'll inline them)
const cleanHead = originalHead
  .replace(/<script[^>]*>[\s\S]*?<\/script>/g, "")
  .replace(/<link[^>]*rel="stylesheet"[^>]*\/?>/g, "");

// Build the report HTML — fonts are loaded from Google Fonts CDN (requires internet)
// For fully offline use, the fonts degrade gracefully to system fonts
const reportHtml = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>SCOPE — Security Report</title>
    <link rel="icon" href="data:," />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet" />
    <style>
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body { background: #0a0e17; overflow: hidden; }
      #root { width: 100vw; height: 100vh; }
      ::-webkit-scrollbar { width: 6px; }
      ::-webkit-scrollbar-track { background: transparent; }
      ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
      ::-webkit-scrollbar-thumb:hover { background: #475569; }
    </style>
${cssContent ? `    <style>${cssContent}</style>` : ""}
${cleanHead}
  </head>
  <body>
    <div id="root"></div>
    ${dataScript}
    <script type="module">${jsContent}</script>
  </body>
</html>`;

// --- Step 6: Write the report ---
let outputPath = process.argv[2];
if (!outputPath) {
  // Use RUN_DIR environment variable if set by SCOPE agents (already resolved above)
  if (runDir && existsSync(runDir)) {
    outputPath = join(runDir, "dashboard.html");
  } else {
    // Derive filename from the latest run ID to avoid overwriting prior dashboards.
    // Each run gets its own dashboard file (e.g., audit-20260408-123456-all-dashboard.html).
    const latestRunId = currentRunId
      || (existsSync(join(publicDir, "index.json"))
        ? selectReportForInline(reportsFromIndex(JSON.parse(readFileSync(join(publicDir, "index.json"), "utf-8"))))?.report_id
        : null);
    const dashName = latestRunId ? `${latestRunId}-dashboard.html` : "dashboard.html";
    outputPath = join(reportsDir, dashName);
  }
}
outputPath = resolve(outputPath);
mkdirSync(dirname(outputPath), { recursive: true });

writeFileSync(outputPath, reportHtml, "utf-8");
const sizeKB = (Buffer.byteLength(reportHtml, "utf-8") / 1024).toFixed(1);
console.log(`[SCOPE] Report written to ${outputPath} (${sizeKB} KB)`);
console.log("[SCOPE] Open in any browser — no server required.");
