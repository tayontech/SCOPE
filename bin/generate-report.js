#!/usr/bin/env node
// SCOPE Report Generator
// Builds the dashboard and inlines all assets + JSON data into a single
// self-contained HTML file that opens in any browser without a server.
//
// Usage:
//   node bin/generate-report.js [output-path]
//   npm run dashboard                          (from dashboard/)
//   npm run dashboard -- ../dashboard.html     (custom output path)
//
// The script:
//   1. Runs `vite build` to produce dist/
//   2. Reads the built HTML, JS, and CSS from dist/
//   3. Reads all JSON data from dashboard/public/ (via index.json)
//   4. Inlines everything into a single dashboard.html
//   5. Writes to the specified output path (default: $RUN_DIR/dashboard.html or ./dashboard.html)

import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync, readdirSync, renameSync, unlinkSync } from "node:fs";
import { join, dirname, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const dashboardDir = join(__dirname, "..", "dashboard");
const publicDir = join(dashboardDir, "public");
const distDir = join(dashboardDir, "dist");

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
    const existingRuns = dashIndex?.runs || [];

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

    // Single-pass filter: cull orphans + dedup for current run_id
    const culledRuns = [];
    let orphanCount = 0;
    for (const run of existingRuns) {
      const file = run.file || `${run.run_id}.json`;
      const filePath = join(publicDir, file);
      if (!existsSync(filePath)) {
        // Orphan entry — the data file is gone; skip AND delete any leftover file
        orphanCount++;
        try { unlinkSync(filePath); } catch (_) { /* already gone */ }
        console.log(`[SCOPE] Culled orphan dashboard entry: ${run.run_id}`);
        continue;
      }
      if (run.run_id === currentRunId) {
        // Dedup: remove the stale entry; fresh one will be prepended below
        continue;
      }
      culledRuns.push(run);
    }

    // Propagate status: update status field on each run in the culled list using data/index.json
    // (so existing entries get status backfilled if they were written before status support)
    if (existsSync(dataIndexPath)) {
      try {
        const dataIndex = JSON.parse(readFileSync(dataIndexPath, "utf-8"));
        const dataRunMap = new Map((dataIndex?.runs || []).map((r) => [r.run_id, r]));
        for (const run of culledRuns) {
          if (!run.status) {
            const dataEntry = dataRunMap.get(run.run_id);
            if (dataEntry?.status) run.status = dataEntry.status;
            else run.status = "complete"; // backward compat default
          }
        }
      } catch (_) { /* status backfill is best-effort */ }
    }

    // Prepend the new/updated entry (if we know the current run_id and file exists)
    if (currentRunId) {
      const currentFile = `${currentRunId}.json`;
      const currentFilePath = join(publicDir, currentFile);
      if (existsSync(currentFilePath)) {
        // Find any existing run in existingRuns for metadata (source, date, etc.)
        const existingEntry = existingRuns.find((r) => r.run_id === currentRunId) || {};
        culledRuns.unshift({
          ...existingEntry,
          run_id: currentRunId,
          status: currentRunStatus,
          file: currentFile,
        });
      }
    }

    // Write updated index atomically
    const updatedIndex = {
      version: "1.1.0",
      updated: new Date().toISOString(),
      runs: culledRuns,
    };
    writeFileSync(dashboardIndexTmpPath, JSON.stringify(updatedIndex, null, 2), "utf-8");
    renameSync(dashboardIndexTmpPath, dashboardIndexPath);
    if (orphanCount > 0) {
      console.log(`[SCOPE] Dashboard index updated: culled ${orphanCount} orphan(s), version 1.1.0`);
    }
  } catch (err) {
    console.warn("[SCOPE] Dashboard index update failed (non-blocking):", err.message);
  }
}

// --- Step 4: Read JSON data from public/ ---
const inlineData = {};

if (existsSync(join(publicDir, "index.json"))) {
  const index = JSON.parse(readFileSync(join(publicDir, "index.json"), "utf-8"));
  const runs = index?.runs || [];

  // Find latest run per source type (same logic as App.jsx)
  const latestBySource = {};
  for (const run of runs) {
    const src = run.source || "audit";
    if (!latestBySource[src]) latestBySource[src] = run;
  }

  for (const [src, run] of Object.entries(latestBySource)) {
    const file = run.file || `${run.run_id}.json`;
    const filePath = join(publicDir, file);
    if (existsSync(filePath)) {
      try {
        const json = JSON.parse(readFileSync(filePath, "utf-8"));
        // Note: defend account_id backfill is done in a second pass below
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
          // 2. Fallback: parse iam.json from the audit run directory for role trust policies
          if (edges.length === 0 && run.run_id) {
            // Build node ID lookup to match edge format to existing node IDs
            const nodeById = {};
            for (const n of json.graph.nodes || []) nodeById[n.id] = n;
            // Detect format: ARN-based ("arn:aws:...") or short ("user:name")
            const firstId = json.graph.nodes?.[0]?.id || "";
            const useArns = firstId.startsWith("arn:");

            const auditRunDir = join(dashboardDir, "..", "audit", run.run_id);
            const iamPath = join(auditRunDir, "iam.json");
            if (existsSync(iamPath)) {
              try {
                const iam = JSON.parse(readFileSync(iamPath, "utf-8"));
                const roles = iam?.findings?.roles?.Roles || [];
                const accountId = json.account_id || "";
                for (const role of roles) {
                  const trustDoc = role.AssumeRolePolicyDocument;
                  if (!trustDoc) continue;
                  const policy = typeof trustDoc === "string" ? JSON.parse(decodeURIComponent(trustDoc)) : trustDoc;
                  for (const stmt of policy.Statement || []) {
                    if (stmt.Effect !== "Allow") continue;
                    const principals = [];
                    const p = stmt.Principal;
                    if (typeof p === "string") principals.push(p);
                    else if (p?.AWS) {
                      const aws = Array.isArray(p.AWS) ? p.AWS : [p.AWS];
                      principals.push(...aws);
                    }
                    for (const prin of principals) {
                      // Match the node ID format used in the graph
                      let srcId, tgtId;
                      if (useArns) {
                        srcId = prin === "*" ? "external:*" : prin;
                        tgtId = role.Arn || `arn:aws:iam::${accountId}:role/${role.RoleName}`;
                      } else {
                        srcId = prin.includes(":user/") ? `user:${prin.split("/").pop()}`
                          : prin.includes(":role/") ? `role:${prin.split("/").pop()}`
                          : prin === "*" ? "external:*" : prin;
                        tgtId = `role:${role.RoleName}`;
                      }
                      const trustType = prin.includes(accountId) && accountId ? "same-account"
                        : prin === "*" ? "wildcard" : "cross-account";
                      edges.push({ source: srcId, target: tgtId, trust_type: trustType, edge_type: "trust", label: "can_assume" });
                    }
                  }
                }
                if (edges.length > 0) console.log(`[SCOPE] Derived ${edges.length} trust edges from iam.json`);
              } catch (e) {
                console.warn(`[SCOPE] Edge backfill: failed to parse iam.json:`, e.message);
              }
            }
          }
          if (edges.length > 0) {
            json.graph.edges = edges;
            console.log(`[SCOPE] Backfilled ${edges.length} graph edges total`);
          }
        }
        // Propagate status field from index entry into inlined data for dashboard badge rendering
        if (run.status && run.status !== "complete") {
          json._run_status = run.status;
        }
        inlineData[src] = json;
        console.log(`[SCOPE] Inlined ${src} data from ${file}${run.status && run.status !== "complete" ? ` [${run.status}]` : ""}`);
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
        const json = JSON.parse(readFileSync(join(publicDir, file), "utf-8"));
        const src = json.source || (file.startsWith("defend") ? "defend" : "audit");
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
      const json = JSON.parse(readFileSync(fallback, "utf-8"));
      const src = json.source || "audit";
      inlineData[src] = json;
      console.log(`[SCOPE] Inlined ${src} data from results.json`);
    }
  }
}

// Second pass: backfill defend account_id from audit data (order-independent)
if (inlineData["defend"] && !inlineData["defend"].account_id && inlineData["audit"]?.account_id) {
  inlineData["defend"].account_id = inlineData["audit"].account_id;
  console.log(`[SCOPE] Backfilled defend account_id from audit data: ${inlineData["audit"].account_id}`);
}

if (Object.keys(inlineData).length === 0) {
  console.error("[SCOPE] No data files found in dashboard/public/. Run an audit first.");
  process.exit(1);
}

// --- Step 5: Build self-contained HTML ---
const dataScript = `<script>window.__SCOPE_INLINE_DATA__ = ${JSON.stringify(inlineData)};</script>`;

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
    outputPath = join(dashboardDir, "dashboard.html");
  }
}
outputPath = resolve(outputPath);

writeFileSync(outputPath, reportHtml, "utf-8");
const sizeKB = (Buffer.byteLength(reportHtml, "utf-8") / 1024).toFixed(1);
console.log(`[SCOPE] Report written to ${outputPath} (${sizeKB} KB)`);
console.log("[SCOPE] Open in any browser — no server required.");
