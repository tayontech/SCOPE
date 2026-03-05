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
import { readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const dashboardDir = join(__dirname, "..", "dashboard");
const publicDir = join(dashboardDir, "public");
const distDir = join(dashboardDir, "dist");

// --- Step 1: Build the dashboard ---
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

// --- Step 3: Read JSON data from public/ ---
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
        // Backfill defend account_id from audit data
        if (!json.account_id && src === "defend") {
          const auditData = inlineData["audit"];
          if (auditData?.account_id) {
            json.account_id = auditData.account_id;
          }
        }
        inlineData[src] = json;
        console.log(`[SCOPE] Inlined ${src} data from ${file}`);
      } catch (err) {
        console.warn(`[SCOPE] Failed to read ${file}:`, err.message);
      }
    } else {
      console.warn(`[SCOPE] Data file not found: ${filePath}`);
    }
  }
} else {
  // Fallback: try results.json
  const fallback = join(publicDir, "results.json");
  if (existsSync(fallback)) {
    const json = JSON.parse(readFileSync(fallback, "utf-8"));
    const src = json.source || "audit";
    inlineData[src] = json;
    console.log(`[SCOPE] Inlined ${src} data from results.json`);
  }
}

if (Object.keys(inlineData).length === 0) {
  console.error("[SCOPE] No data files found in dashboard/public/. Run an audit first.");
  process.exit(1);
}

// --- Step 4: Build self-contained HTML ---
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

// --- Step 5: Write the report ---
let outputPath = process.argv[2];
if (!outputPath) {
  // Check for RUN_DIR environment variable (set by SCOPE agents)
  const runDir = process.env.RUN_DIR || process.env.DEFEND_RUN_DIR || process.env.AUDIT_RUN_DIR;
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
