#!/usr/bin/env node
/**
 * SCOPE Install Script
 * Installs SCOPE agents into editor config directories.
 * Usage: node bin/install.js [--claude] [--gemini] [--codex] [--all] [--global|--local] [--help]
 *
 * Dependencies: Node.js built-ins only (fs, path, os). No npm required.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

// ---------------------------------------------------------------------------
// Editor directory mapping
// ---------------------------------------------------------------------------
// Skills directories per platform — each gets its own path for clean separation.
// Claude: .claude/skills/ (only path Claude Code scans)
// Gemini: .gemini/skills/ (native path — Gemini also scans .agents/skills/ but we use
//         .gemini/skills/ to keep platform installs separated. Only one platform is
//         installed at a time so .agents/skills/ precedence is not an issue.)
// Codex:  .agents/skills/ (only user-install path — no .codex/skills/ exists)
const EDITOR_DIRS = {
  claude: {
    global: path.join(os.homedir(), '.claude', 'skills'),
    local: path.join(process.cwd(), '.claude', 'skills'),
  },
  gemini: {
    global: path.join(os.homedir(), '.gemini', 'skills'),
    local: path.join(process.cwd(), '.gemini', 'skills'),
  },
  codex: {
    global: path.join(os.homedir(), '.agents', 'skills'),
    local: path.join(process.cwd(), '.agents', 'skills'),
  },
};

// ---------------------------------------------------------------------------
// Model tier configuration (single source of truth)
// ---------------------------------------------------------------------------

const MODELS_CONFIG_PATH = path.join(__dirname, '..', 'config', 'models.json');
let MODELS_CONFIG;
try {
  MODELS_CONFIG = JSON.parse(fs.readFileSync(MODELS_CONFIG_PATH, 'utf8'));
} catch (err) {
  console.error(`Error: config/models.json not found or invalid JSON.\n  Path: ${MODELS_CONFIG_PATH}\n  ${err.message}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// YAML frontmatter parser (manual — no yaml library required)
// ---------------------------------------------------------------------------

/**
 * Parse YAML frontmatter from a markdown file.
 * Returns { frontmatter: Record<string, string>, body: string } or null if no frontmatter.
 */
function parseFrontmatter(content) {
  if (!content.startsWith('---')) {
    return null;
  }
  const firstEnd = content.indexOf('\n---', 3);
  if (firstEnd === -1) {
    return null;
  }
  const rawFm = content.slice(4, firstEnd); // between first --- and second ---
  const body = content.slice(firstEnd + 4).replace(/^\n/, ''); // after second ---

  const frontmatter = {};
  for (const line of rawFm.split('\n')) {
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    const key = line.slice(0, colonIdx).trim();
    const value = line.slice(colonIdx + 1).trim().replace(/^["']|["']$/g, '');
    if (key) {
      frontmatter[key] = value;
    }
  }
  return { frontmatter, body };
}

/**
 * Rebuild frontmatter YAML string from a key-value map,
 * omitting specified keys.
 *
 * Values are quoted with double quotes when they contain characters that would
 * produce invalid YAML in an unquoted scalar:
 *   - ": " (colon + space) — YAML parsers treat this as a mapping entry separator
 *   - "#"  at any position  — YAML comment marker
 *   - leading "["  or "{"  — YAML flow sequence/mapping
 *   - leading ">"  or "|"  — YAML block scalar indicators
 *
 * Any existing double quotes within the value are escaped as \".
 */
function rebuildFrontmatter(frontmatter, omitKeys) {
  const lines = [];
  for (const [key, value] of Object.entries(frontmatter)) {
    if (omitKeys.includes(key)) continue;
    const needsQuoting =
      value.includes(': ') ||
      value.includes(' #') ||
      /^[#[{>|]/.test(value);
    if (needsQuoting) {
      const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
      lines.push(`${key}: "${escaped}"`);
    } else {
      lines.push(`${key}: ${value}`);
    }
  }
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// @include resolver
// ---------------------------------------------------------------------------

/**
 * Resolve @include directives in agent body content.
 * Directives must appear on their own line: "@include path/to/file.md"
 * Paths are relative to repoRoot. No nesting — shared files are leaf content.
 *
 * @param {string} content   Agent body content (after frontmatter extraction)
 * @param {string} repoRoot  Absolute path to repo root
 * @returns {string}         Content with all @include directives expanded
 */
function resolveIncludes(content, repoRoot) {
  const includeRe = /^@include\s+(\S+)$/gm;
  let match;
  // Collect all directives first to detect them before mutation
  const directives = [];
  while ((match = includeRe.exec(content)) !== null) {
    directives.push({ full: match[0], filePath: match[1] });
  }

  if (directives.length === 0) return content;

  let expanded = content;
  for (const directive of directives) {
    const absPath = path.join(repoRoot, directive.filePath);
    if (!fs.existsSync(absPath)) {
      console.error(`Error: @include references missing file: ${absPath}`);
      process.exit(1);
    }
    const included = fs.readFileSync(absPath, 'utf8');
    // Reject nesting
    if (/^@include\s+\S+$/m.test(included)) {
      console.error(`Error: @include nesting not allowed. File ${absPath} contains @include directives.`);
      process.exit(1);
    }
    expanded = expanded.replace(directive.full, included.trimEnd());
  }

  // Post-expansion safety check: no unresolved @include should remain
  if (/^@include\s+\S+$/m.test(expanded)) {
    console.error(`Error: Unresolved @include directive remains after expansion. Check for edge cases.`);
    process.exit(1);
  }

  return expanded;
}

// ---------------------------------------------------------------------------
// Per-editor transformation functions
// ---------------------------------------------------------------------------

/**
 * Claude Code: copy SKILL.md as-is.
 */
function installClaude(skillName, skillMdContent, targetDir) {
  const dest = path.join(targetDir, skillName);
  fs.mkdirSync(dest, { recursive: true });
  const destFile = path.join(dest, 'SKILL.md');
  // Strip fields not valid for skills (model, maxTurns, etc.)
  const SKILL_STRIP_KEYS = ['model', 'maxTurns', 'max_turns', 'timeout_mins', 'kind'];
  const parsed = parseFrontmatter(skillMdContent);
  if (parsed) {
    const fm = rebuildFrontmatter(parsed.frontmatter, SKILL_STRIP_KEYS);
    skillMdContent = `---\n${fm}\n---\n\n${parsed.body}`;
  }
  fs.writeFileSync(destFile, skillMdContent, 'utf8');
  return destFile;
}

/**
 * Gemini CLI: write SKILL.md using the Agent Skills open standard.
 * - Strips Claude-specific frontmatter fields (argument-hint, disable-model-invocation)
 * - Retains: name, description, allowed-tools
 */
function installGemini(skillName, skillMdContent, targetDir) {
  const parsed = parseFrontmatter(skillMdContent);
  if (!parsed) {
    console.warn(`  WARN: Skipping ${skillName} — no frontmatter found`);
    return null;
  }
  const { frontmatter, body } = parsed;

  const GEMINI_STRIP_KEYS = ['argument-hint', 'disable-model-invocation', 'color', 'compatibility', 'memory', 'context', 'agent', 'model', 'maxTurns', 'max_turns'];
  const cleanedFm = rebuildFrontmatter(frontmatter, GEMINI_STRIP_KEYS);
  const cleanedContent = `---\n${cleanedFm}\n---\n\n${body}`;

  const dest = path.join(targetDir, skillName);
  fs.mkdirSync(dest, { recursive: true });
  const destFile = path.join(dest, 'SKILL.md');
  fs.writeFileSync(destFile, cleanedContent, 'utf8');
  return destFile;
}

/**
 * Codex: copy SKILL.md but strip Claude-specific frontmatter fields.
 * Retains: name, description
 * Strips: argument-hint, disable-model-invocation, allowed-tools, tools, color, compatibility
 */
function installCodex(skillName, skillMdContent, targetDir) {
  const parsed = parseFrontmatter(skillMdContent);
  if (!parsed) {
    console.warn(`  WARN: Skipping ${skillName} — no frontmatter found`);
    return null;
  }
  const { frontmatter, body } = parsed;

  const CODEX_STRIP_KEYS = ['argument-hint', 'color', 'compatibility', 'disable-model-invocation', 'allowed-tools', 'tools', 'memory', 'context', 'agent', 'model', 'maxTurns', 'max_turns'];
  const cleanedFm = rebuildFrontmatter(frontmatter, CODEX_STRIP_KEYS);
  const cleanedContent = `---\n${cleanedFm}\n---\n\n${body}`;

  const dest = path.join(targetDir, skillName);
  fs.mkdirSync(dest, { recursive: true });
  const destFile = path.join(dest, 'SKILL.md');
  fs.writeFileSync(destFile, cleanedContent, 'utf8');
  return destFile;
}

// ---------------------------------------------------------------------------
// Core install logic
// ---------------------------------------------------------------------------

// Agents that are user-invocable slash commands.
// scope-controls also installs as a subagent because scope-audit dispatches it.
const INSTALLABLE_AGENTS = new Set([
  'scope-audit',
  'scope-controls',
  'scope-exploit',
  'scope-hunt',
]);

// Agents from agents/ (top-level) that must also be deployed as subagents.
// scope-controls: operator-invocable AND dispatched by scope-audit — needs both skill and subagent paths.
// On Claude Code it is read inline from agents/scope-controls.md via Agent tool path.
// On Gemini/Codex it must be deployed to .agents/agents/ so the orchestrator can delegate to it.
const TOP_LEVEL_SUBAGENTS = new Set([
  'scope-controls',
]);

/**
 * Resolve a tier label (or literal model string) from source frontmatter to
 * a vendor-specific model name for the given platform.
 *
 * - "enum"      → config/models.json[platform].enum
 * - "reasoning" → config/models.json[platform].reasoning
 * - "inherit"   → null (no model field in installed output)
 * - anything else → returned as-is (literal model string, backward compat)
 *
 * @param {string|undefined} modelValue  Value of the model: field in source frontmatter
 * @param {string} platform              "claude" | "gemini" | "codex"
 * @returns {string|null}               Resolved model string, or null for inherit
 */
function resolveModelTier(modelValue, platform) {
  if (!modelValue) return null;
  const tiers = ['enum', 'reasoning', 'inherit'];
  if (tiers.includes(modelValue)) {
    // Tier keyword — resolve to platform-specific model name
    if (modelValue === 'inherit') return null;
    const resolved = MODELS_CONFIG[platform]?.[modelValue];
    if (!resolved) {
      console.error(`Error: config/models.json missing key [${platform}][${modelValue}]`);
      process.exit(1);
    }
    return resolved;
  }
  // Literal model string — reverse-lookup the tier from ANY platform, then resolve for target.
  // This handles cross-platform install: source has "claude-sonnet-4-6" (literal),
  // target is gemini → find that "claude-sonnet-4-6" = reasoning tier → resolve to gemini reasoning model.
  for (const [sourcePlatform, tiers] of Object.entries(MODELS_CONFIG)) {
    for (const [tier, model] of Object.entries(tiers)) {
      if (model === modelValue && tier !== 'inherit') {
        const resolved = MODELS_CONFIG[platform]?.[tier];
        if (resolved) return resolved;
      }
    }
  }
  // No mapping found — pass through unchanged (custom model string)
  return modelValue;
}

/**
 * Discover installable agent .md files from the agents/ source directory.
 * Only agents in INSTALLABLE_AGENTS are included — middleware, verification,
 * and auto-called agents are skipped (they are read at runtime by source agents).
 * Returns array of { name: string, content: string }.
 */
function discoverAgents(agentsDir) {
  if (!fs.existsSync(agentsDir)) {
    console.error(`Error: agents/ directory not found. Run this script from the SCOPE repo root.`);
    process.exit(1);
  }

  const agents = [];
  const skipped = [];
  const entries = fs.readdirSync(agentsDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith('.md')) continue;
    const filePath = path.join(agentsDir, entry.name);
    const content = fs.readFileSync(filePath, 'utf8');
    const parsed = parseFrontmatter(content);
    if (!parsed || !parsed.frontmatter.name) {
      console.warn(`  WARN: Skipping ${entry.name} — no frontmatter or missing name field`);
      continue;
    }
    const name = entry.name.replace(/\.md$/, '');
    if (!INSTALLABLE_AGENTS.has(name)) {
      skipped.push(name);
      continue;
    }
    agents.push({ name, content });
  }
  if (skipped.length > 0) {
    const asSubagents = skipped.filter(n => TOP_LEVEL_SUBAGENTS.has(n));
    const trulySkipped = skipped.filter(n => !TOP_LEVEL_SUBAGENTS.has(n));
    if (asSubagents.length > 0) {
      console.log(`Skipped ${asSubagents.length} agent(s) from skills (will be deployed as subagents): ${asSubagents.join(', ')}`);
    }
    if (trulySkipped.length > 0) {
      console.log(`Skipped ${trulySkipped.length} inline-only agent(s): ${trulySkipped.join(', ')}`);
    }
  }
  return agents;
}

/**
 * Discover subagent .md files from agents/subagents/ and select top-level agents/.
 * Excludes scope-verify.md — it is read inline at runtime, not deployed as
 * a dispatchable subagent.
 * Also includes agents in TOP_LEVEL_SUBAGENTS from the agents/ root dir
 * (e.g., scope-controls — dispatched by orchestrator on Gemini/Codex).
 * Returns array of { name: string, content: string }.
 */
function discoverSubagents(subagentsDir) {
  const subagents = [];

  // Primary: agents/subagents/ directory
  // All .md files are installed for discoverability (D-22, D-23).
  // scope-verify is read inline at runtime but its .md file is present in
  // agents/ directories so platforms can discover it.
  if (fs.existsSync(subagentsDir)) {
    const entries = fs.readdirSync(subagentsDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.md')) continue;
      const name = entry.name.replace(/\.md$/, '');
      const filePath = path.join(subagentsDir, entry.name);
      const content = fs.readFileSync(filePath, 'utf8');
      const parsed = parseFrontmatter(content);
      if (!parsed || !parsed.frontmatter.name) {
        console.warn(`  WARN: Skipping subagent ${entry.name} — no frontmatter or missing name field`);
        continue;
      }
      subagents.push({ name, content });
    }
  }

  // Secondary: top-level agents/ that are also dispatched as subagents
  const agentsDir = path.join(subagentsDir, '..');
  for (const name of TOP_LEVEL_SUBAGENTS) {
    const filePath = path.join(agentsDir, `${name}.md`);
    if (!fs.existsSync(filePath)) {
      console.warn(`  WARN: TOP_LEVEL_SUBAGENT ${name}.md not found in agents/`);
      continue;
    }
    const content = fs.readFileSync(filePath, 'utf8');
    subagents.push({ name, content });
  }

  return subagents;
}

/**
 * Prune stale subagent .md files from target agents directory.
 * Deletes any .md file whose basename (without .md) is NOT in the current installed set.
 * Only removes .md files — safe for Codex dirs that contain .toml files too.
 *
 * @param {string} agentsDir - Target agents directory (e.g., .claude/agents/)
 * @param {Set<string>} installedNames - Set of currently-valid agent names from discoverSubagents()
 * @returns {number} Count of pruned files
 */
function pruneStaleSubagentFiles(agentsDir, installedNames) {
  if (!fs.existsSync(agentsDir)) return 0;
  const existing = fs.readdirSync(agentsDir).filter(f => f.endsWith('.md'));
  let pruned = 0;
  for (const file of existing) {
    const name = file.replace(/\.md$/, '');
    if (!installedNames.has(name)) {
      fs.unlinkSync(path.join(agentsDir, file));
      const displayPath = path.join(agentsDir, file).replace(os.homedir(), '~');
      console.log(`  Pruned stale subagent: ${displayPath}`);
      pruned++;
    }
  }
  if (pruned > 0) {
    console.log(`Pruned ${pruned} stale subagent file(s)`);
  }
  return pruned;
}

/**
 * Prune stale Codex .toml config layer files from target agents directory.
 * Deletes any .toml file whose basename (without .toml) is NOT in the current installed set.
 * Companion to pruneStaleSubagentFiles() — handles Codex-specific .toml artifacts.
 *
 * @param {string} agentsDir - Target agents directory (e.g., .codex/agents/)
 * @param {Set<string>} installedNames - Set of currently-valid agent names from discoverSubagents()
 * @returns {number} Count of pruned files
 */
function pruneStaleTomlFiles(agentsDir, installedNames) {
  if (!fs.existsSync(agentsDir)) return 0;
  const existing = fs.readdirSync(agentsDir).filter(f => f.endsWith('.toml'));
  let pruned = 0;
  for (const file of existing) {
    const name = file.replace(/\.toml$/, '');
    if (!installedNames.has(name)) {
      fs.unlinkSync(path.join(agentsDir, file));
      const displayPath = path.join(agentsDir, file).replace(os.homedir(), '~');
      console.log(`  Pruned stale Codex config layer: ${displayPath}`);
      pruned++;
    }
  }
  if (pruned > 0) {
    console.log(`Pruned ${pruned} stale Codex .toml file(s)`);
  }
  return pruned;
}

/**
 * Claude Code subagent deployment.
 * Deploys flat .md files to .claude/agents/ (local) or ~/.claude/agents/ (global).
 * Injects the platform-specific model into frontmatter.
 */
function installSubagentsClaude(subagents, scope) {
  const agentsDir = scope === 'local'
    ? path.join(process.cwd(), '.claude', 'agents')
    : path.join(os.homedir(), '.claude', 'agents');

  fs.mkdirSync(agentsDir, { recursive: true });
  let count = 0;

  const repoRoot = path.join(__dirname, '..');

  for (const subagent of subagents) {
    const parsed = parseFrontmatter(subagent.content);
    let content = subagent.content;

    if (parsed) {
      const { frontmatter, body } = parsed;
      const originalModel = frontmatter.model; // capture BEFORE any mutation
      const includeCount = (body.match(/^@include\s+\S+$/gm) || []).length;
      const expandedBody = resolveIncludes(body, repoRoot);
      const resolvedModel = resolveModelTier(frontmatter.model, 'claude');
      const omitKeys = resolvedModel === null ? ['model'] : [];
      if (resolvedModel !== null) frontmatter.model = resolvedModel;
      const fm = rebuildFrontmatter(frontmatter, omitKeys);
      content = `---\n${fm}\n---\n\n${expandedBody}`;
      const tierLabel = originalModel || 'inherit';
      console.log(`    [${subagent.name}] includes=${includeCount} tier=${tierLabel}->${resolvedModel ?? 'inherit'} chars=${content.length}`);
    }

    const destFile = path.join(agentsDir, `${subagent.name}.md`);
    fs.writeFileSync(destFile, content, 'utf8');
    const displayPath = destFile.replace(os.homedir(), '~');
    console.log(`  Installing subagent ${subagent.name} -> ${displayPath}`);
    count++;
  }

  console.log(`Installed ${count} subagent${count !== 1 ? 's' : ''} to claude (${scope})`);
  return count;
}

/**
 * Gemini CLI subagent deployment.
 * Deploys to .gemini/agents/ (local) or ~/.gemini/agents/ (global).
 * Requires experimental.enableAgents: true in gemini settings.json.
 * Strips model field and Claude-specific keys.
 */
function installSubagentsGemini(subagents, scope) {
  const agentsDir = scope === 'local'
    ? path.join(process.cwd(), '.gemini', 'agents')
    : path.join(os.homedir(), '.gemini', 'agents');

  fs.mkdirSync(agentsDir, { recursive: true });
  const GEMINI_STRIP_KEYS = ['argument-hint', 'disable-model-invocation', 'allowed-tools', 'tools', 'color', 'compatibility', 'memory', 'context', 'agent', 'maxTurns'];
  let count = 0;

  // Gemini defaults: max_turns=15 — too low for SCOPE agents.
  // Inject appropriate turn limits and explicit tool access per agent type.
  // Agents NOT in this config lose their tools field entirely (stripped by GEMINI_STRIP_KEYS).
  // Source frontmatter tools: values are comma-separated strings — Gemini needs YAML arrays.
  const GEMINI_AGENT_CONFIG = {
    'scope-attack-analyze':     { max_turns: 60, tools: ['run_shell_command', 'read_file', 'grep_search', 'write_file'] },
    'scope-controls':             { max_turns: 60, tools: ['run_shell_command', 'read_file', 'grep_search', 'write_file'] },
    'scope-controls-guardrails':  { max_turns: 40, tools: ['run_shell_command', 'read_file', 'grep_search', 'write_file'] },
    'scope-controls-policy':      { max_turns: 40, tools: ['run_shell_command', 'read_file', 'grep_search', 'write_file'] },
    'scope-controls-remediation': { max_turns: 40, tools: ['run_shell_command', 'read_file', 'grep_search', 'write_file'] },
    'scope-controls-detections':      { max_turns: 40, tools: ['run_shell_command', 'read_file', 'grep_search', 'write_file'] },
    'scope-controls-validate':    { max_turns: 40, tools: ['run_shell_command', 'read_file', 'grep_search', 'write_file'] },
    'scope-hunt-audit':         { max_turns: 40, tools: ['run_shell_command', 'read_file', 'grep_search', 'write_file'] },
    'scope-hunt-intel':         { max_turns: 40, tools: ['run_shell_command', 'read_file', 'grep_search', 'write_file', 'google_web_search', 'web_fetch'] },
    'scope-hunt-investigate':   { max_turns: 40, tools: ['run_shell_command', 'read_file', 'grep_search', 'write_file'] },
    'scope-research':           { max_turns: 40, tools: ['run_shell_command', 'read_file', 'grep_search', 'google_web_search', 'web_fetch'] },
    'scope-synthesizer':        { max_turns: 40, tools: ['run_shell_command', 'read_file', 'write_file', 'grep_search', 'glob'] },
    'scope-verify':             { max_turns: 30, tools: ['run_shell_command', 'read_file', 'grep_search', 'write_file', 'google_web_search', 'web_fetch'] },
  };

  const repoRoot = path.join(__dirname, '..');

  for (const subagent of subagents) {
    const parsed = parseFrontmatter(subagent.content);
    let content = subagent.content;

    if (parsed) {
      const { frontmatter, body } = parsed;
      const originalModel = frontmatter.model; // capture BEFORE any mutation
      const includeCount = (body.match(/^@include\s+\S+$/gm) || []).length;
      const expandedBody = resolveIncludes(body, repoRoot);
      // Inject Gemini-specific config
      const config = GEMINI_AGENT_CONFIG[subagent.name];
      if (config) {
        frontmatter.max_turns = String(config.max_turns);
      }
      // Inject platform-specific model
      const resolvedModel = resolveModelTier(frontmatter.model, 'gemini');
      const geminiOmitKeys = resolvedModel === null
        ? [...GEMINI_STRIP_KEYS, 'model']
        : GEMINI_STRIP_KEYS;
      if (resolvedModel !== null) frontmatter.model = resolvedModel;
      const fm = rebuildFrontmatter(frontmatter, geminiOmitKeys);
      // Build tools as YAML array (rebuildFrontmatter only handles strings)
      let toolsYaml = '';
      if (config && config.tools) {
        toolsYaml = '\ntools:\n' + config.tools.map(t => `  - ${t}`).join('\n');
      }
      content = `---\n${fm}${toolsYaml}\n---\n\n${expandedBody}`;
      const tierLabel = originalModel || 'inherit';
      console.log(`    [${subagent.name}] includes=${includeCount} tier=${tierLabel}->${resolvedModel ?? 'inherit'} chars=${content.length}`);
    }

    const destFile = path.join(agentsDir, `${subagent.name}.md`);
    fs.writeFileSync(destFile, content, 'utf8');
    const displayPath = destFile.replace(os.homedir(), '~');
    console.log(`  Installing subagent ${subagent.name} -> ${displayPath}`);
    count++;
  }

  console.log(`Installed ${count} subagent${count !== 1 ? 's' : ''} to gemini (${scope})`);
  return count;
}

/**
 * Codex subagent deployment.
 * Codex does not use file-based agent discovery — agents are registered via
 * [agents] sections in .codex/config.toml (project) or ~/.codex/config.toml (global).
 * This function:
 *   1. Deploys stripped .md files to .codex/agents/ (local) or ~/.codex/agents/ (global).
 *      The .md files are present on disk for runtime reads but are NOT the primary instruction
 *      delivery mechanism for Codex (which uses developer_instructions in the .toml instead).
 *   2. Generates per-agent .toml config layer files at .codex/agents/<name>.toml.
 *      Per Codex multi-agent docs (developers.openai.com/codex/multi-agent/), per-role
 *      config layers support ONLY: model, model_reasoning_effort, sandbox_mode,
 *      developer_instructions. The field model_instructions_file does NOT exist in the
 *      ConfigProfile schema (ConfigProfile.additionalProperties: false — unknown fields
 *      cause silent deserialization failure, making the agent role fall back to generic worker).
 *      Strategy: read the .md body at install time and embed it as developer_instructions
 *      using TOML multi-line literal string syntax ('''...''') — no backslash escaping needed,
 *      safe for bash line-continuation backslashes and all other content in the .md files.
 *      developer_instructions is sent as a role=developer message to the spawned agent,
 *      which has higher priority than user-level AGENTS.md instructions.
 *   3. Ensures [features] multi_agent = true is present in config.toml.
 *      Codex multi-agent is an experimental feature disabled by default. Without this flag,
 *      automatic agent role dispatch is unavailable and the orchestrator falls back to inline
 *      sequential execution. The installer idempotently injects this flag on every run.
 *   4. Auto-merges [agents] entries into .codex/config.toml (local) or ~/.codex/config.toml
 *      (global). Uses a marked SCOPE block that is replaced on re-install.
 *      Each [agents.<name>] entry references the per-agent .toml via config_file.
 * Strips model field and Claude-specific keys from the .md frontmatter.
 */
function installSubagentsCodex(subagents, scope) {
  const agentsDir = scope === 'local'
    ? path.join(process.cwd(), '.codex', 'agents')
    : path.join(os.homedir(), '.codex', 'agents');

  fs.mkdirSync(agentsDir, { recursive: true });
  const CODEX_STRIP_KEYS = ['model', 'argument-hint', 'color', 'compatibility', 'disable-model-invocation', 'allowed-tools', 'tools', 'memory', 'context', 'agent', 'maxTurns'];
  let count = 0;
  const tomlEntries = [];
  const repoRoot = path.join(__dirname, '..');

  // CODEX_NO_REGISTER: installed for discoverability (.md present on disk) but not
  // registered in config.toml (prevents accidental dispatch of inline-read agents).
  const CODEX_NO_REGISTER = new Set(['scope-verify']);

  for (const subagent of subagents) {
    const parsed = parseFrontmatter(subagent.content);
    let content = subagent.content;
    let description = subagent.name;
    let sourceFrontmatter = null;
    let expandedBody = null;

    if (parsed) {
      const { frontmatter, body } = parsed;
      const originalModel = frontmatter.model; // capture BEFORE any mutation
      const includeCount = (body.match(/^@include\s+\S+$/gm) || []).length;
      expandedBody = resolveIncludes(body, repoRoot);
      sourceFrontmatter = frontmatter;
      if (frontmatter.description) description = frontmatter.description;
      const resolvedModel = resolveModelTier(frontmatter.model, 'codex');
      const codexMdOmitKeys = resolvedModel === null
        ? CODEX_STRIP_KEYS // 'model' already in CODEX_STRIP_KEYS
        : CODEX_STRIP_KEYS; // model goes to .toml only, not the .md
      const fm = rebuildFrontmatter(frontmatter, codexMdOmitKeys);
      content = `---\n${fm}\n---\n\n${expandedBody}`;
      const tierLabel = originalModel || 'inherit';
      console.log(`    [${subagent.name}] includes=${includeCount} tier=${tierLabel}->${resolvedModel ?? 'inherit'} chars=${content.length}`);
    }

    // Deploy stripped .md file
    const destMd = path.join(agentsDir, `${subagent.name}.md`);
    fs.writeFileSync(destMd, content, 'utf8');
    const displayMd = destMd.replace(os.homedir(), '~');
    console.log(`  Installing subagent ${subagent.name} -> ${displayMd}`);
    count++;

    const codexModel = resolveModelTier(sourceFrontmatter?.model, 'codex') || MODELS_CONFIG['codex']['enum'];
    const reasoningEffort = 'medium';

    // Generate per-agent .toml config layer.
    // Per Codex multi-agent docs, valid fields: model, model_reasoning_effort, sandbox_mode,
    // developer_instructions. ConfigProfile.additionalProperties: false — unknown fields OR
    // invalid enum values cause silent deserialization failure.
    //
    // sandbox_mode valid values: "read-only", "workspace-write", "danger-full-access".
    // SCOPE uses "workspace-write" — subagents need network + filesystem access.
    //
    // developer_instructions: full .md body inlined as TOML multi-line literal string (''').
    // Sent as role=developer message (higher priority than AGENTS.md).
    const mdBody = expandedBody !== null ? expandedBody : (parsed ? parsed.body : subagent.content);
    const agentToml = [
      `# SCOPE subagent config layer — auto-generated by bin/install.js`,
      `# Referenced from .codex/config.toml via config_file = "agents/${subagent.name}.toml"`,
      ``,
      `model = "${codexModel}"`,
      `model_reasoning_effort = "${reasoningEffort}"`,
      `sandbox_mode = "workspace-write"`,
      ``,
      `# developer_instructions is sent as role=developer to the spawned agent (higher priority`,
      `# than user-level AGENTS.md). Inlined from agents/subagents/${subagent.name}.md body.`,
      `# Uses TOML multi-line literal string (''') — no backslash escaping required.`,
      `developer_instructions = '''`,
      mdBody.trimEnd(),
      `'''`,
    ].join('\n') + '\n';

    // CODEX_NO_REGISTER agents: installed as .md for discoverability but skip .toml
    // generation entirely — Codex scans .toml files from agents/ and rejects those
    // without a name field, producing "malformed agent role definition" warnings.
    if (CODEX_NO_REGISTER.has(subagent.name)) {
      continue;
    }

    const destToml = path.join(agentsDir, `${subagent.name}.toml`);
    fs.writeFileSync(destToml, agentToml, 'utf8');
    const displayToml = destToml.replace(os.homedir(), '~');
    console.log(`  Installing config layer  ${subagent.name} -> ${displayToml}`);

    // config_file is resolved relative to the directory containing config.toml (.codex/).
    // Use "agents/<name>.toml" — Codex resolves to .codex/agents/<name>.toml.
    // IMPORTANT: config_file must point to a .toml file (a config layer), not the .md file.
    // Agent instructions are delivered via developer_instructions inside the .toml.
    const configFilePath = `agents/${subagent.name}.toml`;

    tomlEntries.push(
      `[agents.${subagent.name}]`,
      `description = "${description}"`,
      `config_file = "${configFilePath}"`,
      ``
    );
  }

  // Auto-merge into config.toml
  const configTomlPath = scope === 'local'
    ? path.join(process.cwd(), '.codex', 'config.toml')
    : path.join(os.homedir(), '.codex', 'config.toml');

  const scopeHeader = '# --- SCOPE subagent registrations (auto-generated) ---';
  const scopeFooter = '# --- END SCOPE subagent registrations ---';
  // [agents] global must appear BEFORE [agents.*] sub-tables in TOML
  const agentsGlobalBlock = '[agents]\nmax_threads = 16\nmax_depth = 2\njob_max_runtime_seconds = 3600\n';
  const scopeBlock = [scopeHeader, '', agentsGlobalBlock, ...tomlEntries, scopeFooter].join('\n');

  let existingConfig = '';
  if (fs.existsSync(configTomlPath)) {
    existingConfig = fs.readFileSync(configTomlPath, 'utf8');
  }

  // Ensure [features] multi_agent = true is present.
  // Codex multi-agent is experimental and disabled by default. Without this flag,
  // the spawn_agents_on_csv tool and automatic agent role dispatch are not available
  // at runtime — the orchestrator will fall back to inline sequential execution.
  // Strategy: if a [features] section already exists, inject multi_agent = true into it
  // (if missing). If no [features] section exists, prepend one before the SCOPE block.
  let configWithFeatures = existingConfig;
  const featuresHeaderRe = /^\[features\]/m;
  const multiAgentLineRe = /^\s*multi_agent\s*=/m;

  if (featuresHeaderRe.test(configWithFeatures)) {
    // [features] section exists — inject multi_agent = true if not already there
    if (!multiAgentLineRe.test(configWithFeatures)) {
      configWithFeatures = configWithFeatures.replace(
        /(\[features\][^\n]*\n)/,
        '$1multi_agent = true\n'
      );
      console.log(`  Injected multi_agent = true into existing [features] section`);
    }
    // else: already present, nothing to do
  } else {
    // No [features] section at all — prepend it
    const featuresBlock = '[features]\nmulti_agent = true\n';
    configWithFeatures = configWithFeatures
      ? featuresBlock + '\n' + configWithFeatures
      : featuresBlock;
    console.log(`  Added [features] section with multi_agent = true`);
  }

  // Ensure [mcp_servers.splunk-mcp-server] is present.
  // Codex reads MCP config from [mcp_servers.*] sections in config.toml.
  // Only add if not already present — operator may have customized.
  const mcpHeaderRe = /^\[mcp_servers\.splunk-mcp-server\]/m;
  if (!mcpHeaderRe.test(configWithFeatures)) {
    const mcpBlock = [
      '',
      '[mcp_servers.splunk-mcp-server]',
      'url = "${SPLUNK_URL}"',
      '',
    ].join('\n');
    configWithFeatures = configWithFeatures.trimEnd() + '\n' + mcpBlock + '\n';
    console.log(`  Added [mcp_servers.splunk-mcp-server] to config.toml`);
  }

  // Replace existing SCOPE block or append
  const scopeBlockRegex = new RegExp(
    scopeHeader.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') +
    '[\\s\\S]*?' +
    scopeFooter.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  );

  let newConfig;
  if (scopeBlockRegex.test(configWithFeatures)) {
    newConfig = configWithFeatures.replace(scopeBlockRegex, scopeBlock);
    console.log(`  Updated SCOPE block in config.toml`);
  } else {
    newConfig = configWithFeatures ? configWithFeatures.trimEnd() + '\n\n' + scopeBlock + '\n' : scopeBlock + '\n';
    console.log(`  Added SCOPE block to config.toml`);
  }
  fs.writeFileSync(configTomlPath, newConfig, 'utf8');
  const configDisplay = configTomlPath.replace(os.homedir(), '~');
  console.log(`  Config: ${configDisplay}`);

  console.log(`Installed ${count} subagent${count !== 1 ? 's' : ''} to codex (${scope})`);
  return count;
}

/**
 * Check for stale files from previous installs (old module deployments).
 * Warns only — does not auto-delete (operator must clean up manually).
 */
function cleanupOldModules(scope) {
  const claudeBase = scope === 'local'
    ? path.join(process.cwd(), '.claude', 'skills')
    : path.join(os.homedir(), '.claude', 'skills');
  const agentsBase = scope === 'local'
    ? path.join(process.cwd(), '.agents', 'skills')
    : path.join(os.homedir(), '.agents', 'skills');

  const stalePrefixes = ['scope-audit-'];
  const staleDirs = [];

  for (const base of [claudeBase, agentsBase]) {
    if (!fs.existsSync(base)) continue;
    const entries = fs.readdirSync(base, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (stalePrefixes.some(prefix => entry.name.startsWith(prefix))) {
        staleDirs.push(path.join(base, entry.name));
      }
    }
  }

  if (staleDirs.length > 0) {
    console.warn('\n  WARN: Stale module skill directories found (from pre-Phase-3 installs):');
    staleDirs.forEach(d => console.warn(`    - ${d.replace(os.homedir(), '~')}`));
    console.warn('  These are now replaced by subagents in .claude/agents/, .gemini/agents/, and .codex/agents/.');
    console.warn('  Remove stale directories manually:');
    staleDirs.forEach(d => console.warn(`    rm -rf "${d.replace(os.homedir(), '~')}"`));
    console.warn('');
  }
}

/**
 * Install agents for a single editor.
 */
function installForEditor(editor, scope, agents) {
  const targetDir = EDITOR_DIRS[editor][scope];
  const repoRoot = path.join(__dirname, '..');
  let count = 0;

  for (const agent of agents) {
    let destFile = null;

    // Resolve @include directives before platform-specific transformation
    const preParsed = parseFrontmatter(agent.content);
    let resolvedContent = agent.content;
    if (preParsed) {
      const expandedBody = resolveIncludes(preParsed.body, repoRoot);
      const fm = rebuildFrontmatter(preParsed.frontmatter, []);
      resolvedContent = `---\n${fm}\n---\n\n${expandedBody}`;
    }

    try {
      if (editor === 'claude') {
        destFile = installClaude(agent.name, resolvedContent, targetDir);
      } else if (editor === 'gemini') {
        destFile = installGemini(agent.name, resolvedContent, targetDir);
      } else if (editor === 'codex') {
        destFile = installCodex(agent.name, resolvedContent, targetDir);
      }
    } catch (err) {
      console.error(`  ERROR: Failed to install ${agent.name} to ${editor}: ${err.message}`);
      process.exit(1);
    }

    if (destFile) {
      // Normalize path for display: replace home dir with ~
      const displayPath = destFile.replace(os.homedir(), '~');
      console.log(`  Installing ${agent.name} -> ${displayPath}`);
      count++;
    }
  }

  console.log(`Installed ${count} agent${count !== 1 ? 's' : ''} to ${editor} (${scope})`);
  return count;
}

// ---------------------------------------------------------------------------
// Usage / help
// ---------------------------------------------------------------------------

function printUsage() {
  console.log(`
SCOPE Install Script
Install SCOPE agents and subagents into AI editor config directories.

Usage:
  node bin/install.js [editors] [scope] [options]

Editors (pick one or more, or --all):
  --claude    Install to Claude Code (.claude/skills/ and .claude/agents/)
  --gemini    Install to Gemini CLI (.agents/skills/ and .agents/agents/)
  --codex     Install to Codex (.agents/skills/ and .agents/agents/)
  --all       Install to all three editors

Scope:
  --local     Install to current project directory (default)
  --global    Install to user home directory

Options:
  --help      Print this usage message

What gets installed:
  Skills      Operator-invoked slash commands (scope-audit, scope-controls, scope-exploit, scope-hunt)
              -> .claude/skills/ (Claude Code) or .agents/skills/ (Gemini/Codex)
  Subagents   Orchestrator-dispatched workers (attack analysis, controls, hunt, research, synthesis)
              -> .claude/agents/ (Claude Code)
              -> .gemini/agents/ (Gemini CLI) — requires experimental.enableAgents: true
              -> .codex/agents/ + .codex/config.toml (Codex)
              Note: scope-verify is installed for discoverability but read inline at runtime
              Note (Codex): installer also adds [features] multi_agent = true — required for parallel dispatch

Examples:
  node bin/install.js --all
  node bin/install.js --claude --global
  node bin/install.js --gemini --local
  node bin/install.js --codex --local

Invocation syntax varies by editor:
  Claude Code:  /scope:audit <target>
  Gemini CLI:   /scope:audit <target>
  Codex:        $scope-audit <target>
`);
}

// ---------------------------------------------------------------------------
// Interactive prompt (when no editor flags given)
// ---------------------------------------------------------------------------

function promptUser(question) {
  // Synchronous readline using /dev/tty
  try {
    const { execSync } = require('child_process');
    process.stdout.write(question);
    const result = execSync('read -r line && echo "$line"', {
      stdio: ['inherit', 'pipe', 'inherit'],
      shell: '/bin/bash',
    });
    return result.toString().trim();
  } catch {
    return '';
  }
}

function runInteractive() {
  const purple = '\x1b[35m';
  const dim = '\x1b[2m';
  const bold = '\x1b[1m';
  const reset = '\x1b[0m';

  console.log('');
  console.log(purple + '   ___  ___ ___  ___ ___');
  console.log('  / __|/ __/ _ \\| _ \\ __|');
  console.log('  \\__ \\ (_| (_) |  _/ _|');
  console.log('  |___/\\___\\___/|_| |___|' + reset);
  console.log('');
  console.log(dim + '  Security Cloud Ops Purple Engagement' + reset);
  console.log(dim + '  AI agent suite for AWS purple team operations' + reset);
  console.log('');
  console.log(bold + '  Which runtime(s) would you like to install for?' + reset);
  console.log('');
  console.log(purple + '  1) Claude Code   ' + dim + '(.claude/)' + reset);
  console.log(purple + '  2) Gemini CLI    ' + dim + '(.gemini/ + .agents/)' + reset);
  console.log(purple + '  3) Codex         ' + dim + '(.codex/ + .agents/)' + reset);
  console.log(purple + '  4) All' + reset);
  console.log('');
  const choice = promptUser(purple + '  Choice: ' + reset);

  let editors = [];
  if (choice === '1') editors = ['claude'];
  else if (choice === '2') editors = ['gemini'];
  else if (choice === '3') editors = ['codex'];
  else if (choice === '4') editors = ['claude', 'gemini', 'codex'];
  else {
    console.error('Invalid choice. Enter 1-4.');
    process.exit(1);
  }

  console.log('');
  console.log(bold + '  Install scope:' + reset);
  console.log('');
  console.log(purple + '  1) Local     ' + dim + '(./<editor>/ in project)' + reset);
  console.log(purple + '  2) Global    ' + dim + '(~/.<editor>/ in home)' + reset);
  console.log('');
  const scopeChoice = promptUser(purple + '  Choice: ' + reset);
  if (scopeChoice !== '1' && scopeChoice !== '2') {
    console.error('Invalid choice. Enter 1 or 2.');
    process.exit(1);
  }
  const scope = scopeChoice === '2' ? 'global' : 'local';

  console.log('');
  return { editors, scope };
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    printUsage();
    process.exit(0);
  }

  // Parse flags
  const wantClaude = args.includes('--claude') || args.includes('--all');
  const wantGemini = args.includes('--gemini') || args.includes('--all');
  const wantCodex = args.includes('--codex') || args.includes('--all');
  const scope = args.includes('--global') ? 'global' : 'local';

  let editors = [];
  if (wantClaude) editors.push('claude');
  if (wantGemini) editors.push('gemini');
  if (wantCodex) editors.push('codex');

  // No editor flags — run interactive prompt
  if (editors.length === 0) {
    const result = runInteractive();
    editors = result.editors;
    // scope already determined above, but override if interactive chose
    // (interactive prompt handles its own scope)
    return runInstall(editors, result.scope);
  }

  runInstall(editors, scope);
}

/**
 * Copy hook scripts and settings.json for an editor.
 * Scripts are copied from config/hooks/ to the platform-native hooks directory
 * (.claude/hooks/ or .gemini/hooks/), and settings are written with absolute
 * paths so hooks resolve correctly regardless of CWD (Stop hooks fire from ~).
 */
function installHooks(editor, scope) {
  const settingsMap = {
    claude: { src: 'config/settings/claude.settings.json', dest: '.claude/settings.json', hooksDir: '.claude/hooks' },
    gemini: { src: 'config/settings/gemini.settings.json', dest: '.gemini/settings.json', hooksDir: '.gemini/hooks' },
    codex:  { src: 'config/settings/codex.hooks.json',     dest: '.codex/hooks.json',     hooksDir: '.codex/hooks'  },
  };
  const entry = settingsMap[editor];
  const srcSettings = path.join(__dirname, '..', entry.src);
  if (!fs.existsSync(srcSettings)) return;

  const base = scope === 'global' ? os.homedir() : process.cwd();

  // Step 1: Copy hook scripts to platform-native hooks directory
  const srcHooksDir = path.join(__dirname, '..', 'config', 'hooks');
  const destHooksDir = path.join(base, entry.hooksDir);
  if (fs.existsSync(srcHooksDir)) {
    fs.mkdirSync(destHooksDir, { recursive: true });
    const hookFiles = fs.readdirSync(srcHooksDir).filter(f => f.endsWith('.sh'));
    for (const file of hookFiles) {
      const src = path.join(srcHooksDir, file);
      const dest = path.join(destHooksDir, file);
      fs.copyFileSync(src, dest);
      fs.chmodSync(dest, 0o755);
    }
    console.log(`  Installed ${hookFiles.length} hook scripts -> ${entry.hooksDir}/`);
  }

  // Step 2: Write settings with absolute hook paths
  const destFile = path.join(base, entry.dest);
  const destDir = path.dirname(destFile);
  let content = fs.readFileSync(srcSettings, 'utf8');
  content = content.replace(/__HOOKS_DIR__/g, path.join(base, entry.hooksDir));

  fs.mkdirSync(destDir, { recursive: true });
  fs.writeFileSync(destFile, content, 'utf8');
  console.log(`  Updated hook settings -> ${entry.dest}`);
}

/**
 * Deploy .mcp.json for Claude Code (project-scoped MCP server config).
 * Gemini CLI uses mcpServers in .gemini/settings.json (already in the template).
 */
function installMcpConfig(editor, scope) {
  if (editor !== 'claude') return; // Gemini has MCP in settings.json; Codex doesn't support MCP
  if (scope !== 'local') return; // .mcp.json is project-scoped only

  const srcMcp = path.join(__dirname, '..', 'config', 'settings', 'mcp.json');
  if (!fs.existsSync(srcMcp)) return;

  const destFile = path.join(process.cwd(), '.mcp.json');
  if (fs.existsSync(destFile)) {
    console.log('  .mcp.json already exists — skipping (edit manually to update)');
    return;
  }

  fs.copyFileSync(srcMcp, destFile);
  console.log('  Created .mcp.json — set SPLUNK_URL and SPLUNK_TOKEN env vars to enable Splunk MCP');
}

/**
 * Warn if stale SCOPE skills exist in .agents/skills/ (legacy shared path).
 * Gemini now uses .gemini/skills/ natively; .agents/skills/ is Codex-only.
 * Stale Gemini skills in .agents/skills/ can shadow Codex skills on name collision.
 */
function checkLegacyGeminiSkills(scope) {
  const legacyBase = scope === 'global'
    ? path.join(os.homedir(), '.agents', 'skills')
    : path.join(process.cwd(), '.agents', 'skills');

  // Check if .agents/skills/ has more skill dirs than expected for Codex-only
  // (leftover from when Gemini also wrote here)
  if (!fs.existsSync(legacyBase)) return;

  const scopeSkills = ['scope-audit', 'scope-controls', 'scope-exploit', 'scope-hunt'];
  const found = scopeSkills.filter(s => fs.existsSync(path.join(legacyBase, s)));

  // If Codex is not being installed but .agents/skills/ has SCOPE skills, warn
  // (they're orphaned from when Gemini used the shared path)
  if (found.length > 0) {
    console.log(`  .agents/skills/ contains ${found.length} SCOPE skill(s) (Codex path — OK)`);
  }
}

function runInstall(editors, scope) {
  const agentsDir = path.join(__dirname, '..', 'agents');
  const agents = discoverAgents(agentsDir);

  if (agents.length === 0) {
    console.log('No agents found in agents/ directory.');
    process.exit(0);
  }

  console.log(`Found ${agents.length} agent${agents.length !== 1 ? 's' : ''}: ${agents.map(a => a.name).join(', ')}\n`);

  // Each platform gets its own skills directory — no collision.
  // Claude -> .claude/skills/, Gemini -> .gemini/skills/, Codex -> .agents/skills/
  for (const editor of editors) {
    installForEditor(editor, scope, agents);
  }

  // Hooks: install for ALL requested editors (no collision — different config dirs)
  for (const editor of editors) {
    installHooks(editor, scope);
  }

  // MCP config: deploy .mcp.json for Claude Code (Gemini has MCP in settings.json)
  for (const editor of editors) {
    installMcpConfig(editor, scope);
  }

  // Subagent deployment — each editor has its own target dir, no collision
  const subagentsDir = path.join(agentsDir, 'subagents');
  const subagents = discoverSubagents(subagentsDir);
  const installedNames = new Set(subagents.map(s => s.name));
  if (subagents.length > 0) {
    console.log(`\nFound ${subagents.length} subagent(s): ${subagents.map(s => s.name).join(', ')}\n`);
    for (const editor of editors) {
      if (editor === 'claude') {
        installSubagentsClaude(subagents, scope);
        const claudeAgentsDir = scope === 'local'
          ? path.join(process.cwd(), '.claude', 'agents')
          : path.join(os.homedir(), '.claude', 'agents');
        pruneStaleSubagentFiles(claudeAgentsDir, installedNames);
      } else if (editor === 'gemini') {
        installSubagentsGemini(subagents, scope);
        const geminiAgentsDir = scope === 'local'
          ? path.join(process.cwd(), '.gemini', 'agents')
          : path.join(os.homedir(), '.gemini', 'agents');
        pruneStaleSubagentFiles(geminiAgentsDir, installedNames);
      } else if (editor === 'codex') {
        installSubagentsCodex(subagents, scope);
        const codexAgentsDir = scope === 'local'
          ? path.join(process.cwd(), '.codex', 'agents')
          : path.join(os.homedir(), '.codex', 'agents');
        pruneStaleSubagentFiles(codexAgentsDir, installedNames);
        pruneStaleTomlFiles(codexAgentsDir, installedNames);
      }
    }
  }

  // Check for and warn about stale module deployments from pre-Phase-3 installs
  cleanupOldModules(scope);

  if (editors.includes('gemini')) {
    checkLegacyGeminiSkills(scope);
  }

  // Project docs: copy platform-specific project instructions to repo root
  installProjectDocs(editors, scope);
}

/**
 * Copy unified project instruction file from config/project-docs/PROJECT.md to repo root.
 * Single source file, copied to platform-specific filename.
 * Source file in config/project-docs/ is committed. Root copies are gitignored.
 * Claude → CLAUDE.md, Gemini → GEMINI.md, Codex → AGENTS.md
 */
function installProjectDocs(editors, scope) {
  const projectRoot = scope === 'local' ? process.cwd() : os.homedir();
  const src = path.join(__dirname, '..', 'config', 'project-docs', 'PROJECT.md');

  if (!fs.existsSync(src)) return;

  const docMap = {
    claude: 'CLAUDE.md',
    gemini: 'GEMINI.md',
    codex: 'AGENTS.md',
  };

  for (const editor of editors) {
    const filename = docMap[editor];
    if (!filename) continue;
    const dest = path.join(projectRoot, filename);
    fs.copyFileSync(src, dest);
    console.log(`  → ${filename} (project docs from PROJECT.md)`);
  }
}

main();
