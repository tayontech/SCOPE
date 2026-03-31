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
const EDITOR_DIRS = {
  claude: {
    global: path.join(os.homedir(), '.claude', 'skills'),
    local: path.join(process.cwd(), '.claude', 'skills'),
  },
  gemini: {
    global: path.join(os.homedir(), '.agents', 'skills'),
    local: path.join(process.cwd(), '.agents', 'skills'),
  },
  codex: {
    global: path.join(os.homedir(), '.agents', 'skills'),
    local: path.join(process.cwd(), '.agents', 'skills'),
  },
};

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
// Per-editor transformation functions
// ---------------------------------------------------------------------------

/**
 * Claude Code: copy SKILL.md as-is.
 */
function installClaude(skillName, skillMdContent, targetDir) {
  const dest = path.join(targetDir, skillName);
  fs.mkdirSync(dest, { recursive: true });
  const destFile = path.join(dest, 'SKILL.md');
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

  const GEMINI_STRIP_KEYS = ['argument-hint', 'disable-model-invocation', 'color', 'compatibility', 'memory', 'context', 'agent'];
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

  const CODEX_STRIP_KEYS = ['argument-hint', 'color', 'compatibility', 'disable-model-invocation', 'allowed-tools', 'tools', 'memory', 'context', 'agent'];
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
// All others (defend) are auto-called internally and should NOT be installed as skills.
const INSTALLABLE_AGENTS = new Set([
  'scope-audit',
  'scope-exploit',
  'scope-hunt',
]);

// Agents from agents/ (top-level) that must also be deployed as subagents.
// scope-defend: operator-invocable AND dispatched by scope-audit — needs both skill and subagent paths.
// On Claude Code it is read inline from agents/scope-defend.md via Agent tool path.
// On Gemini/Codex it must be deployed to .agents/agents/ so the orchestrator can delegate to it.
const TOP_LEVEL_SUBAGENTS = new Set([
  'scope-defend',
]);

// Model assignments for subagents — two-tier routing.
// Tier 1 (haiku): Enum subagents — structured CLI data collection, no reasoning.
//   Fast and cheap; haiku is correct for AWS API calls and JSON output.
// Tier 2 (sonnet): Reasoning agents — attack path analysis and defensive controls.
//   These agents evaluate policy chains, generate SCP/RCP policies, and write SPL.
//   Explicit sonnet pin prevents session-model inheritance (e.g., --model haiku)
//   from silently degrading security-critical reasoning to an under-powered model.
// scope-verify and scope-pipeline are NOT deployed as subagents — they are read inline.
const SUBAGENT_MODELS = {
  claude: {
    enum: 'claude-haiku-4-5',
    reasoning: 'claude-sonnet-4-6',
  },
  gemini: {
    enum: 'gemini-3.1-flash-lite-preview',
    reasoning: 'gemini-3.1-pro-preview',
  },
  codex: {
    enum: 'gpt-5.4-mini',
    reasoning: 'gpt-5.4',
  },
};

const REASONING_AGENTS = new Set(['scope-attack-paths', 'scope-defend']);

function getModelForAgent(agentName, editor) {
  const tier = REASONING_AGENTS.has(agentName) ? 'reasoning' : 'enum';
  return SUBAGENT_MODELS[editor]?.[tier] || SUBAGENT_MODELS.claude[tier];
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
    const truelySkipped = skipped.filter(n => !TOP_LEVEL_SUBAGENTS.has(n));
    if (asSubagents.length > 0) {
      console.log(`Skipped ${asSubagents.length} agent(s) from skills (will be deployed as subagents): ${asSubagents.join(', ')}`);
    }
    if (truelySkipped.length > 0) {
      console.log(`Skipped ${truelySkipped.length} inline-only agent(s): ${truelySkipped.join(', ')}`);
    }
  }
  return agents;
}

/**
 * Discover subagent .md files from agents/subagents/ and select top-level agents/.
 * Excludes scope-verify.md and scope-pipeline.md — those are read inline
 * at runtime, not deployed as dispatchable subagents.
 * Also includes agents in TOP_LEVEL_SUBAGENTS from the agents/ root dir
 * (e.g., scope-defend — dispatched by orchestrator on Gemini/Codex).
 * Returns array of { name: string, content: string }.
 */
function discoverSubagents(subagentsDir) {
  // Files that are read inline by source agents — do NOT deploy as subagents
  const INLINE_ONLY = new Set(['scope-verify', 'scope-pipeline']);

  const subagents = [];

  // Primary: agents/subagents/ directory
  if (fs.existsSync(subagentsDir)) {
    const entries = fs.readdirSync(subagentsDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.md')) continue;
      const name = entry.name.replace(/\.md$/, '');
      if (INLINE_ONLY.has(name)) continue;
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

  for (const subagent of subagents) {
    const parsed = parseFrontmatter(subagent.content);
    let content = subagent.content;

    if (parsed) {
      const { frontmatter, body } = parsed;
      frontmatter.model = getModelForAgent(subagent.name, 'claude');
      const fm = rebuildFrontmatter(frontmatter, []);
      content = `---\n${fm}\n---\n\n${body}`;
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
  // Model routing handled by getModelForAgent('name', 'gemini')
  let count = 0;

  // Gemini defaults: max_turns=15 — too low for SCOPE agents.
  // Inject appropriate turn limits and explicit tool access per agent type.
  // NOTE: timeout_mins removed — was causing agents to be killed mid-execution.
  const GEMINI_AGENT_CONFIG = {
    'scope-enum-iam':        { max_turns: 50, tools: ['run_shell_command', 'read_file', 'grep_search'] },
    'scope-enum-ec2':        { max_turns: 50, tools: ['run_shell_command', 'read_file', 'grep_search'] },
    'scope-enum-s3':         { max_turns: 40, tools: ['run_shell_command', 'read_file', 'grep_search'] },
    'scope-enum-lambda':     { max_turns: 40, tools: ['run_shell_command', 'read_file', 'grep_search'] },
    'scope-enum-kms':        { max_turns: 30, tools: ['run_shell_command', 'read_file', 'grep_search'] },
    'scope-enum-secrets':    { max_turns: 30, tools: ['run_shell_command', 'read_file', 'grep_search'] },
    'scope-enum-sts':        { max_turns: 30, tools: ['run_shell_command', 'read_file', 'grep_search'] },
    'scope-enum-rds':        { max_turns: 30, tools: ['run_shell_command', 'read_file', 'grep_search'] },
    'scope-enum-sns':        { max_turns: 30, tools: ['run_shell_command', 'read_file', 'grep_search'] },
    'scope-enum-sqs':        { max_turns: 30, tools: ['run_shell_command', 'read_file', 'grep_search'] },
    'scope-enum-apigateway': { max_turns: 30, tools: ['run_shell_command', 'read_file', 'grep_search'] },
    'scope-enum-codebuild':  { max_turns: 30, tools: ['run_shell_command', 'read_file', 'grep_search'] },
    'scope-attack-paths':    { max_turns: 80, tools: ['run_shell_command', 'read_file', 'grep_search', 'write_file'] },
    'scope-defend':          { max_turns: 60, tools: ['run_shell_command', 'read_file', 'grep_search', 'write_file'] },
  };

  for (const subagent of subagents) {
    const parsed = parseFrontmatter(subagent.content);
    let content = subagent.content;

    if (parsed) {
      const { frontmatter, body } = parsed;
      // Inject Gemini-specific config
      const config = GEMINI_AGENT_CONFIG[subagent.name];
      if (config) {
        frontmatter.max_turns = String(config.max_turns);
      }
      // Inject platform-specific model
      frontmatter.model = getModelForAgent(subagent.name, 'gemini');
      const fm = rebuildFrontmatter(frontmatter, GEMINI_STRIP_KEYS);
      // Build tools as YAML array (rebuildFrontmatter only handles strings)
      let toolsYaml = '';
      if (config && config.tools) {
        toolsYaml = '\ntools:\n' + config.tools.map(t => `  - ${t}`).join('\n');
      }
      content = `---\n${fm}${toolsYaml}\n---\n\n${body}`;
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

  for (const subagent of subagents) {
    const parsed = parseFrontmatter(subagent.content);
    let content = subagent.content;
    let description = subagent.name;

    if (parsed) {
      const { frontmatter, body } = parsed;
      if (frontmatter.description) description = frontmatter.description;
      const fm = rebuildFrontmatter(frontmatter, CODEX_STRIP_KEYS);
      content = `---\n${fm}\n---\n\n${body}`;
    }

    // Deploy stripped .md file
    const destMd = path.join(agentsDir, `${subagent.name}.md`);
    fs.writeFileSync(destMd, content, 'utf8');
    const displayMd = destMd.replace(os.homedir(), '~');
    console.log(`  Installing subagent ${subagent.name} -> ${displayMd}`);
    count++;

    const codexModel = getModelForAgent(subagent.name, 'codex');
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
    const mdBody = parsed ? parsed.body : subagent.content;
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
  const agentsGlobalBlock = '[agents]\nmax_threads = 16\nmax_depth = 1\njob_max_runtime_seconds = 3600\n';
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
  let count = 0;

  for (const agent of agents) {
    let destFile = null;
    try {
      if (editor === 'claude') {
        destFile = installClaude(agent.name, agent.content, targetDir);
      } else if (editor === 'gemini') {
        destFile = installGemini(agent.name, agent.content, targetDir);
      } else if (editor === 'codex') {
        destFile = installCodex(agent.name, agent.content, targetDir);
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
  Skills      Operator-invoked slash commands (scope-audit, scope-exploit, scope-hunt)
              -> .claude/skills/ (Claude Code) or .agents/skills/ (Gemini/Codex)
  Subagents   Orchestrator-dispatched workers (enum subagents, attack-paths, scope-defend)
              -> .claude/agents/ (Claude Code)
              -> .gemini/agents/ (Gemini CLI) — requires experimental.enableAgents: true
              -> .codex/agents/ + .codex/config.toml (Codex)
              Note: scope-verify and scope-pipeline are read inline, not deployed as subagents
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
  if (editor === 'codex') return; // Codex does not support hooks

  const settingsMap = {
    claude: { src: 'config/settings/claude.settings.json', dest: '.claude/settings.json', hooksDir: '.claude/hooks' },
    gemini: { src: 'config/settings/gemini.settings.json', dest: '.gemini/settings.json', hooksDir: '.gemini/hooks' },
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
  const destDir = path.join(base, path.dirname(entry.dest));
  const destFile = path.join(destDir, 'settings.json');
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
 * Warn if stale skills exist in deprecated .gemini/skills/ path.
 * Called after unifying Gemini to .agents/skills/.
 */
function checkLegacyGeminiSkills(scope) {
  const legacyBase = scope === 'global'
    ? path.join(os.homedir(), '.gemini', 'skills')
    : path.join(process.cwd(), '.gemini', 'skills');

  const scopeSkills = ['scope-audit', 'scope-exploit', 'scope-hunt'];
  const stale = scopeSkills.filter(s => fs.existsSync(path.join(legacyBase, s)));

  if (stale.length > 0) {
    console.warn(`\n  WARN: Stale SCOPE skills found in deprecated ${
      scope === 'global' ? '~/.gemini/skills/' : '.gemini/skills/'
    }:`);
    stale.forEach(s => console.warn(`    - ${s}/`));
    console.warn('  Remove these to prevent stale skill conflicts:');
    console.warn(`    rm -rf ${legacyBase}/scope-{audit,exploit,hunt}\n`);
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

  // Detect skill collision: Gemini and Codex both write to .agents/skills/ — install once.
  // Subagents no longer collide: Gemini -> .gemini/agents/, Codex -> .codex/agents/.
  const hasGemini = editors.includes('gemini');
  const hasCodex = editors.includes('codex');
  const skillsCollision = hasGemini && hasCodex;

  if (skillsCollision) {
    console.log('NOTE: Gemini + Codex both target .agents/skills/ — installing shared-compatible skill files once.\n');
  }

  // For skills: when both collide, install .agents/skills/ once via Codex (superset strip list),
  // skip Gemini's .agents/skills/ pass. Subagents always run per-editor (different dirs).
  const effectiveSkillEditors = skillsCollision
    ? editors.filter(e => e !== 'gemini')
    : editors;

  for (const editor of effectiveSkillEditors) {
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
      }
    }
  }

  // Check for and warn about stale module deployments from pre-Phase-3 installs
  cleanupOldModules(scope);

  if (editors.includes('gemini')) {
    checkLegacyGeminiSkills(scope);
  }
}

main();
