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
 */
function rebuildFrontmatter(frontmatter, omitKeys) {
  const lines = [];
  for (const [key, value] of Object.entries(frontmatter)) {
    if (omitKeys.includes(key)) continue;
    lines.push(`${key}: ${value}`);
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
  'scope-investigate',
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
const SUBAGENT_MODEL_MAP = {
  'scope-enum-iam': 'haiku',
  'scope-enum-sts': 'haiku',
  'scope-enum-s3': 'haiku',
  'scope-enum-kms': 'haiku',
  'scope-enum-secrets': 'haiku',
  'scope-enum-lambda': 'haiku',
  'scope-enum-ec2': 'haiku',
  'scope-enum-rds': 'haiku',
  'scope-enum-sns': 'haiku',
  'scope-enum-sqs': 'haiku',
  'scope-enum-apigateway': 'haiku',
  'scope-enum-bedrock': 'haiku',
  'scope-enum-sagemaker': 'haiku',
  'scope-enum-codebuild': 'haiku',
  'scope-attack-paths': 'sonnet',
  'scope-defend': 'sonnet',
};

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
 * Claude Code subagent deployment.
 * Deploys flat .md files to .claude/agents/ (local) or ~/.claude/agents/ (global).
 * Injects the model field from SUBAGENT_MODEL_MAP into frontmatter.
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
      const model = SUBAGENT_MODEL_MAP[subagent.name];
      if (model) {
        frontmatter.model = model;
      }
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
  const GEMINI_STRIP_KEYS = ['model', 'argument-hint', 'disable-model-invocation', 'allowed-tools', 'tools', 'color', 'compatibility', 'memory', 'context', 'agent'];
  let count = 0;

  for (const subagent of subagents) {
    const parsed = parseFrontmatter(subagent.content);
    let content = subagent.content;

    if (parsed) {
      const { frontmatter, body } = parsed;
      const fm = rebuildFrontmatter(frontmatter, GEMINI_STRIP_KEYS);
      content = `---\n${fm}\n---\n\n${body}`;
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
 *   1. Deploys stripped .md files to .codex/agents/ (local) or ~/.codex/agents/ (global)
 *      so operators can reference them via config_file in config.toml.
 *   2. Auto-merges [agents] entries into .codex/config.toml (local) or ~/.codex/config.toml
 *      (global). Uses a marked SCOPE block that is replaced on re-install.
 * Strips model field and Claude-specific keys.
 */
function installSubagentsCodex(subagents, scope) {
  const agentsDir = scope === 'local'
    ? path.join(process.cwd(), '.codex', 'agents')
    : path.join(os.homedir(), '.codex', 'agents');

  fs.mkdirSync(agentsDir, { recursive: true });
  const CODEX_STRIP_KEYS = ['model', 'argument-hint', 'color', 'compatibility', 'disable-model-invocation', 'allowed-tools', 'tools', 'memory', 'context', 'agent'];
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

    const destFile = path.join(agentsDir, `${subagent.name}.md`);
    fs.writeFileSync(destFile, content, 'utf8');
    const displayPath = destFile.replace(os.homedir(), '~');
    console.log(`  Installing subagent ${subagent.name} -> ${displayPath}`);
    count++;

    // Determine model — Codex uses gpt-4o for haiku tier, o3 for sonnet tier
    const scopeModel = SUBAGENT_MODEL_MAP[subagent.name] || 'haiku';
    const codexModel = scopeModel === 'sonnet' ? 'o3' : 'gpt-4o';
    const configFilePath = scope === 'local'
      ? `.codex/agents/${subagent.name}.md`
      : `~/.codex/agents/${subagent.name}.md`;

    tomlEntries.push(
      `[agents.${subagent.name}]`,
      `description = "${description}"`,
      `config_file = "${configFilePath}"`,
      `model = "${codexModel}"`,
      `model_reasoning_effort = "medium"`,
      `sandbox_mode = "network-disabled"`,
      ``
    );
  }

  // Auto-merge into config.toml
  const configTomlPath = scope === 'local'
    ? path.join(process.cwd(), '.codex', 'config.toml')
    : path.join(os.homedir(), '.codex', 'config.toml');

  const scopeHeader = '# --- SCOPE subagent registrations (auto-generated) ---';
  const scopeFooter = '# --- END SCOPE subagent registrations ---';
  const scopeBlock = [scopeHeader, '', ...tomlEntries, scopeFooter].join('\n');

  let existingConfig = '';
  if (fs.existsSync(configTomlPath)) {
    existingConfig = fs.readFileSync(configTomlPath, 'utf8');
  }

  // Replace existing SCOPE block or append
  const scopeBlockRegex = new RegExp(
    scopeHeader.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') +
    '[\\s\\S]*?' +
    scopeFooter.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  );

  let newConfig;
  if (scopeBlockRegex.test(existingConfig)) {
    newConfig = existingConfig.replace(scopeBlockRegex, scopeBlock);
    console.log(`  Updated SCOPE block in config.toml`);
  } else {
    newConfig = existingConfig ? existingConfig.trimEnd() + '\n\n' + scopeBlock + '\n' : scopeBlock + '\n';
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
  Skills      Operator-invoked slash commands (scope-audit, scope-exploit, scope-investigate)
              -> .claude/skills/ (Claude Code) or .agents/skills/ (Gemini/Codex)
  Subagents   Orchestrator-dispatched workers (enum subagents, attack-paths, scope-defend)
              -> .claude/agents/ (Claude Code)
              -> .gemini/agents/ (Gemini CLI) — requires experimental.enableAgents: true
              -> .codex/agents/ + .codex/config.toml (Codex)
              Note: scope-verify and scope-pipeline are read inline, not deployed as subagents

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
  console.log('\nSCOPE Install Script');
  console.log('Which editor(s) would you like to install to?');
  console.log('  1) Claude Code');
  console.log('  2) Gemini CLI');
  console.log('  3) Codex');
  console.log('  4) All three editors');
  const choice = promptUser('\nEnter choice [1-4]: ');

  let editors = [];
  if (choice === '1') editors = ['claude'];
  else if (choice === '2') editors = ['gemini'];
  else if (choice === '3') editors = ['codex'];
  else if (choice === '4') editors = ['claude', 'gemini', 'codex'];
  else {
    console.error('Invalid choice. Run with --help for usage.');
    process.exit(1);
  }

  const scopeChoice = promptUser('Install globally (~/.<editor>/) or locally (./<editor>/)? [G/l]: ');
  const scope = scopeChoice.toLowerCase() === 'l' ? 'local' : 'global';

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
 * Copy hook settings.json for an editor if installing locally.
 * Only copies the project-level settings file — global hooks are not deployed.
 */
function installHooks(editor, scope) {
  if (scope !== 'local') return;
  if (editor === 'codex') return; // Codex does not support hooks

  const settingsMap = {
    claude: { src: '.scope/settings/claude.settings.json', dest: '.claude/settings.json' },
    gemini: { src: '.scope/settings/gemini.settings.json', dest: '.gemini/settings.json' },
  };
  const srcSettings = path.join(__dirname, '..', settingsMap[editor].src);
  if (!fs.existsSync(srcSettings)) return;

  const destDir = path.join(process.cwd(), path.dirname(settingsMap[editor].dest));
  const destFile = path.join(destDir, 'settings.json');
  if (fs.existsSync(destFile)) {
    console.log(`  Hook settings already exist: ${settingsMap[editor].dest} (skipped)`);
    return;
  }

  fs.mkdirSync(destDir, { recursive: true });
  fs.copyFileSync(srcSettings, destFile);
  console.log(`  Installed hook settings -> ${settingsMap[editor].dest}`);
}

/**
 * Warn if stale skills exist in deprecated .gemini/skills/ path.
 * Called after unifying Gemini to .agents/skills/.
 */
function checkLegacyGeminiSkills(scope) {
  const legacyBase = scope === 'global'
    ? path.join(os.homedir(), '.gemini', 'skills')
    : path.join(process.cwd(), '.gemini', 'skills');

  const scopeSkills = ['scope-audit', 'scope-exploit', 'scope-investigate'];
  const stale = scopeSkills.filter(s => fs.existsSync(path.join(legacyBase, s)));

  if (stale.length > 0) {
    console.warn(`\n  WARN: Stale SCOPE skills found in deprecated ${
      scope === 'global' ? '~/.gemini/skills/' : '.gemini/skills/'
    }:`);
    stale.forEach(s => console.warn(`    - ${s}/`));
    console.warn('  Remove these to prevent stale skill conflicts:');
    console.warn(`    rm -rf ${legacyBase}/scope-{audit,exploit,investigate}\n`);
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

  // Subagent deployment — each editor has its own target dir, no collision
  const subagentsDir = path.join(agentsDir, 'subagents');
  const subagents = discoverSubagents(subagentsDir);
  if (subagents.length > 0) {
    console.log(`\nFound ${subagents.length} subagent(s): ${subagents.map(s => s.name).join(', ')}\n`);
    for (const editor of editors) {
      if (editor === 'claude') installSubagentsClaude(subagents, scope);
      else if (editor === 'gemini') installSubagentsGemini(subagents, scope);
      else if (editor === 'codex') installSubagentsCodex(subagents, scope);
    }
  }

  // Check for and warn about stale module deployments from pre-Phase-3 installs
  cleanupOldModules(scope);

  if (editors.includes('gemini')) {
    checkLegacyGeminiSkills(scope);
  }
}

main();
