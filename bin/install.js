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
    global: path.join(os.homedir(), '.gemini', 'commands', 'scope'),
    local: path.join(process.cwd(), '.gemini', 'commands', 'scope'),
  },
  codex: {
    global: path.join(os.homedir(), '.codex', 'skills'),
    local: path.join(process.cwd(), '.codex', 'skills'),
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
 * Gemini CLI: convert SKILL.md to TOML.
 * - Extracts description from frontmatter
 * - Replaces ${ARGUMENTS} with {{args}}
 * - Strips scope- prefix from skill name for the filename
 * - Uses literal multi-line strings '''...''' to avoid escape issues
 */
function installGemini(skillName, skillMdContent, targetDir) {
  const parsed = parseFrontmatter(skillMdContent);
  if (!parsed) {
    console.warn(`  WARN: Skipping ${skillName} — no frontmatter found`);
    return null;
  }
  const { frontmatter, body } = parsed;
  const description = frontmatter.description || '';

  // Strip the 'scope-' prefix for the TOML filename
  // e.g., scope-engage -> engage.toml, scope-audit -> audit.toml
  const tomlName = skillName.replace(/^scope-/, '');

  // Replace ${ARGUMENTS} or $ARGUMENTS style substitutions with {{args}}
  const prompt = body
    .replace(/\$\{ARGUMENTS\}/g, '{{args}}')
    .replace(/\$ARGUMENTS/g, '{{args}}');

  // Build TOML content using literal multi-line strings (''' ''') to avoid escape issues
  const tomlContent = `description = "${description.replace(/"/g, '\\"')}"\nprompt = '''\n${prompt}\n'''\n`;

  fs.mkdirSync(targetDir, { recursive: true });
  const destFile = path.join(targetDir, `${tomlName}.toml`);
  fs.writeFileSync(destFile, tomlContent, 'utf8');
  return destFile;
}

/**
 * Codex: copy SKILL.md but strip Claude-specific frontmatter fields.
 * Retains: name, description, compatibility
 * Strips: color, disable-model-invocation, allowed-tools, tools
 */
function installCodex(skillName, skillMdContent, targetDir) {
  const parsed = parseFrontmatter(skillMdContent);
  if (!parsed) {
    console.warn(`  WARN: Skipping ${skillName} — no frontmatter found`);
    return null;
  }
  const { frontmatter, body } = parsed;

  const CODEX_STRIP_KEYS = ['color', 'disable-model-invocation', 'allowed-tools', 'tools'];
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
// All others (verify-*, data, evidence, defend) are auto-called internally
// and should NOT be installed as skills.
// Note: /scope:help is not an agent — editors serve it by reading commands/help.md directly.
const INSTALLABLE_AGENTS = new Set([
  'scope-audit',
  'scope-exploit',
  'scope-investigate',
]);

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
    console.log(`Skipped ${skipped.length} internal agent(s): ${skipped.join(', ')}`);
  }
  return agents;
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
Install SCOPE agents into AI editor config directories.

Usage:
  node bin/install.js [editors] [scope] [options]

Editors (pick one or more, or --all):
  --claude    Install to Claude Code (.claude/skills/)
  --gemini    Install to Gemini CLI (.gemini/commands/scope/)
  --codex     Install to Codex (.codex/skills/)
  --all       Install to all three editors

Scope:
  --global    Install to ~/.<editor>/ (default)
  --local     Install to ./.<editor>/ in current directory

Options:
  --help      Print this usage message

Examples:
  node bin/install.js --all
  node bin/install.js --claude --global
  node bin/install.js --gemini --local
  node bin/install.js --codex --local
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
  const scope = args.includes('--local') ? 'local' : 'global';

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

function runInstall(editors, scope) {
  const agentsDir = path.join(__dirname, '..', 'agents');
  const agents = discoverAgents(agentsDir);

  if (agents.length === 0) {
    console.log('No agents found in agents/ directory.');
    process.exit(0);
  }

  console.log(`Found ${agents.length} agent${agents.length !== 1 ? 's' : ''}: ${agents.map(a => a.name).join(', ')}\n`);

  for (const editor of editors) {
    installForEditor(editor, scope, agents);
  }
}

main();
