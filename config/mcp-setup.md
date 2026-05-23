# SCOPE — MCP Server Setup

## Overview

SCOPE's `scope-investigate` agent can execute SIEM queries live via MCP. When connected, the agent runs queries directly with analyst approval. Without MCP, it falls back to MANUAL mode (generates queries for copy-paste).

**Default configuration uses Splunk Cloud's MCP Server app (Splunkbase app 7931, v1.0.2+).** You can substitute any SIEM MCP server that exposes search tools — see [Using a Different SIEM](#using-a-different-siem) below.

---

## Prerequisites

1. **Node.js v18+** — required by `mcp-remote` stdio transport
2. **SIEM MCP endpoint URL and authentication token**
3. **One of:** Claude Code (v1.0.48+), Gemini CLI, or Codex CLI

---

## Configuration

Set environment variables in your shell profile (`.zshrc`, `.bashrc`, etc.):

```bash
export SPLUNK_URL="https://your-mcp-endpoint"
export SPLUNK_TOKEN="your-mcp-token"
```

Reload your shell, then verify both are set:

```bash
echo "$SPLUNK_URL"
echo "$SPLUNK_TOKEN"
```

The installer (`node bin/install.js`) deploys platform-specific MCP config automatically. If you need to configure manually:

### Claude Code (`.mcp.json`)

```json
{
  "mcpServers": {
    "splunk-mcp-server": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "${SPLUNK_URL}", "--header", "Authorization: Bearer ${SPLUNK_TOKEN}"]
    }
  }
}
```

### Gemini CLI (`.gemini/settings.json`)

Add `mcpServers` at the top level:

```json
{
  "mcpServers": {
    "splunk-mcp-server": {
      "command": "sh",
      "args": ["-c", "npx -y mcp-remote \"$SPLUNK_URL\" --header \"Authorization: Bearer $SPLUNK_TOKEN\""],
      "env": {
        "SPLUNK_URL": "$SPLUNK_URL",
        "SPLUNK_TOKEN": "$SPLUNK_TOKEN"
      }
    }
  }
}
```

The `env` block is required — Gemini CLI redacts variables matching `*TOKEN*` patterns unless explicitly declared. The `sh -c` wrapper is required because Gemini CLI does not expand `$VAR` references in the `args` array.

### Codex CLI (`.codex/config.toml`)

```toml
[mcp_servers.splunk-mcp-server]
url = "${SPLUNK_URL}"

[mcp_servers.splunk-mcp-server.env]
SPLUNK_URL = "$SPLUNK_URL"
SPLUNK_TOKEN = "$SPLUNK_TOKEN"
```

---

## Verify

1. Start your CLI tool in the SCOPE project directory
2. Run `/scope:investigate`
3. The agent probes for MCP connectivity at startup

**Connected:** `Splunk MCP connected via search_oneshot -> https://your-endpoint`
**Not connected:** Falls back to MANUAL mode (SPL generation for paste-back)

---

## Using a Different SIEM

SCOPE's MCP configuration is not locked to Splunk. If your SIEM provides an MCP server (Elastic, Sentinel, QRadar, etc.), replace the `mcpServers` block with your SIEM's MCP server command and credentials.

The `scope-investigate` agent probes for available search tools at startup. If it finds a working search tool exposed by your MCP server, it enters CONNECTED mode. If no recognized tool responds, it falls back to MANUAL mode where it generates queries for you to run externally.

To use a different SIEM MCP server:
1. Replace the `splunk-mcp-server` entry in your platform's config with your SIEM's MCP server definition
2. Set the appropriate environment variables for your SIEM's authentication
3. The agent will probe the available tools and adapt

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| 401 Unauthorized | Token generated from Splunk Settings instead of MCP Server app | Regenerate from within the MCP Server app |
| Transport failure (-32000) | Wrong URL (Splunk Web URL vs MCP endpoint) | Use URL from MCP Server app's Connect screen |
| Literal `${SPLUNK_TOKEN}` in header | Claude Code below v1.0.48 | Upgrade Claude Code |
| Token redacted (Gemini) | Missing `env` block | Add explicit `env` block to settings.json |
| npx not found | Node.js not in PATH | Install Node.js v18+ |
| Probe fails but SIEM reachable | Tool name mismatch across app versions | Tell agent the correct tool name when prompted |

---

## Safety

All Splunk MCP Server tools (app 7931, v1.0.2) are Splunk-scoped. None accept AWS resource identifiers or credentials as parameters. Zero AWS write operation risk.

| Tool | Purpose |
|------|---------|
| validate_spl | Validate SPL before execution |
| search_oneshot | Execute blocking SPL search |
| search_export | Stream large result sets |
| get_indexes | List Splunk indexes when the MCP server exposes it. SCOPE does not depend on this tool; current index discovery uses `\| rest /services/data/indexes` through the selected search tool. |
| get_saved_searches | List saved searches |
| run_saved_search | Execute a saved search |
| saia_generate_spl | Natural language to SPL |
| saia_explain_spl | Explain SPL in plain language |
| saia_optimize_spl | Optimize SPL query |
