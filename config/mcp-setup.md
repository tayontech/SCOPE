# SCOPE MCP Setup

## Overview

`scope-investigate` can execute investigation queries through MCP when a supported SIEM server is connected. The built-in workflow is Splunk-first and generates SPL. Splunk MCP is optional:

- **Splunk MCP connected:** the agent runs approved SPL through the selected MCP tool.
- **No Splunk MCP:** the agent prints SPL and waits for pasted Splunk results.
- **Different SIEM MCP:** replace the MCP server config with your SIEM server. SCOPE can call a custom query tool only after the operator gives the tool name and query-language expectations. Detection generation and built-in investigation templates remain SPL until SCOPE adds SIEM profiles.

The bundled default uses Splunk MCP Server for Splunk Platform from Splunkbase app 7931. Splunk's 1.1 docs list app version 1.1.3 as released on May 19, 2026.

---

## Prerequisites

1. Node.js v18+ for `mcp-remote`
2. Claude Code, Gemini CLI, Antigravity CLI, or Codex CLI
3. Optional Splunk MCP path:
   - Splunk MCP Server app installed on the Splunk search head or search head cluster
   - `mcp_tool_execute` role capability for users who run tools
   - `mcp_tool_admin` plus Splunk token-edit capability for users who create encrypted MCP tokens
   - Encrypted MCP token generated inside the Splunk MCP Server app
   - MCP server endpoint from the Splunk MCP Server app

SCOPE does not use a direct Splunk REST client. Splunk's MCP app has its own server-side prerequisites, including API access and token authentication in Splunk.

---

## Install Choice

Interactive install asks whether to configure the bundled Splunk MCP defaults.

Scripted installs do not write MCP server settings unless you opt in:

```bash
uv run python -m scope.install --claude --with-splunk-mcp
uv run python -m scope.install --antigravity --with-splunk-mcp
uv run python -m scope.install --gemini --with-splunk-mcp
uv run python -m scope.install --codex --with-splunk-mcp
```

Use `--no-splunk-mcp` for explicit no-MCP scripted installs or automation that wants the flag visible in logs.

Antigravity CLI is the preferred Google target. Google announced on May 19, 2026 that Gemini CLI stops serving requests for Google AI Pro, Ultra, and free individual users on June 18, 2026. SCOPE keeps Gemini support for enterprise/API-key users and migration compatibility.

---

## Splunk MCP Configuration

Set environment variables in your shell profile:

```bash
export SPLUNK_URL="https://your-mcp-server-endpoint"
export SPLUNK_TOKEN="your-encrypted-mcp-token"
```

Reload your shell, then verify both are set:

```bash
echo "$SPLUNK_URL"
echo "$SPLUNK_TOKEN"
```

The installer deploys platform-specific config when Splunk MCP is enabled. If you configure it manually, use the Splunk MCP endpoint and encrypted MCP token from the Splunk MCP Server app.

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

The `env` block is required because Gemini CLI can redact variables matching `*TOKEN*` patterns unless the settings file declares them. The `sh -c` wrapper allows shell expansion of `$SPLUNK_URL` and `$SPLUNK_TOKEN`.

### Antigravity CLI (`.agents/mcp_config.json`)

Workspace installs write Antigravity MCP config to `.agents/mcp_config.json`. Global Antigravity CLI installs use `~/.gemini/antigravity-cli/mcp_config.json`.

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

### Codex CLI (`.codex/config.toml`)

The installer can add a project MCP endpoint block for Codex:

```toml
[mcp_servers.splunk-mcp-server]
url = "${SPLUNK_URL}"
```

If your Codex runtime requires a command transport with custom headers, configure it manually with `mcp-remote` and the same `Authorization: Bearer <encrypted token>` header shown above. If your runtime cannot pass the Splunk MCP encrypted token, use manual SPL mode.

---

## Verify

1. Start your CLI tool in the SCOPE project directory.
2. Run `/scope:investigate`.
3. The agent probes for MCP connectivity at startup.

Expected results:

- Connected: `Splunk MCP connected via splunk_run_query -> https://your-endpoint`
- Not connected: manual SPL mode. The agent prints SPL and waits for pasted results.

---

## Splunk MCP Tools

Splunk MCP Server 1.1 namespaces platform tools with `splunk_` and AI Assistant tools with `saia_`. SCOPE relies on these tools when available:

| Tool | Purpose |
|------|---------|
| `splunk_run_query` | Execute approved SPL searches. This is the primary execution path. |
| `splunk_get_info` | Probe Splunk MCP connectivity and collect instance metadata when available. |
| `splunk_get_indexes` | List Splunk indexes for connected-mode runtime discovery. |
| `splunk_get_index_info` | Inspect a specific index when the operator requests detail. |
| `splunk_get_metadata` | Retrieve host, source, or sourcetype metadata across indexes. |
| `splunk_get_knowledge_objects` | List supported knowledge objects such as saved searches, alerts, macros, lookups, and data models. |
| `splunk_run_saved_search` | Run saved searches when the beta tool is enabled. |
| `saia_generate_spl` | Generate SPL from natural language when Splunk AI Assistant is installed. |
| `saia_explain_spl` | Explain SPL when Splunk AI Assistant is installed. |
| `saia_optimize_spl` | Optimize SPL when Splunk AI Assistant is installed. |
| `saia_ask_splunk_question` | Ask Splunk questions when Splunk AI Assistant is installed. |

SCOPE keeps legacy probe names for older local MCP servers, but current Splunk MCP 1.1 uses `splunk_run_query`, `splunk_get_info`, and `splunk_get_indexes`.

---

## Using Another SIEM

SCOPE can run without the bundled Splunk MCP default. Teams using Elastic, Sentinel, QRadar, or another SIEM have two supported options:

1. Use manual mode. SCOPE prints SPL and query intent. The analyst translates and runs it in the SIEM, then pastes results back.
2. Replace the MCP server config with a custom SIEM MCP server and tell `scope-investigate` the query tool name when prompted. The custom server must accept the query language the analyst chooses for that session.

Current limitation: SCOPE controls detections and investigation templates generate SPL. Other SIEMs need an adapter, operator translation, or a future query-language profile.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| 401 Unauthorized | Token came from Splunk Settings instead of the MCP Server app | Regenerate an encrypted token from the MCP Server app |
| Transport failure (-32000) | Wrong URL, such as Splunk Web instead of MCP endpoint | Use the endpoint from the MCP Server app Connect screen |
| Literal `${SPLUNK_TOKEN}` in header | Client did not expand environment variables | Upgrade the client or use the shell-wrapper form |
| Token redacted in Gemini | Missing `env` block | Add explicit `env` block to settings.json |
| `npx` not found | Node.js not in PATH | Install Node.js v18+ |
| `splunk_get_indexes` missing | Admin disabled the tool server-side | Ask the Splunk MCP admin to enable it or provide a temporary index list |
| Probe fails but MCP server works | Tool name differs from the default probe list | Tell the agent the correct tool name when prompted |

---

## Safety

SCOPE gates every query behind analyst approval. Splunk MCP tools stay Splunk-scoped. They do not accept AWS credentials as parameters, and they do not execute AWS write operations.

The Splunk MCP 1.1 docs also describe server-side controls:

- admins can enable or disable tools centrally
- encrypted MCP tokens cannot serve as direct Splunk API tokens
- `splunk_run_query` has guardrails for unsafe commands, execution time, and response size
- saved-search execution and rate limiting are beta features in 1.1
