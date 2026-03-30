# SCOPE — Splunk MCP Server Setup

## Overview

This guide walks you through connecting SCOPE's `scope-hunt` agent to your Splunk Cloud instance via the official Splunk MCP Server app (Splunkbase app 7931). Once configured, the agent executes SPL queries live with analyst approval — no more manual copy-paste loops.

**What this enables:** Live Splunk query execution from `scope-hunt` instead of the default MANUAL mode (SPL generation with paste-back). The agent probes for MCP connectivity at startup and falls back to MANUAL mode automatically when no MCP server is available.

**Scope:** Splunk Cloud Platform only (official Splunkbase app 7931, version 1.0.2+). Splunk Enterprise and on-premises deployments are out of scope for this guide.

---

## Prerequisites

Before starting, confirm you have:

1. **Splunk Cloud Platform 9.2–10.2** — admin role required to install apps from Splunkbase
2. **Node.js v18 or later** — required by the `mcp-remote` stdio transport

   ```bash
   node --version
   # Expected: v18.x.x or higher
   ```

3. **One of the following CLI tools:**

   | Platform | Minimum Version | MCP Config Location |
   |----------|----------------|---------------------|
   | Claude Code | v1.0.48+ | `.mcp.json` (project root) |
   | Gemini CLI | Latest | `.gemini/settings.json` |
   | Codex CLI | Latest | `.codex/config.toml` |

---

## Step 1 — Install the Splunk MCP Server App

1. Log in to your Splunk Cloud instance as an admin
2. Go to **Apps** → **Find More Apps**
3. Search for **"MCP Server for Splunk Platform"** (Splunkbase app 7931)
4. Click **Install** and follow the installation prompts
5. After installation, the **MCP Server** app appears in your Splunk Cloud navigation bar

---

## Step 2 — Generate an MCP Token

> **Important:** Token generation is done INSIDE the MCP Server app, NOT via Splunk Settings → Tokens. Tokens generated from Splunk Settings are standard HEC/REST tokens and will not work with the MCP protocol.

1. Click the **MCP Server** app from the Splunk navigation bar
2. Follow the app's built-in token generation workflow
3. The generated token is MCP-specific and encrypted — it cannot be reused for direct Splunk REST API calls
4. **Copy the token value** — you will set it as `SPLUNK_TOKEN` in your shell environment

---

## Step 3 — Get the MCP Endpoint URL

> **Important:** The MCP endpoint URL is NOT the same as your Splunk Web URL. Do not use your standard Splunk Cloud URL (e.g., `https://org.splunkcloud.com`).

1. In the MCP Server app, navigate to the **Connect** screen
2. Copy the **MCP endpoint URL** shown there (typically ends in `/services/mcp` or similar)
3. **Copy the full URL** — you will set it as `SPLUNK_URL` in your shell environment

---

## Step 4 — Configure Environment Variables

Add the two variables to your shell profile (`.zshrc`, `.bashrc`, or equivalent):

```bash
export SPLUNK_URL="https://your-endpoint-from-step-3"
export SPLUNK_TOKEN="your-token-from-step-2"
```

Then reload your shell:

```bash
source ~/.zshrc   # or source ~/.bashrc
```

Verify the variables are set:

```bash
echo "$SPLUNK_URL"
echo "$SPLUNK_TOKEN"
```

Both should print non-empty values before continuing.

---

## Step 5 — Configure SCOPE

Pick the tab for your platform. Each platform reads MCP config from a different location and format.

### Claude Code

Copy the MCP configuration template:

```bash
cp .mcp.example.json .mcp.json
```

No edits needed. The `.mcp.json` file reads `SPLUNK_URL` and `SPLUNK_TOKEN` from your shell environment at startup. As a defense-in-depth measure, `.mcp.json` is listed in `.gitignore`.

```json
{
  "mcpServers": {
    "splunk-mcp-server": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "${SPLUNK_URL}",
        "--header",
        "Authorization: Bearer ${SPLUNK_TOKEN}"
      ]
    }
  }
}
```

### Gemini CLI

The MCP config goes in `.gemini/settings.json`. SCOPE includes a launcher script (`bin/splunk-mcp-start.sh`) that handles environment variable loading, PATH setup, validation, and debug logging.

Add the `mcpServers` block at the top level of `.gemini/settings.json`:

```json
{
  "mcpServers": {
    "splunk-mcp-server": {
      "command": "bash",
      "args": ["bin/splunk-mcp-start.sh"],
      "env": {
        "SPLUNK_URL": "$SPLUNK_URL",
        "SPLUNK_TOKEN": "$SPLUNK_TOKEN"
      }
    }
  }
}
```

> **Why the `env` block?** Gemini CLI automatically redacts environment variables matching patterns like `*TOKEN*`, `*SECRET*`, `*KEY*`. Without the explicit `env` block, `SPLUNK_TOKEN` gets stripped before reaching the MCP server. Variables declared in `env` bypass this redaction.

> **Debug logging:** The launcher writes to `~/.scope/splunk-mcp.log` on every startup. If the connection fails, check that log for the exact error. It records env var state (token length only, never the value), node/npx paths, and any startup failures.

### Codex CLI

Codex reads MCP config from `.codex/config.toml`. Create the file if it doesn't exist:

```toml
[mcp_servers.splunk-mcp-server]
command = "npx"
args = ["-y", "mcp-remote"]
startup_timeout_sec = 30
tool_timeout_sec = 60

[mcp_servers.splunk-mcp-server.env]
SPLUNK_URL = "$SPLUNK_URL"
SPLUNK_TOKEN = "$SPLUNK_TOKEN"
```

> **Note:** Codex uses TOML format, not JSON. The `bearer_token_env_var` field can be used for HTTP transport, but since the Splunk MCP server uses the `mcp-remote` stdio bridge, environment variables are passed via the `env` block.

---

## Step 6 — Verify the Connection

1. Open a terminal in the SCOPE project directory
2. Start your CLI tool (`claude`, `gemini`, or `codex`)
3. Run the investigate command: `/scope:hunt`
4. Watch the startup output — the agent probes for Splunk MCP connectivity automatically

**Expected output (success):**

```
Checking for Splunk MCP connection...
Splunk MCP connected via search_oneshot -> https://your-endpoint. Queries execute automatically after your approval.
```

**Expected output (not connected):**

```
Checking for Splunk MCP connection...
Splunk MCP not available. I will generate SPL queries for you to run manually. Paste results back to continue.
See config/mcp-setup.md to enable live queries.
```

If you see the MANUAL message, proceed to the Troubleshooting section below.

---

## Safety Audit — MCP Tool Manifest

SCOPE's safety model requires that no MCP tool can execute AWS write operations. The Splunk MCP Server app (app 7931, v1.0.2) exposes the following tools — all of which are Splunk-scoped:

| Tool Name          | Purpose                              | AWS Write Risk |
|--------------------|--------------------------------------|----------------|
| validate_spl       | Validate SPL query before execution  | None           |
| search_oneshot     | Execute blocking SPL search          | None           |
| search_export      | Stream large result sets             | None           |
| get_indexes        | List Splunk indexes                  | None           |
| get_saved_searches | List saved searches                  | None           |
| run_saved_search   | Execute a saved search               | None           |
| get_config         | Retrieve MCP server config           | None           |
| saia_generate_spl  | Convert natural language to SPL      | None           |
| saia_explain_spl   | Explain SPL in plain language        | None           |
| saia_optimize_spl  | Optimize an SPL query                | None           |

**Verdict:** All tools are Splunk-scoped. None accept AWS resource identifiers, API names, or credentials as parameters. Zero AWS write operation risk.

> **Note:** If a future app version adds new tools, operators should review the updated tool manifest before upgrading. Check the app's release notes on Splunkbase.

---

## Troubleshooting

### MCP Error -32000 (Transport Failure)

**Cause:** The MCP server process starts but cannot reach the Splunk endpoint. Most common reasons:

1. `SPLUNK_URL` is the Splunk Web URL instead of the MCP endpoint URL
2. Environment variables are not exported in the shell that launched the CLI tool
3. Firewall blocking the MCP endpoint port

**Fix:** Verify the endpoint URL is from the MCP Server app's Connect screen (not your Splunk Web login URL). Test the connection manually:

```bash
npx -y mcp-remote "$SPLUNK_URL" --header "Authorization: Bearer $SPLUNK_TOKEN"
```

If this errors, the issue is between your machine and Splunk, not the CLI tool.

---

### 401 Unauthorized

**Cause:** Token was generated from Splunk Settings → Tokens instead of the MCP Server app.

**Fix:** Open the MCP Server app and regenerate the token from within the app's token generation workflow. Replace `SPLUNK_TOKEN` in your shell profile with the new value and reload.

---

### Connection Refused / 404 Not Found

**Cause:** `SPLUNK_URL` is set to the Splunk Web URL (e.g., `https://org.splunkcloud.com`) instead of the MCP endpoint URL.

**Fix:** Copy the MCP endpoint URL from the MCP Server app's Connect screen. The MCP endpoint is a different URL from your Splunk Web login URL.

---

### npx: command not found

**Cause:** Node.js is not installed or not in your PATH.

**Fix:** Install Node.js v18 or later from [nodejs.org](https://nodejs.org) or via your system package manager. After installation, verify:

```bash
node --version
npx --version
```

---

### Literal `${SPLUNK_TOKEN}` Appears in Auth Header / 401

**Cause:** Claude Code version is below v1.0.48. Older versions do not expand `${VAR}` references in `.mcp.json` at launch.

**Fix:** Upgrade Claude Code:

```bash
claude --version
# If below 1.0.48, update via your installation method
```

---

### Gemini CLI: Token Redacted / Empty Auth Header

**Cause:** Gemini CLI's automatic environment sanitization strips variables matching `*TOKEN*` patterns before they reach the MCP server.

**Fix:** Ensure the `env` block is present in your `.gemini/settings.json` MCP config. Variables explicitly declared in `env` bypass Gemini's redaction. See the Gemini CLI section in Step 5.

---

### Connection Timeout

**Cause:** Outbound firewall blocking access to your Splunk Cloud MCP endpoint. The MCP protocol may use port 8089 (non-standard) in addition to 443.

**Fix:** Verify outbound access from your workstation to the full MCP endpoint URL on ports 443 and 8089. Contact your network team if firewall rules need adjustment.

---

### Tool Probe Fails but Splunk Is Reachable

**Cause:** The app version on your Splunk Cloud instance exposes `splunk_run_query` as the primary tool name rather than `search_oneshot`.

**Fix:** When `scope-hunt` starts and shows the MANUAL message, use the analyst override option:
1. Tell the agent: "Splunk MCP IS connected"
2. When prompted, enter: `splunk_run_query`
3. The agent will attempt that tool and switch to CONNECTED mode if it succeeds

This is a known version difference in app 7931 — SCOPE's `allowed-tools` includes `splunk_run_query` for this reason.
