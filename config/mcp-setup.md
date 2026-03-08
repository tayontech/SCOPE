# SCOPE — Splunk MCP Server Setup

## Overview

This guide walks you through connecting SCOPE's `scope-investigate` agent to your Splunk Cloud instance via the official Splunk MCP Server app (Splunkbase app 7931). Once configured, the agent executes SPL queries live with analyst approval — no more manual copy-paste loops.

**What this enables:** Live Splunk query execution from `scope-investigate` instead of the default MANUAL mode (SPL generation with paste-back). The agent probes for MCP connectivity at startup and falls back to MANUAL mode automatically when no MCP server is available.

**Scope:** Splunk Cloud Platform only (official Splunkbase app 7931, version 1.0.2+). Splunk Enterprise and on-premises deployments are out of scope for this guide.

---

## Prerequisites

Before starting, confirm you have all three of the following:

1. **Splunk Cloud Platform 9.2–10.2** — admin role required to install apps from Splunkbase
2. **Node.js v18 or later** — required by the `mcp-remote` stdio transport that connects Claude Code to the MCP server

   ```bash
   node --version
   # Expected: v18.x.x or higher
   ```

3. **Claude Code v1.0.48 or later** — required for `${VAR}` environment variable expansion in `.mcp.json` at launch time

   ```bash
   claude --version
   # Expected: 1.0.48 or higher
   ```

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

Add the two variables to your shell profile (`.bashrc`, `.zshrc`, or equivalent):

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

Copy the MCP configuration template to activate it:

```bash
cp .mcp.example.json .mcp.json
```

No edits are needed. The `.mcp.json` file reads `SPLUNK_URL` and `SPLUNK_TOKEN` from your shell environment at Claude Code startup — no credential values are stored in the file itself. As a defense-in-depth measure, `.mcp.json` is listed in `.gitignore` to prevent accidental credential commits.

See `.mcp.example.json` for the full template:

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

---

## Step 6 — Verify the Connection

1. Open a terminal in the SCOPE project directory (where `.mcp.json` is located)
2. Start Claude Code: `claude`
3. Run the investigate command: `/scope:investigate`
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

### Connection Timeout

**Cause:** Outbound firewall blocking access to your Splunk Cloud MCP endpoint. The MCP protocol may use port 8089 (non-standard) in addition to 443.

**Fix:** Verify outbound access from your workstation to the full MCP endpoint URL on ports 443 and 8089. Contact your network team if firewall rules need adjustment.

---

### Tool Probe Fails but Splunk Is Reachable

**Cause:** The app version on your Splunk Cloud instance exposes `splunk_run_query` as the primary tool name rather than `search_oneshot`.

**Fix:** When `scope-investigate` starts and shows the MANUAL message, use the analyst override option:
1. Tell the agent: "Splunk MCP IS connected"
2. When prompted, enter: `splunk_run_query`
3. The agent will attempt that tool and switch to CONNECTED mode if it succeeds

This is a known version difference in app 7931 — SCOPE's `allowed-tools` includes `splunk_run_query` for this reason.
