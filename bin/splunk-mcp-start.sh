#!/bin/bash
# SCOPE — Splunk MCP Server launcher with debug logging
# Usage: Used as the MCP server command in .gemini/settings.json or .mcp.json
# Logs to ~/.scope/splunk-mcp.log for troubleshooting connection issues

LOGDIR="$HOME/.scope"
LOGFILE="$LOGDIR/splunk-mcp.log"
mkdir -p "$LOGDIR"

echo "=== Splunk MCP Start: $(date) ===" >> "$LOGFILE"

# Ensure PATH includes common Node.js install locations
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

# Source shell profiles to pick up SPLUNK_URL and SPLUNK_TOKEN if set there
for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zprofile"; do
  if [ -f "$rc" ]; then
    source "$rc" 2>/dev/null
  fi
done

# Log environment state (token value is never logged, only length)
echo "SPLUNK_URL=${SPLUNK_URL:-EMPTY}" >> "$LOGFILE"
echo "SPLUNK_TOKEN_LENGTH=${#SPLUNK_TOKEN}" >> "$LOGFILE"
echo "NODE=$(which node 2>/dev/null || echo 'NOT FOUND')" >> "$LOGFILE"
echo "NPX=$(which npx 2>/dev/null || echo 'NOT FOUND')" >> "$LOGFILE"

# Validate required variables
if [ -z "$SPLUNK_URL" ]; then
  echo "ERROR: SPLUNK_URL is not set" >> "$LOGFILE"
  exit 1
fi

if [ -z "$SPLUNK_TOKEN" ]; then
  echo "ERROR: SPLUNK_TOKEN is not set" >> "$LOGFILE"
  exit 1
fi

echo "Launching npx mcp-remote..." >> "$LOGFILE"
exec npx -y mcp-remote "$SPLUNK_URL" --header "Authorization: Bearer $SPLUNK_TOKEN" 2>> "$LOGFILE"
