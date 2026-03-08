#!/bin/bash
# SCOPE AWS Output Inject — BeforeTool hook (Gemini CLI only)
# Auto-injects --output json into AWS CLI calls that lack an explicit --output flag,
# ensuring consistent structured output for enumeration subagents on Gemini CLI.
#
# Ordering: runs AFTER scope-safety-guard.sh (second in BeforeTool hooks array).
# The safety guard must fire first to block destructive commands before this hook
# can modify them; injection of --output json must never circumvent safety checks.
#
# Exit semantics:
#   Exit 0 + {"decision":"allow"}                   = pass through unchanged
#   Exit 0 + {"decision":"allow","hookSpecificOutput":{...}} = allow with modified command

set -euo pipefail

# Fast-path: check raw stdin for 'aws' before parsing JSON.
# Avoids jq overhead on non-AWS commands.
INPUT=$(cat /dev/stdin)
if ! echo "$INPUT" | grep -q '"aws '; then
  echo '{"decision":"allow"}'
  exit 0
fi

TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Guard 1: Only process run_shell_command tool calls.
if [ "$TOOL_NAME" != "run_shell_command" ]; then
  echo '{"decision":"allow"}'
  exit 0
fi

# Guard 2: Only process commands that invoke the AWS CLI.
if ! echo "$COMMAND" | grep -qE '(^|\s)aws\s'; then
  echo '{"decision":"allow"}'
  exit 0
fi

# Guard 3: Idempotency — do not inject if --output is already specified.
# Covers all valid AWS CLI output formats: json, text, table, yaml, yaml-stream.
if echo "$COMMAND" | grep -qE '\-\-output\s+(json|text|table|yaml|yaml-stream)'; then
  echo '{"decision":"allow"}'
  exit 0
fi

# All guards passed: inject --output json at the end of the command.
# Use jq -n for safe JSON construction — never embed $COMMAND in a raw echo string,
# as AWS commands with quotes, equals signs, and special chars break shell quoting.
MODIFIED="${COMMAND} --output json"
jq -n --arg cmd "$MODIFIED" '{"decision":"allow","hookSpecificOutput":{"tool_input":{"command":$cmd}}}'
exit 0
