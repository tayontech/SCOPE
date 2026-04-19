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
# Match 'aws ' anywhere — covers both direct 'aws ...' and 'VAR=value aws ...'
INPUT=$(cat /dev/stdin)
if ! echo "$INPUT" | grep -q 'aws '; then
  echo '{"decision":"allow"}'
  exit 0
fi

TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null) || TOOL_NAME=""
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null) || COMMAND=""

# Guard 1: Only process run_shell_command tool calls.
if [ "$TOOL_NAME" != "run_shell_command" ]; then
  echo '{"decision":"allow"}'
  exit 0
fi

# Guard 2: Only process commands that invoke the AWS CLI.
# Allow leading VAR=value assignments (e.g., AWS_PROFILE=prod aws ...).
if ! echo "$COMMAND" | grep -qE '(^|\s)([A-Za-z_][A-Za-z_0-9]*=[^ ]*\s+)*aws\s'; then
  echo '{"decision":"allow"}'
  exit 0
fi

# All guards passed: use jq to parse the command string, find the aws subcommand,
# check if it already has --output, and inject --output json if not.
#
# The jq approach handles:
# - Quoted strings (JMESPath with |, ;, & inside quotes)
# - Backslash-escaped quotes inside double-quoted strings
# - && as a two-character operator (not split on first &)
# - Guard 3 (idempotency) scoped to the aws subcommand only, not the full pipeline

MODIFIED=$(jq -rn --arg cmd "$COMMAND" '
  # Find the boundaries of the first aws subcommand, respecting quotes and escapes.
  # Returns {start, end} where start is the position of "aws" and end is the position
  # of the first unquoted shell operator after it (or string length if none).
  def find_aws_bounds:
    $cmd | split("") | length as $len |
    # Phase 1: find "aws " token
    { i: 0, aws_start: -1 } |
    until(.i >= $len or .aws_start >= 0;
      # Check for "aws " preceded by start-of-string, whitespace, or = (VAR=val aws)
      if (.i == 0 or ($cmd[.i-1:.i] | test("[ =]"))) and
         $cmd[.i:.i+4] == "aws " then
        .aws_start = .i
      else . end
      | .i += 1
    ) |
    if .aws_start < 0 then { start: -1, end: $len }
    else
      # Phase 2: find end of aws subcommand (first unquoted |, ;, &&, ||)
      .i = (.aws_start + 4) |
      { i: .i, aws_start: .aws_start, in_sq: false, in_dq: false, escaped: false, end: $len } |
      until(.i >= $len;
        ($cmd[.i:.i+1]) as $ch |
        if .escaped then .escaped = false
        elif $ch == "\\" and .in_dq then .escaped = true
        elif $ch == "\"" and (.in_sq | not) then .in_dq = (.in_dq | not)
        elif $ch == "\u0027" and (.in_dq | not) then .in_sq = (.in_sq | not)
        elif (.in_sq or .in_dq) then .
        elif $ch == "|" or $ch == ";" then .end = .i | .i = $len
        elif $ch == "&" and $cmd[.i:.i+2] == "&&" then .end = .i | .i = $len
        else .
        end | .i += 1
      ) | { start: .aws_start, end: .end }
    end;

  find_aws_bounds as $bounds |
  if $bounds.start < 0 then $cmd
  else
    $cmd[$bounds.start:$bounds.end] as $aws_part |
    # Guard 3: idempotency — only check the aws subcommand for existing --output
    if ($aws_part | test("--output\\s+(json|text|table|yaml|yaml-stream)")) then $cmd
    else
      $cmd[0:$bounds.end] + " --output json" +
      (if $bounds.end < ($cmd | length) then " " + $cmd[$bounds.end:] else "" end)
    end
  end
')

# If jq produced no change, pass through unchanged
if [ "$MODIFIED" = "$COMMAND" ]; then
  echo '{"decision":"allow"}'
  exit 0
fi

jq -n --arg cmd "$MODIFIED" '{"decision":"allow","hookSpecificOutput":{"tool_input":{"command":$cmd}}}'
exit 0
