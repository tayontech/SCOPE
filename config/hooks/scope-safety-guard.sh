#!/bin/bash
# SCOPE Safety Guard — PreToolUse / BeforeTool hook
# Blocks destructive AWS operations and enforces path sanitization.
# SCOPE agents are read-only by default. Destructive operations require
# explicit operator approval at runtime, not silent execution through agent commands.
#
# Exit 0 = allow, Exit 2 = block (stderr = reason)
#
# Design:
# 1. Parse command from JSON input
# 2. Path sanitization — blocks commands referencing paths outside allowed prefixes
# 3. Block command wrappers hiding AWS calls
# 4. Strip heredocs and quotes to get executable text
# 5. Block destructive IaC operations
# 6. AWS fast-path — exit early if no executable AWS command remains
# 7. Check executable text against destructive AWS patterns

set -euo pipefail

# Read stdin once
INPUT=$(cat /dev/stdin)

# Parse command from JSON
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // .toolCall.args.CommandLine // empty' 2>/dev/null) || COMMAND=""
IS_ANTIGRAVITY=$(echo "$INPUT" | jq -r 'has("toolCall")' 2>/dev/null || echo "false")

block() {
  local reason="$1"
  if [ "$IS_ANTIGRAVITY" = "true" ]; then
    jq -n --arg reason "$reason" '{decision: "deny", reason: $reason}'
    exit 0
  fi
  echo "$reason" >&2
  exit 2
}

# Empty command — allow
[ -z "$COMMAND" ] && exit 0

# =============================================================================
# PATH SANITIZATION — applies to ALL commands (not just AWS)
# =============================================================================

# Path traversal detection — block any command containing ../
if grep -qE '\.\./' <<<"$COMMAND" ; then
  block "SCOPE Safety Guard: Blocked — path traversal (..) detected. Use direct paths within allowed prefixes."
fi

# Extract all relative path references (./something/)
PATHS=$(grep -oE '\./[a-zA-Z0-9_.-]+/' <<<"$COMMAND" | sort -u) || true

if [ -n "$PATHS" ]; then
  # Allowed output directories (operator-provided run paths land here)
  ALLOWED_PREFIXES=('./runs/' './exploit/' './investigations/' './engagements/')

  # Internal project directories (never block — not operator-provided)
  INTERNAL_PREFIXES=('./config/' './bin/' './agents/' './dashboard/' './tests/' './node_modules/' './.planning/' './.claude/' './.git/' './.codex/' './.gemini/')

  while IFS= read -r p; do
    [ -z "$p" ] && continue

    # Skip internal project paths
    is_internal=false
    for ip in "${INTERNAL_PREFIXES[@]}"; do
      if [[ "$p" == "$ip"* ]]; then
        is_internal=true
        break
      fi
    done
    $is_internal && continue

    # Check against allowlist
    is_allowed=false
    for ap in "${ALLOWED_PREFIXES[@]}"; do
      if [[ "$p" == "$ap"* ]]; then
        is_allowed=true
        break
      fi
    done

    if ! $is_allowed; then
      block "SCOPE Safety Guard: Blocked — path outside allowed prefixes: '$p'. Allowed: ./runs/, ./exploit/, ./investigations/, ./engagements/"
    fi
  done <<< "$PATHS"
fi

# Block dangerous command wrappers that can hide AWS calls from text inspection.
# eval can construct any command from string arguments; xargs can pipe args into aws.
if grep -qiE 'aws[[:space:]]' <<<"$COMMAND"; then
  if grep -qEi '(^|[[:space:]]|;|&&|\|\|)(eval|xargs)[[:space:]]' <<<"$COMMAND"; then
    block "SCOPE Safety Guard: Blocked — 'eval' or 'xargs' with AWS CLI detected. These wrappers can hide destructive operations from static analysis. Run the AWS command directly."
  fi

  # shell -c and language eval wrappers execute AWS from quoted strings. The
  # quote stripper below would hide those strings, so block wrapper execution when
  # AWS appears anywhere in the submitted command.
  if grep -qEi '(^|[[:space:]]|;|&&|\|\|)(bash|sh|zsh|fish)[[:space:]]+-c[[:space:]]' <<<"$COMMAND"; then
    block "SCOPE Safety Guard: Blocked — shell -c with AWS CLI detected. Run the AWS command directly."
  fi

  if grep -qEi '(^|[[:space:]]|;|&&|\|\|)(python|python3|node|perl|ruby)[[:space:]]+(-c|-e)[[:space:]]' <<<"$COMMAND"; then
    block "SCOPE Safety Guard: Blocked — code-eval wrapper with AWS CLI detected. Run the AWS command directly."
  fi
fi

# Extract executable text from the command string by stripping:
# 1. Heredoc bodies (<<EOF ... EOF, <<'EOF' ... EOF, <<"EOF" ... EOF)
# 2. Quoted strings (single and double, with backslash escape handling)
# This ensures `echo "aws iam create-access-key"` and heredocs containing
# AWS CLI examples are NOT flagged, but actual invocations ARE flagged.

# Step 1: Strip heredoc bodies. Heredocs span multiple lines:
#   cat <<EOF\n..body..\nEOF  (also <<'EOF', <<"EOF", <<-EOF)
# Use awk to detect the delimiter and skip all lines until the closing delimiter.
STRIPPED=$(awk '
  /<<-?[ ]*[\x27"\\]?[A-Za-z_]/ {
    # Extract the delimiter word from the <<DELIM pattern
    line = $0
    # Remove everything before <<
    sub(/.*<<-?[ ]*/, "", line)
    # Strip quoting around delimiter ('\''EOF'\'', "EOF", \EOF -> EOF)
    gsub(/[\x27"\\]/, "", line)
    # Take first word as delimiter
    split(line, parts, /[^A-Za-z_0-9]/)
    delim = parts[1]
    if (delim != "") {
      # Print only the part before <<
      sub(/<<.*/, "", $0)
      print $0
      # Skip lines until we find the closing delimiter
      while ((getline line) > 0) {
        # Trim leading whitespace for <<- variant
        trimmed = line
        gsub(/^[[:space:]]+/, "", trimmed)
        if (trimmed == delim) break
      }
      next
    }
  }
  { print }
' <<<"$COMMAND" 2>/dev/null) || STRIPPED="$COMMAND"

# Step 2: Strip quoted strings using jq character walker.
EXECUTABLE=$(jq -rn --arg cmd "$STRIPPED" '
  $cmd | split("") | length as $len |
  { i: 0, in_sq: false, in_dq: false, escaped: false, out: "" } |
  until(.i >= $len;
    ($cmd[.i:.i+1]) as $ch |
    if .escaped then .escaped = false | .out += " "
    elif $ch == "\\" and .in_dq then .escaped = true | .out += " "
    elif $ch == "\u0027" and (.in_dq | not) then .in_sq = (.in_sq | not) | .out += " "
    elif $ch == "\"" and (.in_sq | not) then .in_dq = (.in_dq | not) | .out += " "
    elif .in_sq or .in_dq then .out += " "
    else .out += $ch
    end | .i += 1
  ) | .out
' 2>/dev/null) || EXECUTABLE="$STRIPPED"

# IaC tools mutate cloud state without the AWS CLI token, so check them before
# the AWS fast-path.
IAC_PATTERNS=(
  '(^|[[:space:]]|;|&&|\|\|)terraform[[:space:]]+(apply|destroy|import)'
  '(^|[[:space:]]|;|&&|\|\|)cdk[[:space:]]+deploy'
  '(^|[[:space:]]|;|&&|\|\|)pulumi[[:space:]]+(up|destroy)'
)

for pattern in "${IAC_PATTERNS[@]}"; do
  if grep -qEi "$pattern" <<<"$EXECUTABLE"; then
    MATCHED_OP=$(grep -oEi "$pattern" <<<"$EXECUTABLE" | sed -n '1p' | sed 's/^[[:space:];&|]*//')
    block "SCOPE Safety Guard: Blocked destructive IaC operation — '$MATCHED_OP'. SCOPE agents are read-only. Generate reviewable plans instead of applying changes."
  fi
done

# AWS fast-path — if no executable AWS command remains, skip AWS checks.
if ! grep -qiE '(^|[[:space:]]|;|&&|\|\|)aws[[:space:]]' <<<"$EXECUTABLE"; then
  exit 0
fi

# AWS CLI global options may appear before the service, such as
# `aws --profile prod --region us-east-1 iam create-user`. Strip known global
# options for destructive-pattern matching while preserving the original command
# in the block message context.
NORMALIZED_EXECUTABLE=$(sed -E '
  s/(^|[[:space:];&|])aws([[:space:]]+--(profile|region|endpoint-url|output|query|ca-bundle|cli-input-json|cli-binary-format|color)[= ][^[:space:]]+|[[:space:]]+--(no-cli-pager|no-paginate|no-sign-request|no-verify-ssl|debug|cli-auto-prompt|no-cli-auto-prompt))*[[:space:]]+/\1aws /g
' <<<"$EXECUTABLE")

# Destructive patterns — each requires `aws <service>` prefix to match.
# This ensures we only catch actual AWS CLI invocations, not documentation text.
DESTRUCTIVE_PATTERNS=(
  'aws\s+iam\s+(put-|create-|delete-|attach-|detach-|update-|remove-|add-|deactivate-|enable-|set-|upload-|change-|reset-|tag-|untag-)'
  'aws\s+s3(api)?\s+(rm|rb|mb|cp|mv|sync|put-|delete-|create-|restore-)'
  'aws\s+ec2\s+(run-|terminate-|stop-|start-|create-|delete-|modify-|revoke-|authorize-|associate-|disassociate-|replace-|release-|attach-|detach-|import-|deregister-|cancel-)'
  'aws\s+lambda\s+(create-|delete-|update-|publish-|put-|add-|remove-|tag-|untag-)'
  'aws\s+kms\s+(create-|delete-|disable-|enable-|schedule-|cancel-|put-|update-|revoke-|retire-|generate-data-key|encrypt|decrypt|re-encrypt|create-grant)'
  'aws\s+secretsmanager\s+(create-|delete-|put-|update-|restore-|rotate-|cancel-|remove-|tag-|untag-)'
  'aws\s+ssm\s+(send-command|start-session|create-|delete-|put-|update-|register-|deregister-|cancel-|terminate-|resume-|label-|remove-)'
  'aws\s+organizations\s+(create-|delete-|update-|move-|attach-|detach-|enable-|disable-|leave-|remove-|invite-|accept-|decline-|tag-|untag-)'
  'aws\s+sts\s+get-federation-token'
  'aws\s+cloudtrail\s+(create-|delete-|update-|start-|stop-|put-|add-|remove-)'
  'aws\s+cloudformation\s+(create-|delete-|update-|execute-|cancel-|continue-|signal-|set-)'
  'aws\s+rds\s+(create-|delete-|modify-|stop-|start-|reboot-|restore-|promote-)'
  'aws\s+dynamodb\s+(create-|delete-|update-|put-|batch-write-)'
  'aws\s+ecs\s+(create-|delete-|update-|run-|stop-|deregister-|put-)'
  'aws\s+eks\s+(create-|delete-|update-|associate-|disassociate-)'
  'aws\s+sns\s+(create-|delete-|publish|subscribe|unsubscribe|set-|put-|tag-|untag-)'
  'aws\s+sqs\s+(create-|delete-|send-|purge-|set-|tag-|untag-)'
  'aws\s+logs\s+(create-|delete-|put-|associate-|disassociate-|tag-|untag-)'
  'aws\s+guardduty\s+(create-|delete-|update-|archive-|unarchive-|invite-|decline-|disassociate-|enable-|disable-|start-|stop-)'
  'aws\s+route53\s+(create-|delete-|update-|change-|associate-|disassociate-)'
  'aws\s+ses\s+(send-|create-|delete-|put-|update-|verify-)'
  'aws\s+wafv2\s+(create-|delete-|update-|put-|associate-|disassociate-)'
  'aws\s+events\s+(put-|delete-|create-|update-|remove-|enable-|disable-)'
  'aws\s+cognito-idp\s+(create-|delete-|update-|admin-create-|admin-delete-|admin-set-|admin-update-)'
  'aws\s+glue\s+(create-|delete-|update-|batch-delete-|start-|stop-)'
  'aws\s+acm\s+(delete-|import-|request-|renew-)'
)

# Check the quote-stripped executable text for destructive patterns.
for pattern in "${DESTRUCTIVE_PATTERNS[@]}"; do
  if grep -qEi "$pattern" <<<"$NORMALIZED_EXECUTABLE"; then
    MATCHED_OP=$(grep -oEi "$pattern" <<<"$NORMALIZED_EXECUTABLE" | sed -n '1p')
    block "SCOPE Safety Guard: Blocked destructive AWS operation — '$MATCHED_OP'. SCOPE agents are read-only. Use /scope:exploit to generate playbooks without execution."
  fi
done

# No destructive patterns found in executable text — allow
exit 0
