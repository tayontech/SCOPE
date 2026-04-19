#!/bin/bash
# SCOPE Safety Guard — PreToolUse / BeforeTool hook
# Blocks destructive AWS operations. SCOPE agents are read-only by default.
# Destructive operations require explicit operator approval at runtime,
# not silent execution through agent commands.
#
# Exit 0 = allow, Exit 2 = block (stderr = reason)
#
# Design: Only blocks commands where `aws <service> <destructive-action>` appears
# as an executable invocation. Does NOT block quoted text, heredocs, or echo'd
# strings that merely contain AWS CLI examples (e.g., playbook generation).

set -euo pipefail

# Fast-path: read stdin once, check for 'aws' before parsing JSON.
# Avoids jq overhead on non-AWS commands (mkdir, echo, cp, etc.)
# Case-insensitive match — covers 'aws', 'AWS', and 'Aws'
INPUT=$(cat /dev/stdin)
if ! echo "$INPUT" | grep -qi 'aws '; then
  exit 0
fi

COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null) || COMMAND=""

# Empty command after parse — allow (no AWS call possible)
[ -z "$COMMAND" ] && exit 0

# Block dangerous command wrappers that can hide AWS calls from text inspection.
# eval can construct any command from string arguments; xargs can pipe args into aws.
if echo "$COMMAND" | grep -qEi '(^|\s|;|&&|\|\|)(eval|xargs)\s'; then
  # Check if aws appears anywhere in the command — if so, block
  if echo "$COMMAND" | grep -qi 'aws'; then
    echo "SCOPE Safety Guard: Blocked — 'eval' or 'xargs' with AWS CLI detected. These wrappers can hide destructive operations from static analysis. Run the AWS command directly." >&2
    exit 2
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
STRIPPED=$(echo "$COMMAND" | awk '
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
' 2>/dev/null) || STRIPPED="$COMMAND"

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
  # IaC tools
  'terraform\s+(apply|destroy|import)'
  'cdk\s+deploy'
  'pulumi\s+(up|destroy)'
)

# Check the quote-stripped executable text for destructive patterns.
for pattern in "${DESTRUCTIVE_PATTERNS[@]}"; do
  if echo "$EXECUTABLE" | grep -qEi "$pattern"; then
    MATCHED_OP=$(echo "$EXECUTABLE" | grep -oEi "$pattern" | head -1)
    echo "SCOPE Safety Guard: Blocked destructive AWS operation — '$MATCHED_OP'. SCOPE agents are read-only. Use /scope:exploit to generate playbooks without execution." >&2
    exit 2
  fi
done

# No destructive patterns found in executable text — allow
exit 0
