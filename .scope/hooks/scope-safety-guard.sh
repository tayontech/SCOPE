#!/bin/bash
# SCOPE Safety Guard — PreToolUse / BeforeTool hook
# Blocks destructive AWS operations. SCOPE agents are read-only by default.
# Destructive operations require explicit operator approval at runtime,
# not silent execution through agent commands.
#
# Exit 0 = allow, Exit 2 = block (stderr = reason)

set -euo pipefail

# Fast-path: read stdin once, check for 'aws' before parsing JSON.
# Avoids jq overhead on non-AWS commands (mkdir, echo, cp, etc.)
INPUT=$(cat /dev/stdin)
if ! echo "$INPUT" | grep -q '"aws '; then
  exit 0
fi

COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Only inspect commands that contain AWS CLI calls (including subshells and pipes)
if ! echo "$COMMAND" | grep -qE '(^|\$\(|`|;|&&|\|\|?|\n)\s*aws\s'; then
  exit 0
fi

# Read-only operations — always allowed
READONLY_PATTERN='^\s*aws\s+\S+\s+(get-|list-|describe-|head-|check-|lookup-|batch-get|search-|select-|scan-|query-|estimate-|preview-|simulate-|generate-|decode-|download-|export-|verify-|validate-|test-|wait\s)'

if echo "$COMMAND" | grep -qEi "$READONLY_PATTERN"; then
  exit 0
fi

# sts get-caller-identity is always safe (credential check)
if echo "$COMMAND" | grep -qE 'sts\s+get-caller-identity'; then
  exit 0
fi

# sts assume-role is read-only (returns temporary credentials, no state change)
if echo "$COMMAND" | grep -qE 'sts\s+assume-role'; then
  exit 0
fi

# s3api head-object, s3 ls — read-only S3 operations
if echo "$COMMAND" | grep -qE 's3(api)?\s+(ls|head-object|get-object-tagging|get-bucket-location|get-bucket-policy|get-bucket-acl)'; then
  exit 0
fi

# Explicitly blocked destructive patterns
DESTRUCTIVE_PATTERNS=(
  'iam\s+(put-|create-|delete-|attach-|detach-|update-|remove-|add-|deactivate-|enable-|set-|upload-|change-|reset-|tag-|untag-)'
  'iam\s+create-access-key'
  'iam\s+create-login-profile'
  'iam\s+put-role-policy'
  'iam\s+attach-role-policy'
  'iam\s+create-policy-version'
  's3(api)?\s+(rm|rb|mb|cp|mv|sync|put-|delete-|create-|restore-)'
  's3api\s+put-bucket-policy'
  's3api\s+delete-bucket-policy'
  'ec2\s+(run-|terminate-|stop-|start-|create-|delete-|modify-|revoke-|authorize-|associate-|disassociate-|replace-|release-|attach-|detach-|import-|deregister-|cancel-)'
  'lambda\s+(create-|delete-|update-|publish-|put-|add-|remove-|tag-|untag-)'
  'kms\s+(create-|delete-|disable-|enable-|schedule-|cancel-|put-|update-|revoke-|retire-|generate-data-key|encrypt|decrypt|re-encrypt|create-grant)'
  'secretsmanager\s+(create-|delete-|put-|update-|restore-|rotate-|cancel-|remove-|tag-|untag-)'
  'ssm\s+(send-command|start-session|create-|delete-|put-|update-|register-|deregister-|cancel-|terminate-|resume-|label-|remove-)'
  'organizations\s+(create-|delete-|update-|move-|attach-|detach-|enable-|disable-|leave-|remove-|invite-|accept-|decline-|tag-|untag-)'
  'sts\s+get-federation-token'
  'cloudtrail\s+(create-|delete-|update-|start-|stop-|put-|add-|remove-)'
  'cloudformation\s+(create-|delete-|update-|execute-|cancel-|continue-|signal-|set-)'
  'terraform\s+(apply|destroy|import)'
  'cdk\s+deploy'
  'pulumi\s+(up|destroy)'
)

for pattern in "${DESTRUCTIVE_PATTERNS[@]}"; do
  if echo "$COMMAND" | grep -qEi "$pattern"; then
    MATCHED_OP=$(echo "$COMMAND" | grep -oEi "$pattern" | head -1)
    echo "SCOPE Safety Guard: Blocked destructive AWS operation — '$MATCHED_OP'. SCOPE agents are read-only. Use /scope:exploit to generate playbooks without execution." >&2
    exit 2
  fi
done

# Catch-all: warn on unrecognized aws commands (non-blocking)
# If we got here, the command doesn't match known read-only OR destructive patterns.
# Let it through but log a note.
exit 0
