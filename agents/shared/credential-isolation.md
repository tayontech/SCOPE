## Credential Isolation Rule

All cross-account credential usage MUST be scoped to subshells. No temporary credential variable (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) may persist in the parent shell. This prevents `/proc` filesystem exposure if the process crashes mid-operation.

**Required pattern — single hop:**
```bash
(
  CREDS=$(aws sts assume-role --role-arn $ROLE_ARN --role-session-name hop --query 'Credentials' --output json)
  export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
  export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
  export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .SessionToken)
  # ... operations in target account ...
)
# Credentials automatically discarded — subshell exited
```

**Multi-hop:** Nest subshells — each hop opens a new `( )` block inside the previous one.

**Anti-pattern (NEVER do this):**
```bash
# WRONG — credentials leak into parent shell
export AWS_ACCESS_KEY_ID=...
aws s3 ls
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```
