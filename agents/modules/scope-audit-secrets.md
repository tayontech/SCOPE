<secrets_module>
## Secrets Manager Enumeration Module

Enumerate Secrets Manager secrets, analyze resource policies for cross-account access, detect rotation gaps, and check secret value accessibility. Secrets Manager is a high-value target — it stores database passwords, API keys, and other credentials that unlock further access.

### Step 1: Secret Discovery

```bash
aws secretsmanager list-secrets --output json 2>&1
```

This returns metadata for all secrets in the current region:
- Secret name, ARN, description
- `RotationEnabled` — whether automatic rotation is configured
- `LastRotatedDate` — when the secret was last rotated
- `LastAccessedDate` — when the secret was last read
- `Tags` — resource tags (may reveal purpose: "database", "api-key", etc.)

**ARN-targeted mode:** If the input is a specific secret ARN, extract the secret name and skip directly to Step 2 for that secret only.

If `list-secrets` returns AccessDenied: log "PARTIAL: Cannot list secrets — caller lacks secretsmanager:ListSecrets permission. Provide a specific secret ARN to analyze." and continue to next module.

### Step 2: Per-Secret Analysis

For each secret, gather detailed metadata and access configuration:

**Secret description:**
```bash
aws secretsmanager describe-secret --secret-id SECRET_NAME --output json 2>&1
```
Extract and analyze:
- `RotationEnabled` — if `false`, flag as a finding: "Rotation not enabled for secret [SECRET_NAME]"
- `LastRotatedDate` — if the secret has not been rotated in 90+ days, flag as HIGH risk: "Secret [SECRET_NAME] not rotated in [N] days"
- `LastAccessedDate` — if the secret has not been accessed recently, it may be unused (potential cleanup candidate)
- `VersionIdsToStages` — map of version IDs to staging labels (AWSCURRENT, AWSPREVIOUS). Multiple versions may exist.

If AccessDenied: log "PARTIAL: Could not describe secret [SECRET_NAME] — AccessDenied" and continue.

**Resource policy (CRITICAL for attack path mapping):**
```bash
aws secretsmanager get-resource-policy --secret-id SECRET_NAME --output json 2>&1
```
The resource policy controls who can access the secret independently of IAM policies. This is the most important Secrets Manager enumeration step for cross-account access detection.

If no resource policy exists, the response will have an empty or null `ResourcePolicy` field — this means only IAM policies control access.
If AccessDenied: log "PARTIAL: Could not read resource policy for [SECRET_NAME] — AccessDenied" and continue.

### Step 3: Resource Policy Analysis

For each secret that has a resource policy, parse the policy JSON and check for:

**Cross-account principals:**
- Principal contains an AWS account ID different from the current account
- Note the external account ID and the actions granted
- Flag as HIGH: "Cross-account access: account [EXTERNAL-ID] can access secret [SECRET_NAME]"

**Overly broad principals:**
- `"Principal": "*"` — anyone can access the secret. CRITICAL finding, even with IP conditions.
- `"Principal": {"AWS": "*"}` with only IP-based conditions — risky because IP conditions can be spoofed or bypassed in some scenarios

**Missing conditions on sensitive actions:**
- `secretsmanager:GetSecretValue` without conditions — this is the "money action." If granted broadly, anyone matching the principal can read the secret value.
- `secretsmanager:PutSecretValue` without conditions — allows secret modification (potential backdoor)

**Condition analysis:**
- Check for `aws:SourceVpc` or `aws:SourceVpce` conditions — restricts access to specific VPCs (good practice)
- Check for `aws:PrincipalOrgID` conditions — restricts to specific AWS Organization (limits cross-account exposure)
- Note any conditions and their restrictiveness — conditions reduce risk but do not eliminate it

### Step 4: Secret Value Access Check (RECONNAISSANCE ONLY)

Test whether the current credentials can read the secret value:
```bash
aws secretsmanager get-secret-value --secret-id SECRET_NAME 2>&1
```

**If AccessDenied:** Log that the secret value is protected and note which error message was returned. This is expected and not a finding — it means access controls are working.

**If success:** DO NOT output the actual secret value in the audit report. The secret value is sensitive data. Instead, output:
```
FINDING: SECRET READABLE — current credentials can read secret [SECRET_NAME].
This means the caller's effective permissions include secretsmanager:GetSecretValue on this secret.
The secret value has been verified as accessible but is not displayed for security.
```
The finding is that ACCESS EXISTS, not the secret content itself.

**Version history check:**
```bash
aws secretsmanager list-secret-version-ids --secret-id SECRET_NAME --output json 2>&1
```
Check for multiple versions — previous versions (AWSPREVIOUS) may contain old credentials that are still valid. If the secret has many versions, flag: "Secret [SECRET_NAME] has [N] versions — previous versions may contain old but still valid credentials."

### Step 4b: Recursive Policy-Following

After analyzing resource policies, **recursively follow specific ARN grants** to map the full access chain.

**When to recurse:** When a secret's resource policy grants access to a specific principal ARN (not `*` or the account root).

**When NOT to recurse:** When the grant is wildcard (`Principal: "*"`) — the blast radius is already "everyone." Log it as CRITICAL and move on.

**Recursion logic:**
1. For each specific principal ARN found in resource policies:
   - If the ARN is a role → check what else that role can access (other secrets, S3 buckets, KMS keys, Lambda functions)
   - If the ARN is in another account → note the cross-account chain (cannot query external account)
   - If the ARN is a user → check that user's full permission set for lateral movement paths
2. For each permission discovered on the followed principal:
   - If it grants access to other secrets → follow those secrets' resource policies too
   - If it grants KMS Decrypt on the secret's encryption key → note the encryption chain
   - If it grants broader access (Lambda invoke, EC2 SSM, etc.) → follow those resources
3. Continue until:
   - A resource has already been visited (cycle detection)
   - AccessDenied stops further traversal
   - No new specific ARN edges are discovered

**Chain output:**
```
[CHAIN] secret/db-credentials → resource policy grants to role:AppServerRole
[CHAIN] role:AppServerRole → s3:GetObject → bucket/config-data
[CHAIN] role:AppServerRole → lambda:InvokeFunction → function/data-exporter
[CHAIN] function/data-exporter → execution role → role:ExporterRole → s3:* on bucket/prod-data
```

### Step 5: Build Graph Data

Construct nodes and edges for the SCOPE dashboard:

**Nodes:**
- Each secret: `{id: "data:secrets:SECRET_NAME", label: "SECRET_NAME", type: "data"}`

**Edges:**
- Cross-account resource policy: `{source: "ext:arn:aws:iam::<external-id>:root", target: "data:secrets:SECRET_NAME", trust_type: "cross-account"}`
- IAM-based access: `{source: "user:<name>", target: "data:secrets:SECRET_NAME", edge_type: "data_access", access_level: "read|write|admin"}` or `{source: "role:<name>", target: "data:secrets:SECRET_NAME", edge_type: "data_access", access_level: "read|write|admin"}`
- KMS dependency: `{source: "data:kms:KEY_ID", target: "data:secrets:SECRET_NAME", edge_type: "data_access", access_level: "read"}` — link secrets to their encryption keys

**access_level classification for Secrets Manager:**
- `"read"` — principal has only secretsmanager:GetSecretValue, secretsmanager:DescribeSecret, secretsmanager:ListSecrets
- `"write"` — principal has secretsmanager:PutSecretValue, secretsmanager:UpdateSecret, secretsmanager:CreateSecret
- `"admin"` — principal has secretsmanager:* or secretsmanager:DeleteSecret + secretsmanager:PutResourcePolicy (full secret control)

**Error handling:** On AccessDenied or any error for a specific secret:
1. Log: "PARTIAL: Could not read [description/policy/value] for secret [SECRET_NAME] — [error message]"
2. Continue to the next secret
3. NEVER stop the Secrets Manager module because a single secret fails
4. At the end of the module, report how many secrets were fully analyzed vs. partially analyzed vs. skipped
</secrets_module>
