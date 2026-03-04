<s3_module>
## S3 Enumeration Module

Enumerate S3 buckets, analyze bucket policies and ACLs, detect public access, and map data exposure paths. S3 is the most common data storage target — misconfigurations here frequently lead to data breaches.

### Step 1: Bucket Discovery

Run the primary bucket enumeration command:
```bash
aws s3api list-buckets --output json 2>&1
```

This returns all bucket names and creation dates in the current account.

**ARN-targeted mode:** If the input is a specific S3 bucket ARN (e.g., `arn:aws:s3:::my-bucket`), extract the bucket name from the ARN and skip directly to Step 2 for that bucket only. Do not enumerate all buckets.

**--all mode:** Process all buckets returned by `list-buckets`, but follow the "accessible only" rule: attempt `get-bucket-policy` on each bucket first. If a bucket immediately returns AccessDenied on `get-bucket-policy`, skip that bucket and move to the next. Do not waste time on buckets the caller cannot inspect.

If `list-buckets` returns AccessDenied: log "PARTIAL: Cannot list buckets — caller lacks s3:ListAllMyBuckets permission. Provide a specific bucket ARN to analyze." and continue to next module.

### Step 2: Per-Bucket Analysis

For each accessible bucket, run these commands in sequence. Wrap EVERY command with error checking — on AccessDenied or any error, log the partial result and continue to the next command or next bucket. NEVER stop the module because one bucket or one command fails.

**Bucket Policy:**
```bash
aws s3api get-bucket-policy --bucket BUCKET_NAME --output json 2>&1
```
If AccessDenied: log "PARTIAL: Could not read bucket policy for [BUCKET_NAME] — AccessDenied" and continue.
If NoSuchBucketPolicy: log "INFO: No bucket policy configured for [BUCKET_NAME]" — this means only IAM policies control access.

**Bucket ACL:**
```bash
aws s3api get-bucket-acl --bucket BUCKET_NAME --output json 2>&1
```
Check the `Grants` array for public grants:
- `Grantee.URI` containing `http://acs.amazonaws.com/groups/global/AllUsers` — PUBLIC access (anyone on the internet)
- `Grantee.URI` containing `http://acs.amazonaws.com/groups/global/AuthenticatedUsers` — any AWS account can access (effectively public)
Flag either of these as a CRITICAL finding.

**Public Access Status:**
```bash
aws s3api get-bucket-policy-status --bucket BUCKET_NAME --output json 2>&1
```
Check `PolicyStatus.IsPublic` — if `true`, the bucket policy grants public access. This is a CRITICAL finding even if the S3 Block Public Access settings might override it (check block public access separately).

**Unauthenticated Access Test:**
```bash
aws s3api head-bucket --bucket BUCKET_NAME --no-sign-request 2>&1
```
This tests whether the bucket is accessible WITHOUT any AWS credentials:
- HTTP 200 or 301: bucket is publicly accessible — CRITICAL finding
- HTTP 403: access denied without credentials (expected, not a finding)
- HTTP 404: bucket does not exist

Also test listing without credentials:
```bash
aws s3 ls s3://BUCKET_NAME --no-sign-request 2>&1
```
If this returns objects, the bucket is publicly listable — CRITICAL finding with immediate data exposure risk.

**Block Public Access Settings:**
```bash
aws s3api get-public-access-block --bucket BUCKET_NAME --output json 2>&1
```
Check all four settings: `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`. All four should be `true` for secure configuration. Any `false` value when combined with public policies/ACLs indicates active public exposure.

### Step 3: Policy Analysis

For each bucket that has a bucket policy, parse the policy JSON and check for:

**Public access patterns:**
- `"Principal": "*"` — anyone can access
- `"Principal": {"AWS": "*"}` — any AWS principal can access
- Either of these without restrictive `Condition` blocks is a CRITICAL finding

**Cross-account access:**
- Principal contains an AWS account ID different from the current account
- Note the external account ID and the actions granted
- Flag as HIGH if write actions (PutObject, DeleteObject) are granted cross-account

**Overly broad actions:**
- `"Action": "s3:*"` — full S3 access on the bucket
- `"Action": ["s3:GetObject", "s3:ListBucket"]` — read access (data exposure if public)
- `"Action": ["s3:PutObject", "s3:DeleteObject"]` — write access (data tampering risk)

**Missing conditions on sensitive actions:**
- PutObject without IP or VPC endpoint conditions — anyone with credentials can upload
- DeleteObject without MFA condition — no deletion protection
- GetObject with `Principal: "*"` — full public read access

**Combined exposure check:**
- If a bucket has BOTH `s3:GetObject` and `s3:ListBucket` with `Principal: "*"` — this means full data exposure: an attacker can list all objects AND download them. Flag as CRITICAL with the message: "Full public data exposure — bucket is both listable and readable by anyone."

### Step 3b: Recursive Policy-Following

After analyzing bucket policies, **recursively follow specific ARN grants** to map the full access chain.

**When to recurse:** When a bucket policy grants access to a specific principal ARN (not `*` or admin-level).

**When NOT to recurse:** When the grant is admin-level (`s3:*` with `Principal: "*"`) or wildcard — the blast radius is already "everything." Log the finding and move on.

**Recursion logic:**
1. For each specific principal ARN found in bucket policies:
   - If the ARN is in the current account → query that principal's IAM policies to see what ELSE they can access
   - If the ARN is a role → check trust policy to see who can assume it, and what permissions it has beyond S3
   - If the ARN is cross-account → note the cross-account chain but do not query (no credentials for external accounts)
2. For each IAM permission discovered on the followed principal:
   - If it grants access to another specific resource ARN (Lambda function, KMS key, Secrets Manager secret, etc.) → follow that resource too
   - If it's admin-level or wildcard (`*`) → stop recursion for this branch, log the blast radius
3. Continue until:
   - A resource has already been visited in this session (cycle detection)
   - AccessDenied stops further traversal
   - No new specific ARN edges are discovered (leaf node)

**Chain output:**
```
[CHAIN] bucket/prod-data → policy grants s3:GetObject to role:DataPipelineRole
[CHAIN] role:DataPipelineRole → secretsmanager:GetSecretValue → secret/db-credentials
[CHAIN] role:DataPipelineRole → kms:Decrypt → key/data-key-001
[CHAIN] key/data-key-001 → encrypts → secret/db-credentials, bucket/encrypted-data
```

Add discovered edges to the graph data. Each hop in the chain becomes an edge.

### Step 4: Object Enumeration

Only enumerate objects if relevant to the attack path (e.g., bucket is publicly accessible, or investigating a specific bucket). Do NOT enumerate all objects in large buckets.

**Sample objects:**
```bash
aws s3api list-objects-v2 --bucket BUCKET_NAME --max-keys 20 --output json 2>&1
```

Check the returned object keys for sensitive file patterns:
- `.env`, `.env.production`, `.env.local` — environment variable files
- `*.pem`, `*.key`, `*.p12`, `*.pfx` — private keys and certificates
- `credentials`, `credentials.json`, `credentials.csv` — AWS or other credentials
- `backup*`, `dump*`, `*.sql`, `*.bak` — database backups
- `*.log`, `access.log`, `error.log` — log files that may contain secrets
- `terraform.tfstate`, `*.tfvars` — infrastructure state files with secrets

If sensitive patterns are found: flag as HIGH finding with the message: "Sensitive files detected in bucket [BUCKET_NAME]: [list of matching keys]"

**Object versioning check:**
```bash
aws s3api get-bucket-versioning --bucket BUCKET_NAME --output json 2>&1
```
If versioning is enabled, previous object versions may contain old credentials or sensitive data even if the current version has been cleaned.

### Step 4b: S3 Event Notification Discovery (Service Integration Edges)

For each bucket, check for Lambda trigger configurations that create implicit service-to-service data flows:

```bash
aws s3api get-bucket-notification-configuration --bucket BUCKET_NAME --output json 2>&1
```

For each `LambdaFunctionConfiguration` found in the response, extract the Lambda function ARN from `LambdaFunctionArn`. These triggers mean that an `s3:PutObject` event on this bucket automatically invokes the connected Lambda function — a critical attack chain link: writing to a trigger bucket = code execution via Lambda.

**Emit service integration edges:**
- For each Lambda trigger: `{source: "data:s3:BUCKET_NAME", target: "data:lambda:FUNCTION_NAME", edge_type: "data_access", access_level: "write", label: "s3_trigger"}` — S3 event notification triggers Lambda execution. The `access_level` is "write" because the trigger passes event data that the function processes.

**Attack chain significance:** If a principal has s3:PutObject on a trigger bucket, they can indirectly execute code via the triggered Lambda function. The function then runs with its execution role's permissions — follow the `exec_role` edge to determine the blast radius. This is one of the most commonly overlooked escalation paths.

If `get-bucket-notification-configuration` returns AccessDenied: log "PARTIAL: Could not read notification configuration for bucket [BUCKET_NAME] — AccessDenied" and continue. If no Lambda triggers are found, skip edge creation for this bucket.

### Step 5: Build Graph Data

Construct nodes and edges for the SCOPE dashboard:

**Nodes:**
- Each bucket: `{id: "data:s3:BUCKET_NAME", label: "BUCKET_NAME", type: "data"}`

**Edges:**
- IAM-based access: `{source: "user:<name>", target: "data:s3:BUCKET_NAME", edge_type: "data_access", access_level: "read|write|admin"}` or `{source: "role:<name>", target: "data:s3:BUCKET_NAME", edge_type: "data_access", access_level: "read|write|admin"}` — connect IAM principals that have S3 permissions to the buckets they can access
- Public access: `{source: "ext:internet", target: "data:s3:BUCKET_NAME", edge_type: "data_access", access_level: "read|write|admin"}` — for publicly accessible buckets
- Cross-account access: `{source: "ext:arn:aws:iam::<external-id>:root", target: "data:s3:BUCKET_NAME", trust_type: "cross-account"}` — for cross-account bucket policy grants

**access_level classification for S3:**
- `"read"` — principal has only s3:Get* and/or s3:List* actions (e.g., s3:GetObject, s3:ListBucket)
- `"write"` — principal has s3:Put* and/or s3:Delete* actions (e.g., s3:PutObject, s3:DeleteObject)
- `"admin"` — principal has s3:* (full S3 access) or a combination of read + write + management actions (s3:PutBucketPolicy, s3:PutBucketAcl)

**Error handling reminder:** Every per-bucket AWS CLI call MUST be wrapped with error handling. On AccessDenied or any error:
1. Log: "PARTIAL: Could not read [operation] for bucket [BUCKET_NAME] — [error message]"
2. Continue to the next command for this bucket, or the next bucket
3. NEVER stop the entire S3 module because a single bucket or command fails
4. At the end of the module, report how many buckets were fully analyzed vs. partially analyzed vs. skipped
</s3_module>
