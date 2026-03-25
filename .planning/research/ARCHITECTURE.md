# Architecture Research

**Domain:** AWS enumeration agent optimization — bulk API migration
**Researched:** 2026-03-25
**Confidence:** HIGH

## Standard Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    scope-audit orchestrator                          │
│   Dispatches 12 enum subagents in parallel, waits for summaries     │
├─────────────────────────────────────────────────────────────────────┤
│  Enum Subagent Pattern (all 12 agents follow this shape)            │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Phase 1: Enumerate — AWS CLI calls → shell variables        │   │
│  │  Phase 2: Extract  — jq templates → findings arrays         │   │
│  │  Phase 3: Analyze  — model adds severity + description       │   │
│  │  Phase 4: Combine  — sort_by(.arn) → FINDINGS_JSON           │   │
│  │  Phase 5: Write    — envelope jq → $RUN_DIR/<svc>.json       │   │
│  │  Phase 6: Validate — validate-enum-output.js                 │   │
│  └──────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│                    Downstream consumers                              │
│  ┌──────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │
│  │ scope-attack-    │  │ scope-pipeline    │  │   dashboard     │  │
│  │ paths (reads     │  │ (normalizes +     │  │ (reads          │  │
│  │ all .json files) │  │ indexes data)     │  │ results.json)   │  │
│  └──────────────────┘  └───────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Current Pattern |
|-----------|----------------|-----------------|
| IAM agent | Principal discovery, trust chains, privilege paths | Per-resource loops: list-users/roles/groups → N individual detail calls |
| S3 agent | Bucket policy, public access, encryption | list-buckets → per-bucket: get-policy, get-public-access-block, etc. |
| KMS agent | Key policy, grants, rotation | list-keys → per-key: describe-key, get-key-policy, list-grants |
| Secrets agent | Resource policy, rotation, KMS deps | list-secrets → per-secret: get-resource-policy |
| Lambda agent | Resource policy, exec roles, env vars | list-functions → per-function: get-policy, get-function-url-config |
| EC2 agent | Instances, SGs, VPCs, snapshots, ELBs | 6 parallel bulk calls per region; per-snapshot: describe-snapshot-attribute |
| RDS agent | DB instances, snapshots | 2 bulk calls per region; no per-resource loops |
| API Gateway agent | REST + HTTP/WS APIs, authorizers | get-rest-apis → per-REST API: get-authorizers, get-stages, get-resources |
| SNS agent | Topic policy, subscriptions, KMS | list-topics → per-topic: get-topic-attributes |
| SQS agent | Queue policy, encryption, DLQ | list-queues → per-queue: get-queue-attributes |
| CodeBuild agent | Projects, service roles, env vars | list-projects → batch-get-projects (already bulk) |
| STS agent | Caller identity, org, SCPs | 3 single-shot calls; no loops |

---

## Recommended Project Structure

```
agents/subagents/
├── scope-enum-iam.md         # HIGHEST priority — per-resource loops → get-account-authorization-details
├── scope-enum-s3.md          # MEDIUM — per-bucket loops (unavoidable); optimize per-bucket calls
├── scope-enum-kms.md         # MEDIUM — per-key loops across regions
├── scope-enum-secrets.md     # MEDIUM — per-secret loops; list-secrets already includes detail
├── scope-enum-lambda.md      # MEDIUM — per-function loops; list-functions includes config
├── scope-enum-ec2.md         # LOW — already bulk per region; snapshot loop is the main cost
├── scope-enum-rds.md         # LOW — already bulk; no optimization needed
├── scope-enum-apigateway.md  # MEDIUM — per-API loops (REST only); v1 has no bulk
├── scope-enum-sns.md         # MEDIUM — per-topic loops; no batch attributes API exists
├── scope-enum-sqs.md         # MEDIUM — per-queue loops; no batch attributes API exists
├── scope-enum-codebuild.md   # DONE — already uses batch-get-projects
└── scope-enum-sts.md         # DONE — already 3 single-shot calls; nothing to optimize
```

### Structure Rationale

- **IAM is the outlier:** It has 3+ separate loops (users, roles, groups) each making N per-resource calls. `get-account-authorization-details` collapses all of these into a single paginated call. This is the most dramatic win.
- **Most regional services have unavoidable per-resource calls:** AWS provides no batch-get for SNS topic attributes, SQS queue attributes, KMS key policies, or S3 bucket policies. The loop structure is correct and cannot be eliminated — only per-call redundancy can be removed.
- **CodeBuild and STS are already optimal:** CodeBuild uses `batch-get-projects` (purpose-built bulk API). STS has three single-shot calls with no resources to loop over.
- **EC2 and RDS are already bulk:** EC2 calls `describe-instances`, `describe-security-groups`, `describe-vpcs` once per region, returning all resources. RDS calls `describe-db-instances` once per region.

---

## Architectural Patterns

### Pattern 1: Bulk Single-Call Replacement (IAM only)

**What:** One paginated bulk call replaces N+1 per-resource calls. All principal types (users, roles, groups) and their policies come back in a single response.

**When to use:** Only IAM has a purpose-built API (`get-account-authorization-details`) that returns the complete account IAM state in one call family. No other SCOPE service has an equivalent.

**Response shape difference from loop pattern:**

Old loop pattern — data arrives as N separate API responses:
```bash
# Each iteration: one aws iam get-role call → {Role: {...}}
ROLE=$(aws iam get-role --role-name "$ROLE_NAME" --output json)
# AssumeRolePolicyDocument is decoded JSON (get-role decodes it)
```

Bulk call pattern — all data in one response:
```bash
# Single call returns: {UserDetailList: [...], RoleDetailList: [...],
#                       GroupDetailList: [...], Policies: [...]}
IAM_BULK=$(aws iam get-account-authorization-details --output json)
# CRITICAL: AssumeRolePolicyDocument is URL-encoded (RFC 3986)
# CLI does NOT auto-decode. Must pipe through python -c "import urllib.parse, sys; print(urllib.parse.unquote(sys.stdin.read()))"
# OR: use python/boto3 which auto-decodes
```

**jq template structural change:**

The loop-based `ROLE_FINDINGS` template took `ROLE_DETAIL` (a pre-assembled array built by the loop) as input. The bulk template takes the entire `IAM_BULK` response directly and extracts all four resource type arrays in separate jq passes:

```bash
# Old: operated on pre-assembled $ROLE_DETAIL array
ROLE_FINDINGS=$(echo "$ROLE_DETAIL" | jq --arg account_id "$ACCOUNT_ID" '...')

# New: operates directly on bulk response
BULK=$(aws iam get-account-authorization-details --output json)

# URL-decode AssumeRolePolicyDocument before jq processing
# Method: write bulk to temp file, decode with python helper, then pass to jq
BULK_DECODED=$(echo "$BULK" | python3 -c "
import json, sys, urllib.parse
data = json.load(sys.stdin)
for role in data.get('RoleDetailList', []):
    doc = role.get('AssumeRolePolicyDocument', '')
    if isinstance(doc, str):
        role['AssumeRolePolicyDocument'] = json.loads(urllib.parse.unquote(doc))
print(json.dumps(data))
")

USER_FINDINGS=$(echo "$BULK_DECODED" | jq --arg account_id "$ACCOUNT_ID" '
  [.UserDetailList[] | {
    resource_type: "iam_user",
    resource_id: .UserName,
    arn: .Arn,
    region: "global",
    created: .CreateDate,
    has_mfa: ((.UserMFADevices // []) | length > 0),
    has_console_access: false,   # not in bulk response — needs separate credential report
    access_keys: [],             # not in bulk — needs separate list-access-keys
    groups: (.GroupList // []),
    findings: []
  }]')

ROLE_FINDINGS=$(echo "$BULK_DECODED" | jq --arg account_id "$ACCOUNT_ID" \
  "$TRUST_CLASSIFY_JQ"'
  [.RoleDetailList[] |
    select(.RoleName | startswith("AWSServiceRole") | not) | . as $role |
    ($role.AssumeRolePolicyDocument.Statement // []) as $stmts |
    [
      $stmts[] | select(.Effect == "Allow") |
      .Principal | normalize_principals | .[] | classify_principal
    ] | unique_by(.principal) |
    [.[] |
      . + {
        has_external_id: ([($stmts[] | select(.Effect == "Allow") |
          .Condition.StringEquals["sts:ExternalId"] // empty)] | length > 0),
        has_mfa_condition: ([($stmts[] | select(.Effect == "Allow") |
          .Condition.Bool["aws:MultiFactorAuthPresent"] // empty)] | length > 0)
      } | . + {risk: (. | derive_risk)}
    ] as $trust |
    {
      resource_type: "iam_role",
      resource_id: $role.RoleName,
      arn: $role.Arn,
      region: "global",
      trust_relationships: $trust,
      is_service_linked: ($role.Path | startswith("/aws-service-role/")),
      permission_boundary: ($role.PermissionsBoundary.PermissionsBoundaryArn // null),
      findings: []
    }
  ]')
```

**Trade-offs:**
- Pro: Eliminates N `get-role` calls (was the dominant IAM cost), N `list-mfa-devices`, N `list-groups-for-user`, N `list-attached-*-policies`, N `list-*-policies` calls
- Con: `get-account-authorization-details` does NOT include MFA device details or access key metadata — these require separate calls (`iam list-virtual-mfa-devices` and `iam generate-credential-report` + `iam get-credential-report`)
- Con: `has_console_access` is not in the bulk response — the credential report CSV is the efficient source
- Con: `AssumeRolePolicyDocument` is URL-encoded in the response, unlike `get-role` which returns decoded JSON. Must decode before jq processing.

### Pattern 2: Loop-With-Consolidated-Input (Secrets, Lambda, SNS, SQS)

**What:** The list call already returns enough metadata to avoid separate per-resource detail calls for most fields. Only the resource policy/attributes call remains per-resource.

**When to use:** When `list-*` returns sufficient metadata but policies/attributes require a separate per-resource call with no batch equivalent.

**Secrets example — field consolidation from list-secrets:**

```bash
SECRETS=$(aws secretsmanager list-secrets --region "$CURRENT_REGION" --output json)
# list-secrets response includes: ARN, Name, RotationEnabled, LastRotatedDate,
# LastAccessedDate, KmsKeyId. All per-secret metadata fields are available WITHOUT
# a separate describe-secret call.
# Only get-resource-policy remains as an unavoidable per-secret call.

for row in $(echo "$SECRETS" | jq -c '.SecretList[]'); do
  SECRET_ARN=$(echo "$row" | jq -r '.ARN')
  # Extract all non-policy fields directly from list-secrets row — no describe-secret needed
  SECRET_NAME=$(echo "$row" | jq -r '.Name')
  ROTATION_ENABLED=$(echo "$row" | jq '.RotationEnabled // false')
  LAST_ROTATED=$(echo "$row" | jq -r '.LastRotatedDate // ""')
  LAST_ACCESSED=$(echo "$row" | jq -r '.LastAccessedDate // ""')
  KMS_KEY_ID=$(echo "$row" | jq -r '.KmsKeyId // ""')
  # Only policy requires a separate call
  RESOURCE_POLICY_RAW=$(aws secretsmanager get-resource-policy --secret-id "$SECRET_ARN" ...)
done
```

**Lambda example — environment variable extraction from list-functions:**

The current agent correctly reads `FUNC_CONFIG` from the list-functions response (not a separate call), but then calls `aws lambda get-function-url-config` and `aws lambda get-policy` per function. Both remain necessary — no batch equivalent exists for either. The extraction template change here is documentation clarity, not API count reduction.

**KMS example — skip describe-key round trip:**

```bash
# Current: list-keys → describe-key (to get KeyManager, KeyState, KeyUsage, Origin)
# Optimized: list-keys with --include-aliases OR use describe-keys-batch (does not exist)
# VERDICT: No bulk describe exists. Must keep per-key describe-key call.
# OPTIMIZATION: Use list-keys with Limit=1000 (max) to reduce pagination calls.
# Filter to CUSTOMER keys in the describe-key loop — this is already correct.
```

**Trade-offs:**
- Pro: Removes describe-secret, describe-function calls where list response includes all needed fields
- Con: Per-resource policy calls cannot be batched — SNS, SQS, KMS, Secrets all have single-resource policy APIs only

### Pattern 3: Region-Parallel Bulk Call (EC2 — already implemented)

**What:** All resource types for a given region are fetched in one pass using bulk describe calls. No per-resource loops for the primary resource type.

**When to use:** EC2 already implements this correctly. `describe-instances`, `describe-security-groups`, `describe-vpcs`, `describe-snapshots --owner-ids self`, `describe-load-balancers` all return every resource of that type in one paginated call.

**The remaining EC2 loop is the EBS snapshot attribute check:**

```bash
# Current: for each snapshot, call describe-snapshot-attribute
# This is unavoidable — no bulk equivalent for createVolumePermission attribute
# OPTIMIZATION: Filter to snapshots only (--owner-ids self already does this)
# and skip the per-snapshot call if describe-snapshots returns PubliclyAccessible
# field directly. It does NOT — must keep the per-snapshot loop for public detection.
```

**Trade-offs:**
- EC2 is essentially optimal. The snapshot attribute loop is the only remaining per-resource cost.

### Pattern 4: Already-Bulk (CodeBuild, RDS, STS — no changes needed)

**What:** These agents already use the most efficient available API.

- **CodeBuild:** `list-projects` + `batch-get-projects` — single bulk fetch of all project configs
- **RDS:** `describe-db-instances` and `describe-db-snapshots` return all instances/snapshots per region in one call. No per-resource loops. `publicly_accessible` on snapshots requires checking `DBSnapshotAttributes` via `describe-db-snapshot-attributes` — this loop remains necessary.
- **STS:** Three single-shot calls (`get-caller-identity`, `describe-organization`, `list-policies`). No loops at all.

---

## Data Flow

### Request Flow: Old IAM (per-resource loop)

```
list-users
    ↓ N users
    for each user:
        list-access-keys       (1 call/user)
        list-mfa-devices       (1 call/user)
        list-groups-for-user   (1 call/user)
        list-attached-user-policies (1 call/user)
        list-user-policies     (1 call/user)
        get-login-profile      (1 call/user)
    ↓ 6N calls for N users
list-roles
    ↓ M roles
    for each role:
        get-role               (1 call/role) ← needed to decode AssumeRolePolicyDocument
        list-attached-role-policies (1 call/role)
        list-role-policies     (1 call/role)
    ↓ 3M calls for M roles
list-groups
    ↓ P groups
    for each group:
        get-group              (1 call/group)
        list-attached-group-policies (1 call/group)
    ↓ 2P calls for P groups
list-policies --scope Local (1 call)
Total: 3 + 6N + 3M + 2P + 1 calls
```

### Request Flow: New IAM (bulk)

```
get-account-authorization-details (paginated, ~1-3 calls for most accounts)
    ↓ Returns: UserDetailList, RoleDetailList, GroupDetailList, Policies
    ↓ Includes: group memberships, inline policies, attached policies for all types
generate-credential-report → get-credential-report (2 calls, replaces 2N login-profile + MFA calls)
[for users with access keys that need key IDs]:
    list-access-keys per user (unavoidable — bulk response omits key IDs)
Total: 2-4 calls for auth details + P calls for access keys (P = users with keys)
```

### Request Flow: Bulk regional services (unchanged, already optimal)

```
For EC2 (per region):
    describe-instances         (1 paginated call)
    describe-security-groups   (1 paginated call)
    describe-vpcs              (1 paginated call)
    describe-snapshots --owner-ids self (1 paginated call)
    elbv2 describe-load-balancers (1 call)
    elb describe-load-balancers  (1 call)
    [per ALB/NLB]: describe-listeners (1 call each — unavoidable)
    [per snapshot]: describe-snapshot-attribute (1 call each — unavoidable)
```

### Key Data Flows

1. **IAM bulk → jq extraction:** Single shell variable `$BULK_DECODED` (URL-decode done once in Python) fans out to four separate jq invocations — one per resource type. Each jq invocation navigates `.UserDetailList[]`, `.RoleDetailList[]`, `.GroupDetailList[]`, or `.Policies[]`. The `FINDINGS_JSON` combine step is identical to current.

2. **Secrets/SNS/SQS loop consolidation:** `$row` variable passed to jq extraction template contains all needed metadata from the list response. Extraction template reads from `$row` instead of separate shell variables for each field. Only policy variable remains from a per-resource call.

3. **Output schema compatibility:** The output envelope (`$RUN_DIR/<svc>.json`) and the findings array structure do not change. Downstream consumers (attack-paths, dashboard) see identical JSON.

---

## Build Order

### Tier 1: Highest ROI, Implement First

**IAM — scope-enum-iam.md**

- Current API call count: `3 + 6N + 3M + 2P` where N=users, M=roles, P=groups
- Post-optimization count: `3-5 calls` (bulk + credential report + access keys for users with keys)
- Complexity: HIGH — AssumeRolePolicyDocument URL-decoding requirement, credential report CSV parsing, losing MFA device detail from bulk (must use credential report or list-virtual-mfa-devices)
- Risk: HIGH — trust classification jq templates change input shape significantly. `has_console_access` and `has_mfa` fields need alternate data sources.
- Schema impact: None. Output fields are identical.
- Prerequisite for: Nothing. IAM is independent.

### Tier 2: Moderate ROI, Implement Second

**Lambda — scope-enum-lambda.md**

- Current pattern: list-functions (includes full config) → per-function: get-policy, get-function-url-config
- Optimization: `list-functions` already includes Environment.Variables, Runtime, Role, Layers, LastModified. No separate `get-function-configuration` needed (current agent correctly avoids this). The env var extraction template is already reading from list-functions response.
- Remaining loop: get-policy and get-function-url-config are truly per-resource — no batch equivalent.
- Complexity: LOW — only documentation/comment cleanup. No behavioral change needed for this agent. It is already close to optimal.
- Net API reduction: Low. Agent already avoids the redundant describe call.

**Secrets — scope-enum-secrets.md**

- Current pattern: list-secrets → per-secret: extract fields by filtering list response + get-resource-policy
- The agent already reads metadata fields from `list-secrets` by filtering on ARN. This is correct but verbose — iterating the full list once per field extraction.
- Optimization: Read each secret's row once from list-secrets, extract all fields in a single jq pass, then call get-resource-policy. Eliminates repeated jq filter passes over the list for each field.
- Complexity: LOW — refactor of shell variable extraction, not API changes.
- Net API reduction: Zero new APIs eliminated (get-resource-policy is unavoidable). Shell variable extraction efficiency only.

**SNS — scope-enum-sns.md**

- Current pattern: list-topics → per-topic: get-topic-attributes
- No batch equivalent for get-topic-attributes exists (confirmed via AWS docs). Loop is unavoidable.
- Optimization: Pagination — add `--page-size 100` to list-topics. The extraction template shape is already correct (attributes response goes directly to jq).
- Complexity: VERY LOW — pagination parameter only.

**SQS — scope-enum-sqs.md**

- Current pattern: list-queues → per-queue: get-queue-attributes --attribute-names All
- No batch equivalent for get-queue-attributes exists. Loop is unavoidable.
- Optimization: Pagination — add `--max-results 1000` to list-queues. The extraction template is already correct.
- Complexity: VERY LOW — pagination parameter only.

**KMS — scope-enum-kms.md**

- Current pattern: list-keys → describe-key (CUSTOMER filter) → get-key-policy + list-grants + get-key-rotation-status per key
- No bulk describe exists for KMS. Per-key loop is unavoidable.
- Optimization: Use `--limit 1000` on list-keys to minimize pagination calls. Filter CUSTOMER keys early to reduce downstream calls.
- Complexity: VERY LOW — pagination parameter and early-exit filter (already implemented).

### Tier 3: Low ROI, Implement Last

**S3 — scope-enum-s3.md**

- Current pattern: list-buckets (global) → per-bucket: get-bucket-location, get-bucket-policy, get-public-access-block, get-bucket-versioning, get-bucket-encryption, get-bucket-logging, get-bucket-acl
- 7 calls per bucket. No S3 batch-get-bucket-details API exists.
- Optimization: Combine multiple per-bucket calls into parallel subshell executions. No API count reduction possible.
- Complexity: MEDIUM — parallel subshell management with bash `&` + `wait`. Error handling becomes more complex.
- Net benefit: Speed improvement (parallel within-bucket calls), not API count reduction.

**API Gateway — scope-enum-apigateway.md**

- Current pattern: get-rest-apis → per-API: get-authorizers, get-stages, get-resources; apigatewayv2 get-apis → per-API: get-authorizers, get-stages, get-integrations
- REST API resource policy is embedded in get-rest-apis response (`.policy` field). The agent already extracts this inline — no separate `get-rest-api` call needed.
- Remaining loop: authorizers, stages, resources per API. No batch equivalent.
- Complexity: LOW — REST API policy is already available in get-rest-apis response. Verify the agent uses `.items[].policy` directly rather than calling get-rest-api separately.
- Net benefit: If agent currently calls get-rest-api per-API for policy, eliminate that call.

**EC2 — scope-enum-ec2.md**

- Already optimal for primary resources. EBS snapshot loop and ALB listener loop are unavoidable.
- No changes recommended.

**RDS — scope-enum-rds.md**

- Already optimal. describe-db-instances and describe-db-snapshots return all resources per region. No per-resource loops.
- No changes recommended.

**CodeBuild — scope-enum-codebuild.md**

- Already optimal. batch-get-projects is the correct bulk pattern.
- No changes recommended.

**STS — scope-enum-sts.md**

- Already optimal. Three single-shot calls. No loops.
- No changes recommended.

---

## Scaling Considerations

| Scale | Architecture Adjustment |
|-------|------------------------|
| Small account (< 100 IAM principals) | Current loop pattern acceptable. Bulk API wins are modest. |
| Medium account (100-1000 IAM principals) | Bulk API eliminates hundreds of API calls. Rate limiting risk drops significantly. |
| Large account (1000+ IAM principals) | Bulk API is critical. Loop pattern will hit rate limits and take 10+ minutes. get-account-authorization-details handles this via pagination. |
| Multi-region scan (8+ regions) | Regional agents (KMS, Secrets, Lambda, EC2, RDS, SNS, SQS, CodeBuild, API Gateway) multiply call counts by N_regions. Pagination optimization applies in all regions. |

### Scaling Priorities

1. **First bottleneck:** IAM rate limiting on per-user/per-role detail calls in large accounts. The bulk API eliminates this entirely.
2. **Second bottleneck:** SNS/SQS per-topic/per-queue loops in multi-region scans with many resources. No API-level fix — consider parallelizing per-region or per-resource calls within the agent.

---

## Anti-Patterns

### Anti-Pattern 1: Assuming get-account-authorization-details Replaces All IAM Calls

**What people do:** Replace every IAM call with get-account-authorization-details and assume nothing is missing.

**Why it's wrong:** The bulk response omits:
- Access key IDs and metadata (need `iam list-access-keys` per user)
- Virtual MFA device serial numbers (need `iam list-virtual-mfa-devices` or credential report)
- `has_console_access` (LoginProfile) — the credential report CSV includes `password_enabled` and is the efficient alternative
- Per-user `has_mfa` detail — the bulk response omits MFA device details; credential report has `mfa_active` column

**Do this instead:** Use get-account-authorization-details for policy and group membership data, use `generate-credential-report` + `get-credential-report` for access key age, console access, and MFA status.

### Anti-Pattern 2: Processing URL-Encoded AssumeRolePolicyDocument Directly in jq

**What people do:** Pass get-account-authorization-details output directly to jq and try to parse AssumeRolePolicyDocument as a JSON object.

**Why it's wrong:** The CLI returns `AssumeRolePolicyDocument` as a URL-encoded string (RFC 3986). jq will receive a string, not an object. `.AssumeRolePolicyDocument.Statement` will be null. Trust classification will produce empty results silently.

**Do this instead:** Decode before jq. Use a Python one-liner to decode all policy documents in the bulk response before piping to jq:
```bash
BULK_DECODED=$(echo "$BULK" | python3 -c "
import json, sys, urllib.parse
data = json.load(sys.stdin)
for role in data.get('RoleDetailList', []):
    doc = role.get('AssumeRolePolicyDocument', '')
    if isinstance(doc, str):
        role['AssumeRolePolicyDocument'] = json.loads(urllib.parse.unquote(doc))
print(json.dumps(data))
")
```
Note: `get-role` (the old per-role call) auto-decoded this field in the CLI. get-account-authorization-details does not.

### Anti-Pattern 3: Building Pre-Assembled Arrays Before jq (Loop Accumulator Pattern)

**What people do:** In the loop-based pattern, accumulate results into shell arrays (`USER_ACCESS_KEYS`, `USER_MFA_DEVICES`, etc.) then pass all arrays to a single jq invocation via `--argjson`. This worked for the loop pattern because data arrived piecemeal.

**Why it's wrong for bulk:** The bulk response already contains all data in one object. Building intermediate arrays by filtering the bulk response is wasteful. The jq template should navigate `.UserDetailList[]` directly.

**Do this instead:** Write jq templates that operate on the top-level bulk response object directly, using sub-expressions to navigate nested arrays:
```bash
# Old: passes pre-assembled side arrays as --argjson
USER_FINDINGS=$(echo "$IAM_USERS" | jq --argjson access_keys "$USER_ACCESS_KEYS" ...)

# New: navigates bulk response internally
USER_FINDINGS=$(echo "$BULK_DECODED" | jq '.UserDetailList[] | ...')
```

### Anti-Pattern 4: Eliminating Loops Where No Batch API Exists

**What people do:** Assume all per-resource loops should be eliminated, attempt to batch SNS get-topic-attributes or KMS get-key-policy.

**Why it's wrong:** These APIs are single-resource only. AWS does not provide bulk-get for SNS topic attributes, SQS queue attributes, KMS key policies, S3 bucket policies, or Lambda resource policies. Attempting to parallelize with background processes introduces error handling complexity without API count benefit.

**Do this instead:** Keep the per-resource loop. Optimize pagination parameters on the list call. Ensure the extraction template processes the per-resource response inline (no intermediate accumulator arrays).

---

## Integration Points

### External Services

| Service | Integration Pattern | Notes |
|---------|---------------------|-------|
| IAM `get-account-authorization-details` | Single paginated call, handles IsTruncated/Marker | Returns UserDetailList, RoleDetailList, GroupDetailList, Policies. AssumeRolePolicyDocument is URL-encoded. |
| IAM `generate-credential-report` + `get-credential-report` | Two calls, returns CSV base64-encoded | Provides has_console_access (password_enabled), has_mfa (mfa_active), access_key_1/2 status and last_used. Replaces per-user login-profile and MFA device calls. |
| IAM `list-access-keys` | Still per-user, unavoidable | Needed for access key IDs and creation dates. Credential report gives status but not key IDs. |
| Lambda `list-functions` | Already returns full FunctionConfiguration including Environment.Variables | No separate get-function-configuration needed. get-policy and get-function-url-config remain per-function. |
| Secrets `list-secrets` | Returns RotationEnabled, LastRotatedDate, LastAccessedDate, KmsKeyId | No separate describe-secret needed for these fields. |
| CodeBuild `batch-get-projects` | Already bulk, no change | Accepts up to 100 project names per call. |

### Internal Boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| IAM agent → output schema | `$RUN_DIR/iam.json` envelope | Findings array shape is unchanged. resource_type, resource_id, arn, region, findings fields remain identical. |
| IAM agent → TRUST_CLASSIFY_JQ | Inline jq function definition | Trust classification logic is unchanged. Input to `normalize_principals` and `classify_principal` is the same Principal object shape extracted from policies. |
| Any agent → validate-enum-output.js | `node bin/validate-enum-output.js $RUN_DIR/<svc>.json` | module-envelope.schema.json requires module, account_id, region, timestamp, status, findings. All agents produce this shape. Schema does not constrain findings array contents. |
| Any agent → attack-paths | reads `$RUN_DIR/<svc>.json` findings array | attack-paths reads resource_type, arn, trust_relationships, findings fields. These are unchanged by bulk migration. |

---

## Sources

- [GetAccountAuthorizationDetails API Reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html) — HIGH confidence
- [get-account-authorization-details CLI Reference](https://docs.aws.amazon.com/cli/latest/reference/iam/get-account-authorization-details.html) — HIGH confidence. Confirms URL-encoding of policy documents.
- [ListTopics CLI Reference](https://docs.aws.amazon.com/cli/latest/reference/sns/list-topics.html) — HIGH confidence. No batch attributes API.
- [GetTopicAttributes API](https://docs.aws.amazon.com/sns/latest/api/API_GetTopicAttributes.html) — HIGH confidence. Single-topic only.
- [ListFunctions CLI Reference](https://docs.aws.amazon.com/cli/latest/reference/lambda/list-functions.html) — HIGH confidence. Full FunctionConfiguration in response.
- [ListKeys CLI Reference](https://docs.aws.amazon.com/cli/latest/reference/kms/list-keys.html) — HIGH confidence. No bulk describe-key.
- Direct code inspection of all 12 scope-enum-*.md files — HIGH confidence.

---

*Architecture research for: SCOPE v1.7 Enumeration Efficiency — bulk API migration*
*Researched: 2026-03-25*
