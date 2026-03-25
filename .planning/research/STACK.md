# Stack Research

**Domain:** AWS API enumeration efficiency — bulk vs per-resource call patterns
**Researched:** 2026-03-25
**Confidence:** HIGH (verified against official AWS documentation for all 12 services)

---

## Overview

This research covers the most efficient AWS CLI call patterns for each of the 12 SCOPE enumeration agents. The goal is to identify where per-resource loops can be replaced with bulk/consolidated APIs, note what data is unavailable from bulk APIs and still requires per-resource calls, and document pagination considerations.

The primary criterion: **fewest round trips to retrieve the most data**, measured against what each agent actually needs for its output schema.

---

## Service-by-Service Analysis

### IAM

**Current approach:** `list-users` + per-user (`list-access-keys`, `list-mfa-devices`, `list-groups-for-user`, `list-user-policies`), `list-roles` + per-role `get-role`, `list-groups` + per-group `get-group`.

**Optimized approach:** `get-account-authorization-details`

This single paginated call returns all users with their group memberships, attached managed policies, and inline policy names; all groups with attached policies and inline policies; all roles with decoded `AssumeRolePolicyDocument` (unlike `list-roles` which URL-encodes it), attached policies, and inline policies; and all customer-managed policies. One call replaces 4-5 separate list calls plus N per-resource calls.

**Pagination:** Uses `Marker` / `IsTruncated`. Default page size handles most accounts; large accounts need `--max-items` with loop on `NextToken`.

**Critical: NOT available from `get-account-authorization-details`:**
- Access key metadata (key ID, status, created date) — still requires `list-access-keys --user-name`
- MFA device enrollment — still requires `list-mfa-devices --user-name`
- Login profile (console access) — still requires `get-login-profile --user-name` (or catch NoSuchEntity)

**Important format caveat:** `AssumeRolePolicyDocument` in `get-account-authorization-details` is URL-encoded (RFC 3986), same as `list-roles`. It is already decoded JSON in `get-role`. For the optimized path, URL-decode via `python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))"` or equivalent before passing to jq.

**Credential report as supplement:** `generate-credential-report` + `get-credential-report` returns a CSV with all users' password status, access key ages, MFA status, and last-used dates in one call. This completely replaces per-user `list-access-keys`, `list-mfa-devices`, and `get-login-profile` loops. Generate takes 5-15 seconds to complete; poll `generate-credential-report` until response is COMPLETE. Parse CSV with `awk` or convert to JSON. Reports can be generated at most once per 4 hours; if a cached report is acceptable, use `get-credential-report` directly without re-generating.

**Net effect:** 1 bulk call (`get-account-authorization-details`) + 1 credential report call replaces the current 4 list calls + (5N per-user calls) + (3M per-role calls) + (2K per-group calls) for a typical account. For 50 users, 80 roles, 10 groups: ~285 calls reduced to ~3.

---

### S3

**Current approach:** `list-buckets` (global, one call — correct), then per bucket: `get-bucket-location`, `get-bucket-policy`, `get-public-access-block`, `get-bucket-versioning`, `get-bucket-encryption`, `get-bucket-logging`, `get-bucket-acl` — 7 calls per bucket.

**No consolidated bulk API exists for bucket configuration.** AWS S3 Batch Operations operates on objects, not bucket configuration metadata. There is no `get-bucket-attributes` or equivalent.

**Optimization available:** S3 Storage Lens and AWS Config can surface bucket configuration at scale, but those are not enumeration-safe paths for a read-only audit agent without prerequisites.

**Practical optimization:** Parallelize per-bucket calls within each bucket where possible (6 calls per bucket that are independent of each other — location must come first to check region). Use `--no-cli-pager` on all calls. For large accounts (>100 buckets), use background subshells per bucket.

**Pagination:** `list-buckets` is not paginated — returns all buckets in one response. Per-bucket configuration APIs do not paginate (single-resource calls).

**Data available from `list-buckets`:** Only bucket name and creation date. Everything else requires per-bucket calls.

**Data NOT available without per-bucket calls:** region/location, policy, public access block, versioning, encryption, logging, ACL — all require separate calls.

---

### EC2/VPC/EBS/ELB

**Current approach:** Per region: `describe-instances`, `describe-security-groups`, `describe-vpcs`, `describe-snapshots --owner-ids self`, `elbv2 describe-load-balancers`, `elb describe-load-balancers`. For public snapshot check: per-snapshot `describe-snapshot-attribute` loop.

**Optimized approach for public snapshot detection:** Replace the per-snapshot `describe-snapshot-attribute` loop with a single filter on `describe-snapshots`:

```bash
# Get public snapshots owned by this account in one call
PUBLIC_SNAPS=$(aws ec2 describe-snapshots \
  --owner-ids "$ACCOUNT_ID" \
  --restorable-by-user-ids all \
  --region "$CURRENT_REGION" \
  --output json 2>&1)
```

`--restorable-by-user-ids all` filters to only snapshots that are publicly accessible. Combined with `--owner-ids self` (or `$ACCOUNT_ID`), this returns only account-owned public snapshots. Compare this list against `--owner-ids self` to determine which snapshots are public. Eliminates N per-snapshot `describe-snapshot-attribute` calls for an account with many snapshots.

**ELB listeners:** `elbv2 describe-listeners` accepts only a single `--load-balancer-arn`. No batch version. Current per-LB loop is correct. However, `describe-load-balancers` returns up to 20 LBs per call and supports pagination.

**Bulk calls already used correctly:** `describe-instances`, `describe-security-groups`, `describe-vpcs` all return all resources in one call per region (with pagination). These are already optimal.

**Pagination:** All EC2 `describe-*` calls paginate via `NextToken`. The AWS CLI handles auto-pagination by default (fetches all pages). For very large environments (thousands of instances), use `--page-size 100` to avoid throttling.

**Data NOT available without per-resource calls:** Snapshot public permissions (optimized above with filter), instance user data (`describe-instance-attribute --attribute userData` — still per-instance).

---

### Lambda

**Current approach:** `list-functions` per region, then per function: `get-function-url-config`, `get-policy`.

**`list-functions` already returns:** FunctionName, FunctionArn, Runtime, Role (execution role ARN), LastModified, Layers array with ARNs, Environment.Variables (keys AND values), Code, VpcConfig, MemorySize, Timeout. The current code re-parses `list-functions` output per function to extract this — that is correct and no extra call is needed for these fields.

**Optimization:** The inner loop `for FUNC_ARN in ...` re-queries the already-fetched `$FUNCTIONS` JSON with jq for each function. This is CPU-inefficient but not an API call inefficiency. A single jq `map(...)` over the full `list-functions` response can replace the per-function jq re-queries.

**`get-policy` cannot be eliminated:** Resource-based policies are not returned by `list-functions`. Per-function `get-policy` call is still required. ResourceNotFoundException (no policy) is expected and is not an error.

**`get-function-url-config` cannot be eliminated:** Function URL configuration is not in `list-functions` response. Per-function call is still required.

**Pagination:** `list-functions` returns a maximum of 50 functions per call. The AWS CLI auto-paginates. `NextMarker` is the pagination token. For accounts with many functions, ensure `--no-paginate` is NOT set; the default auto-pagination is correct.

**Net effect:** No API call reduction possible for Lambda. Optimization is structural (one jq pass vs N jq re-queries). Current 2 calls per function minimum is already the minimum.

---

### KMS

**Current approach:** `list-keys`, then per key: `describe-key` (filter to CUSTOMER), `get-key-rotation-status`, `get-key-policy`, `list-grants`.

**No bulk `describe-key` exists.** `list-keys` returns only KeyId and KeyArn. `describe-key` must be called individually per key to get KeyManager, KeyState, KeyUsage, Origin.

**Optimization available:** Filter CUSTOMER vs AWS-managed keys at the `list-keys` stage using `--key-filters KeyType=CUSTOMER_MANAGED`. This avoids calling `describe-key` on all AWS-managed keys.

```bash
KEYS=$(aws kms list-keys \
  --key-filters KeyType=CUSTOMER_MANAGED \
  --region "$CURRENT_REGION" \
  --output json 2>&1)
```

`--key-filters` was added to `ListKeys` in 2023. This skips describe-key calls for all AWS-managed keys, which can be the majority in accounts that use many AWS services (S3, CloudTrail, EBS default encryption all create AWS-managed keys). Verify `--key-filters` support in the AWS CLI version available; fall back to post-filter with `describe-key` if unavailable.

**Confidence on `--key-filters`:** MEDIUM — parameter appears in recent CLI docs but was not confirmed via official API reference fetch. Test `aws kms list-keys --key-filters KeyType=CUSTOMER_MANAGED` against a live account before baking into agent.

**`get-key-rotation-status`, `get-key-policy`, `list-grants`:** No bulk versions exist. Still required per customer-managed key.

**Pagination:** `list-keys` paginates via `NextMarker` / `Truncated`. Default limit is 100 keys per page.

---

### Secrets Manager

**Current approach:** `list-secrets` per region, then per secret: `get-resource-policy`.

**`list-secrets` already returns:** ARN, Name, RotationEnabled, LastRotatedDate, LastAccessedDate, KmsKeyId, RotationLambdaARN, RotationRules, Tags, Description, NextRotationDate. These are the fields the agent extracts in its loop. The current per-secret jq re-queries against `$SECRETS` are CPU work only, not API calls.

**`get-resource-policy` cannot be eliminated:** Resource policies are not returned by `list-secrets`. Per-secret call is still required.

**Net effect:** No API call reduction possible for Secrets Manager. The inner loop is already correct — it only makes one additional API call per secret (`get-resource-policy`). The jq re-queries can be optimized to a single `map(...)` pass like Lambda.

**Pagination:** `list-secrets` paginates via `NextToken`. Default returns up to 100 secrets per page. AWS CLI auto-paginates.

---

### STS

**Current approach:** `get-caller-identity`, `organizations describe-organization`, `organizations list-policies`, `organizations describe-policy` per SCP.

**Already optimal.** `get-caller-identity` is a single call. Organizations calls are conditional on having management account access. `describe-policy` is per-SCP but the number of SCPs is typically small (single digits to tens).

**No consolidation opportunity.** There is no bulk `describe-policies` that fetches document content for multiple SCPs at once.

**Pagination:** `list-policies` paginates via `NextToken`. Typically returns all SCPs in one page (most accounts have fewer than 20).

---

### RDS

**Current approach:** Per region: `describe-db-instances`, `describe-db-snapshots --snapshot-type manual`. Per snapshot: check public access via describe-db-snapshot-attributes (not explicitly shown in agent but implied by `publicly_accessible` field).

**`describe-db-instances` already returns all needed fields in one call:** DBInstanceIdentifier, DBInstanceArn, Engine, PubliclyAccessible, StorageEncrypted, DeletionProtection, IAMDatabaseAuthenticationEnabled, KmsKeyId, VpcSecurityGroups. No per-instance follow-up calls required. Agent is already optimal for instances.

**Snapshot public access:** The agent's jq template references `.DBSnapshotAttributes` on the snapshot object, but `describe-db-snapshots` does NOT return attribute permissions in the base response. `describe-db-snapshot-attributes` is a separate per-snapshot call needed to check the `restore` attribute for `all` (public). The agent's current template will silently produce `publicly_accessible: false` for all snapshots unless this per-snapshot call is added or the agent handles this gap.

**Optimization for public snapshots:** Use `--include-public` filter when calling `describe-db-snapshots` does not exist. Instead, after getting snapshot list, call `describe-db-snapshot-attributes --db-snapshot-identifier` per snapshot to check `restore` attribute. This is unavoidable — there is no filter equivalent to EC2's `--restorable-by-user-ids all` for RDS.

**Pagination:** Both `describe-db-instances` and `describe-db-snapshots` paginate via `Marker`. AWS CLI auto-paginates.

---

### API Gateway

**Current approach:** Per region: `get-rest-apis` (v1), then per API: `get-authorizers`, `get-stages`, `get-resources`. For v2: `get-apis`, then per API: `get-authorizers`, `get-stages`, `get-integrations`.

**`get-rest-apis` already includes the resource policy** in the `policy` field (URL-encoded JSON string). The current agent correctly extracts `REST_API_POLICY` from the bulk response without a separate `get-rest-api` call. This is already optimal for the policy field.

**`get-authorizers` cannot be eliminated:** Not included in `get-rest-apis` or `get-apis` responses. Per-API call required.

**`get-stages` cannot be eliminated:** Not included in list responses. Per-API call required.

**`get-resources` for Lambda integration detection:** This is the expensive call — returns all resources/methods/integrations for a REST API. For large APIs with many routes, this can return hundreds of items. It is the only way to discover Lambda integrations. Cannot be eliminated, but can be optimized with `--embed` or `--query` to reduce response size.

**v2 optimization:** `get-integrations` for HTTP/WebSocket APIs is similarly unavoidable for Lambda integration detection.

**Pagination:** `get-rest-apis` and `get-resources` use `position` token for pagination. `get-apis` uses `NextToken`. AWS CLI auto-paginates.

---

### SNS

**Current approach:** `list-topics` per region, then per topic: `get-topic-attributes`.

**No bulk `get-topic-attributes` equivalent exists.** `list-topics` returns only the TopicArn per topic — no attributes. `get-topic-attributes` must be called per topic to get Policy, KmsMasterKeyId, SubscriptionsConfirmed, etc.

**No optimization available at the API level.** The current two-call-per-topic pattern (list + get-attributes) is the minimum. Parallelization within a region (background subshells) is the only performance lever.

**Pagination:** `list-topics` returns up to 100 topics per page with `NextToken`. Agent should handle pagination.

---

### SQS

**Current approach:** `list-queues` per region, then per queue: `get-queue-attributes --attribute-names All`.

**No bulk `get-queue-attributes` equivalent exists.** `get-queue-attributes` accepts a single `--queue-url`. Multiple queues require multiple calls.

**`list-queues` with `--queue-name-prefix`:** No security benefit, but filtering by prefix is available if the account uses naming conventions.

**Optimization:** `get-queue-attributes --attribute-names All` is already the correct approach — it returns Policy, KmsMasterKeyId, SseType, VisibilityTimeout, RedrivePolicy, QueueArn, FifoQueue in a single call per queue. Using specific attribute names would require multiple calls or omit needed data.

**Pagination:** `list-queues` returns up to 1000 queue URLs per response with `NextToken`. Most accounts fit in one page.

---

### CodeBuild

**Current approach:** `list-projects` per region, then `batch-get-projects --names $PROJECT_NAMES`.

**Already optimal.** `batch-get-projects` is the purpose-built bulk API. It accepts up to 100 project names in a single call and returns full project configuration including service role, environment variables (names and values), source type, VPC config, and artifacts.

**Limit caveat:** Maximum 100 names per `batch-get-projects` call. For accounts with more than 100 projects in a region, chunk names into batches of 100 and make multiple `batch-get-projects` calls.

**`list-source-credentials` is a separate call:** Not included in `batch-get-projects` response. Single call per region (not per project). Already efficient.

**No per-project follow-up calls needed** for any data in the current schema. Agent is already using the optimal bulk pattern.

---

## Summary Table

| Service | Current Pattern | Optimized Pattern | API Call Reduction | Remaining Per-Resource Calls |
|---------|----------------|-------------------|-------------------|------------------------------|
| IAM | list* + N per-user/role/group | `get-account-authorization-details` + credential report | Large (50+ users: ~285 → ~3) | None for policy/group data |
| S3 | list-buckets + 7 per bucket | list-buckets + 6 per bucket (unchanged) | None at API level | location, policy, PAB, versioning, encryption, logging, ACL |
| EC2 | describe-* bulk + per-snapshot attribute | describe-* bulk + `--restorable-by-user-ids all` filter | Eliminates N snapshot-attribute calls | user-data per instance |
| Lambda | list-functions + 2 per function | list-functions + 2 per function (unchanged) | None | get-policy, get-function-url-config |
| KMS | list-keys + 4 per key | list-keys `--key-filters CUSTOMER_MANAGED` + 4 per key | Skips describe-key for AWS-managed | get-key-rotation-status, get-key-policy, list-grants |
| Secrets | list-secrets + 1 per secret | list-secrets + 1 per secret (unchanged) | None | get-resource-policy |
| STS | individual calls | individual calls (unchanged) | None — already minimal | describe-policy per SCP |
| RDS | describe-db-instances + describe-db-snapshots | unchanged | None | describe-db-snapshot-attributes per snapshot for public check |
| API Gateway | get-rest-apis + 3 per API | get-rest-apis (policy included) + 2 per API (authorizers + stages) | Eliminates get-rest-api call | get-resources (Lambda integrations) |
| SNS | list-topics + 1 per topic | unchanged | None | get-topic-attributes |
| SQS | list-queues + 1 per queue | unchanged | None | get-queue-attributes |
| CodeBuild | list-projects + batch-get-projects | already optimal | None — already bulk | None |

---

## Critical Gaps in Current Agents

### IAM: AssumeRolePolicyDocument URL-encoding in `get-account-authorization-details`

The current agent uses `get-role` (per-role) specifically because it returns decoded `AssumeRolePolicyDocument`, noting that `list-roles` returns URL-encoded. `get-account-authorization-details` also returns URL-encoded policy documents. When migrating to the bulk API, URL-decoding must be added before the trust classification jq runs. Failing to decode will silently produce empty trust_relationships arrays.

### RDS: Snapshot public access field is structurally broken

The jq template references `.DBSnapshotAttributes` on the snapshot object, but `describe-db-snapshots` does not include this field. The `publicly_accessible` field in the current agent will always evaluate to `false`. A per-snapshot `describe-db-snapshot-attributes` call is required to populate this correctly.

### API Gateway: `get-rest-apis` policy is URL-encoded

The `policy` field in `get-rest-apis` response is URL-encoded JSON (same pattern as IAM). The current agent does URL-decode it via `printf '%b'` substitution. This is correct but fragile — test that this decoding handles percent-encoded braces and quotes correctly in practice.

### EC2: Per-instance user data still requires per-instance call

`describe-instance-attribute --attribute userData` is a per-instance call. No bulk version exists. The checklist includes user data credential scanning, which means this cost is unavoidable if implemented. For accounts with many instances, this is the dominant cost of EC2 enumeration.

---

## Pagination Patterns

All AWS CLI v2 commands auto-paginate by default (fetches all pages into a single response). This is convenient but can cause memory issues and throttling for very large resources.

**Recommended approach for large accounts:**

```bash
# Use --page-size to control batch size, let CLI auto-paginate
aws iam get-account-authorization-details \
  --output json \
  --page-size 100

# Or stream paginator output to a temp file to avoid ARG_MAX
aws iam get-account-authorization-details \
  --output json > "$RUN_DIR/raw/iam_auth_details.json"
```

Services with meaningful pagination limits:
- Lambda `list-functions`: 50 per page (auto-paginated by CLI)
- SNS `list-topics`: 100 per page
- EC2 `describe-*`: variable, recommend `--page-size 500` for large accounts
- KMS `list-keys`: 100 per page default

---

## Alternatives Considered

| Recommended | Alternative | Why Not |
|-------------|-------------|---------|
| `get-account-authorization-details` | `list-users` + per-user loops | 100x more API calls for typical account |
| `generate-credential-report` for access key/MFA data | per-user `list-access-keys` / `list-mfa-devices` | N calls vs 2 calls; report covers all users |
| EC2 snapshot filter `--restorable-by-user-ids all` | per-snapshot `describe-snapshot-attribute` | N calls vs 1 call; filter is direct and authoritative |
| KMS `--key-filters CUSTOMER_MANAGED` | `describe-key` + filter by KeyManager | Avoids N describe-key calls for AWS-managed keys |
| CodeBuild `batch-get-projects` (current) | per-project `get-project` | Already correct — batch API purpose-built for this |

---

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `iam get-role` in per-role loop | O(N) API calls when bulk API exists | `get-account-authorization-details` |
| `iam list-access-keys` per user in loop | O(N) when credential report covers all users | `generate-credential-report` + `get-credential-report` |
| `ec2 describe-snapshot-attribute` per snapshot in loop | O(N) when filter eliminates the need | `describe-snapshots --restorable-by-user-ids all` |
| `apigateway get-rest-api` per API for policy | Policy already in `get-rest-apis` bulk response | Extract `policy` field from `get-rest-apis` items |
| `kms describe-key` on all keys before filtering | Calls describe on AWS-managed keys unnecessarily | `list-keys --key-filters KeyType=CUSTOMER_MANAGED` |

---

## Sources

- [GetAccountAuthorizationDetails API Reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html) — confirmed returned fields (users, groups, roles, policies with inline/attached; excludes access keys, MFA, login profile)
- [ListFunctions API Reference](https://docs.aws.amazon.com/lambda/latest/api/API_ListFunctions.html) — confirmed environment variables included, resource policy NOT included, 50/page limit
- [SecretListEntry API Reference](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_SecretListEntry.html) — confirmed RotationEnabled, LastRotatedDate, LastAccessedDate, KmsKeyId included; resource policy NOT included
- [DescribeSnapshots API Reference](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshots.html) — confirmed `--restorable-by-user-ids all` filter pattern for public snapshot detection
- [GetRestApis response format](https://docs.aws.amazon.com/cli/latest/reference/apigateway/get-rest-apis.html) — confirmed policy field included in bulk list response
- [BatchGetProjects API Reference](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_BatchGetProjects.html) — confirmed 100 project name limit per call
- [ListKeys API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html) — returns KeyId + KeyArn only; no bulk describe-key equivalent
- [SNS ListTopics](https://docs.aws.amazon.com/sns/latest/api/API_ListTopics.html) — confirmed TopicArn only in list response; no bulk attributes API
- [SQS GetQueueAttributes](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html) — confirmed single-queue API; no bulk version
- [IAM Credential Reports](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html) — confirmed report includes password status, access key ages, MFA status for all users
- [Hacking the Cloud — Public EBS Snapshots](https://hackingthe.cloud/aws/enumeration/loot_public_ebs_snapshots/) — confirmed `--restorable-by-user-ids all --owner-ids ACCOUNT_ID` pattern
- AWS SDK Go v2 Issue #227 — confirmed AssumeRolePolicyDocument URL-encoding behavior in GetAccountAuthorizationDetails

---

*Stack research for: SCOPE v1.7 enumeration efficiency optimization*
*Researched: 2026-03-25*
