# Feature Research

**Domain:** AWS Security Enumeration Efficiency (agent-based tooling for purple team operations)
**Researched:** 2026-03-25
**Confidence:** HIGH — findings are based on direct inspection of existing agent code, official AWS API documentation, and cross-referenced with how major open-source tools (Prowler, ScoutSuite, Steampipe) solve the same problem.

---

## Context: What SCOPE Currently Does vs. What the Tools Do

Before categorizing features, it helps to understand the gap being closed.

**Current SCOPE pattern (all 12 agents):** List resources (e.g., `list-users`), then loop per-resource calling multiple detail APIs (`list-access-keys`, `list-mfa-devices`, `get-login-profile`, `get-role`, etc.). For IAM this is 5-6 API calls per user/role. For SQS it is 1 list call plus 1 `get-queue-attributes` per queue.

**How reference tools handle this:**
- **ScoutSuite** uses a facade-per-service pattern with bulk caching. The first call to a region populates a cache used by all subsequent resource lookups within that region, reducing redundant round trips. Pagination is handled by the facade, not the consumer.
- **Prowler** exposes `--aws-retries-max-attempts` to control boto3's standard retrier. Parallel execution is available and parallelizes at the check/service level.
- **Steampipe** parallelizes three ways: across sub-APIs, across regions, and across accounts simultaneously. It caches query results across controls so the same API call is not repeated for separate checks.

**Official AWS API landscape for SCOPE's services:**
- **IAM:** `get-account-authorization-details` returns all users (with inline/attached policies + group memberships), all roles (with trust policy + inline/attached policies), all groups, and all managed policies in one paginated call. It does NOT return access keys, MFA device status, or login profiles — those still require per-user calls. The trust policy is URL-encoded in this response, same as in `list-roles`.
- **Lambda:** `list-functions` already returns the full `FunctionConfiguration` including runtime, role ARN, environment variables, layers, last modified, VPC config. Per-function `get-function` or `get-function-configuration` is not needed unless you want function-level settings (state machine info, image config).
- **RDS:** `describe-db-instances` returns the complete instance configuration including encryption, IAM auth, public accessibility, security groups, KMS key ID, deletion protection — all from one paginated call per region. No per-instance follow-up is needed for the fields SCOPE uses.
- **EC2:** `describe-instances` returns full `InstanceType`, `MetadataOptions` (HttpTokens, HttpPutResponseHopLimit), `IamInstanceProfile`, `PublicIpAddress`, `VpcId`, `SubnetId`, `State` — everything in SCOPE's ec2_instance extraction template. EBS snapshot public permissions still need `describe-snapshot-attribute` per snapshot.
- **Secrets Manager:** `list-secrets` includes `RotationEnabled`, `LastRotatedDate`, `LastAccessedDate`, `KmsKeyId`, and tags per secret in the list response. Per-secret `describe-secret` is redundant for the fields SCOPE already uses. Resource policy still requires per-secret `get-resource-policy`.
- **SQS:** `get-queue-attributes --attribute-names All` per-queue is the correct bulk call. There is no bulk `batch-get-queue-attributes` API — per-queue attribute fetch is the intended pattern here.
- **SNS:** `list-topics` returns ARNs only. Per-topic `get-topic-attributes` is still required to get `Policy`, `KmsMasterKeyId`, `SubscriptionsConfirmed`.
- **KMS:** `list-keys` returns ARNs only. `describe-key` per key is needed (no batch describe API). However, filtering to `KeyManager == CUSTOMER` early (first `describe-key`) prevents fetching policy and grants for hundreds of AWS-managed keys.
- **STS:** Single identity call — no loop, no optimization needed.

---

## Feature Landscape

### Table Stakes (Users Expect These)

Features that any credible AWS security enumeration optimization must include. Missing any of these means the optimization is incomplete or breaks existing behavior.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| IAM bulk auth details via `get-account-authorization-details` | This is the canonical "one call for all IAM principals" API; Prowler and ScoutSuite both use it; the PROJECT.md names it explicitly as the primary optimization target | MEDIUM | Replaces the per-user/per-role detail loops entirely for permission data. Still requires per-user follow-up calls for access keys, MFA, and login profile. Trust policy is URL-encoded in this response — jq must URL-decode (`@uri` decode) or use a shell helper before passing to the existing TRUST_CLASSIFY_JQ template. |
| Preserve existing output schema exactly | Downstream consumers (scope-attack-paths, dashboard) have zero tolerance for schema changes; the PROJECT.md lists this as a hard constraint | LOW | All existing field names and types must be preserved. New fields can be added to findings objects but nothing removed. Every extraction template must produce the same jq output shape as before. |
| Handle pagination explicitly for all bulk calls | `get-account-authorization-details` paginates with `Marker`/`IsTruncated`; `list-functions` paginates with `NextMarker`; `list-secrets` with `NextToken`. Missing a page silently drops resources | MEDIUM | AWS CLI auto-paginates by default when `--output json` is used without `--no-paginate`. The current agents already rely on this, so it is already handled — but any replacement pattern must not accidentally introduce `--no-paginate` or explicit `--max-items` that truncates. |
| Filter AWS-managed keys in KMS before detail calls | Current agent already does `KeyManager == CUSTOMER` check after `describe-key`; the optimization is to filter earlier to avoid unnecessary policy/grant calls on AWS keys | LOW | Confirmed: `list-keys` returns all keys, `describe-key` returns `KeyManager`. The filter already happens; the optimization is ordering (filter on first describe, skip the rest) — current code does this correctly. The real win is avoiding `get-key-policy` and `list-grants` on AWS-managed keys. |
| Retry on rate limiting with backoff | All 12 agents already have "wait 2-5s, retry once" in their error handling sections; any replacement bulk calls must preserve this behavior | LOW | IAM uses a token-bucket throttler; bulk calls consume the same bucket. `get-account-authorization-details` is a heavier call — it may consume more tokens per invocation. One retry with 2-5s delay is sufficient for the audit use case. |
| AccessDenied produces valid empty output, not error exit | All 12 agents have this behavior: AccessDenied on a resource type yields `[]` findings with `status: partial`, not a crash | LOW | The output schema requires `status: complete\|partial\|error`. Bulk calls that are AccessDenied must produce the same empty-array behavior as today. This is the most important failure mode to test. |

### Differentiators (Competitive Advantage)

Features that would make SCOPE's enumeration noticeably faster or more reliable without being strictly required.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Lambda: eliminate redundant per-function calls | `list-functions` already returns all fields SCOPE uses (runtime, role ARN, layers, last modified, VPC config, environment variable names). The current agent calls `get-function-url-config` and `get-policy` per function — these are unavoidable, but iterating `list-functions` JSON in-memory via jq eliminates the per-function config parse overhead | LOW | The per-function loop in the current agent calls `get-function-url-config` and `get-policy` which are still needed (they are not in `list-functions`). What can be eliminated is re-fetching the function config: the current code stores `FUNCTIONS` from `list-functions` and jq-selects per ARN in the loop — this is already efficient. Real gain: confirm no per-function `get-function` call is happening, which would be redundant. |
| Secrets: eliminate per-secret `describe-secret` if used | `list-secrets` includes `RotationEnabled`, `LastRotatedDate`, `LastAccessedDate`, `KmsKeyId`, `Name`, `ARN`. If any agent currently calls `describe-secret` per secret in addition to `list-secrets`, that is redundant for those fields | LOW | Reading the current secrets agent: it does NOT call `describe-secret`. It extracts all metadata from `list-secrets` response directly. This means the secrets agent is already optimal for the metadata pass. Only `get-resource-policy` per secret remains necessary. |
| EC2: confirm no per-instance follow-up calls for IMDS/profile | `describe-instances` returns `MetadataOptions.HttpTokens`, `MetadataOptions.HttpPutResponseHopLimit`, and `IamInstanceProfile.Arn` in the list response. If any per-instance API calls are used to fetch these, they are unnecessary | LOW | Reading the current EC2 agent: `describe-instances` is already used as the sole source for instance metadata. The agent extracts IMDS fields from the response directly. No per-instance follow-up for these fields exists. EC2 agent is already optimal for instance data. EBS snapshot public permission check (`describe-snapshot-attribute` per snapshot) is the one remaining per-resource loop. |
| RDS: confirm no per-instance follow-up calls | `describe-db-instances` returns the complete set of fields SCOPE uses | LOW | The current RDS agent does not do per-instance follow-up for the fields it extracts. `describe-db-snapshot-attributes` per snapshot is still needed to check public restore permissions. This is analogous to EC2 snapshot handling — unavoidable. |
| IAM: batch credential-related calls with xargs or parallel | Access key list, MFA list, and login profile check still require per-user calls even after adopting `get-account-authorization-details`. These can be parallelized with `xargs -P` or `&` background jobs with `wait` | HIGH | This is complex to implement reliably in bash within a subagent's `maxTurns: 25` constraint. Background jobs require careful process management and error collection. Prowler uses Python threading for this. ScoutSuite uses asyncio. Bash parallelism is fragile. Flag as a future consideration unless the IAM module is demonstrably slow in practice. |
| Explicit `--max-items` tuning for large accounts | For accounts with thousands of IAM principals, `get-account-authorization-details` may return very large responses that stress jq in-memory processing. Setting `--max-items 100` with a pagination loop distributes memory pressure | MEDIUM | The current agents already use AWS CLI's automatic pagination (no explicit limit). For the `get-account-authorization-details` response in particular, the entire account's IAM state can be very large. The agents already note "For large accounts (1000+ users), pipe JSON via stdin instead of --argjson to avoid ARG_MAX limits." This note should be carried forward explicitly in the optimized IAM agent. |
| KMS: early-exit after `list-keys` if count is zero | Rather than entering the per-key loop when no keys exist, check array length first | LOW | Zero-finding behavior is already required and documented in the current kms agent. Adding an explicit early-exit reduces unnecessary iteration bookkeeping. Low complexity, moderate reliability improvement. |

### Anti-Features (Commonly Requested, Often Problematic)

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| Replace SNS per-topic attribute calls with a bulk fetch | Seems like an obvious optimization — list 100 topics, get all attributes at once | SNS has no batch `GetTopicAttributes` API. The only bulk option is `ListTopicAttributes` which does not exist. Per-topic `get-topic-attributes` is the only way to get `Policy` and `KmsMasterKeyId`. Implementing a fake "bulk" using background processes adds unreliable bash concurrency. | Accept that SNS requires N+1 API calls. SNS accounts rarely have thousands of topics. The per-topic call count is proportional to actual resource count and is already the minimum possible. |
| SQS batch attribute fetch | Seems natural to get all queue attributes in one API call | AWS has no `BatchGetQueueAttributes`. `GetQueueAttributes` is per-URL. The current one-call-per-queue pattern is already optimal. | No change needed. The current sqs agent pattern is correct. Document explicitly that this is not improvable without AWS adding a batch API. |
| Python subprocess in bash agents for async enumeration | Python has asyncio and threading; wrapping boto3 in a Python script called from the agent bash would be much faster | Agents are LLM-authored bash scripts with `maxTurns: 25`. Adding Python subprocesses introduces dependencies, error propagation complexity, temp file management, and defeats the agent's read-only `$RUN_DIR` constraint. The safety hooks operate on Bash tool calls — Python subprocesses bypass the hook's pattern matching for destructive operations. | Use AWS CLI's built-in automatic pagination (already in use). Accept that bash-based agents are sequential. SCOPE's parallelism is at the agent level (12 agents run in parallel), not within a single agent. |
| Cache `get-account-authorization-details` output to disk for reuse across agents | IAM data is used by multiple modules — why call the API once per agent? | Only the IAM agent enumerates IAM. Other agents (S3, Lambda, KMS, Secrets) do policy classification of resource-based policies, not IAM principal enumeration. There is no cross-agent data sharing during a run except through the completed `$RUN_DIR/*.json` files. Writing intermediate IAM data to disk for other agents to read during parallel execution creates race conditions. | Each agent fetches its own service data. The pipeline stage (scope-pipeline) handles cross-service correlation after all agents complete. |
| Call IAM Access Analyzer APIs to replace manual trust policy analysis | IAM Access Analyzer can identify resources shared with external entities | Access Analyzer requires a separate analyzer resource to be configured in the account. Its findings are scoped to a Region. It is not guaranteed to exist. SCOPE's `TRUST_CLASSIFY_JQ` pattern works without any pre-configured resources and with consistent field output. Using Access Analyzer would create a hard dependency on an optional service configuration. | Keep the jq-based trust classification. It is deterministic, fast, and operates entirely from the data already fetched. |
| Use `aws iam generate-credential-report` to replace per-user access key and MFA checks | The credential report is a CSV with all users, their MFA status, access key ages, and last used dates in one bulk fetch | `generate-credential-report` starts an async job; a second call to `get-credential-report` retrieves the result. The report can take up to 4 hours to generate if recently regenerated. The agent must poll until ready, which is unpredictable in duration and turn count. The report is CSV, requiring a CSV parser in jq (not possible cleanly) or external tools. | Continue using per-user `list-access-keys`, `list-mfa-devices`, `get-login-profile` for credential metadata. These three calls can be batched across users more easily than polling an async CSV job. |

---

## Feature Dependencies

```
IAM bulk API adoption (get-account-authorization-details)
    └──requires──> URL-decode of AssumeRolePolicyDocument before TRUST_CLASSIFY_JQ
                       └──requires──> jq update or shell sed/python decode step in IAM agent

IAM bulk API adoption
    └──requires──> Explicit pagination loop (Marker + IsTruncated) in IAM agent
                       └──requires──> bash while loop pattern (standard, low risk)

IAM bulk API adoption
    └──does NOT eliminate──> Per-user calls: list-access-keys, list-mfa-devices, get-login-profile
                                 (these fields are not in get-account-authorization-details)

Schema preservation constraint
    └──blocks──> Any field removal or renaming from existing findings objects
    └──allows──> Adding new fields (e.g., role_last_used from RoleDetailList)

Output schema unchanged
    └──required by──> scope-attack-paths (reads iam.json, lambda.json, etc.)
    └──required by──> dashboard (reads findings.[] fields by name)
```

### Dependency Notes

- **URL-decode requires IAM bulk API:** `get-account-authorization-details` URL-encodes `AssumeRolePolicyDocument` per RFC 3986. The existing TRUST_CLASSIFY_JQ template expects a decoded JSON string. A decode step must be added before the jq template is applied — `python3 -c "import urllib.parse,sys; print(urllib.parse.unquote(sys.stdin.read()))"` or `node -e "process.stdout.write(decodeURIComponent(require('fs').readFileSync('/dev/stdin','utf8')))"` can be used as a shell pipe. This dependency blocks the adoption of `get-account-authorization-details` until it is resolved.

- **Pagination loop blocks naive adoption:** The current IAM agent uses `list-users` and `list-roles` which auto-paginate via the CLI. `get-account-authorization-details` also auto-paginates via the CLI when called with `--output json`. No explicit loop is needed if relying on the AWS CLI's built-in pagination behavior. Confirm the AWS CLI handles the `Marker` token transparently for this API (MEDIUM confidence — behavior should be identical to `list-users`, but should be verified).

- **Per-user credential calls remain:** Adopting `get-account-authorization-details` for permission structure does not eliminate `list-access-keys`, `list-mfa-devices`, and `get-login-profile`. These three calls per user are still required. For the fields SCOPE captures, the net API reduction for IAM is: N users × 5 calls becomes N users × 3 calls + 1 bulk authorization call. At 100 users that is 500 calls → ~301 calls.

---

## MVP Definition

This milestone has a clear scope: optimize existing agents, do not break existing output.

### Launch With (v1.7.0 — the current milestone)

- [ ] IAM: Replace per-user/role detail calls for permission data with `get-account-authorization-details` — requires URL-decode solution for AssumeRolePolicyDocument, preserve all existing output fields, keep per-user calls for access keys/MFA/login profile
- [ ] Audit all 12 agents for redundant per-resource calls — document findings per agent with specific API names and call counts
- [ ] Lambda: Confirm `list-functions` is already used as the sole data source for function config (eliminate any hidden per-function `get-function` calls if present)
- [ ] Secrets: Confirm `list-secrets` response fields already eliminate any need for per-secret `describe-secret`
- [ ] EC2/RDS: Confirm no per-instance follow-up calls for fields available in `describe-instances`/`describe-db-instances`

### Add After Validation (v1.7.x)

- [ ] IAM: Add `role_last_used` field from `RoleDetailList[].RoleLastUsed` — this is available in `get-account-authorization-details` but not in the current per-role `get-role` calls. Adding it is a schema extension (new field, no breakage).
- [ ] KMS: Add explicit early-exit when `list-keys` returns an empty array before entering the per-key loop
- [ ] IAM: Evaluate per-user credential call batching using background processes — only if profiling shows IAM enumeration as the bottleneck on large accounts

### Future Consideration (v2+)

- [ ] IAM credential report integration as optional supplement — useful for accounts where per-user calls are throttled and async CSV is acceptable
- [ ] Intra-agent parallelism for per-resource attribute calls (SNS, KMS) — requires bash background job management or a switch to a Python helper script pattern

---

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| IAM bulk auth via `get-account-authorization-details` | HIGH — biggest API call reduction, primary stated goal of v1.7 | MEDIUM — URL-decode step is the blocker | P1 |
| Schema preservation constraint enforcement | HIGH — prevents breaking downstream consumers | LOW — existing schema validation node script covers this | P1 |
| Explicit pagination in IAM bulk call | HIGH — silent data loss if missed | LOW — AWS CLI auto-paginates, verify it applies to this API | P1 |
| Audit all 12 agents for redundant calls | HIGH — identifies which agents actually have optimization potential | LOW — reading existing code, no writes needed | P1 |
| Lambda: confirm no hidden per-function calls | MEDIUM — list-functions is comprehensive, current code appears correct | LOW — code inspection only | P2 |
| Secrets: confirm list-secrets eliminates describe-secret | MEDIUM — current code appears correct | LOW — code inspection only | P2 |
| KMS: early-exit on empty key list | LOW — cosmetic reliability improvement | LOW | P3 |
| IAM: expose `role_last_used` field | MEDIUM — useful for attack path reasoning, available "for free" in bulk call | LOW — schema additive only | P2 |
| IAM: per-user credential call parallelism | MEDIUM — reduces wall-clock time for large accounts | HIGH — bash concurrency is fragile | P3 |

---

## Competitor Feature Analysis

| Feature | Prowler | ScoutSuite | Steampipe | SCOPE Approach |
|---------|---------|------------|-----------|----------------|
| IAM bulk enumeration | Uses `get-account-authorization-details` as primary IAM data source in Python via boto3 | Uses facade pattern with bulk list + cache; individual API calls wrapped in service provider classes | Per-table mapping with caching across queries; parallelized per region | Replace per-principal loops with `get-account-authorization-details`, keep per-user calls for credential data |
| Pagination handling | boto3 paginators — transparent automatic pagination with configurable `--aws-retries-max-attempts` | Facade handles pagination internally per service | FDW layer handles pagination transparently | AWS CLI's built-in auto-pagination (`--output json` without `--no-paginate`); current agents already rely on this |
| Rate limiting and retry | Configurable `--aws-retries-max-attempts`, default 3 retries; boto3 standard retrier with exponential backoff | ScoutSuite does not document explicit retry config in public docs | Steampipe parallelizes sub-APIs; queries cached to avoid redundant calls | Per-agent retry: one retry after 2-5s delay; rate-limited calls logged in ERRORS field |
| EC2 instance enumeration | `describe_instances` via boto3 paginator; all metadata extracted from list response | Region-scoped facade; `describe-instances` with VPC-level caching | SQL table over `describe-instances`; all fields available as columns | `describe-instances` already used as sole source; no per-instance follow-up needed for SCOPE's fields |
| Partial failure handling | AccessDenied on one check does not stop others; findings are per-check | Per-service AccessDenied: empty service result, scan continues | AccessDenied on a table query returns null rows | Per-agent: AccessDenied on one resource type sets `status: partial`, continues with other resource types |
| KMS enumeration | Filter to customer-managed keys via `describe_key`; policy and grants fetched per key | Per-key policy and grant fetching after list | SQL table; filters applied in SQL WHERE clause | `list-keys` then `describe-key` filter to CUSTOMER keys; policy and grants per key; no batch alternative available |

---

## Per-Agent API Call Audit

This section maps the current call pattern for each agent against the optimized pattern and identifies which agents have real wins vs. which are already optimal.

| Agent | Current Pattern | Optimization Available | Expected Call Reduction |
|-------|----------------|----------------------|------------------------|
| scope-enum-iam | `list-users` + 5 per-user calls + `list-roles` + 3 per-role calls + `list-groups` + 2 per-group calls + `list-policies` | Replace permission/trust calls with `get-account-authorization-details` (1 bulk); keep 3 per-user credential calls | For 50 users + 50 roles + 20 groups: ~520 calls → ~204 calls (~60% reduction) |
| scope-enum-s3 | `list-buckets` + 6 per-bucket calls | No bulk alternative for bucket-level metadata; per-bucket calls are the only pattern | No reduction possible — already minimal |
| scope-enum-lambda | `list-functions` (full config) + 2 per-function calls (`get-function-url-config`, `get-policy`) | Config data already bulk from `list-functions`; 2 per-function calls are irreducible | No reduction — already uses list-functions as bulk source |
| scope-enum-ec2 | `describe-instances` (full) + `describe-security-groups` (full) + `describe-snapshots` (full) + per-snapshot `describe-snapshot-attribute` + per-LB `describe-listeners` | Instances, SGs, VPCs, snapshots are already bulk fetched; snapshot attribute and listener calls are irreducible | Minor: confirm no per-instance calls exist; snapshot permissions are unavoidably per-snapshot |
| scope-enum-kms | `list-keys` + `describe-key` + `get-key-policy` + `list-grants` per customer key | No batch key API; filter to CUSTOMER early to skip policy/grant calls on AWS-managed keys | Already filters to CUSTOMER keys — optimization is already in place |
| scope-enum-secrets | `list-secrets` (includes rotation/accessed/KMS metadata) + `get-resource-policy` per secret | `list-secrets` already bulk; `get-resource-policy` is irreducible | Already optimal — list-secrets is the bulk call |
| scope-enum-rds | `describe-db-instances` (full config) + `describe-db-snapshots` + per-snapshot `describe-db-snapshot-attributes` | Instances and snapshots already bulk fetched; snapshot attributes are per-snapshot (no batch API) | Already optimal for instances; snapshot public permission check is irreducible |
| scope-enum-sqs | `list-queues` + `get-queue-attributes --attribute-names All` per queue | No batch attribute API for SQS; per-queue is the AWS-intended pattern | No reduction possible |
| scope-enum-sns | `list-topics` + `get-topic-attributes` per topic | No batch attribute API for SNS; per-topic is unavoidable | No reduction possible |
| scope-enum-sts | `sts:GetCallerIdentity` (single call) | Already a single call — no optimization needed | Already optimal |
| scope-enum-apigateway | Per-region `get-rest-apis` + `get-resources`/`get-stages` per API | `get-rest-apis` is a list call returning basic config; stage and resource data requires per-API calls | Minimal reduction; already uses list as primary |
| scope-enum-codebuild | Per-region `list-projects` + `batch-get-projects` | `batch-get-projects` accepts up to 100 project names per call — this IS a bulk API and may already be used | Check agent code: if currently doing per-project `get-project`, switch to `batch-get-projects` for HIGH gain |

---

## Schema Dependency Map

The following output fields are consumed by `scope-attack-paths` and the dashboard. All must be preserved unchanged.

| Field | Source Agent | Used By | Risk of Change |
|-------|-------------|---------|---------------|
| `resource_type` | All agents | attack-paths, dashboard | CRITICAL — primary discriminator |
| `resource_id` | All agents | attack-paths, dashboard | CRITICAL |
| `arn` | All agents | attack-paths, dashboard | CRITICAL — used for edge construction |
| `region` | All agents | dashboard display | CRITICAL |
| `trust_relationships` | IAM roles | attack-paths | CRITICAL — trust chain analysis |
| `key_policy_principals` | KMS | attack-paths | CRITICAL |
| `bucket_policy_principals` | S3 | attack-paths | CRITICAL |
| `resource_policy_principals` | Lambda, Secrets, SQS | attack-paths | CRITICAL |
| `execution_role_arn` | Lambda | attack-paths | CRITICAL — priv esc path |
| `iam_profile_arn` | EC2 | attack-paths | CRITICAL — instance profile chain |
| `imds_v1_enabled` | EC2 | attack-paths | HIGH |
| `has_mfa` | IAM users | attack-paths | HIGH |
| `has_console_access` | IAM users | attack-paths | HIGH |
| `access_keys` | IAM users | attack-paths | HIGH |
| `findings` | All agents | dashboard | CRITICAL — severity badges |

---

## Sources

- [AWS IAM GetAccountAuthorizationDetails API Reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)
- [AWS CLI get-account-authorization-details](https://docs.aws.amazon.com/cli/latest/reference/iam/get-account-authorization-details.html)
- [AWS Lambda ListFunctions API](https://docs.aws.amazon.com/lambda/latest/api/API_ListFunctions.html)
- [AWS Secrets Manager ListSecrets API](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html)
- [AWS Secrets Manager BatchGetSecretValue blog post](https://aws.amazon.com/blogs/security/how-to-use-the-batchgetsecretsvalue-api-to-improve-your-client-side-applications-with-aws-secrets-manager/)
- [AWS CLI pagination documentation](https://docs.aws.amazon.com/cli/v1/userguide/cli-usage-pagination.html)
- [ScoutSuite Resources Fetching System Architecture](https://github.com/nccgroup/ScoutSuite/wiki/Resources-fetching-system-architecture)
- [Prowler parallel execution documentation](https://docs.prowler.com/user-guide/cli/tutorials/parallel-execution)
- [Prowler GitHub — rate limiting discussion](https://github.com/prowler-cloud/prowler/discussions/2807)
- [Steampipe AWS plugin](https://hub.steampipe.io/plugins/turbot/aws)
- [Steampipe GitHub](https://github.com/turbot/steampipe-plugin-aws)
- [AWS EC2 DescribeInstances API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
- [IAM and AWS STS quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html)

---
*Feature research for: AWS security enumeration efficiency optimization (SCOPE v1.7)*
*Researched: 2026-03-25*
