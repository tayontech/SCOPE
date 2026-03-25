# Pitfalls Research

**Domain:** Bulk AWS API migration for agentic enumeration agents
**Researched:** 2026-03-25
**Confidence:** HIGH

---

## Critical Pitfalls

### Pitfall 1: get-account-authorization-details Does Not Return Access Keys or Login Profile

**What goes wrong:**
The IAM agent currently collects `access_keys`, `has_console_access`, and `has_mfa` per user by calling `list-access-keys`, `list-mfa-devices`, and `get-login-profile` in a per-user loop. The `UserDetail` object returned by `get-account-authorization-details` does not include any of these fields. A naive replacement of the per-user loop with a single bulk call silently drops access key metadata, MFA device status, and console access detection from every `iam_user` finding. The schema validator will not catch this — `findings: []` is schema-valid, but the attack path agent downstream relies on `access_keys[].status`, `has_mfa`, and `has_console_access` to flag aged keys, missing MFA, and combined-credential risk.

**Why it happens:**
`get-account-authorization-details` is an authorization-oriented API: it captures policies, group memberships, and trust relationships. It does not capture credential-oriented user state. Developers conflate "comprehensive IAM data" with "all IAM data" and assume the bulk call is a full replacement.

**How to avoid:**
The bulk call replaces the permission/policy collection loops only. Access key enumeration (`list-access-keys`), MFA device enumeration (`list-mfa-devices`), and login profile detection (`get-login-profile`) must still run per-user. Use `get-account-authorization-details` to get the authorization graph, then loop only over the credential-state calls. This is still a net win: the old loop also called `list-groups-for-user`, `list-attached-user-policies`, and `list-user-policies` per user — those are eliminated. Net API call reduction is still substantial.

**Warning signs:**
- `iam_user` findings all have `has_mfa: false`, `has_console_access: false`, `access_keys: []` even in accounts that clearly have users with keys
- Attack path agent fails to emit "MFA not enabled" or "access key age" findings
- METRICS return shows `users: N` but finding count is lower than expected for an active account

**Phase to address:** Phase 1 (IAM bulk migration). Document the field gap explicitly in the agent instructions before writing any code.

---

### Pitfall 2: AssumeRolePolicyDocument Is URL-Encoded When Read via AWS API (Raw HTTP), But Decoded by AWS CLI v2

**What goes wrong:**
The AWS API documentation states that all policies returned by `get-account-authorization-details` are "URL-encoded compliant with RFC 3986." The current agent already notes this risk in the iam_role section: "list-roles returns URL-encoded; always use get-role which returns decoded JSON." However, the behavior with AWS CLI v2 `--output json` is that CLI v2 transparently URL-decodes the policy strings and returns them as nested JSON objects, not strings. This is consistent behavior regardless of whether you use `get-account-authorization-details` or `get-role` via the CLI. The risk is: any future shell-level processing that tries to `fromjson` or double-decode the policy document, or any code that treats it as a string when it is already a JSON object, will silently break the jq extraction.

Additionally, the current agent instructions explicitly say "list-roles returns URL-encoded; always use get-role" as the rationale for the per-role loop. When switching to `get-account-authorization-details`, developers may assume they need a URL-decode step, write one, and double-decode — producing a partially corrupted or empty policy string.

**Why it happens:**
There is a real URL-encoding difference between `list-roles` and `get-role` for the trust policy. Developers over-apply this lesson to the bulk API without testing whether CLI v2 already handles the decode.

**How to avoid:**
Test `get-account-authorization-details --output json` against a real account and verify `AssumeRolePolicyDocument` arrives as a JSON object, not a string, in the CLI output. The jq extraction template already processes `AssumeRolePolicyDocument.Statement` as a JSON object — this should work without modification. Remove the comment "always use get-role which returns decoded JSON" from the agent, replacing it with "get-account-authorization-details via AWS CLI v2 returns AssumeRolePolicyDocument as a decoded JSON object." Do not add an explicit URL-decode step.

**Warning signs:**
- jq extraction of `.AssumeRolePolicyDocument.Statement` returns `null` or empty for all roles
- `ROLE_FINDINGS` has `trust_relationships: []` for every role in an account where cross-account trusts are known to exist
- `[ERROR] jq extraction failed for iam_role` fires for roles with non-trivial trust policies

**Phase to address:** Phase 1 (IAM bulk migration). Verify empirically before updating jq templates.

---

### Pitfall 3: ManagedPolicyDetail.PolicyVersionList Contains Only the Default Version Document — Inline Policies via get-account-authorization-details Are Already Embedded, But Attached Policy Documents Are Not

**What goes wrong:**
`get-account-authorization-details` returns `UserPolicyList` (inline policies for users) and `RolePolicyList` (inline policies for roles) directly in the UserDetail and RoleDetail objects — the inline policy document is embedded. However, `AttachedManagedPolicies` contains only `{PolicyName, PolicyArn}` — not the policy document. The full policy documents for managed policies are in the top-level `Policies` array as `ManagedPolicyDetail` objects with a `PolicyVersionList`. Only the version where `IsDefaultVersion: true` has the `Document` populated. The current per-resource approach builds `USER_ATTACHED_POLICIES` as a list of ARNs and does not retrieve the managed policy document content either — but if the optimization goal expands to include policy document analysis (for overly broad permission detection), the developer must know to traverse the `Policies` array and join on ARN, not expect the document to appear in the user or role object.

**Why it happens:**
The response structure has a non-obvious two-level design: principal objects contain policy references, and the actual document lives in a separate top-level array. Developers expecting a self-contained role or user record with all policies embedded will miss the document.

**How to avoid:**
When extracting `iam_policy` findings from the bulk response, use `.Policies[] | select(.IsDefaultVersion == true) | .Document` traversal pattern. When building `iam_role` or `iam_user` findings, accept that attached policy ARNs are present but documents are not in the role/user object — join against the `Policies` array if document content is needed. The current SCOPE schema does not require policy document content in role or user findings, so this is currently a non-issue for schema compatibility, but would become critical if that changes.

**Warning signs:**
- jq extraction attempts to traverse `.AttachedManagedPolicies[].Document` and silently produces `null` values
- Policy permission analysis shows all managed policies as empty

**Phase to address:** Phase 1 (IAM bulk migration). Note in agent instructions that attached policy documents require a separate join step against the top-level `Policies[]` array.

---

### Pitfall 4: Pagination Truncation Without --no-paginate Drops Resources in Large Accounts

**What goes wrong:**
`get-account-authorization-details` defaults to 100 items per page and AWS may return fewer items than requested even when more are available. Without `--no-paginate` (which enables AWS CLI automatic pagination), a single call returns an incomplete snapshot. The existing per-resource loops implicitly handle this because each `list-*` call uses `--no-paginate` or the agent retries on `IsTruncated`. When switching to the bulk call, omitting `--no-paginate` silently truncates after the first page.

For large enterprise accounts (hundreds of roles, thousands of users), a single un-paginated call may return only 100 of 800 roles. The agent will report `STATUS: complete` and `METRICS: {roles: 100}` with no error, producing a fundamentally incomplete audit without any visible failure.

**Why it happens:**
Developers testing against small dev accounts see full results in a single call and assume pagination is not needed. The truncation only manifests in production-sized accounts.

**How to avoid:**
Always use `aws iam get-account-authorization-details --output json --no-paginate` for the bulk call. Verify by checking `IsTruncated` in the response if not using `--no-paginate`. Add a post-call assertion: if `IsTruncated` is `true` in any page response, log `[ERROR] get-account-authorization-details truncated — use --no-paginate` and set STATUS to "error."

**Warning signs:**
- METRICS shows role or user count that is a round number (100, 200) exactly matching the default page size
- Known roles from a previous audit are absent from the current run
- No `IsTruncated` check in the agent code

**Phase to address:** Phase 1 (IAM bulk migration). Add pagination verification as part of the agent's post-enumeration self-check.

---

### Pitfall 5: jq --argjson Breaks on Large Bulk Response Payloads Due to Shell ARG_MAX

**What goes wrong:**
The current IAM agent accumulates per-resource results into shell variables (`ROLE_DETAIL`, `USER_ACCESS_KEYS`, etc.) and then passes them as `--argjson` arguments to jq. This pattern has a known ARG_MAX limit: the kernel limits the total size of command-line arguments. On Linux, ARG_MAX is typically 2MB. On macOS, it is 256KB. The current per-resource loop hits ARG_MAX only in very large accounts (1000+ users) because each variable contains data for one resource at a time. With `get-account-authorization-details`, the entire IAM state is in a single variable that can be 3-10MB for enterprise accounts. Passing a 5MB JSON blob as `--argjson` to jq will fail with `Argument list too long`.

The current agent already notes this risk in a comment: "For large accounts (1000+ users), pipe JSON via stdin instead of --argjson to avoid ARG_MAX limits." However, this note is positioned under the user extraction template and may not be applied when the bulk response variable is used as the primary input.

**Why it happens:**
Developers test against small accounts where `get-account-authorization-details` returns 50KB and `--argjson` works fine. Enterprise accounts return 3-10MB and hit the limit.

**How to avoid:**
For the bulk response, always pipe via stdin rather than using `--argjson` for the primary data source:
```bash
echo "$GAAD_RESPONSE" | jq --arg account_id "$ACCOUNT_ID" '[.RoleDetailList[] | ...]'
```
Reserve `--argjson` only for small secondary variables (account_id, flags). Never pass the full `get-account-authorization-details` response as an `--argjson` parameter.

**Warning signs:**
- `jq: error: argument list too long` or `bash: /usr/bin/jq: Argument list too long` in agent output
- Agent fails silently (no output from jq template) on accounts with many principals
- Works in testing but fails in production

**Phase to address:** Phase 1 (IAM bulk migration). Enforce stdin piping for all large-variable jq invocations in the updated IAM agent.

---

### Pitfall 6: Output Schema Field Name Divergence Between Bulk and Per-Resource Response Structures

**What goes wrong:**
The per-resource loop for roles collects `ROLE_DETAIL` as an array of `.Role` objects from `get-role`, each with `AssumeRolePolicyDocument`, `RoleName`, `Arn`, `Path`, `PermissionsBoundary.PermissionsBoundaryArn`, etc. The `get-account-authorization-details` response puts roles in `.RoleDetailList[]` objects with the same field names but with additions (`InstanceProfileList`, `RolePolicyList`, `AttachedManagedPolicies`). The jq extraction template for `iam_role` currently processes `$role.AssumeRolePolicyDocument.Statement` — this path works identically in both response formats since the field name is the same.

However, the user extraction template has a subtler divergence: `list-users` returns `.Users[].UserName` while the bulk response uses `.UserDetailList[].UserName`. If a developer updates the outer iterator (`for USERNAME in $(... .UserDetailList[].UserName)`) but forgets to update interior references that still dereference `.Users[].UserName`, jq will silently return empty arrays. The group member extraction uses `.GetGroup.Users[].UserName` which has no equivalent in the bulk response at all.

**Why it happens:**
The outer collection path changes (`Users[]` to `UserDetailList[]`, `Roles[]` to `RoleDetailList[]`, `Groups[]` to `GroupDetailList[]`) but the per-field paths inside each object are largely the same. Partial updates leave mismatched paths.

**How to avoid:**
When updating jq templates, do a full search-and-replace of collection paths and test each template individually against a real bulk response. The canonical path mapping is:
- `list-users` `.Users[]` → `get-account-authorization-details` `.UserDetailList[]`
- `list-roles` `.Roles[]` → `get-account-authorization-details` `.RoleDetailList[]`
- `list-groups` `.Groups[]` → `get-account-authorization-details` `.GroupDetailList[]`
- Customer-managed policies: `list-policies` `.Policies[]` → `get-account-authorization-details` `.Policies[]` (same key)

Run `node bin/validate-enum-output.js` against actual output after every template change.

**Warning signs:**
- `iam_user` findings have empty `groups: []` or `attached_policies: []` in accounts where they are known to be non-empty
- No `[ERROR] jq extraction failed` but finding counts are lower than known resource counts
- Schema validation passes (findings array is valid) but finding content is unexpectedly sparse

**Phase to address:** Phase 1 (IAM bulk migration). Create a test assertion comparing known resource counts from the old output against new output on the same account.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Replace all per-resource loops with get-account-authorization-details in one PR | Faster delivery | High risk of missing fields (access keys, login profile); hard to review diff | Never — do IAM first, verify output parity, then extend to other services |
| Skip output parity testing and rely on schema validation only | Saves test time | Schema validates envelope shape, not field content; silent data loss passes validation | Never — schema validation is necessary but not sufficient for migration correctness |
| Use `--argjson` for bulk response "just to match existing style" | Code consistency | Breaks silently on large accounts; ARG_MAX limits are OS-dependent and not caught in CI | Never for responses > 100KB |
| Consolidate all 12 agents in one milestone phase | Reduces phase count | One agent regression can block all 12; harder to isolate failures | Never — phase per service group (IAM, then regional services, then specialty) |
| Remove the per-user loop entirely instead of narrowing it | Simplest code | Drops access key/MFA/login-profile data which attack-path agent requires | Never without replacing those specific calls |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| get-account-authorization-details + jq trust classification | Pass full GAAD response as `--argjson` | Pipe full response via stdin; use `--argjson` only for scalar args like `$account_id` |
| get-account-authorization-details + scope-schema-validate.sh hook | Assume schema validation confirms complete data | Schema validates envelope and field types; add a separate content assertion that checks access_keys, has_mfa, has_console_access fields are populated for known-active users |
| get-account-authorization-details + scope-attack-paths | Assume attack-paths gets all data it needs from iam.json | Verify attack-paths still receives `access_keys[].status`, `access_keys[].created`, `has_mfa`, `has_console_access` after bulk migration — these drive HIGH-severity findings |
| RoleLastUsed field in RoleDetail | Assume same structure as get-role response | RoleLastUsed in GAAD is `{LastUsedDate, Region}` — same as get-role; but only populated for trailing 400 days of activity; treat null/absent as "no recent use" not as "field missing" |
| list-policies + get-account-authorization-details | Call both to get policy list | list-policies is redundant after GAAD migration; GAAD already returns `Policies[]` for LocalManagedPolicy and AWSManagedPolicy in the same call |

---

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Keeping per-resource loops AND adding the bulk call | No performance improvement; double API call count | Remove per-resource policy loops after confirming bulk call covers the same data | Every account — immediately doubles call count |
| Not scoping get-account-authorization-details with --filter | Fetching AWSManagedPolicy adds hundreds of entries to the response (~1000+ AWS-managed policies) increasing response size significantly without security value | Always pass `--filter User Role Group LocalManagedPolicy` to exclude AWS-managed policies from the bulk response | Every account — AWS has 1000+ managed policies; unfiltered response can be 10x larger |
| Inline jq accumulation loop for multi-page GAAD responses | Agent hangs or takes 5+ minutes on accounts with many principals across many pages | Use `--no-paginate` to let AWS CLI handle pagination automatically and return a single merged response | Accounts with > 100 principals per entity type |
| Per-snapshot loop in EC2 for describe-snapshot-attribute | Takes minutes on accounts with many snapshots | Batch snapshot attribute calls or limit to snapshots where tags/metadata suggest sensitivity | Accounts with > 50 snapshots |

---

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Logging the raw GAAD response to agent-log.jsonl | Inline policy documents contain full permission grants; logging to agent-log.jsonl exposes complete authorization state in a persistent file | Log only METRICS (counts), not raw API responses; existing agent-logger hook logs CLI invocations, not response bodies — verify this is preserved after migration |
| Dropping PasswordLastUsed from iam_user findings | Removes detection of dormant accounts with active credentials — a common lateral movement vector | Retain list-users for PasswordLastUsed even after moving policy collection to GAAD |
| Removing LoginProfile check when eliminating per-user loop | Users with console access but no MFA stop being flagged | Explicitly retain get-login-profile per user as a separate targeted loop even after bulk migration |

---

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| Agent reports STATUS: complete but silently dropped access key data | Operators trust audit results; attack paths built on incomplete data may miss HIGH-severity findings | Add a post-enum self-check (similar to EC2's IMDS check) that verifies access_keys arrays are populated when user count > 0 |
| METRICS shows fewer resources after bulk migration due to filter change | Operator assumes resource count changed, not the query | Document in agent that count changes after optimization reflect filter exclusions (e.g., AWSManagedPolicy filtered out) and note this in the STATUS summary line |
| Bulk call takes longer for paginated large accounts than expected | Operator assumes optimization made things faster | GAAD with `--no-paginate` on a 600-role account produces 10+ pages and can take 10-30 seconds; set expectations in agent output with a `[INFO] Fetching IAM bulk snapshot...` message |

---

## "Looks Done But Isn't" Checklist

- [ ] **GAAD access key gap:** IAM agent still calls `list-access-keys` per user — verify this call is retained and `access_keys[]` is populated in iam_user findings after migration
- [ ] **GAAD MFA gap:** IAM agent still calls `list-mfa-devices` per user — verify `has_mfa` is derived from this call, not from GAAD (GAAD does not include MFA devices)
- [ ] **GAAD login profile gap:** IAM agent still calls `get-login-profile` per user — verify `has_console_access` is derived from this call, not assumed false
- [ ] **Pagination complete:** `get-account-authorization-details` called with `--no-paginate` — verify `--no-paginate` flag is present in the Bash command
- [ ] **GAAD filter applied:** `--filter User Role Group LocalManagedPolicy` present — verify AWSManagedPolicy is excluded to avoid inflating response size
- [ ] **stdin piping:** Full GAAD response is piped via stdin (`echo "$GAAD" | jq ...`), not passed as `--argjson` — verify no ARG_MAX risk
- [ ] **Trust policy decoding test:** AssumeRolePolicyDocument arrives as a JSON object (not a string) in CLI v2 output — verify trust classification jq template still works without a URL-decode step
- [ ] **Schema validation still passes:** `node bin/validate-enum-output.js $RUN_DIR/iam.json` exits 0 after bulk migration
- [ ] **PasswordLastUsed retained:** `list-users` is still called for PasswordLastUsed field even if all policy data comes from GAAD
- [ ] **Attack path compatibility:** scope-attack-paths still receives `access_keys`, `has_mfa`, `has_console_access` in iam_user findings — these fields did not disappear from the output schema

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Access key / MFA data dropped from iam_user findings | MEDIUM | Re-add per-user `list-access-keys`, `list-mfa-devices`, `get-login-profile` loops; no schema change required; re-run audit |
| GAAD response truncated (missing --no-paginate) | LOW | Add `--no-paginate` flag to GAAD call; re-run audit |
| ARG_MAX failure on large accounts | LOW | Switch from `--argjson GAAD_RESPONSE` to stdin pipe pattern; test on smaller account first |
| jq template path mismatch (.Users[] vs .UserDetailList[]) | LOW | Fix path in jq template; validate output against known resource count |
| Double URL-decode corrupts policy documents | MEDIUM | Remove explicit URL-decode step; verify CLI v2 output format; re-run jq extraction; spot-check trust relationships for known roles |
| attack-paths agent produces no findings after IAM migration | HIGH | Diff old vs new iam.json output field by field; identify which fields went missing; restore missing data collection calls |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Access key / MFA / login profile gap in GAAD | Phase 1: IAM bulk migration | Diff iam.json before/after; verify access_keys populated for known users |
| AssumeRolePolicyDocument URL-encoding assumption | Phase 1: IAM bulk migration | Run jq trust extraction against real GAAD output; confirm trust_relationships non-empty for known cross-account roles |
| ManagedPolicyDetail two-level join requirement | Phase 1: IAM bulk migration | Verify inline policies appear in UserPolicyList/RolePolicyList; verify document content extraction if needed |
| Pagination truncation without --no-paginate | Phase 1: IAM bulk migration | Run on account with > 100 principals; compare resource count to list-roles output |
| ARG_MAX on large bulk response | Phase 1: IAM bulk migration | Test on account with 200+ roles; verify no `Argument list too long` error |
| jq path mismatch after collection path rename | Phase 1 (IAM) and each subsequent agent phase | Post-migration output parity test: compare finding counts against old output for same account |
| AWS-managed policy inflation without --filter | Phase 1: IAM bulk migration | Verify GAAD called with `--filter User Role Group LocalManagedPolicy` |
| Missing --no-paginate on other bulk calls in later phases | Phase 2+ (non-IAM agents) | Add pagination check to each agent's enumeration checklist |
| Per-snapshot loop performance in EC2 | Phase 2: Regional service optimization | Measure snapshot attribute loop time on account with 50+ snapshots; consider batching |

---

## Sources

- [GetAccountAuthorizationDetails API Reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html) — official field definitions, URL-encoding note, pagination behavior (HIGH confidence)
- [UserDetail type reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UserDetail.html) — confirmed absence of access key, login profile, and PasswordLastUsed fields (HIGH confidence)
- [get-account-authorization-details CLI reference](https://docs.aws.amazon.com/cli/latest/reference/iam/get-account-authorization-details.html) — --filter parameter, --no-paginate, IsTruncated behavior (HIGH confidence)
- [IAM and AWS STS quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html) — rate limit context (MEDIUM confidence — IAM API throttling limits are not publicly documented per-endpoint)
- [PMapper get-account-authorization-details optimization issue #26](https://github.com/nccgroup/PMapper/issues/26) — real-world report of 3MB/10-second response for 600 roles, 13 pages of pagination (MEDIUM confidence)
- [jq ARG_MAX issue #732](https://github.com/jqlang/jq/issues/732) — confirmed ARG_MAX breakage pattern when passing large JSON via shell args (HIGH confidence)
- [list-users PasswordLastUsed field documentation](https://docs.aws.amazon.com/cli/latest/reference/iam/list-users.html) — confirmed PasswordLastUsed is only in list-users and get-user, not GAAD (HIGH confidence)
- Existing scope-enum-iam.md agent code — current per-resource loop structure, jq template paths, ARG_MAX note already present in codebase (HIGH confidence — direct code inspection)

---
*Pitfalls research for: AWS bulk API migration — agentic IAM and multi-service enumeration optimization*
*Researched: 2026-03-25*
