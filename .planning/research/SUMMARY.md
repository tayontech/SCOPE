# Project Research Summary

**Project:** SCOPE v1.7 — Enumeration Efficiency Optimization
**Domain:** AWS API enumeration efficiency — bulk vs. per-resource call patterns across 12 service agents
**Researched:** 2026-03-25
**Confidence:** HIGH

## Executive Summary

SCOPE v1.7 is a targeted optimization milestone for the 12 parallel AWS enumeration subagents that underpin the audit pipeline. The core problem is that the existing agents use per-resource loops — calling individual detail APIs (get-role, list-access-keys, list-mfa-devices, etc.) for each resource returned by a list call. For large AWS accounts this produces hundreds or thousands of API round trips, creates rate limiting exposure, and extends audit wall-clock time significantly. Research confirms that only one service (IAM) has a purpose-built bulk API (`get-account-authorization-details`) that produces a dramatic reduction; all other services either already use optimal bulk patterns or have no batch alternative available at the AWS API level.

The recommended approach is a phased migration starting with IAM (highest ROI — collapses ~285 calls into ~3 for a typical 50-user account), followed by a confirmation pass on already-optimal agents (Lambda, Secrets, EC2, RDS), and finally minor pagination/filter improvements for the irreducible per-resource loops (KMS, SNS, SQS, API Gateway). CodeBuild and STS require no changes — they are already at the minimum possible call count. The output schema must be preserved exactly throughout; downstream consumers (scope-attack-paths, dashboard) parse specific fields by name and will silently break if any field is dropped or renamed.

The dominant risk is in the IAM migration: `get-account-authorization-details` does NOT return access key metadata, MFA device status, or login profile (console access). A naive replacement of all per-user loops silently drops exactly the fields that drive HIGH-severity attack path findings (`access_keys[].status`, `has_mfa`, `has_console_access`). This pitfall is the most consequential in the project — schema validation will pass even with the data missing. Mitigation is straightforward: retain targeted per-user calls for credential state fields while using the bulk API for policy and group membership data only.

## Key Findings

### Recommended Stack

SCOPE's 12 enumeration agents are bash scripts using AWS CLI v2 with inline jq processing. This is the correct tool selection for agentic subagents operating within `maxTurns: 25` constraints. No stack changes are required for v1.7. The optimization is entirely at the API call pattern level, not at the tooling level. Python subprocess wrappers (boto3 asyncio) would improve raw throughput but are explicitly anti-pattern for SCOPE agents — they bypass the safety hooks' Bash pattern matching and introduce dependency/error-propagation risks incompatible with the agent model.

**Core technologies:**
- `aws iam get-account-authorization-details`: IAM bulk API — replaces 4 separate list calls plus N×5 per-resource calls for policy/group data
- `aws iam generate-credential-report` + `get-credential-report`: Two-call credential state bulk fetch — replaces per-user login-profile and MFA device loops
- AWS CLI v2 auto-pagination (`--output json` without `--no-paginate`): Already in use; `--no-paginate` must be added explicitly for `get-account-authorization-details` to ensure complete results
- `jq` stdin piping (`echo "$VAR" | jq ...`): Required for large bulk responses to avoid ARG_MAX limits on macOS (256KB) and Linux (2MB)

### Expected Features

**Must have (table stakes):**
- IAM bulk auth details via `get-account-authorization-details` — canonical "one call for all IAM principals" API; used by Prowler and ScoutSuite; primary stated goal of v1.7
- Preserve existing output schema exactly — zero-tolerance constraint; downstream consumers (attack-paths, dashboard) have hard field dependencies
- Explicit `--no-paginate` on all bulk calls — silent data loss if missed; omission only manifests on large accounts
- Retain per-user credential calls (list-access-keys, list-mfa-devices, get-login-profile) — not in bulk response; required for has_mfa, has_console_access, access_keys fields
- Apply `--filter User Role Group LocalManagedPolicy` to GAAD call — prevents AWS-managed policy inflation (1000+ entries) that can 10x response size

**Should have (competitive):**
- Add `role_last_used` field from `RoleDetailList[].RoleLastUsed` — available for free in bulk call, useful for attack path reasoning, purely additive schema extension
- KMS early-exit when `list-keys` returns zero keys — low-cost reliability improvement
- Per-agent confirmation pass on agents already believed optimal (Lambda, Secrets, EC2, RDS) — documents correctness and closes any undiscovered gaps

**Defer (v2+):**
- IAM credential report CSV integration as replacement for per-user credential calls — async polling with unpredictable duration is incompatible with `maxTurns: 25` agent constraint
- Intra-agent parallelism for SNS/SQS/KMS per-resource loops — requires bash background job management; fragile in agentic context; SCOPE parallelism is at the agent level, not within agents

### Architecture Approach

All 12 agents follow the same 6-phase pattern: Enumerate → Extract → Analyze → Combine → Write → Validate. The optimization operates entirely in Phase 1 (Enumerate) — changing which AWS CLI calls are made and how responses are structured. Phases 2-6 are unchanged. The `TRUST_CLASSIFY_JQ` inline function, the `FINDINGS_JSON` combine step, the `module-envelope.schema.json` validation, and the `scope-attack-paths` integration contract are all unaffected by the bulk API migration as long as the output field names and types are preserved.

**Major components:**
1. **IAM agent (scope-enum-iam.md)** — Tier 1 target; replace per-user/role/group policy loops with GAAD; retain credential-state per-user calls; URL-decode handling for AssumeRolePolicyDocument is a non-issue with CLI v2 (auto-decoded), but must be tested empirically
2. **Regional service agents (Lambda, Secrets, KMS, SNS, SQS, API Gateway, EC2, RDS, CodeBuild)** — Tier 2/3; most already optimal or have only minor pagination improvements available; confirmation pass establishes documented baseline
3. **Downstream consumers (scope-attack-paths, dashboard, scope-pipeline)** — Read-only contract; output schema is the interface; no changes to these components in v1.7

### Critical Pitfalls

1. **GAAD does not return access keys, MFA status, or login profile** — silently drops HIGH-severity attack path inputs; schema validation passes with empty arrays; retain `list-access-keys`, `list-mfa-devices`, `get-login-profile` per user even after bulk migration

2. **AssumeRolePolicyDocument encoding: test before assuming** — architecture research notes URL-encoding is transparently handled by CLI v2 (`--output json`); pitfalls research flags the inverse mistake (adding an unnecessary decode step and double-decoding); the correct action is to test empirically and remove the existing agent comment that says "always use get-role for decoded policy" — do not add a URL-decode step until testing confirms one is needed

3. **Pagination truncation without --no-paginate produces silent data loss** — GAAD defaults to 100 items/page; without `--no-paginate`, large accounts get partial results with `STATUS: complete`; add `--no-paginate` flag and a post-call assertion checking for `IsTruncated`

4. **ARG_MAX failure on large bulk responses** — macOS limit is 256KB; GAAD for enterprise accounts can be 3-10MB; never pass the full GAAD response as `--argjson`; always pipe via stdin (`echo "$GAAD" | jq ...`)

5. **jq path mismatch after collection path rename** — `list-users` uses `.Users[]`; GAAD uses `.UserDetailList[]`; partial template updates leave mismatched paths that silently return empty arrays without jq errors; run `node bin/validate-enum-output.js` against real output after every template change

## Implications for Roadmap

Based on research, suggested phase structure:

### Phase 1: IAM Bulk Migration
**Rationale:** IAM is the single highest-ROI optimization in the codebase — ~285 API calls reduced to ~3 for a typical account. All 6 critical pitfalls are concentrated here. Must be completed and verified before touching other agents to establish the output parity testing methodology.
**Delivers:** Dramatically reduced IAM enumeration time; `get-account-authorization-details` as primary IAM data source; retained per-user credential calls; optional `role_last_used` field addition
**Addresses:** IAM bulk auth (P1 table stakes), schema preservation, pagination correctness, GAAD filter application
**Avoids:** Pitfalls 1-6 (all are IAM-specific); ARG_MAX failure; silent data loss on credential fields
**Must verify:** Diff iam.json before/after on a real account with known users; confirm `access_keys`, `has_mfa`, `has_console_access` populated; trust_relationships non-empty for cross-account roles

### Phase 2: Confirmed-Optimal Agent Pass
**Rationale:** Research indicates Lambda, Secrets, EC2, and RDS agents are already at or near optimal call patterns. A formal confirmation pass closes any undiscovered gaps and produces documented baseline for each agent. No breaking changes expected.
**Delivers:** Documented confirmation that 4 agents are already optimal; any discovered gaps fixed; RDS snapshot public access bug resolved (jq template references `.DBSnapshotAttributes` which doesn't exist in `describe-db-snapshots` response — will always return `publicly_accessible: false`)
**Uses:** Direct agent code inspection + AWS API reference cross-check
**Implements:** Loop-with-consolidated-input pattern verification (Pattern 2 from architecture research)
**Key fix:** RDS snapshot public access check — requires adding `describe-db-snapshot-attributes` per-snapshot call; currently silently returns false for all snapshots

### Phase 3: Regional Service Optimization
**Rationale:** KMS, SNS, SQS, and API Gateway have no batch API alternatives but have minor pagination and filter improvements. Group together as they follow the same "unavoidable per-resource loop, optimize pagination" pattern.
**Delivers:** Pagination parameters tuned; KMS `--key-filters CUSTOMER_MANAGED` filter verified (MEDIUM confidence — added to AWS CLI in 2023, needs live test); API Gateway confirms `.items[].policy` extraction without redundant `get-rest-api` call; KMS early-exit on empty key list
**Avoids:** Pagination truncation pitfall on regional services; wasted `describe-key` calls on AWS-managed keys
**Note:** No API call count reduction possible for SNS and SQS — `get-topic-attributes` and `get-queue-attributes` are single-resource APIs with no batch equivalent; loop is already minimal

### Phase Ordering Rationale

- IAM first because it has the largest optimization gap, all pitfalls are concentrated there, and the testing methodology (diff before/after on real account) established here applies to all subsequent phases
- Confirmed-optimal pass second because it resolves the RDS snapshot bug (a correctness issue, not a performance issue) and closes documentation gaps before the regional optimization pass
- Regional services last because they have the lowest ROI (no API count reduction, only minor pagination tuning) and no correctness bugs that compromise security findings

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 1 (IAM):** AssumeRolePolicyDocument encoding behavior with CLI v2 must be empirically tested before jq template changes — architecture and pitfalls research give conflicting guidance on whether a decode step is needed
- **Phase 1 (IAM):** Credential report polling behavior within `maxTurns: 25` constraint — async job takes 5-15 seconds; feasibility as a per-user MFA/console alternative needs evaluation
- **Phase 3 (KMS):** `--key-filters KeyType=CUSTOMER_MANAGED` availability — MEDIUM confidence only; verify against live account before baking into agent

Phases with standard patterns (skip research-phase):
- **Phase 2 (confirmation pass):** Code inspection and AWS API reference lookup only; no novel integration
- **Phase 3 (SNS, SQS):** Confirmed no batch API exists; pagination parameter addition is trivial

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All API references verified against official AWS documentation; AWS CLI v2 behavior confirmed via SDK issues and CLI reference |
| Features | HIGH | Based on direct inspection of existing agent code + official AWS API documentation + cross-reference with Prowler, ScoutSuite, Steampipe behavior |
| Architecture | HIGH | Direct code inspection of all 12 scope-enum-*.md files; AWS API reference for all bulk call response shapes |
| Pitfalls | HIGH | GAAD field gaps confirmed via UserDetail type reference; ARG_MAX pattern confirmed via jq issue tracker; PMapper real-world response size data |

**Overall confidence:** HIGH

### Gaps to Address

- **AssumeRolePolicyDocument CLI v2 auto-decode behavior:** Architecture research says CLI v2 auto-decodes (no decode step needed); pitfalls research warns about adding a decode step from other sources. Resolve empirically: run `aws iam get-account-authorization-details --output json` against a test account and inspect whether `.RoleDetailList[0].AssumeRolePolicyDocument` is a JSON object or a string.

- **KMS `--key-filters KeyType=CUSTOMER_MANAGED` availability:** Listed as MEDIUM confidence — parameter appears in recent CLI docs but was not confirmed via official API reference fetch. Test against a live account with a mix of AWS-managed and customer-managed keys before including in agent.

- **`generate-credential-report` polling within maxTurns constraint:** The credential report approach is the architecturally cleanest replacement for per-user MFA/login-profile calls, but the async polling pattern (poll until COMPLETE, max 4-hour cache interval) may be impractical within the agent's `maxTurns: 25` limit. Evaluate feasibility as part of Phase 1 planning; if infeasible, retain the per-user `list-mfa-devices` and `get-login-profile` loop without change.

- **RDS snapshot public access — confirmed bug:** The RDS agent's jq template references `.DBSnapshotAttributes` on snapshot objects returned by `describe-db-snapshots`. This field does not exist in that response. All RDS snapshot public access checks currently return `false` regardless of actual permissions. Fixing requires adding `describe-db-snapshot-attributes` per snapshot, analogous to EC2's `describe-snapshot-attribute` loop. Address in Phase 2.

## Sources

### Primary (HIGH confidence)
- [GetAccountAuthorizationDetails API Reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html) — returned fields, pagination, URL-encoding behavior
- [UserDetail type reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UserDetail.html) — confirmed absence of access key, login profile, PasswordLastUsed
- [ListFunctions API Reference](https://docs.aws.amazon.com/lambda/latest/api/API_ListFunctions.html) — environment variables in list response, 50/page limit
- [DescribeSnapshots API Reference](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshots.html) — `--restorable-by-user-ids all` filter pattern
- [BatchGetProjects API Reference](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_BatchGetProjects.html) — 100 project limit per call
- [IAM Credential Reports](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html) — report fields, generation timing
- Direct code inspection of all 12 scope-enum-*.md files

### Secondary (MEDIUM confidence)
- [PMapper get-account-authorization-details optimization issue #26](https://github.com/nccgroup/PMapper/issues/26) — real-world 3MB/10-second response for 600 roles, 13 pages
- [ScoutSuite Resources Fetching System Architecture](https://github.com/nccgroup/ScoutSuite/wiki/Resources-fetching-system-architecture) — facade pattern with bulk caching
- [Prowler parallel execution documentation](https://docs.prowler.com/user-guide/cli/tutorials/parallel-execution) — retry and parallel execution patterns
- [KMS ListKeys API Reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html) — `--key-filters` availability uncertain; parameter appears in recent docs

### Tertiary (LOW confidence)
- AWS SDK Go v2 Issue #227 — AssumeRolePolicyDocument URL-encoding behavior in GetAccountAuthorizationDetails (contradicted by architecture research that CLI v2 auto-decodes; needs empirical test)

---
*Research completed: 2026-03-25*
*Ready for roadmap: yes*
