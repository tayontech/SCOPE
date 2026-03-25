---
phase: 01-iam-bulk-migration
plan: "02"
subsystem: security-tooling
tags: [iam, aws-cli, jq, bash, gaad, enumeration, agent]

# Dependency graph
requires:
  - phase: 01-iam-bulk-migration/01-01
    provides: "bin/validate-enum-output.js — shared enum validator; 01-DECODE-FINDING.md — AssumeRolePolicyDocument is object in CLI v2"
provides:
  - "agents/subagents/scope-enum-iam.md — fully rewritten IAM enum agent with GAAD primary path and per-resource fallback"
  - ".planning/phases/01-iam-bulk-migration/test-fixtures/valid-iam.json — test fixture for iam.json output shape"
affects:
  - "01-03 and later — GAAD migration pattern established; other enum agents can reference this rewrite"
  - "scope-audit orchestrator — IAM enum subagent output shape is stable and validated"
  - "scope-attack-paths — inline_policies, attached_policy_documents, role_last_used now available for path analysis"

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "GAAD primary path: get-account-authorization-details replaces ~520 per-resource list+get calls with ~4 + 3N credential-state calls"
    - "Temp-file append pattern: write intermediate extraction results to $RUN_DIR/raw/ files, combine with jq -s — avoids O(n^2) jq accumulation and ARG_MAX limits"
    - "stdin piping for bulk data: pass large JSON to jq via file argument or stdin, never --argjson for GAAD response"
    - "Fallback path: GAAD AccessDenied triggers per-resource loops with identical output shape; STATUS=complete when all data collected regardless of path"
    - "Defensive AssumeRolePolicyDocument decode: runtime type check handles both CLI v1 (URL-encoded string) and CLI v2 (parsed object)"

key-files:
  created:
    - .planning/phases/01-iam-bulk-migration/test-fixtures/valid-iam.json
  modified:
    - agents/subagents/scope-enum-iam.md

key-decisions:
  - "GAAD path does not include group member lists — retain per-group get-group calls for member enumeration; GAAD GroupDetailList omits members"
  - "PasswordLastUsed requires separate list-users call in GAAD path — GAAD UserDetailList omits this field; single extra call, not per-user loop"
  - "Fallback status semantics: STATUS=complete when all resource data is collected via fallback; STATUS=partial only when specific resource type list calls return AccessDenied — path choice (GAAD vs fallback) does not affect completeness status"
  - "Output Contract section preserved verbatim from original — --argjson findings for final combined output is acceptable (processed output, not raw GAAD bulk response)"

patterns-established:
  - "IAM GAAD migration pattern: bulk call → per-group member calls → per-user credential-state → jq -s combine on temp files"
  - "Fallback parity rule: fallback path must produce identical output shape including all new enrichment fields"

requirements-completed: [IAM-01, IAM-02, IAM-04, PAGE-02, PERF-01]

# Metrics
duration: 4min
completed: "2026-03-25"
---

# Phase 01 Plan 02: IAM GAAD Bulk Migration Summary

**scope-enum-iam.md rewritten with get-account-authorization-details as primary data source — replaces ~520 per-resource API calls with ~4 + 3N credential-state calls, adds inline_policies/attached_policy_documents/role_last_used enrichment, and retains exact output contract**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-25T16:04:08Z
- **Completed:** 2026-03-25T16:08:46Z
- **Tasks:** 2
- **Files modified:** 2 (1 modified + 1 created)

## Accomplishments

- Rewrote `agents/subagents/scope-enum-iam.md` with GAAD as the primary data source using `--filter User Role Group LocalManagedPolicy` — eliminates the per-resource list+get loop pattern for users, roles, groups, and policies
- Added automatic fallback to per-resource loops on GAAD AccessDenied — fallback produces identical output shape with all enrichment fields; STATUS=complete when data is collected successfully regardless of path
- Added three new enrichment fields (inline_policies, attached_policy_documents, role_last_used) available in both GAAD primary and fallback paths
- Retained per-user credential-state calls (list-access-keys, list-mfa-devices, get-login-profile) that GAAD omits — these fields drive HIGH-severity attack path findings
- Used temp-file append pattern and stdin piping throughout — no O(n^2) jq accumulation, no --argjson for bulk responses
- Created test fixture at `test-fixtures/valid-iam.json` with all 4 IAM resource types and verified it passes `bin/validate-enum-output.js`

## Task Commits

Each task was committed atomically:

1. **Task 1: Rewrite scope-enum-iam.md with GAAD primary path** — `a41905b` (feat)
2. **Task 2: Create test fixture and validate rewritten agent structure** — `162f787` (feat)

**Plan metadata:** (docs commit — see final_commit step)

## Files Created/Modified

- `/Users/tayvionp/SCOPE/agents/subagents/scope-enum-iam.md` — Fully rewritten IAM enumeration agent; GAAD primary path + per-resource fallback; per-user credential-state retained; 3 new enrichment fields; temp-file pattern; stdin piping; defensive CLI v1/v2 type check for AssumeRolePolicyDocument
- `/Users/tayvionp/SCOPE/.planning/phases/01-iam-bulk-migration/test-fixtures/valid-iam.json` — Minimal valid iam.json fixture with all 4 resource types and all new fields; validates with exit 0 against bin/validate-enum-output.js

## Decisions Made

- GAAD GroupDetailList omits group member lists — retain per-group `get-group` calls specifically for member enumeration. This is a single loop but necessary for correctness.
- PasswordLastUsed requires a separate `list-users` call in the GAAD path. GAAD UserDetailList does not include this field. Added as a single bulk call (not per-user loop), keeping the API call count increase minimal.
- Fallback path STATUS semantics: STATUS reflects data completeness, not which path was used. Fallback sets STATUS=complete when all data is collected. Only sets STATUS=partial when a specific resource type's list call returns AccessDenied (making that resource's findings empty).
- Output Contract preserved verbatim including `--argjson findings "$FINDINGS_JSON"` — the plan requires the Output Contract section to be unchanged, and FINDINGS_JSON is the processed output (not the raw GAAD bulk response), so this is acceptable per the plan's constraint.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

- `.planning/` directory is gitignored — required `git add -f` for the test fixtures file. Consistent with Plan 01 behavior and expected.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `agents/subagents/scope-enum-iam.md` is ready for live AWS testing against a real account
- The GAAD migration pattern (bulk call + temp-file append + jq -s combine) is established and can be referenced for other enum agents in future phases
- Requirements IAM-01, IAM-02, IAM-04, PAGE-02, PERF-01 are complete
- IAM-03 was completed in Plan 01 (AssumeRolePolicyDocument encoding finding)
- Remaining blocker: KMS `--key-filters KeyType=CUSTOMER_MANAGED` confidence (noted in STATE.md) is not IAM-related and does not block further IAM work

---
*Phase: 01-iam-bulk-migration*
*Completed: 2026-03-25*
