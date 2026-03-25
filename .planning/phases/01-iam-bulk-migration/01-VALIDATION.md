---
phase: 1
slug: iam-bulk-migration
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-25
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Node.js (no test framework — direct script validation) |
| **Config file** | `bin/validate-enum-output.js` (Wave 0 — does not yet exist) |
| **Quick run command** | `node bin/validate-enum-output.js $RUN_DIR/iam.json` |
| **Full suite command** | `node bin/validate-enum-output.js $RUN_DIR/iam.json && echo "Schema: OK"` |
| **Estimated runtime** | ~1 second |

---

## Sampling Rate

- **After every task commit:** Run `node bin/validate-enum-output.js $RUN_DIR/iam.json`
- **After every plan wave:** Run full suite — schema validation + count assertions
- **Before `/gsd:verify-work`:** Full suite must be green on real AWS account output
- **Max feedback latency:** 2 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 01-01 | 01 | 0 | COMPAT-02 | unit | `node bin/validate-enum-output.js test-fixtures/iam.json` | ❌ W0 | ⬜ pending |
| 01-02 | 02 | 1 | IAM-01 | smoke | `jq '.UserDetailList \| length' gaad-output.json` | ❌ W0 | ⬜ pending |
| 01-03 | 02 | 1 | IAM-03 | smoke | `jq '[.findings[] \| select(.resource_type=="iam_role" and (.trust_relationships \| length > 0))] \| length' $RUN_DIR/iam.json` | ❌ W0 | ⬜ pending |
| 01-04 | 02 | 1 | IAM-04 | unit | `jq '[.findings[] \| select(.resource_type=="iam_policy" and .is_aws_managed==true)] \| length == 0' $RUN_DIR/iam.json` | ❌ W0 | ⬜ pending |
| 01-05 | 03 | 1 | IAM-02 | smoke | `jq '[.findings[] \| select(.resource_type=="iam_user") \| .access_keys] \| length > 0' $RUN_DIR/iam.json` | ❌ W0 | ⬜ pending |
| 01-06 | 03 | 3 | PERF-01 | static | `grep -n "\-\-argjson" agents/subagents/scope-enum-iam.md` (expect no GAAD arg) | ❌ W0 | ⬜ pending |
| 01-07 | 03 | 3 | PAGE-01 | static | `grep -n "no-paginate" agents/subagents/scope-enum-iam.md` (expect zero results) | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `bin/validate-enum-output.js` — shared validation tool; validates envelope + required finding fields (resource_type, resource_id, arn, region, findings)
- [ ] AssumeRolePolicyDocument empirical test — run `aws iam get-account-authorization-details --filter Role --max-items 1 --output json | jq '.RoleDetailList[0].AssumeRolePolicyDocument | type'` to determine if CLI v2 auto-decodes

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| GAAD resource count matches per-service list counts | PAGE-01 | Requires live AWS account | Compare `jq '.UserDetailList \| length'` on GAAD vs `aws iam list-users \| jq '.Users \| length'` |
| Fallback path fires on AccessDenied | IAM-01 | Requires restricted AWS credentials | Run audit with creds lacking `iam:GetAccountAuthorizationDetails` |
| No field regressions in iam.json | ALL | Requires before/after diff on same account | Diff old vs new `iam.json` for field presence |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 2s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
