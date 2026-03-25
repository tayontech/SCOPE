# Roadmap: SCOPE v1.7 — Enumeration Efficiency

## Overview

Three phases that systematically reduce API call overhead across all 12 enumeration agents. Phase 1 targets IAM — the single highest-ROI change in the codebase — and establishes the output parity testing methodology. Phase 2 audits all remaining agents, fixes correctness bugs, and applies minor performance patterns. Phase 3 adds regional parallelism and validates full output compatibility before the milestone closes.

## Milestones

- 🚧 **v1.7 Enumeration Efficiency** - Phases 1-3 (in progress)

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: IAM Bulk Migration** - Replace per-resource IAM loops with `get-account-authorization-details` bulk API while retaining credential-state calls
- [ ] **Phase 2: Agent Correctness and Performance Pass** - Audit all 12 agents, fix RDS/EC2 snapshot correctness bugs, apply O(n^2) elimination and inner-scan patterns
- [ ] **Phase 3: Regional Optimization and Compatibility Validation** - Parallelize regional agents, validate all modified agents against output schemas

## Phase Details

### Phase 1: IAM Bulk Migration
**Goal**: The IAM enumeration agent fetches all principals, groups, and policies in a single bulk API call instead of per-resource loops, while retaining targeted per-user credential-state calls for fields not included in the bulk response
**Depends on**: Nothing (first phase)
**Requirements**: IAM-01, IAM-02, IAM-03, IAM-04, PAGE-01, PAGE-02, PERF-01
**Success Criteria** (what must be TRUE):
  1. Running `/scope:audit iam` against a real AWS account produces output with `access_keys`, `has_mfa`, and `has_console_access` fields populated — none are empty or false by default
  2. The IAM agent issues `get-account-authorization-details` with `--filter User Role Group LocalManagedPolicy` and the raw response is piped via stdin to jq (never passed as `--argjson`). Note: `--no-paginate` is NOT used — AWS CLI v2 auto-paginates by default; adding `--no-paginate` would silently truncate results.
  3. `trust_relationships` is non-empty for cross-account roles in the output — AssumeRolePolicyDocument decoded correctly
  4. Diffing `iam.json` before and after migration against the same account shows no field regressions — all previously populated fields remain populated
**Plans:** 3/3 plans complete

Plans:
- [x] 01-01-PLAN.md — Foundation: create shared validator and test AssumeRolePolicyDocument encoding
- [x] 01-02-PLAN.md — Core migration: rewrite IAM agent with GAAD primary path and fallback
- [x] 01-03-PLAN.md — Verification: automated checks and human verification against real AWS account

### Phase 2: Agent Correctness and Performance Pass
**Goal**: All 12 enumeration agents are audited against their current API call patterns, correctness bugs in RDS and EC2 snapshot public-access checks are fixed, and O(n^2) jq array building and redundant inner scans are eliminated across Secrets and Lambda agents
**Depends on**: Phase 1
**Requirements**: AFIX-01, AFIX-02, PERF-02, PERF-03, EAUD-01
**Success Criteria** (what must be TRUE):
  1. RDS snapshot output includes correct `publicly_accessible` values — the field is no longer always `false` for snapshots; verified by comparing `describe-db-snapshot-attributes` API response against agent output
  2. EC2 public snapshot detection uses `describe-snapshots --restorable-by-user-ids all` instead of a per-snapshot `describe-snapshot-attribute` loop
  3. An audit document exists for all 12 agents recording current API call count vs. optimized call count, with changes applied or change rationale where no optimization is possible
  4. Lambda and Secrets agents iterate the list response once in jq — no inner `select()` re-scans over the same array
**Plans:** 2/4 plans executed

Plans:
- [ ] 02-01-PLAN.md — Audit document for all 12 agents + RDS snapshot correctness fix
- [ ] 02-02-PLAN.md — EC2 snapshot bulk filter + ELBv2 listener loop + region O(n^2) fix
- [ ] 02-03-PLAN.md — Secrets and Lambda inner select() elimination + O(n^2) fix
- [ ] 02-04-PLAN.md — O(n^2) elimination in S3, KMS, SNS, SQS, API Gateway

### Phase 3: Regional Optimization and Compatibility Validation
**Goal**: Regional enumeration agents run region iteration in parallel where possible, and all agents modified across phases 1 and 2 produce output that conforms to existing JSON schemas and passes automated validation
**Depends on**: Phase 2
**Requirements**: PERF-04, COMPAT-01, COMPAT-02
**Success Criteria** (what must be TRUE):
  1. Regional agents (EC2, Lambda, RDS, API Gateway, KMS, SNS, SQS) iterate over AWS regions using background subshells and `wait` — region results collected and merged rather than processed sequentially
  2. Running `bin/validate-enum-output.js` against all modified agents produces zero validation failures
  3. The attack-paths agent and dashboard consume all modified agent outputs without field errors — no downstream breakage from the optimization changes
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. IAM Bulk Migration | 3/3 | Complete    | 2026-03-25 |
| 2. Agent Correctness and Performance Pass | 2/4 | In Progress|  |
| 3. Regional Optimization and Compatibility Validation | 0/TBD | Not started | - |
