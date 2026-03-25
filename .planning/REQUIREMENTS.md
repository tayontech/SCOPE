# Requirements: SCOPE v1.7 Enumeration Efficiency

**Defined:** 2026-03-25
**Core Value:** Complete purple team coverage from a single command — enumeration through defense, with no manual handoffs

## v1.7 Requirements

### IAM Optimization

- [ ] **IAM-01**: IAM agent uses `get-account-authorization-details` instead of per-resource list+get loops for users, roles, groups, and policies
- [ ] **IAM-02**: IAM agent retains per-user credential-state calls (list-access-keys, list-mfa-devices, get-login-profile) since GAAD omits these fields
- [x] **IAM-03**: IAM agent handles `AssumeRolePolicyDocument` encoding correctly from GAAD response
- [ ] **IAM-04**: IAM agent uses `--filter User Role Group LocalManagedPolicy` to exclude AWS-managed policies from GAAD response

### Pagination

- [x] **PAGE-01**: All enumeration agents handle pagination correctly — no silent truncation of results
- [ ] **PAGE-02**: Agents use `--no-paginate` or implement NextToken/Marker loops for all list/describe calls that paginate

### Performance Patterns

- [ ] **PERF-01**: All agents pipe large JSON via stdin instead of `--argjson` to avoid ARG_MAX limits
- [ ] **PERF-02**: All agents replace O(n^2) incremental jq array building with temp-file append + final `jq -s` merge
- [ ] **PERF-03**: Secrets and Lambda agents eliminate inner `select()` re-scans by iterating list response once in jq
- [ ] **PERF-04**: Regional agents parallelize region iteration where possible (background subshells with `wait`)

### Agent Fixes

- [ ] **AFIX-01**: RDS agent fixes silent false for `publicly_accessible` on snapshots by adding `describe-db-snapshot-attributes` call
- [ ] **AFIX-02**: EC2 agent replaces per-snapshot `describe-snapshot-attribute` loop with `describe-snapshots --restorable-by-user-ids all` filter

### Enumeration Efficiency Audit

- [ ] **EAUD-01**: All 12 enumeration agents audited — each agent's API call pattern documented with current call count vs optimized

### Output Compatibility

- [ ] **COMPAT-01**: All modified agents produce output conforming to existing JSON schemas — no downstream breakage
- [ ] **COMPAT-02**: All modified agents pass `bin/validate-enum-output.js` validation after changes

## Future Requirements

### Credential Report Integration

- **CRED-01**: IAM agent uses `generate-credential-report` + `get-credential-report` for MFA/login profile instead of per-user calls
- **CRED-02**: Output parity testing — automated comparison of old vs new output to verify no data loss

## Out of Scope

| Feature | Reason |
|---------|--------|
| New enumeration agents or AWS services | Focus is optimizing existing 12 |
| Changes to attack-paths, defend, exploit, investigate agents | Enumeration-only milestone |
| Dashboard changes | Output schema remains the same |
| Credential report integration | Deferred — polling feasibility within agent turn budget needs investigation |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| IAM-01 | Phase 1 | Pending |
| IAM-02 | Phase 1 | Pending |
| IAM-03 | Phase 1 | Complete |
| IAM-04 | Phase 1 | Pending |
| PAGE-01 | Phase 1 | Complete |
| PAGE-02 | Phase 1 | Pending |
| PERF-01 | Phase 1 | Pending |
| PERF-02 | Phase 2 | Pending |
| PERF-03 | Phase 2 | Pending |
| PERF-04 | Phase 3 | Pending |
| AFIX-01 | Phase 2 | Pending |
| AFIX-02 | Phase 2 | Pending |
| EAUD-01 | Phase 2 | Pending |
| COMPAT-01 | Phase 3 | Pending |
| COMPAT-02 | Phase 3 | Pending |

**Coverage:**
- v1.7 requirements: 15 total
- Mapped to phases: 15
- Unmapped: 0

---
*Requirements defined: 2026-03-25*
*Last updated: 2026-03-25 after roadmap creation*
