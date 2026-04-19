# Requirements: SCOPE v1.13 Prompt Architecture & Hardening

**Defined:** 2026-04-18
**Core Value:** Every agent produces consistent, schema-validated output that downstream agents and the dashboard can consume without normalization workarounds

## v1.13 Requirements

### Prompt Architecture (PROM)

- [x] **PROM-01**: `install.js` supports `!INCLUDE` directives for shared content injection and tier-based model declarations (`model: reasoning`, `model: enum`, `model: inherit`) — source files are platform-agnostic, install.js resolves to vendor-specific model names per platform
- [ ] **PROM-02**: Shared verification protocol, evidence logging, session isolation, and mandatory outputs extracted to `agents/shared/` and included by pointer from each agent that uses them
- [ ] **PROM-03**: Enum output contract (jq write template, logging boilerplate, validation) centralized to a single shared reference — 12 agents reference it instead of repeating 30+ identical lines each
- [ ] **PROM-04**: scope-defend intake consolidated from 3 overlapping sections (invocation_modes, autonomous_mode, workflow Steps 1-2) to single `<intake_protocol>`
- [ ] **PROM-05**: Role/context blocks across all agents compressed to core mandates (read-only, standard node IDs, no auto-deploy) — eliminate repeated project context paragraphs
- [ ] **PROM-06**: Reference tables (SPL templates, CloudTrail fields, escalation catalogue) moved to config files and loaded at runtime via tool calls instead of prompt-embedded

### Deterministic Extraction (DET)

- [ ] **DET-01**: Phase A graph construction extracted from attack-paths prompt to `bin/extract-graph.js` — agents invoke the script instead of reproducing jq pipelines
- [ ] **DET-02**: Pipeline guards added: empty-variable checks after each major extraction step with fail-fast behavior on silent failures
- [ ] **DET-03**: Operator-provided path arguments sanitized before shell use — restricted to `./audit/`, `./exploit/`, `./engagements/` prefixes
- [ ] **DET-04**: Credential isolation for cross-account hops — subshell-scoped temporary credentials with `AWS_CONFIG_FILE` scoping to prevent `/proc` filesystem exposure on crash

### IAM Simulator (SIM)

- [ ] **SIM-01**: `bin/simulate-access.sh` wrapper with retry logic, `OrganizationsDecisionDetail` checking, batch support (up to 200 actions per call), and cross-path action deduplication to minimize API calls
- [ ] **SIM-02**: Exploit permission discovery integrates simulator as Stage 2.5 between policy self-read and noisy probes
- [ ] **SIM-03**: Attack-paths runs simulation against required actions in top candidate paths before writing to results.json — upgrades Conditional claims to Guaranteed or filters them out
- [ ] **SIM-04**: Graceful degradation — AccessDenied on `simulate-principal-policy` falls back to existing reasoning with confidence cap

### Testing (TEST)

- [ ] **TEST-02**: Phase A extraction regression tests — fixture-based tests using known-good enum JSON that verify `bin/extract-graph.js` produces identical graph output to the inline jq pipeline

## Future Requirements

### Defensive Simulation (DSIM)

- **DSIM-01**: `SimulateCustomPolicy` integration in scope-defend to validate generated SCP/IAM remediation against actual principals before recommending

### Testing (TEST)

- **TEST-01**: Fixture-based integration tests (IAM-only, zero-findings, partial-failure, cross-account) with assertions on artifact existence and count consistency

## Out of Scope

| Feature | Reason |
|---------|--------|
| Concurrent index.json file locking | Single-operator usage pattern — low priority |
| Dashboard normalization workaround removal | Depends on prompt architecture stabilizing first |
| New hook creation (blocked-op logging) | Future — current hooks are sufficient |
| Hunt memory/learning pipeline | Deferred — needs dedicated design for multi-environment isolation |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| PROM-01 | 57 | Complete |
| PROM-02 | 58 | Pending |
| PROM-03 | 58 | Pending |
| PROM-04 | 59 | Pending |
| PROM-05 | 58 | Pending |
| PROM-06 | 60 | Pending |
| DET-01 | 61 | Pending |
| DET-02 | 61 | Pending |
| DET-03 | 62 | Pending |
| DET-04 | 62 | Pending |
| SIM-01 | 63 | Pending |
| SIM-02 | 64 | Pending |
| SIM-03 | 64 | Pending |
| SIM-04 | 64 | Pending |
| TEST-02 | 61 | Pending |

**Coverage:**
- v1.13 requirements: 15 total
- Mapped to phases: 15
- Unmapped: 0

---
*Requirements defined: 2026-04-18*
*Last updated: 2026-04-18 — traceability updated after roadmap definition (phases 57–64)*
