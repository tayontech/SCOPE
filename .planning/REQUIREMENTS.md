# Requirements: SCOPE v1.8 Attack Reasoning

**Defined:** 2026-03-26
**Core Value:** Every agent, reference, and cross-platform config must be correct and tested — a single broken reference or wrong invocation syntax means an operator's security workflow silently fails.

## v1.8 Requirements

Requirements for v1.8 milestone. Each maps to roadmap phases.

### Externalization

- [x] **EXTL-01**: Escalation catalogue (50 methods + 7 chains) externalized to `config/escalation-catalogue.json` with `notes` field preserving reasoning annotations
- [x] **EXTL-02**: MITRE ATT&CK mapping externalized to `config/attack-techniques.json` as shared authoritative source
- [x] **EXTL-03**: Persistence techniques (Parts 7A-7E) externalized to `config/persistence-techniques.json`
- [x] **EXTL-04**: Post-exploitation vectors (Parts 8A-8C) externalized to `config/postex-vectors.json`
- [ ] **EXTL-05**: scope-attack-paths.md reads config files after Phase A with fallback to empty object when absent

### Reasoning

- [ ] **REAS-01**: Checklist-execution framing ("check ALL... do not skip") replaced with reasoning-first + coverage-anchor structure
- [ ] **REAS-02**: 8 worked reasoning examples covering distinct attack families (direct IAM, PassRole-to-compute, code injection, boundary bypass, trust backdoor, service chain, resource-policy, cross-account)
- [ ] **REAS-03**: Coverage anchor list ensures all 50 methods are verified as considered or explicitly ruled out
- [ ] **REAS-04**: Adaptive path depth — Phase A node count determines simple/standard/complex analysis mode

### Output Quality

- [ ] **QUAL-01**: Per-field constraints defined (description max ~200 words, steps one command per element, remediation max 3 items, mitre_techniques T-IDs only)
- [ ] **QUAL-02**: Proactive narrative framing requiring environment-specific descriptions with real ARNs and account-function context

### New Techniques

- [ ] **TECH-01**: 7 new 2025/2026 techniques added to config files with `precondition_data_source` and `without_data_confidence_ceiling` fields
- [ ] **TECH-02**: Each new technique validated against false-positive gate (must not fire when precondition service module absent)

### Validation

- [ ] **XVAL-01**: Phase A jq output unchanged after all modifications (deterministic output preserved)
- [ ] **XVAL-02**: Pre-write completeness checks 1-13 all present and functional
- [ ] **XVAL-03**: Dashboard rendering test passes with v1.8 output

## Future Requirements

Deferred to post-v1.8. Tracked but not in current roadmap.

### Advanced Reasoning

- **ADVR-01**: EKS Pod Identity credential theft technique (requires new eks enum subagent)
- **ADVR-02**: VPC Lattice service network escalation (requires new vpc-lattice enum subagent)
- **ADVR-03**: Cross-agent MITRE consolidation — scope-defend.md and scope-exploit.md use config/attack-techniques.json instead of inline tables
- **ADVR-04**: Runtime token budget monitoring (warn when approaching context limits)

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| New enumeration subagents (EKS, VPC Lattice) | v1.8 is reasoning improvement, not service expansion — per PROJECT.md constraint |
| Removing Phase A jq templates | Deterministic code, not data — externalization would introduce regeneration risk |
| Removing pre-write checks 1-13 | Error recovery rules proven across v1.1-v1.4 — 20-30% compression cap only |
| Generic CoT instructions ("think step by step") | Research P3: does not displace checklist behavior; structural change required |
| Parallel sub-agent dispatch for attack-paths | Architecture change too large for v1.8; single-agent reasoning is correct |
| Splitting persistence/post-ex into sub-agents | Creates context isolation between related analyses |
| Phase A jq edits | Deterministic templates are load-bearing — Research P7 |
| Removing safety constraint duplication | v1.7 research confirmed these are load-bearing reinforcement |

## Traceability (v1.8)

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Phase Name | Status |
|-------------|-------|------------|--------|
| EXTL-01 | 34 | Config File Creation | Pending |
| EXTL-02 | 34 | Config File Creation | Pending |
| EXTL-03 | 34 | Config File Creation | Pending |
| EXTL-04 | 34 | Config File Creation | Pending |
| EXTL-05 | 36 | Prompt Restructuring | Pending |
| REAS-01 | 36 | Prompt Restructuring | Pending |
| REAS-02 | 36 | Prompt Restructuring | Pending |
| REAS-03 | 36 | Prompt Restructuring | Pending |
| REAS-04 | 36 | Prompt Restructuring | Pending |
| QUAL-01 | 36 | Prompt Restructuring | Pending |
| QUAL-02 | 36 | Prompt Restructuring | Pending |
| TECH-01 | 35 | New Technique Addition | Pending |
| TECH-02 | 35 | New Technique Addition | Pending |
| XVAL-01 | 37 | Validation | Pending |
| XVAL-02 | 37 | Validation | Pending |
| XVAL-03 | 37 | Validation | Pending |

**Coverage:**
- v1.8 requirements: 16 total
- Mapped to phases: 16
- Unmapped: 0

**Phase distribution:**
- Phase 34 (Config File Creation): 4 requirements (EXTL-01 through EXTL-04)
- Phase 35 (New Technique Addition): 2 requirements (TECH-01, TECH-02)
- Phase 36 (Prompt Restructuring): 7 requirements (EXTL-05, REAS-01 through REAS-04, QUAL-01, QUAL-02)
- Phase 37 (Validation): 3 requirements (XVAL-01 through XVAL-03)

---

# Requirements: SCOPE v1.9 Threat Hunt

**Defined:** 2026-03-30
**Milestone goal:** Transform scope-investigate into scope-hunt — a proactive threat hunting agent that integrates with audit and exploit output to drive hypothesis-led investigation.

## v1.9 Requirements

### Rebrand (RBRD)

- [ ] **RBRD-01**: Rename scope-investigate to scope-hunt across all agent files, docs, installer, hooks, and installed copies — zero behavior change
- [ ] **RBRD-02**: Rename `./investigate/` runtime directory to `./hunt/` and update `.gitignore`, `CLAUDE.md`, `AGENTS.md`
- [ ] **RBRD-03**: Rename `/scope:investigate` slash command to `/scope:hunt` in all skill registrations and documentation
- [ ] **RBRD-04**: Rename context.json path from `./investigate/context.json` to `./hunt/context.json` and update schema references

### Hypothesis Engine (HYPO)

- [ ] **HYPO-01**: Agent forms an attack hypothesis from any detection event before investigating — reasoning about adversary goal, not just tracing events
- [ ] **HYPO-02**: Agent generates attack hypotheses from SCOPE audit run directory (results.json, attack paths, per-module JSONs)
- [ ] **HYPO-03**: Agent generates attack hypotheses from SCOPE exploit output when available in the audit run
- [ ] **HYPO-04**: Operator selects which hypothesis to hunt when given an audit run directory

### Hunt Techniques (HUNT)

- [ ] **HUNT-01**: Add hunt technique patterns: credential abuse, data exfiltration, persistence establishment, lateral movement, defense evasion
- [ ] **HUNT-02**: Extend reasoning framework — hypothesis-driven step selection where each query confirms or refutes the hypothesis
- [ ] **HUNT-03**: Update output format — hunt report with hypothesis result (confirmed/refuted/inconclusive), evidence, and recommended response actions

### Integration (INTG)

- [ ] **INTG-01**: Break session isolation for hunt mode — agent reads audit/exploit run directories when provided
- [ ] **INTG-02**: Dual entry point detection — directory path triggers hunt mode, Splunk search/ID triggers detection investigation mode
- [ ] **INTG-03**: Update CLAUDE.md and AGENTS.md agent isolation sections, slash commands, architecture, and all references to reflect hunt's new integration with audit/exploit output

## Traceability (v1.9)

| Requirement | Phase | Phase Name | Status |
|-------------|-------|------------|--------|
| RBRD-01 | 38 | Agent Rebrand | Pending |
| RBRD-02 | 38 | Agent Rebrand | Pending |
| RBRD-03 | 38 | Agent Rebrand | Pending |
| RBRD-04 | 38 | Agent Rebrand | Pending |
| INTG-01 | 39 | Session Integration | Pending |
| INTG-02 | 39 | Session Integration | Pending |
| HYPO-01 | 40 | Hypothesis Engine | Pending |
| HYPO-02 | 40 | Hypothesis Engine | Pending |
| HYPO-03 | 40 | Hypothesis Engine | Pending |
| HYPO-04 | 40 | Hypothesis Engine | Pending |
| HUNT-01 | 41 | Hunt Techniques | Pending |
| HUNT-02 | 41 | Hunt Techniques | Pending |
| HUNT-03 | 41 | Hunt Techniques | Pending |
| INTG-03 | 42 | Documentation Update | Pending |

**Coverage:**
- v1.9 requirements: 14 total
- Mapped to phases: 14
- Unmapped: 0

**Phase distribution:**
- Phase 38 (Agent Rebrand): 4 requirements (RBRD-01 through RBRD-04)
- Phase 39 (Session Integration): 2 requirements (INTG-01, INTG-02)
- Phase 40 (Hypothesis Engine): 4 requirements (HYPO-01 through HYPO-04)
- Phase 41 (Hunt Techniques): 3 requirements (HUNT-01 through HUNT-03)
- Phase 42 (Documentation Update): 1 requirement (INTG-03)

---
*Requirements defined: 2026-03-26 (v1.8), 2026-03-30 (v1.9)*
*Last updated: 2026-03-30 — v1.9 Threat Hunt requirements added*
