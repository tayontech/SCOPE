# Roadmap: SCOPE v1.8 Attack Reasoning

## Overview

Transform scope-attack-paths.md from a static checklist-driven engine into an adaptive reasoning system that produces creative, environment-specific attack paths. The work proceeds in dependency order: config files are created first (zero risk — no agent changes), new 2025/2026 techniques are added second (files not yet referenced), all prompt restructuring happens in a single phase (no dual-source intermediate states), and validation closes the milestone. Net token impact is ~7,300 token reduction on scope-attack-paths.md at session start.

## v1.9 Phases

**Phase Numbering:**
- Integer phases (38, 39, 40...): Planned milestone work
- Decimal phases (38.1, 38.2): Urgent insertions (marked with INSERTED)

- [x] **Phase 38: Agent Rebrand** — Rename scope-investigate to scope-hunt across all agent files, docs, installer, hooks, and installed copies; rename ./investigate/ runtime directory to ./hunt/; rename /scope:investigate slash command to /scope:hunt; update context.json path (RBRD-01 through RBRD-04) (completed 2026-03-30)
- [x] **Phase 39: Session Integration** — Break session isolation for hunt mode — agent reads audit/exploit run directories when provided; implement dual entry point detection where directory path triggers hunt mode and Splunk search/ID triggers detection investigation mode (INTG-01, INTG-02) (completed 2026-03-30)
- [ ] **Phase 40: Hypothesis Engine** — Agent forms attack hypothesis from any detection event before investigating; generates hypotheses from SCOPE audit run directory and exploit output; operator selects which hypothesis to hunt when given an audit run directory (HYPO-01 through HYPO-04)
- [ ] **Phase 41: Hunt Techniques** — Add hunt technique patterns for credential abuse, data exfiltration, persistence, lateral movement, and defense evasion; extend reasoning framework with hypothesis-driven step selection; update output format to hunt report with hypothesis result (HUNT-01 through HUNT-03)
- [ ] **Phase 42: Documentation Update** — Update CLAUDE.md and AGENTS.md to reflect hunt's new integration with audit/exploit output; update agent isolation sections, slash commands, architecture, and all cross-references (INTG-03)

## Phase Details

### Phase 38: Agent Rebrand

**Goal:** Mechanical rename of scope-investigate to scope-hunt with zero behavior change. All agent files, skill registrations, installer logic, hooks, installed copies, runtime directory references, gitignore entries, slash command names, and context.json path are updated in a single phase. No logic or prompt content changes in this phase — pure rename.

**Depends on:** Nothing — first phase of v1.9

**Requirements:** RBRD-01, RBRD-02, RBRD-03, RBRD-04

**Success Criteria** (what must be TRUE):
1. `agents/scope-hunt.md` exists and `agents/scope-investigate.md` does not; all internal cross-references in audit, exploit, defend, and pipeline agents point to `scope-hunt`
2. The runtime directory reference in scope-hunt.md and all context reads/writes use `./hunt/` — `./investigate/` does not appear in any agent file or CLAUDE.md/AGENTS.md path reference
3. `/scope:hunt` skill is registered in `.claude/skills/` and `.agents/skills/`; `/scope:investigate` registration does not exist; `bin/install.js` deploys the renamed skill correctly
4. Context file reads and writes use `./hunt/context.json`; `.gitignore` covers `hunt/` (not `investigate/`); schema references in any `.scope/schemas/` files are updated to `hunt`
5. Running `grep -r "scope-investigate\|/scope:investigate\|investigate/context" agents/ bin/ .scope/ CLAUDE.md AGENTS.md` returns zero matches

---

### Phase 39: Session Integration

**Goal:** Break scope-hunt's session isolation so it can consume audit and exploit run directories when provided. Implement dual entry point detection: a directory path argument triggers hunt mode (reads results.json, attack paths, per-module JSONs from that run), while a Splunk search term or alert ID triggers the existing detection investigation mode. The two modes are mutually exclusive — the agent selects one based on input type at session start.

**Depends on:** Phase 38 (agent must be renamed before adding new entry point logic)

**Requirements:** INTG-01, INTG-02

**Success Criteria** (what must be TRUE):
1. When invoked with a directory path, scope-hunt reads `results.json`, attack path JSON, and per-module JSONs from that directory and surfaces them as context before beginning any hunt queries
2. When invoked with a Splunk search term or alert ID, scope-hunt operates in its prior detection investigation mode with no audit data dependencies
3. The entry point detection is unambiguous — a directory path (starts with `/` or `./`, or matches `data/<run-id>`) always triggers hunt mode; any other input triggers investigation mode; the agent states which mode it selected at session start
4. Hunt mode does not require Splunk to be available — it can produce a hypothesis report from audit/exploit output alone without querying Splunk
5. Investigation mode behavior is unchanged from v1.8 scope-investigate — no regressions in Splunk query patterns, timeline building, or IOC correlation

---

### Phase 40: Hypothesis Engine

**Goal:** Add hypothesis formation as the first step in every hunt session. For detection events, the agent reasons about adversary goal before tracing events. For audit run directories, the agent generates a ranked list of attack hypotheses drawn from results.json, attack path output, and exploit playbooks. The operator selects which hypothesis to pursue when multiple are available. All subsequent hunt queries are framed around confirming or refuting the selected hypothesis.

**Depends on:** Phase 39 (audit/exploit run directory reads must work before hypothesis generation from them)

**Requirements:** HYPO-01, HYPO-02, HYPO-03, HYPO-04

**Success Criteria** (what must be TRUE):
1. For every detection event entry point, scope-hunt produces a written hypothesis statement before issuing any Splunk queries — the hypothesis names the suspected adversary goal, not just the observed event
2. When given an audit run directory, scope-hunt generates at least one hypothesis per critical/high attack path present in the run's attack path JSON, with each hypothesis stating the preconditions observed in the audit data
3. When exploit output is present in the audit run directory, scope-hunt incorporates exploit playbook steps into hypothesis generation — hypotheses reference specific techniques from the playbook
4. When multiple hypotheses are generated, scope-hunt presents them as a numbered list and waits for operator selection before proceeding — no auto-selection unless only one hypothesis exists
5. The selected hypothesis is restated at the top of the hunt report as the framing statement for all evidence and conclusions

---

### Phase 41: Hunt Techniques

**Goal:** Add structured hunt technique patterns for the five primary adversary behavior categories. Extend the reasoning framework so each Splunk query is explicitly tied to confirming or refuting the active hypothesis. Update the output format to a hunt report that states the hypothesis result (confirmed / refuted / inconclusive), presents evidence, and recommends response actions.

**Depends on:** Phase 40 (hypothesis framework must exist before technique patterns can reference it)

**Requirements:** HUNT-01, HUNT-02, HUNT-03

**Success Criteria** (what must be TRUE):
1. scope-hunt contains documented hunt technique patterns for all five categories: credential abuse (stolen key usage, role chaining, token replay), data exfiltration (S3 GetObject spikes, Secrets Manager bulk reads, presigned URL generation), persistence establishment (backdoor role creation, SCIMming, access key rotation abuse), lateral movement (AssumeRole traversal, cross-account trust exploitation), and defense evasion (CloudTrail StopLogging, GuardDuty disable, Config recorder tampering)
2. Each Splunk query issued during a hunt session is labeled with its hypothesis linkage — the agent states whether the query is designed to confirm or refute the hypothesis before running it
3. The final hunt report contains exactly three sections: Hypothesis Result (confirmed/refuted/inconclusive with one-sentence rationale), Evidence (chronological list of findings with CloudTrail eventNames and timestamps), and Recommended Response Actions (bulleted, plain-English, max 5 items)
4. Inconclusive verdict is only returned when evidence neither confirms nor refutes — not as a default when Splunk is unavailable; if Splunk is unavailable the report states "unable to query" explicitly
5. Hunt technique patterns are structured so new categories can be added without modifying the reasoning framework — patterns are data, not code

---

### Phase 42: Documentation Update

**Goal:** Update CLAUDE.md and AGENTS.md to reflect hunt's new integration with audit/exploit output. The agent isolation section must accurately describe that scope-hunt is no longer fully isolated — it reads audit/exploit run directories when provided. Slash command documentation, architecture diagrams, and all cross-references are updated. This is the documentation-only close phase for v1.9.

**Depends on:** Phase 41 (all behavior changes complete before documentation is finalized)

**Requirements:** INTG-03

**Success Criteria** (what must be TRUE):
1. CLAUDE.md agent isolation section accurately states: scope-hunt is standalone when invoked with a Splunk input, and reads audit/exploit run directories when invoked with a directory path — the v1.8 "scope-investigate is standalone" statement is removed or replaced
2. The slash commands table in CLAUDE.md lists `/scope:hunt` (not `/scope:investigate`) with a description that reflects both entry point modes
3. AGENTS.md mirrors the same isolation and slash command updates as CLAUDE.md — no drift between the two context files
4. The architecture section in CLAUDE.md and AGENTS.md lists `agents/scope-hunt.md` and `./hunt/` as the correct paths — no remaining references to `scope-investigate` or `./investigate/`
5. Running `grep -r "scope-investigate\|/scope:investigate\|investigate/" CLAUDE.md AGENTS.md` returns zero matches

---

## Prior Milestones

<details>
<summary>v1.0 Platform Foundation (Phases 1-4) - SHIPPED 2026-03-05</summary>
See .planning/MILESTONES.md
</details>

<details>
<summary>v1.1 Performance Optimizations & Integrations (Phases 5-9) - SHIPPED 2026-03-05</summary>
See .planning/MILESTONES.md
</details>

<details>
<summary>v1.2 Cross-Platform Parity & Dashboard Hardening (Phases 10-13) - SHIPPED 2026-03-07</summary>
See .planning/MILESTONES.md
</details>

<details>
<summary>v1.3 Enum Hardening & Cross-Platform Validation (Phases 14-15) - SHIPPED 2026-03-07</summary>
See .planning/MILESTONES.md
</details>

<details>
<summary>v1.4 Dashboard & Pipeline Polish (Phases 16-19) - SHIPPED 2026-03-08</summary>
See .planning/MILESTONES.md
</details>

<details>
<summary>v1.5 Cross-Platform Output Determinism (Phases 20-24) - SHIPPED 2026-03-11</summary>
See .planning/MILESTONES.md
</details>

<details>
<summary>v1.6 Exploit Intelligence (Phases 25-29) - SHIPPED 2026-03-17</summary>
See .planning/MILESTONES.md
</details>

<details>
<summary>v1.7 Context Optimization (Phases 30-33) - SHIPPED 2026-03-18</summary>
See .planning/MILESTONES.md
</details>

## v1.8 Phases

**Phase Numbering:**
- Integer phases (34, 35, 36...): Planned milestone work
- Decimal phases (34.1, 34.2): Urgent insertions (marked with INSERTED)

- [x] **Phase 34: Config File Creation** — Extract escalation catalogue, MITRE mapping, persistence techniques, and post-exploitation vectors from scope-attack-paths.md into four standalone JSON config files (EXTL-01 through EXTL-04) (completed 2026-03-26)
- [x] **Phase 35: New Technique Addition** — Extend the config files with 7 new 2025/2026 attack vectors, each with precondition documentation and false-positive gates (TECH-01, TECH-02) (completed 2026-03-26)
- [x] **Phase 36: Prompt Restructuring** — All scope-attack-paths.md changes in a single phase: config reads, reasoning-first framing, worked examples, coverage anchor, per-field constraints, proactive narrative framing, and adaptive path depth (EXTL-05, REAS-01 through REAS-04, QUAL-01, QUAL-02) (completed 2026-03-27)
- [x] **Phase 37: Validation** — Confirm no regressions in Phase A output, pre-write completeness checks, and dashboard rendering (XVAL-01 through XVAL-03) (completed 2026-03-27)

## Phase Details

### Phase 34: Config File Creation

**Goal:** Extract the four major reference tables from scope-attack-paths.md into standalone JSON config files under `config/`. All four files are committed to the repo as non-sensitive reference data. No changes to scope-attack-paths.md occur in this phase — the extracted content remains inline until Phase 36. The config files become independently useful assets even if Phase 36 is abandoned.

**Depends on:** Nothing — first phase of v1.8

**Requirements:** EXTL-01, EXTL-02, EXTL-03, EXTL-04

**Success Criteria** (what must be TRUE):
1. `config/escalation-catalogue.json` exists, is valid JSON (passes `jq .`), contains all 50 escalation methods and 7 chains from Parts 2–3, and each entry includes a non-null `notes` field with the verbatim annotation (negative examples, cross-references, "No PassRole needed" hints) from the current inline markdown
2. `config/attack-techniques.json` exists, is valid JSON, and contains the complete MITRE ATT&CK mapping from Part 5 with no entries omitted
3. `config/persistence-techniques.json` exists, is valid JSON, and contains all persistence technique entries from Parts 7A–7E
4. `config/postex-vectors.json` exists, is valid JSON, and contains all post-exploitation vector entries from Parts 8A–8C
5. All four files carry `"version": "2026-03"` at the root level and `jq . config/*.json` produces clean output with no parse errors

**Plans:**
2/2 plans complete
- [ ] 34-02-PLAN.md — Create `config/attack-techniques.json`, `config/persistence-techniques.json`, `config/postex-vectors.json`: extract Parts 5, 7, and 8; validate all three with `jq .`

---

### Phase 35: New Technique Addition

**Goal:** Extend the config files created in Phase 34 with 7 new 2025/2026 attack vectors. The config files are not yet referenced by scope-attack-paths.md, so there is zero agent behavior risk. Every new entry must include `precondition_data_source` and `without_data_confidence_ceiling` fields before the phase closes — these are hard gates against false positives when the required service module is absent from SERVICES_COMPLETED.

**Depends on:** Phase 34 (config files must exist and be valid before extension)

**Requirements:** TECH-01, TECH-02

**Success Criteria** (what must be TRUE):
1. `config/escalation-catalogue.json` contains 6 new technique entries: IAM Identity Center permission set escalation, Bedrock Agent action group code execution, AWS Verified Access policy injection, IAM Roles Anywhere credential injection, Service Catalog portfolio escalation, and Organizations delegated administrator abuse
2. `config/postex-vectors.json` contains 2 new entries: CodePipeline/CodeDeploy deployment override via artifact bucket, and S3 Access Points cross-account delegation bypass
3. Every new entry includes a `precondition_data_source` field naming the enum module that must be present (e.g., `"iam.json"`, `"sts.json"`, `"codebuild.json"`) and a `without_data_confidence_ceiling` field capping confidence when that module is absent
4. All extended config files still parse clean with `jq .` after additions
5. A false-positive gate check is documented per technique: the technique must not appear as a finding for an account where the precondition service module is absent from SERVICES_COMPLETED

**Plans:**
1/1 plans complete

---

### Phase 36: Prompt Restructuring

**Goal:** All scope-attack-paths.md changes happen in a single phase to avoid dual-source intermediate states where the agent reads both inline and config for the same data. Changes include: remove extracted inline content and replace with config-read instructions; restructure Part 2/3 to reasoning-first then coverage-anchor; add 8 worked reasoning examples (one per attack family); add per-field output constraints; add proactive narrative framing; add adaptive path depth mode selection; ensure Phase A completion gate is explicit before Phase B.

**Depends on:** Phase 35 (config files must be complete and valid before scope-attack-paths.md references them — mirrors the v1.7 cloudtrail-classes.json precedent)

**Requirements:** EXTL-05, REAS-01, REAS-02, REAS-03, REAS-04, QUAL-01, QUAL-02

**Success Criteria** (what must be TRUE):
1. scope-attack-paths.md reads all four config files after Phase A completes (before Part 1 analysis begins), with an explicit `|| '{}'` fallback for each file when absent, and logs a `[WARN]` message per missing file
2. Checklist-execution framing ("check ALL of the following... do not skip") is removed from Part 2/3; reasoning-first analysis precedes the coverage-anchor list, with clear stage boundaries and different labels for each stage
3. 8 worked reasoning examples are present, each covering a distinct attack family: direct IAM, PassRole-to-compute, code injection, boundary bypass, trust backdoor, service chain, resource-policy, and cross-account — with no two examples sharing the same primary technique
4. Per-field constraints are explicitly stated: description max ~200 words (no raw JSON or CLI), steps one command per array element, remediation plain-English max 3 items, mitre_techniques T-IDs only, detection_opportunities CloudTrail eventNames only
5. Adaptive depth present as a one-sentence hint ("Scale your analysis depth to the account complexity") — no formal modes or thresholds; Phase A has an explicit completion gate ("Do not begin Phase B until PHASE_A_NODES and PHASE_A_EDGES are populated") that is positionally co-located with the Phase A jq block

**Plans:**
3/3 plans complete
- [ ] 36-02-PLAN.md — Restructure Part 2/3 reasoning framing (reasoning-first → coverage-anchor second); add 8 worked examples; add adaptive path depth assessment; add explicit Phase A completion gate
- [ ] 36-03-PLAN.md — Add per-field output constraints (QUAL-01); add proactive narrative framing requiring real ARNs and account-function context (QUAL-02); verify operative constraints remain positionally co-located with governed behavior

---

### Phase 37: Validation

**Goal:** Confirm that all v1.8 changes produce no regressions. Phase A jq output must be deterministic and unchanged (D3 dashboard depends on consistent node IDs). Pre-write completeness checks 1–13 must all be present and functional. Dashboard rendering must pass with v1.8 output. Fallback behavior (missing config files) must log warnings and continue without failing.

**Depends on:** Phase 36 (all prompt changes complete before validation)

**Requirements:** XVAL-01, XVAL-02, XVAL-03

**Success Criteria** (what must be TRUE):
1. Phase A jq output (node IDs, edge types, PHASE_A_NODES structure) is byte-for-byte identical before and after all v1.8 modifications — confirmed by running the same Phase A block against the same test input
2. Pre-write completeness checks 1–13 are all present in scope-attack-paths.md, unmodified, and functionally intact — verified by inspecting each check condition after Phase 36
3. Dashboard rendering test passes: `npm run dashboard` generates `dashboard.html` successfully and all attack path card fields (description, mitre_techniques, steps, remediation, detection_opportunities, severity, confidence_pct, exploitability) render without blank or undefined values on a v1.8 test output
4. Fallback behavior validated: renaming a config file causes scope-attack-paths.md to log `[WARN]` and continue execution without error termination
5. Net token reduction in scope-attack-paths.md is positive (measured against v1.7 baseline) — confirms externalization achieved its goal

**Plans:**
1/2 plans complete
- [ ] 37-02-PLAN.md — Dashboard rendering test with v1.8 output; net token reduction measurement against v1.7 baseline

---

## Requirement Coverage

| Requirement | Phase |
|-------------|-------|
| EXTL-01 | 34 | 2/2 | Complete    | 2026-03-26 |
| EXTL-03 | 34 |
| EXTL-04 | 34 |
| EXTL-05 | 36 | 3/3 | Complete    | 2026-03-27 |
| REAS-02 | 36 |
| REAS-03 | 36 |
| REAS-04 | 36 |
| QUAL-01 | 36 |
| QUAL-02 | 36 |
| TECH-01 | 35 | 1/1 | Complete    | 2026-03-26 |
| XVAL-01 | 37 | 1/2 | Complete    | 2026-03-27 |
| XVAL-03 | 37 |

**Coverage:** 16/16 requirements mapped (100%)

---

## v1.9 Requirement Coverage

| Requirement | Phase |
|-------------|-------|
| RBRD-01 | 38 |
| RBRD-02 | 38 |
| RBRD-03 | 38 |
| RBRD-04 | 38 |
| INTG-01 | 39 |
| INTG-02 | 39 |
| HYPO-01 | 40 |
| HYPO-02 | 40 |
| HYPO-03 | 40 |
| HYPO-04 | 40 |
| HUNT-01 | 41 |
| HUNT-02 | 41 |
| HUNT-03 | 41 |
| INTG-03 | 42 |

**Coverage:** 14/14 requirements mapped (100%)

---
*Roadmap created: 2026-03-26*
*Last updated: 2026-03-30 — Phase 39 complete (plan 39-01)*
