# Roadmap: SCOPE v1.13 Prompt Architecture & Hardening

**Milestone:** v1.13 Prompt Architecture & Hardening
**Requirements:** 15 total (PROM-01–06, DET-01–04, SIM-01–04, TEST-02)
**Phases:** 57–64 (8 phases)
**Defined:** 2026-04-18

---

## Phase 57: @include Infrastructure & Tier Model Declarations

**Requirements:** PROM-01
**Target files:** `bin/install.js`
**Dependency:** None — foundational; all PROM phases depend on this

### What changes

- **PROM-01**: Add `@include <path>` directive support to `install.js` — during agent installation, the installer reads source `.md` files, resolves `@include agents/shared/<file>` references by inlining the referenced content, and writes the expanded output to the platform-native destination. Add tier-based model declarations (`model: reasoning`, `model: enum`, `model: inherit`) to source agent frontmatter and resolve them to vendor-specific model names per platform (Claude: sonnet/haiku, Gemini: gemini-pro/gemini-flash, Codex: gpt-5.4/gpt-4o-mini) during install.

### Success criteria

1. `install.js` processes `@include agents/shared/<file>` directives and the installed agent file contains the inlined content with no `@include` tokens remaining.
2. Tier model declarations (`model: reasoning`, `model: enum`, `model: inherit`) in source frontmatter are resolved to the correct vendor-specific model name in the installed output for each of the three platforms.
3. An `@include` referencing a non-existent path causes `install.js` to exit with a non-zero status and a descriptive error message.
4. The `agents/shared/` directory is created and referenced by at least one agent source file as a validation target.
5. Existing agents without `@include` directives install identically to before — no regression in current install behavior.

---

## Phase 58: Shared Content Extraction — Verification, Enum Contract, Role Compression

**Requirements:** PROM-02, PROM-03, PROM-05
**Target files:** `agents/shared/` (new), all 12 `agents/subagents/scope-enum-*.md`, `agents/scope-exploit.md`, `agents/scope-audit.md`, `agents/scope-hunt.md`, `agents/subagents/scope-attack-paths.md`, `agents/subagents/scope-verify.md`, `agents/subagents/scope-pipeline.md`
**Dependency:** Phase 57 (`@include` must be supported before content can be extracted to shared files)

### What changes

- **PROM-02**: Extract the shared verification protocol, evidence logging format, session isolation rules, and mandatory output sections to `agents/shared/verification-protocol.md`. Each agent that previously repeated this content now uses `@include agents/shared/verification-protocol.md` in its source file.
- **PROM-03**: Extract the enum output contract (jq write template, `$STATUS` envelope, logging boilerplate, post-write validation block) to `agents/shared/enum-output-contract.md`. All 12 enum agents replace their 30+ identical lines with `@include agents/shared/enum-output-contract.md`.
- **PROM-05**: Compress role/context preamble blocks across all agents to core mandates only (read-only operation, standard node IDs, no auto-deploy). Extract the compressed shared preamble to `agents/shared/agent-preamble.md` and replace repeated project-context paragraphs across all agents with `@include agents/shared/agent-preamble.md`.

### Success criteria

1. `agents/shared/verification-protocol.md` exists and is referenced via `@include` in every agent source file that previously contained the inline verification/evidence/session-isolation block — installed outputs contain the inlined text.
2. `agents/shared/enum-output-contract.md` exists; all 12 enum agent source files contain `@include agents/shared/enum-output-contract.md` and do not contain duplicate inline copies of the jq write template or `$STATUS` envelope.
3. `agents/shared/agent-preamble.md` exists with the compressed core mandates; no agent source file contains repeated project-context paragraphs beyond what is in the shared preamble.
4. Installed agent files (post-`install.js`) are functionally equivalent to the pre-extraction versions — the inlined content matches what was previously hardcoded.
5. Total character count across the 12 enum agent source files decreases by at least 30% relative to pre-Phase 58 (each agent shed 30+ lines of boilerplate).

---

## Phase 59: scope-defend Intake Consolidation

**Requirements:** PROM-04
**Target file:** `agents/scope-defend.md`
**Dependency:** Phase 57 (`@include` available for any shared extractions needed during consolidation)

### What changes

- **PROM-04**: Merge the three overlapping intake sections (`invocation_modes`, `autonomous_mode`, and workflow Steps 1–2) in `scope-defend.md` into a single `<intake_protocol>` block. The consolidated block covers all invocation paths (post-audit chain, standalone, re-invoke) with unambiguous routing logic. Contradictions between the three former sections are resolved in favor of the most explicit instruction.

### Success criteria

1. `agents/scope-defend.md` contains exactly one `<intake_protocol>` block and zero instances of the former `invocation_modes`, `autonomous_mode`, or duplicate Steps 1–2 sections.
2. The consolidated `<intake_protocol>` addresses all three invocation paths (post-audit chain, standalone with explicit ARN, re-invoke with existing run directory) with no ambiguity about which path applies under which conditions.
3. The character count of `agents/scope-defend.md` decreases relative to the pre-Phase 59 version (consolidation must not add net content).
4. No behavioral change in defend output contract — schema-required fields and gate sequencing remain intact after the intake consolidation.

---

## Phase 60: Runtime Reference Loading

**Requirements:** PROM-06
**Target files:** `agents/scope-exploit.md`, `agents/subagents/scope-attack-paths.md`, `agents/scope-hunt.md`, relevant config files under `config/`
**Dependency:** None — independent of `@include` infrastructure (different pattern: tool-call loading, not install-time injection)

### What changes

- **PROM-06**: Move prompt-embedded reference tables (SPL field templates, CloudTrail event classification, privilege escalation catalogue) out of agent prompts and into config files. Agents load these references at runtime via tool calls (read `config/cloudtrail-classes.json`, `config/hunt-techniques.json`, and any new config files created) instead of embedding the tables inline. Source agent files replace embedded tables with a load instruction and a reference to the config path.

### Success criteria

1. No agent source file contains an inline SPL field template table — `scope-hunt.md` loads SPL field references from a config file via tool call at session start.
2. The privilege escalation catalogue embedded in `scope-exploit.md` is replaced with a load instruction pointing to an externalized config file; the config file contains the same catalogue content.
3. `scope-attack-paths.md` no longer embeds the full CloudTrail event classification table inline — it loads `config/cloudtrail-classes.json` at runtime.
4. All newly externalized config files are valid JSON and pass a syntax check (`node -e "require('./config/<file>.json')"`).
5. The total character count reduction across the affected agent source files is observable — inline removal is not offset by equivalent replacement prose.

---

## Phase 61: Graph Extraction, Pipeline Guards & Regression Tests

**Requirements:** DET-01, DET-02, TEST-02
**Target files:** `bin/extract-graph.js` (new), `agents/subagents/scope-attack-paths.md`, `agents/subagents/scope-pipeline.md`, test fixtures
**Dependency:** None — independent of PROM workstream

### What changes

- **DET-01**: Extract Phase A graph construction (node/edge assembly from per-module JSON) from the `scope-attack-paths` prompt to `bin/extract-graph.js`. The script accepts a run directory as its argument, reads per-module JSON files, and writes the assembled graph JSON to stdout. The attack-paths agent invokes `node bin/extract-graph.js <run-dir>` instead of executing the jq pipeline inline.
- **DET-02**: Add pipeline guards in `scope-pipeline.md` and `scope-attack-paths.md`: after each major extraction or transform step, verify the output variable is non-empty before proceeding. On empty result, emit a structured `[PIPELINE_ERROR]` message and halt the current phase with a non-zero exit analog rather than silently continuing with empty data.
- **TEST-02**: Create fixture-based regression tests for `bin/extract-graph.js` using known-good enum JSON. Tests verify the extracted script produces identical graph output to what the inline jq pipeline previously produced.

### Success criteria

1. `bin/extract-graph.js` exists, accepts a run directory argument, reads per-module JSON from that directory, and writes valid graph JSON to stdout.
2. `scope-attack-paths.md` no longer contains inline jq pipelines for Phase A graph construction — it invokes `node bin/extract-graph.js` and consumes the output.
3. `bin/extract-graph.js` produces identical graph structure to what the inline jq pipeline previously produced when given the same input fixtures.
4. `scope-pipeline.md` contains explicit empty-variable guards after each major extraction step — a step that produces an empty result emits `[PIPELINE_ERROR]` and does not silently proceed.
5. `scope-attack-paths.md` contains at least one explicit empty-result guard after invoking `extract-graph.js` — an empty graph causes a visible error, not silent empty output.
6. At least one fixture-based test exists that runs `bin/extract-graph.js` against known-good enum JSON and asserts the output matches expected graph structure.

---

## Phase 62: Input Safety — Path Sanitization & Credential Isolation

**Requirements:** DET-03, DET-04
**Target files:** `agents/scope-hunt.md`, `agents/scope-exploit.md`, `agents/scope-audit.md`, `agents/subagents/scope-attack-paths.md`, any agent that accepts operator-provided path arguments
**Dependency:** None — independent of PROM and other DET phases

### What changes

- **DET-03**: Add operator-provided path sanitization before any shell use. Before an agent passes an operator-supplied path to a shell command or tool call, it must validate the path against an allowlist of prefixes (`./audit/`, `./exploit/`, `./engagements/`). Paths that do not match an allowed prefix must be rejected with a visible error — no shell execution occurs.
- **DET-04**: Add credential isolation for cross-account hops. Temporary credentials obtained for a cross-account role assume must be scoped to a subshell with `AWS_CONFIG_FILE` scoping to prevent `/proc` filesystem exposure on crash. No temporary credential variable (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) may persist in the parent shell environment after a cross-account step completes or fails.

### Success criteria

1. Every agent that accepts a run directory or file path argument contains an explicit allowlist check against `./audit/`, `./exploit/`, and `./engagements/` before any shell command referencing that path is issued.
2. A path that does not match the allowlist produces a visible rejection message and no shell execution — this is stated as an explicit rule in each affected agent.
3. Cross-account role assumption in `scope-exploit.md` and `scope-attack-paths.md` uses subshell-scoped credential variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` set within `( )` or an equivalent isolation construct).
4. The credential isolation pattern explicitly unsets or discards temporary credentials on both normal exit and error exit from the subshell — no credential leak path exists in the described flow.
5. The path sanitization and credential isolation rules are stated as hard requirements, not recommendations — language such as "should" or "consider" is absent from these sections.

---

## Phase 63: IAM Simulator Wrapper

**Requirements:** SIM-01
**Target files:** `bin/simulate-access.sh` (new)
**Dependency:** None — foundational for SIM-02/03/04

### What changes

- **SIM-01**: Create `bin/simulate-access.sh` — a wrapper around `aws iam simulate-principal-policy` with retry logic (exponential backoff on throttle), `OrganizationsDecisionDetail` output parsing, batch support (up to 200 actions per API call, chunked automatically), and cross-path action deduplication to minimize API calls in multi-path audits. The script accepts a principal ARN and a list of actions as arguments and outputs structured JSON indicating allowed/denied/conditional per action.

### Success criteria

1. `bin/simulate-access.sh` exists, is executable, and accepts a principal ARN and action list as arguments.
2. The script calls `aws iam simulate-principal-policy` with `--include-simulate-organizations-decision-detail` and parses `OrganizationsDecisionDetail` from the response.
3. Action lists longer than 200 items are automatically chunked — the script issues multiple API calls and merges the results.
4. On throttle error (`ThrottlingException`), the script retries with exponential backoff at least twice before failing.
5. Output is structured JSON with one entry per action containing at least `action`, `decision` (`allowed`/`denied`/`implicitDeny`/`conditionallyAllowed`), and `organizations_decision` fields.

---

## Phase 64: IAM Simulator Integration — Exploit & Attack Paths

**Requirements:** SIM-02, SIM-03, SIM-04
**Target files:** `agents/scope-exploit.md`, `agents/subagents/scope-attack-paths.md`
**Dependency:** Phase 63 (`bin/simulate-access.sh` must exist before agents can reference it)

### What changes

- **SIM-02**: Wire `bin/simulate-access.sh` into exploit permission discovery as Stage 2.5 — after policy self-read (Stage 2) and before noisy live probes (Stage 3). The simulator call verifies claimed permissions deterministically; only permissions returning `denied` or `implicitDeny` from the simulator are escalated to live probes. Permissions confirmed `allowed` by the simulator are marked `CONFIRMED` without a live probe.
- **SIM-03**: Wire `bin/simulate-access.sh` into attack-paths candidate evaluation. Before writing top candidate paths to `results.json`, the agent runs the simulator against the required actions for each candidate. Paths where the simulator returns `allowed` or `conditionallyAllowed` are upgraded to `Guaranteed` or `Conditional`; paths where required actions return `denied` are filtered from the output. The simulation step runs after Phase A graph construction and before the results write.
- **SIM-04**: Define graceful degradation behavior for `AccessDenied` on `iam:SimulatePrincipalPolicy`. When the simulator call fails with `AccessDenied`, the agent logs a `[SIM_UNAVAILABLE]` notice, falls back to existing reasoning-based confidence assessment, and caps all confidence labels at `Conditional` (no `Guaranteed` labels without simulator confirmation). The fallback path must not silently omit the degradation notice.

### Success criteria

1. `scope-exploit.md` Stage 2.5 exists between policy self-read and live probes — it invokes `bin/simulate-access.sh` and routes confirmed-`allowed` permissions directly to `CONFIRMED` without a live probe.
2. Permissions returning `denied` or `implicitDeny` from Stage 2.5 are explicitly routed to live probe (Stage 3) — the routing logic is stated, not implied.
3. `scope-attack-paths.md` invokes `bin/simulate-access.sh` against required actions for each top candidate path before writing `results.json` — simulator output determines final confidence label.
4. A `[SIM_UNAVAILABLE]` notice is emitted and confidence is capped at `Conditional` when `iam:SimulatePrincipalPolicy` returns `AccessDenied` — this fallback path is explicit in both `scope-exploit.md` and `scope-attack-paths.md`.
5. No `Guaranteed` confidence label appears in `results.json` output from a run where the simulator was unavailable — the cap is enforced by the agent logic, not just stated as a rule.

---

## Coverage Verification

| Phase | Requirements | Req Count |
|-------|-------------|-----------|
| 57 | 2/2 | Complete   | 2026-04-19 | 58 | PROM-02, PROM-03, PROM-05 | 3 |
| 59 | PROM-04 | 1 |
| 60 | PROM-06 | 1 |
| 61 | DET-01, DET-02, TEST-02 | 3 |
| 62 | DET-03, DET-04 | 2 |
| 63 | SIM-01 | 1 |
| 64 | SIM-02, SIM-03, SIM-04 | 3 |
| **Total** | **15 requirements** | **15** |

Coverage: 15/15 requirements mapped. No gaps.

---

## Dependency Order

```
Phase 57 (PROM-01: @include + tier models)
    └── Phase 58 (PROM-02, 03, 05: shared content extraction)
    └── Phase 59 (PROM-04: defend intake consolidation)

Phase 60 (PROM-06: runtime reference loading) — independent

Phase 61 (DET-01, 02: graph extraction + pipeline guards) — independent
Phase 62 (DET-03, 04: path sanitization + credential isolation) — independent

Phase 63 (SIM-01: simulate-access.sh wrapper)
    └── Phase 64 (SIM-02, 03, 04: simulator integration + degradation)
```

PROM workstream: Phase 57 must complete before Phases 58 and 59. Phase 60 is independent (runtime loading, not install-time injection).
DET workstream: Phases 61 and 62 are fully independent of each other and of PROM.
SIM workstream: Phase 63 must complete before Phase 64.

---

*Roadmap defined: 2026-04-18*
*Last updated: 2026-04-18*
