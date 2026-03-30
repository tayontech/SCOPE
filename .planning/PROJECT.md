# SCOPE — Security Cloud Ops Purple Engagement

## What This Is

An AI agent suite for purple team security operations against AWS accounts: resource audit, exploit playbook generation, defensive controls (SCPs + SPL detections), and SOC alert investigation. Works across Claude Code, Gemini CLI, and Codex with 14-service enumeration pipeline, parallel subagent dispatch, and file-based handoff architecture. All enum agents self-validate output with structured error reporting.

## Current Milestone: v1.9 Threat Hunt

**Goal:** Transform scope-investigate into scope-hunt — a proactive threat hunting agent that integrates with SCOPE audit and exploit output to drive hypothesis-led investigation. The agent gains a dual entry point (directory path for audit-driven hunting, Splunk input for detection investigation), a hypothesis formation step before any query execution, and a structured hunt report format.

**Target features:**
- Rebrand scope-investigate to scope-hunt across all files, skills, runtime directories, and documentation
- Break session isolation — hunt mode reads audit/exploit run directories when provided
- Dual entry point: directory path triggers hunt mode, Splunk search/ID triggers detection investigation mode
- Hypothesis engine: agent reasons about adversary goal before issuing any Splunk queries
- Hunt technique patterns for 5 adversary behavior categories (credential abuse, exfiltration, persistence, lateral movement, defense evasion)
- Structured hunt report: hypothesis result (confirmed/refuted/inconclusive), chronological evidence, response actions

## Current State

**Shipped:** v1.8 Attack Reasoning (2026-03-27)
**Active:** v1.9 Threat Hunt — roadmap complete, ready to begin Phase 38

## Core Value

Every agent, reference, and cross-platform config must be correct and tested — a single broken reference or wrong invocation syntax means an operator's security workflow silently fails.

## Requirements

### Validated

- ✓ Cross-platform context (CLAUDE.md + AGENTS.md) — v1.0
- ✓ Unified installer (.agents/skills/ for Gemini+Codex) — v1.0
- ✓ Safety hooks (5 hooks, platform-adapted) — v1.0
- ✓ Agent consolidation (10→7 files, zero stale refs) — v1.0
- ✓ Pipeline orchestration (parallel enum, file-based handoff) — v1.0
- ✓ 14-service enumeration (7 slimmed + 7 new) — v1.0
- ✓ Attack-paths extended (50+ methods, 14 services) — v1.0
- ✓ Defend coverage (14-service SCP/SPL) — v1.0
- ✓ Schema validation (module-envelope for 14 services) — v1.0
- ✓ Dashboard visualization (React + D3, self-contained HTML) — existing
- ✓ Model routing hardening (Sonnet for attack-paths/defend, Haiku for enum) — v1.1
- ✓ MCP Splunk integration (template, setup guide, investigate wiring) — v1.1
- ✓ Gemini BeforeTool JSON injection (auto --output json) — v1.1
- ✓ Persistent subagent memory (scope-investigate, ARN hygiene) — v1.1
- ✓ context:fork skill wrappers (entry-point context isolation) — v1.1
- ✓ Attack-paths graph edge completeness (priv_esc, cross-account, data_access, trust, network, membership edges + pre-write check) — v1.2
- ✓ Schema enforcement at write time (severity, edge_type, category enums + defend policy_json/counts) — v1.2
- ✓ Dashboard normalization layer (case-insensitive severity, array-first KPIs, graceful degradation) — v1.2
- ✓ Enumeration depth parity (ENABLED_REGIONS discovery, multi-region iteration, per-finding region tags) — v1.2
- ✓ Pipeline integrity (upsert+cull+atomic-write, absolute RUN_DIR, write-after-verify, partial status) — v1.2
- ✓ Defend output completeness (array-first construction, jq length counts, no heredoc placeholders) — v1.2
- ✓ Enum agent output validation (3-step jq check: non-empty + valid JSON + envelope fields, [VALIDATION] errors) — v1.3
- ✓ IMDS enforcement hardening (mandatory extraction + self-check with STATUS=error) — v1.3
- ✓ Defend output proportionality (independent SCP/RCP/detection gates, STATUS: partial on retry exhaustion) — v1.3
- ✓ Orchestrator dispatch validation (Gate 3 0-byte detection + per-service region table) — v1.3
- ✓ Codex partial module remediation (14/14 modules complete via install.js body sync) — v1.3
- ✓ Codex escalation node connectivity (AGENTS.md Output Quality Rules with self-check) — v1.3
- ✓ Codex severity casing consistency (AGENTS.md lowercase enum + edge_type 8-value enum) — v1.3
- ✓ Dashboard bug fixes (phase switch reset, trust KPI breakdown, graph navigation, wildcard canonicalization, trust display, riskColor) — v1.4
- ✓ Agent output hardening (defend array-first, jq counts, pipeline safety net) — v1.4
- ✓ Cross-platform validation (Gemini path constraints, severity 3-layer defense) — v1.4

### Active

- [ ] Rebrand scope-investigate to scope-hunt across all agent files, skills, runtime dirs, and docs
- [ ] Break session isolation — hunt mode reads audit/exploit run directories when provided
- [ ] Dual entry point detection (directory path vs Splunk input)
- [ ] Hypothesis engine — adversary goal reasoning before any Splunk queries
- [ ] Hunt technique patterns for credential abuse, exfiltration, persistence, lateral movement, defense evasion
- [ ] Hunt report format: hypothesis result, evidence, recommended response actions

### Out of Scope

- AWS credential model changes — environment inheritance is correct
- New security agents beyond current suite — focus is parity, not expansion
- Splunk query language changes — investigate pipeline logic is working
- .toml command files for Gemini CLI — skills provide equivalent invocation
- New enumeration services — 14-service coverage is sufficient
- LLM re-run for edge backfill — creates non-deterministic output; deterministic post-processor is more reliable
- Per-region results.json files — increases file count without improving data quality
- ALL-CAPS emphasis in agent prompts — disrupts Claude/Gemini instruction parsing

## Context

Shipped v1.5 with 24 phases across 6 milestones. Codebase has 12 enum subagents, 4 top-level agents, and a React+D3 dashboard. v1.6 adds exploit intelligence (5 phases, 12 requirements).

**Platform architecture:**
- **Claude Code**: CLAUDE.md for context, .claude/skills/ for skills, .claude/settings.json for hooks
- **Gemini CLI**: AGENTS.md for context, .agents/skills/ for skills, .gemini/settings.json for hooks
- **Codex**: AGENTS.md for context, .agents/skills/ for skills, no hook support — relies on AGENTS.md Output Quality Rules

**Cross-platform test results (v1.4 — 2026-03-08):**
- Test data at: `~/ai-tests/{claude,gemini,codex}-test/SCOPE/`
- v1.4 closed all dashboard bugs, agent output quality gaps, pipeline safety issues
- Key observation: factual enum data (users, roles, trusts) should be identical across platforms but currently varies in structure and completeness

## Constraints

- **Compatibility**: Must work on Claude Code, Gemini CLI, and Codex simultaneously
- **No breaking changes**: Existing Claude Code workflows must continue working unchanged
- **Read-only safety**: All agents remain read-only — no destructive AWS operations
- **Agent Skills standard**: Skills must follow the open standard (SKILL.md with frontmatter)

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Replace GEMINI.md with agnostic AGENTS.md | Single file for Gemini + Codex reduces drift, .agents/ is the shared standard | ✓ Good |
| Keep CLAUDE.md separate | Claude Code reads CLAUDE.md natively, has unique hook syntax | ✓ Good |
| Unify skill deployment to .agents/skills/ | Both Gemini and Codex read from this path, .agents/ takes precedence in Gemini | ✓ Good |
| Two-phase audit: parallel enumerate, sequential attack paths | Enumeration is embarrassingly parallel, but cross-service attack path reasoning needs the full graph | ✓ Good |
| Single orchestrator entry point | One command runs full pipeline (audit->defend->verify->data->evidence->dashboard) | ✓ Good |
| Sequential verification (not parallel) | Verify agents build on each other — core taxonomy first, then aws/splunk checks | ✓ Good |
| No .toml command files needed | Agent Skills provide equivalent invocation without separate .toml maintenance | ✓ Good |
| Consolidate 3 verify → 1 | Single verify agent gets cross-domain context; SPL hook already catches syntax issues | ✓ Good |
| Merge 2 middleware → 1 pipeline | Both run sequentially on same data; merged agent can cross-reference entries | ✓ Good |
| Exploit stays standalone | Separate assessment workflow — operator chooses to run independently | ✓ Good |
| File-based handoff for context rot | Modules write JSON, attack path agent reads fresh — zero token contamination | ✓ Good |
| Slim service modules to checklists | Models know how to enumerate — modules ensure consistent WHAT, not HOW | ✓ Good |
| Keep attack-paths module detailed | Most model-dependent reasoning — explicit threat taxonomy prevents model drift | ✓ Good |
| Schema hook uses inline jq, not ajv-cli | Direct jq validation faster, no npm dependency; ajv-cli for CI only | ✓ Good (v1.2) |
| Edge templates as fill-in-the-blank | Cross-platform consistent edge generation without model-specific hints | ✓ Good (v1.2) |
| Upsert+cull+atomic-write for indexes | Single-pass filter replaces dedup-only append — no orphans, no duplicates | ✓ Good (v1.2) |
| Immediate STATUS=error on validation failure | Retrying jq write without fixing FINDINGS_JSON produces same empty result | ✓ Good (v1.3) |
| Independent SCP/RCP/detection gates | RCP failure never blocks overall coverage when Organizations inaccessible | ✓ Good (v1.3) |
| STATUS: partial as terminal state | Gives Gemini/Codex a clear terminal state vs open-ended "do not complete" | ✓ Good (v1.3) |
| Codex body-only sync via install.js | Frontmatter never touched — Codex uses TOML config, not markdown frontmatter | ✓ Good (v1.3) |
| Output Quality Rules in AGENTS.md | Hookless Codex environment needs imperative guidance matching hook enforcement | ✓ Good (v1.3) |

---
*Last updated: 2026-03-30 during v1.9 milestone start*
