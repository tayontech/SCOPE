---
gsd_state_version: 1.0
milestone: v1.13
milestone_name: milestone
status: executing
last_updated: "2026-04-19T13:38:00.000Z"
last_activity: "2026-04-19 — Completed 61-02: replaced Phase A jq pipelines with extract-graph.js invocation; added 9 PIPELINE_ERROR guards across normalizers"
progress:
  total_phases: 8
  completed_phases: 4
  total_plans: 8
  completed_plans: 9
---

# Project State

## Current Position

Phase: 61 — IN PROGRESS
Plan: 61-02 complete (plan 61-01 pending)
Status: Phase 61 in progress — 61-02 complete, 61-01 pending
Last activity: 2026-04-19 — Completed 61-02: replaced Phase A jq pipelines with extract-graph.js invocation; added 9 PIPELINE_ERROR guards across normalizers

## Phase Index

| Phase | Name | Requirements | Status |
|-------|------|-------------|--------|
| 57 | !INCLUDE Infrastructure & Tier Model Declarations | PROM-01 | Complete (2026-04-19) |
| 58 | Shared Content Extraction — Verification, Enum Contract, Role Compression | PROM-02, PROM-03, PROM-05 | Complete (2026-04-19) |
| 59 | scope-defend Intake Consolidation | PROM-04 | Complete (2026-04-19) |
| 60 | Runtime Reference Loading | PROM-06 | Complete (2026-04-19) |
| 61 | Graph Extraction & Pipeline Guards | DET-01, DET-02 | In Progress (61-02 complete) |
| 62 | Input Safety — Path Sanitization & Credential Isolation | DET-03, DET-04 | Pending |
| 63 | IAM Simulator Wrapper | SIM-01 | Pending |
| 64 | IAM Simulator Integration — Exploit & Attack Paths | SIM-02, SIM-03, SIM-04 | Pending |

## Accumulated Context

- v1.12 shipped: exploit contract fixes, hook security hardening, hunt subagent split, memory removal, model routing, severity/edge/ID standardization
- Root cause of contract drift identified: same rules repeated in 15+ files — centralizing is the fix
- Multi-model analysis (GPT-5.4, Gemini 3.1 Pro, Claude Sonnet 4.6) converged on: LLM for creative reasoning, code/APIs for verification
- Prompt lengths (exploit 129K, defend 116K) exceed reliable instruction adherence window (30-50K)
- Phase A jq pipeline silently fails on cross-platform syntax drift
- IAM Simulator identified as highest-ROI quality improvement
- Phase 57 decision: config/models.json uses inherit:null to signal no model field in installed output (session model passthrough)
- Tier names established: enum (haiku-class), reasoning (sonnet-class), inherit (session passthrough)
- Phase 57-02 decision: resolveModelTier passes through literal model strings unchanged for backward compat — only symbolic tier labels (enum/reasoning/inherit) are mapped via config/models.json
- Phase 57-02 decision: resolveIncludes placed before all platform-specific transformation; no nesting allowed; hard-fail on missing file
- Phase 57-02 decision: Codex TOML developer_instructions uses expandedBody (post-include-resolution) so inlined instructions have @include directives already expanded
- Phase 58-01 decision: --argjson canonical for enum output contract (11/12 agents); IAM's --slurpfile form stays inline
- Phase 58-01 decision: effective_permissions and flush-on-save excluded from shared evidence-logging.md (exploit/hunt-specific)
- Phase 58-01 decision: agent-preamble.md contains only 4 truly cross-agent mandates (read-only, no auto-deploy, external:* IDs, lowercase severity)
- Phase 58-03 decision: scope-audit's agent_log_protocol renamed to evidence_protocol + @include added at top; audit-specific record types (subagent_dispatch, gate_transition) kept as inline extensions
- Phase 58-03 decision: scope-attack-paths and scope-pipeline contain no repeated project context — no changes needed
- Phase 58-03 decision: <session_isolation> renamed to <run_directory> in exploit/defend/hunt; audit replaced with <run_index> for index content; mandate line removed from all
- Phase 59-01 decision: scope-defend intake consolidated into <intake_protocol>; no orchestrator-vs-operator distinction — same routing logic either way; no multi-run aggregation; most-recent fallback selects single audit run
- Phase 60-02 decision: ESC_CAT/PERSIST_CAT/POSTEX_CAT loads are hard-fail mandatory (no fallback); cloudtrail-classes.json retains existing graceful degradation; all four loads co-located in cloudtrail_classification section

## Dependency Order

```
Phase 57 (PROM-01)
    └── Phase 58 (PROM-02, 03, 05)
    └── Phase 59 (PROM-04)
Phase 60 (PROM-06)           — independent
Phase 61 (DET-01, 02)        — independent
Phase 62 (DET-03, 04)        — independent
Phase 63 (SIM-01)
    └── Phase 64 (SIM-02, 03, 04)
```
