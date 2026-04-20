---
phase: 78-defend-agent-rework
plan: "02"
subsystem: defend-subagents
tags: [defend, guardrails, splunk, scp, rcp, spl, subagents]
dependency_graph:
  requires: [78-01]
  provides: [scope-defend-guardrails, scope-defend-splunk]
  affects: [agents/scope-defend.md, config/schemas/defend.schema.json]
tech_stack:
  added: []
  patterns: [fresh-context-subagent, structured-return-summary, atomic-composite-detection]
key_files:
  created:
    - agents/subagents/scope-defend-guardrails.md
    - agents/subagents/scope-defend-splunk.md
  modified: []
decisions:
  - "D-18 enforced: no fixed percentage thresholds in systemic pattern detection — reasoning-based only"
  - "D-19 enforced: both SCPs and RCPs generated when systemic patterns warrant them"
  - "D-23 enforced: break-glass ArnNotLike condition required on every SCP"
  - "detections.json written alongside splunk-detections.md to avoid markdown parsing by orchestrator"
metrics:
  duration: "~15 minutes"
  completed: "2026-04-20"
  tasks_completed: 2
  tasks_total: 2
  files_created: 2
  files_modified: 0
---

# Phase 78 Plan 02: Guardrails and Splunk Defend Subagents Summary

Two new defend subagents created: scope-defend-guardrails (systemic pattern detection → SCP/RCP policies with break-glass) and scope-defend-splunk (attack-path-mapped CloudTrail SPL detections with atomic/composite model and machine-readable detections.json output).

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | Create scope-defend-guardrails.md | d87b36a | agents/subagents/scope-defend-guardrails.md |
| 2 | Create scope-defend-splunk.md | 8eaf5f2 | agents/subagents/scope-defend-splunk.md |

## What Was Built

### scope-defend-guardrails.md

A fresh-context subagent that reads `AUDIT_RUN_DIR/results.json` and all per-module JSONs to detect systemic security patterns across the account. Key behaviors:

- **Reasoning-based detection**: no fixed percentage thresholds — reasons about whether a pattern is widespread enough to warrant an org-level policy vs a targeted fix (D-18)
- **SCPs and RCPs**: generates both types when patterns have both principal-side and resource-side components (D-19). Includes decision guidance on when to use each.
- **Break-glass mandatory**: every SCP must include an `ArnNotLike` condition for emergency access roles — the validator will BLOCK any SCP without it (D-23)
- **Artifact output**: `guardrails.md` (narrative with impact analysis per pattern) + `policies/scp-*.json` and `policies/rcp-*.json` (compact deployable JSON)
- **Return summary**: `STATUS / FILE / METRICS: {scps: N, rcps: N} / ERRORS`

### scope-defend-splunk.md

A fresh-context subagent that reads `attack_paths[]` from `AUDIT_RUN_DIR/results.json` and writes CloudTrail SPL detections. Key behaviors:

- **1:1 mapping**: one or more detections per attack path, derived from `detection_opportunities[]` and MITRE techniques
- **Atomic/composite model**: individual behaviors as atomics; multi-phase TTPs as composites using `| streamstats` (never `| transaction` — the lint hook will reject it)
- **SPL conventions enforced**: `index=cloudtrail`, `earliest`/`latest` bounds, `userIdentity.userName` rename, `sourceIPAddress` field name — all enforced by the `scope-spl-lint.sh` hook that fires automatically on Write
- **Dual output**: `splunk-detections.md` (human-readable, markdown) + `detections.json` (machine-readable array for orchestrator to consume directly during results.json assembly — avoids markdown parsing)
- **Return summary**: `STATUS / FILE / METRICS: {detections: N} / ERRORS`

## Deviations from Plan

None — plan executed exactly as written.

The plan specified `detections.json` as a structured output alongside the markdown artifact. This was included in both the action spec and the acceptance criteria. No deviation needed.

## Threat Flags

None. Both subagents read from disk, write to `DEFEND_RUN_DIR`, and include explicit no-memory directives. No new network endpoints or auth paths introduced.

## Self-Check: PASSED

- agents/subagents/scope-defend-guardrails.md — FOUND (d87b36a)
- agents/subagents/scope-defend-splunk.md — FOUND (8eaf5f2)
- Both files have correct frontmatter (name, model: claude-sonnet-4-6, tools: Read, Write, Bash)
- Both files contain fresh-context declaration
- Both files contain AUDIT_RUN_DIR/DEFEND_RUN_DIR/ACCOUNT_ID/SERVICES_COMPLETED input contract
- Both files contain "Do NOT write to MEMORY.md"
- guardrails: references SCPs, RCPs, break-glass conditions, guardrails.md, policies/
- splunk: references index=cloudtrail, userIdentity.userName, streamstats, earliest/latest, detections.json, splunk-detections.md
