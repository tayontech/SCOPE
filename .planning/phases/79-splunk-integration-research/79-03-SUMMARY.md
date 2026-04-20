---
phase: 79-splunk-integration-research
plan: "03"
subsystem: agents
tags: [splunk, multi-index, hunt, defend, index-routing, index-discovery]
dependency_graph:
  requires: ["79-01", "79-02"]
  provides: ["multi-index-hunt-agent", "multi-index-defend-splunk-agent", "updated-claude-md"]
  affects: ["agents/scope-hunt.md", "agents/subagents/scope-defend-splunk.md", "CLAUDE.md"]
tech_stack:
  added: []
  patterns:
    - "Config-driven index routing (config/index.json group lookup)"
    - "PROBE_INDEX from config/index.json for MCP detection startup probe"
    - "Lazy field sampling (head 1 with earliest=-30d, cached in-session)"
    - "Separate SPL per index, agent correlates after (D-09)"
    - "D-19 operator prompt on index zero results or errors"
    - "D-22 operator prompt for unconfigured data source indexes"
    - "Merge-on-refresh index discovery (D-06, never removes existing entries)"
key_files:
  modified:
    - agents/scope-hunt.md
    - agents/subagents/scope-defend-splunk.md
    - CLAUDE.md
decisions:
  - "MCP probe sequence uses PROBE_INDEX from config/index.json first index, falls back to cloudtrail (D-21, D-23)"
  - "index_discovery section added after mcp_detection block — triggers when index.json absent and Splunk connected"
  - "Separate queries per index enforced in both hunt and defend-splunk (D-09)"
  - "D-19 prompts are explicit ask-the-operator patterns, never silent skip or guess"
  - "Splunk ES internal indexes (notable, risk, etc.) explicitly excluded from config/index.json and allowlist scope"
metrics:
  duration_seconds: 226
  completed_date: "2026-04-20"
  tasks_completed: 3
  tasks_total: 3
  files_modified: 3
---

# Phase 79 Plan 03: Agent Multi-Index Updates Summary

**One-liner:** Multi-index aware hunt and defend-splunk agents with config/index.json routing, index discovery protocol, lazy field sampling, and D-19/D-22 operator prompts.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Update scope-hunt.md for multi-index routing and index discovery | 1352ac6 | agents/scope-hunt.md |
| 2 | Update scope-defend-splunk.md for multi-index detection routing | 86f6226 | agents/subagents/scope-defend-splunk.md |
| 3 | Update CLAUDE.md for multi-index Splunk model | f9c92de | CLAUDE.md |

## What Was Built

### Task 1: scope-hunt.md

**MCP probe sequence (Section 1):** Replaced all three hardcoded `index=cloudtrail | head 1` probe queries with a config-driven flow. Agent now reads `config/index.json` at startup, extracts the first index from any group's `indexes[]` array as PROBE_INDEX, and uses `index={PROBE_INDEX} earliest=-1h | head 1` for the probe. Falls back to `PROBE_INDEX="cloudtrail"` when `config/index.json` is absent (D-21).

**Index discovery protocol (Section 2 — new `<index_discovery>` block):** Added a complete index discovery section following the existing XML section pattern used throughout the file. Covers:
- When to trigger (config absent + Splunk connected) vs skip (config exists, no refresh)
- Step 1: `get_indexes` MCP tool with REST fallback
- Step 2: Internal index filter list (underscore-prefixed + ES internals: notable, risk, ioc, ueba, etc.)
- Step 3: Reasoning about index names to classify into type groups (aws_api, identity, vcs, endpoint, network, cloud_platform)
- Step 4: Formatted table presented to operator for confirmation (D-07)
- Step 5: Write config/index.json with `discovery_method: "auto"` after confirmation
- Refresh flow: reads existing groups, appends only new indexes, never removes existing entries (D-06)

**SPL generation rules (Section 3):** Replaced the single `ALWAYS use index=cloudtrail` rule with:
- Read `config/index.json`, load appropriate type group for investigation context
- Read `config/splunk-patterns.md` for command selection
- Separate query per index, never OR-combine (D-09)
- Lazy field sampling: `index=<name> earliest=-30d latest=now | head 1` on first use of each index, cached in-session (D-11)
- Backward compat fallback to cloudtrail when absent (D-21)
- D-19: explicit ask-operator pattern on zero results or errors

**SPL templates (Section 4):** All four query construction patterns updated to use `<aws_api_index>` placeholder with note to read from `config/index.json`. `index=notable` preserved as-is (ES internal, always valid).

### Task 2: scope-defend-splunk.md

**Conventions block:** Replaced `Every SPL detection MUST use index=cloudtrail` with:
- config/index.json read at session start
- config/splunk-patterns.md reference for command selection
- Separate detection per index type (D-09)
- Index selection logic table mapping data sources to groups (aws_api, identity, vcs, endpoint, network)
- Backward compat: default cloudtrail when absent (D-21)

**D-22 unconfigured index handling:** New instruction — when attack path leads to a data source with no configured index group, ask operator before skipping.

**D-19 index error handling:** New instruction — when detection's target index returns zero results or error, ask operator with full context before finalizing output.

**Detection templates:** Both atomic and composite templates updated to use `<aws_api_index>` placeholder with explicit note to read from config/index.json. Added multi-index attack path pattern (D-10) describing separate named detections per data source with correlation note.

**Lint hook reference:** Updated to describe new rules: streamstats (not transaction), time bounds, config/index.json allowlist, no index=*, no leading wildcards. Added note that absent index.json skips allowlist check and ES internal indexes are always permitted.

### Task 3: CLAUDE.md

**CloudTrail + Splunk section:** Removed "CloudTrail is the only log source for Splunk (index=cloudtrail)". Replaced with multi-index model description covering: config/index.json for index routing, auto-discovery via get_indexes MCP tool with operator confirmation, backward compat fallback, standalone mode preservation, and config/splunk-patterns.md reference.

**Configuration Files table:** Added three new rows: `config/index.json` (gitignored, operator Splunk config), `config/index.example.json` (committed template), `config/splunk-patterns.md` (committed SPL patterns reference). Updated footnote to note index.json is gitignored alongside accounts.json.

**Hooks table:** Updated scope-spl-lint.sh description from "Hard-fail on SPL anti-patterns (missing index, wrong fields, transaction in composites)" to "Validates SPL against config/index.json allowlist, blocks anti-patterns (transaction in composites, leading wildcards, index=*, missing time bounds)".

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None. All changes are behavioral instructions to agents, not data stubs.

## Threat Flags

No new network endpoints, auth paths, file access patterns, or schema changes at trust boundaries were introduced. Changes are agent instruction updates only.

## Self-Check: PASSED

- agents/scope-hunt.md: modified and committed (1352ac6)
- agents/subagents/scope-defend-splunk.md: modified and committed (86f6226)
- CLAUDE.md: modified and committed (f9c92de)
- All automated verification checks passed for all three tasks
