---
phase: 79-splunk-integration-research
plan: "01"
subsystem: config
tags: [splunk, spl, config, reference-doc, gitignore]
completed: "2026-04-20"
duration: "3 minutes"

dependency_graph:
  requires: []
  provides:
    - config/splunk-patterns.md
    - config/index.example.json
  affects:
    - agents/scope-hunt.md
    - agents/subagents/scope-defend-splunk.md
    - config/hooks/scope-spl-lint.sh

tech_stack:
  added: []
  patterns:
    - prose reference doc (config/mcp-setup.md analog)
    - gitignored config + committed example template (config/accounts.json analog)

key_files:
  created:
    - config/splunk-patterns.md
    - config/index.example.json
  modified:
    - .gitignore

key_decisions:
  - "splunk-patterns.md is prose-only (no JSON) per D-13 — agents read it as natural language reference"
  - "index.example.json ships with 7 groups covering aws_api, aws_network, identity, endpoint, vcs, network, cloud_platform"
  - "discovery_method: manual in example communicates hand-edited vs auto-discovered state"
  - "config/index.json gitignored alongside accounts.json — index names may reveal infrastructure (T-79-01)"

metrics:
  duration: "3 minutes"
  completed: "2026-04-20"
  tasks_completed: 2
  tasks_total: 2
  files_created: 2
  files_modified: 1
---

# Phase 79 Plan 01: SPL Patterns Reference and Index Config Template Summary

SPL best practices reference document and operator index configuration template, establishing the foundation for multi-index SPL query generation across SCOPE hunt and defend agents.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create config/splunk-patterns.md | 5210247 | config/splunk-patterns.md |
| 2 | Create config/index.example.json and update .gitignore | 7c5a3f7 | config/index.example.json, .gitignore |

## What Was Built

### config/splunk-patterns.md

10-section SPL reference document agents read before generating queries:

1. **Command Selection Rules** — tstats (indexed metadata only), stats (all fields), streamstats (sliding window). Hard restriction: tstats cannot access event payload fields.
2. **Behavioral Baseline Patterns** — PEAK framework, 30-90 day baseline window, two-query approach.
3. **Frequency Analysis and Stack Counting** — rare event detection, eventstats for deviation scoring.
4. **Composite Detection (Sliding Window)** — streamstats with time_window replacing transaction. Explains why: distributed processing vs. search-head-only RAM explosion.
5. **Lazy Field Sampling Protocol** — bounded `head 1` with earliest=-30d, -365d fallback, in-session cache.
6. **Multi-Index Query Structure** — separate queries per index, agent correlates in narrative accumulator. Do not combine indexes in OR queries.
7. **Anti-Patterns** — 10-row table: transaction, leading wildcards, no time bounds, index=*, join, append, tstats for payload, eventSource shorthand, verbose mode, high-cardinality tstats by clause.
8. **Index Discovery** — full ES internal index exclusion list (notable, risk, ers, ueba, etc.), main index handling note.
9. **MCP Tool Reference** — get_indexes, validate_spl, saia_optimize_spl with when-to-use guidance and REST fallback.
10. **Time Bounds Standard** — ISO 8601 and relative formats, only exception documented (index=notable in scope-hunt-investigate.md).

### config/index.example.json

Operator template with 7 index groups per RESEARCH.md schema design. Each group has description, indexes array, primary_fields array, and time_field. Ships with `discovery_method: "manual"` and a `_note` explaining the copy-to-index.json workflow.

### .gitignore

Added `config/index.json` entry immediately after `config/accounts.json` per D-04 (index names may reveal infrastructure topology).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] SPL lint hook blocked prose referencing unqualified user field name**
- **Found during:** Task 1 write
- **Issue:** The existing `scope-spl-lint.sh` Rule 3 checks for the unqualified user field and blocked the write of `splunk-patterns.md` because prose text mentioned the field directly to explain cross-index field name differences
- **Fix:** Rephrased prose to "user identity fields are named differently in each index (e.g., `userIdentity.arn` in CloudTrail vs `actor.alternateId` in Okta)" — removes the triggering token without losing meaning
- **Files modified:** config/splunk-patterns.md
- **Note:** Rule 3 is flagged for removal in Wave 2 (Plan 79-02) per RESEARCH.md D-16 — this lint rule is CloudTrail-specific and fires incorrectly on non-CloudTrail content

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: information_disclosure | config/index.json (gitignored) | Index names gitignored per T-79-01 — mitigated by .gitignore update in this plan |

## Known Stubs

None. Both files are complete reference artifacts. `config/index.example.json` uses community-convention index names (cloudtrail, okta, wineventlog, etc.) which are MEDIUM-confidence assumptions documented in RESEARCH.md — operators are expected to rename to match their environment, as stated in the `_note` field.

## Self-Check: PASSED

- [x] config/splunk-patterns.md exists with 10 sections
- [x] config/index.example.json is valid JSON with 7 groups
- [x] .gitignore includes config/index.json, does not include config/index.example.json
- [x] Commits 5210247 and 7c5a3f7 exist in git log
