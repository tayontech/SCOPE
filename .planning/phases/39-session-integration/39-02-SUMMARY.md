---
phase: 39
plan: "39-02"
name: "Session Integration — Update Existing Sections (role + session_isolation)"
status: complete
completed: "2026-03-30"
commits: 6
---

# Plan 39-02 Summary

## What Was Done

Updated three existing sections in `agents/scope-hunt.md` to reflect the dual-mode capability added in Plan 39-01. All changes were targeted edits — no rewrites of surrounding content.

## Tasks Executed

| Task | Description | Result |
|------|-------------|--------|
| 1 | Replace `<role>` entry point line with dual-mode description | Complete |
| 2 | Update `<role>` session isolation line with hunt mode exception | Complete |
| 3 | Make `<role>` standalone prohibition conditional on mode | Complete |
| 4 | Replace `<session_isolation>` Rule 3 with conditional audit/exploit read rule | Complete |
| 5 | Add Rule 6 (hunt mode memory hygiene) to `<session_isolation>` | Complete |
| 6 | Add Splunk-optional note to `<mcp_detection>` After MCP Detection subsection | Complete |
| 7 | Verify all changes and confirm untouched sections intact | Complete — all 7 checks passed |

## Key Changes

**`<role>` section:**
- "Entry point is always an alert that fired. Not for freeform threat hunting..." replaced with two-bullet dual-mode description (hunt mode + detection investigation mode)
- Session isolation statement extended: now permits reading the provided audit/exploit run directory in hunt mode; prohibits speculative reads and MEMORY.md writes of run-directory identifiers
- Standalone prohibition made conditional: detection investigation mode retains full prohibition; hunt mode reads only the explicitly provided run directory

**`<session_isolation>` section:**
- Rule 3 replaced: "No audit dependency" → "Audit/exploit reads — conditional" — permits reads in hunt mode, prohibits them in detection investigation mode, prohibits speculative reads of other run directories
- Rule 6 added: "Hunt mode memory hygiene" — ARNs, account IDs, bucket names, role names, key IDs, access key IDs read from run directory are session-scoped only and must not enter MEMORY.md

**`<mcp_detection>` section:**
- Added hunt mode note after Step 2: if MODE=HUNT and MCP_MODE=MANUAL, Splunk is not required; agent can produce hypothesis report from audit/exploit output alone; provides analyst-facing message

## Verification Results

All 7 task checks passed and all Phase 39 success criteria met:

- SC-1: `HUNT_RUN_DIR | hunt_mode_intake | RUN DIRECTORY LOADED` → 12 matches (≥5 required)
- SC-2: `Ready to investigate | After MCP Detection | investigation_context` → all present
- SC-3: `MODE=HUNT | MODE=INVESTIGATION | Detection investigation mode | Hunt mode` → ≥8 matches
- SC-4: `Splunk is not required | hypothesis report from audit/exploit output alone` → 2 matches (both in mcp_detection and hunt_mode_intake)
- SC-5: `speculatively read | not provided at startup` → 3 matches (≥2 required)
- SC-6: `must NOT be written to MEMORY.md | Hunt mode memory hygiene` → 2 matches

## Files Modified

- `agents/scope-hunt.md` — 6 atomic commits

## Untouched Sections (confirmed)

- `<alert_intake>` — "Ready to investigate" present
- `<input_parsing>` — `investigation_context` structure intact
- `<investigation_loop>`, `<reasoning_framework>`, `<evidence_protocol>` — all untouched
