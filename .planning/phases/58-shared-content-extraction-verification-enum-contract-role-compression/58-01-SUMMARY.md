---
phase: 58-shared-content-extraction-verification-enum-contract-role-compression
plan: 01
subsystem: prompt-architecture
tags: [agents, shared-content, verification, evidence-logging, enum-contract, preamble]

requires:
  - phase: 57-include-infrastructure-tier-model-declarations
    provides: "@include resolver in bin/install.js and agents/shared/ directory"

provides:
  - agents/shared/agent-preamble.md — compressed core mandates for all agents
  - agents/shared/verification-protocol.md — 8-step verification base for 4 orchestrators
  - agents/shared/evidence-logging.md — shared evidence log format and record types
  - agents/shared/enum-output-contract.md — 3-step output pipeline for all 12 enum agents

affects: [phase-58-plan-02, phase-58-plan-03, all-enum-agents, all-orchestrator-agents]

tech-stack:
  added: []
  patterns:
    - "Shared content extraction: content extracted verbatim from source agents, not rewritten"
    - "Variable placeholder pattern: $MODULE/$OUTPUT_FILE/$AGENT_NAME set by each enum agent before shared section"
    - "Include-then-extend: @include shared file, then add agent-specific rules inline below"

key-files:
  created:
    - agents/shared/agent-preamble.md
    - agents/shared/verification-protocol.md
    - agents/shared/evidence-logging.md
    - agents/shared/enum-output-contract.md
  modified:
    - agents/shared/.gitkeep (removed)

key-decisions:
  - "--argjson findings form chosen as canonical enum output pattern (11/12 agents use it; IAM is the outlier with --slurpfile)"
  - "effective_permissions record type excluded from shared evidence-logging.md (exploit-only)"
  - "flush-on-save pattern excluded from shared evidence-logging.md (hunt-specific)"
  - "defend's 8-step verification used as canonical base (most complete, includes web search step 8)"
  - "agent-preamble.md contains only 4 truly cross-agent mandates: read-only, no auto-deploy, external:* node IDs, lowercase severity"

requirements-completed:
  - PROM-02
  - PROM-03
  - PROM-05

duration: 15min
completed: 2026-04-19
---

# Phase 58 Plan 01: Create shared content files in agents/shared/ — Summary

**Four canonical shared files extracted verbatim from existing agents: verification protocol (8 steps), evidence logging (4 record types), enum output contract (3-step jq/log/validate pipeline), and core mandate preamble**

## Performance

- **Duration:** 15 min
- **Started:** 2026-04-19T00:00:00Z
- **Completed:** 2026-04-19T00:15:00Z
- **Tasks:** 4
- **Files modified:** 5 (4 created, 1 removed)

## Accomplishments

- Created `agents/shared/agent-preamble.md` with 4 cross-agent core mandates (read-only op, no auto-deploy, external:* node IDs, lowercase severity)
- Created `agents/shared/verification-protocol.md` with the 8-step verification base common to all 4 orchestrator agents, using defend's most complete version as canonical
- Created `agents/shared/evidence-logging.md` with shared evidence ID format, 4 shared record types, and failure handling rule — excluding agent-specific extensions
- Created `agents/shared/enum-output-contract.md` with all 3 pipeline steps (jq write → agent-log append → post-write validation) using `$MODULE`/`$OUTPUT_FILE`/`$AGENT_NAME` variable placeholders
- Removed `agents/shared/.gitkeep` — replaced by 4 real shared content files

## Task Commits

Each task was committed atomically:

1. **Task 58-01-01: Extract agent-preamble.md** - `0a63be7` (feat)
2. **Task 58-01-02: Extract verification-protocol.md** - `8bbe33d` (feat)
3. **Task 58-01-03: Extract evidence-logging.md** - `573e16d` (feat)
4. **Task 58-01-04: Extract enum-output-contract.md + remove .gitkeep** - `dd97fd7` (feat)

## Files Created/Modified

- `agents/shared/agent-preamble.md` — 4 core mandates shared across all agents
- `agents/shared/verification-protocol.md` — 8-step verification protocol base
- `agents/shared/evidence-logging.md` — evidence log format, record types, failure handling
- `agents/shared/enum-output-contract.md` — 3-step jq write/log/validate pipeline with variable placeholders
- `agents/shared/.gitkeep` — removed (real files now exist)

## Decisions Made

- **`--argjson` as canonical enum write pattern:** 11 of 12 enum agents use `--argjson findings "$FINDINGS_JSON"`. IAM is the outlier using `--slurpfile`. The shared file uses `--argjson`; IAM can keep its inline write and use only the logging + validation steps when Phase 58 Plan 03 replaces its inline section.
- **`effective_permissions` excluded from shared evidence-logging.md:** This record type appears only in `scope-exploit.md`. It stays inline in the exploit agent.
- **`flush-on-save` excluded from shared evidence-logging.md:** Hunt-specific pattern (accumulate in memory, flush only on save). Stays inline in `scope-hunt.md`.
- **defend's 8-step verification as canonical base:** defend has the most complete verification steps, including step 8 (web search at <95% confidence) which is genuinely shared. Audit's "inline verification" note and exploit's "Speculative Output Boundary" stay inline as agent-specific extensions.
- **agent-preamble.md kept minimal:** Only 4 mandates present in all agents. Agent-specific context (exploit detection prohibition, defend no-credentials note, audit platform dispatch note) stays inline.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- All 4 shared content files exist and pass verification checks
- No `@include` nesting (shared files contain no `@include` directives)
- No agent-specific content leaked into shared files
- Variable placeholders present in `enum-output-contract.md`
- Ready for Phase 58 Plan 02: replace inline content in orchestrator agents with `@include` directives
- Ready for Phase 58 Plan 03: replace inline enum output contracts in all 12 enum agents with `@include` directives

---
*Phase: 58-shared-content-extraction-verification-enum-contract-role-compression*
*Completed: 2026-04-19*
