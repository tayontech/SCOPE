---
phase: 57-include-infrastructure-tier-model-declarations
plan: "02"
subsystem: infra
tags: [install, model-routing, include-resolver, bin]

requires:
  - phase: 57-01
    provides: config/models.json with enum/reasoning/inherit tier definitions

provides:
  - resolveIncludes() function in bin/install.js — expands @include directives in agent body content
  - resolveModelTier() function — maps tier labels (enum/reasoning/inherit) to vendor model names via config/models.json
  - MODELS_CONFIG startup load — hard-fails if config/models.json missing or invalid
  - Per-agent summary output — includes=/tier=/chars= line per installed subagent

affects: [Phase 58, bin/install.js consumers, agent installation pipeline]

tech-stack:
  added: []
  patterns:
    - "Tier routing: model: field in source frontmatter uses symbolic tier labels (enum/reasoning/inherit), resolved to vendor names at install time via config/models.json"
    - "@include resolution: directives in agent body expanded before platform-specific transformation"
    - "Literal model passthrough: any model: value not in [enum, reasoning, inherit] passes through unchanged for backward compat"

key-files:
  created: []
  modified:
    - bin/install.js

key-decisions:
  - "config/models.json loaded at module startup (hard-fail) — single source of truth for model names, replaces SUBAGENT_MODELS constant"
  - "SUBAGENT_MODELS, REASONING_AGENTS, getModelForAgent removed — replaced by resolveModelTier reading from MODELS_CONFIG"
  - "model: inherit returns null from resolveModelTier — caller omits model key from installed frontmatter (session passthrough)"
  - "resolveIncludes placed after rebuildFrontmatter and before per-editor functions — clean separation of preprocessing from transformation"
  - "Per-agent summary captures originalModel before mutation so the tier label printed reflects source frontmatter, not installed value"

requirements-completed:
  - PROM-01

duration: 30min
completed: 2026-04-18
---

# Phase 57 Plan 02: include-resolver-and-tier-routing Summary

**@include resolver and tier model routing added to bin/install.js — SUBAGENT_MODELS/REASONING_AGENTS/getModelForAgent replaced by resolveModelTier reading from config/models.json, and resolveIncludes() wired into all three subagent install functions and installForEditor()**

## Performance

- **Duration:** ~30 min
- **Started:** 2026-04-18T00:00:00Z
- **Completed:** 2026-04-18T00:30:00Z
- **Tasks:** 3
- **Files modified:** 1

## Accomplishments

- Removed hardcoded SUBAGENT_MODELS constant, REASONING_AGENTS set, and getModelForAgent function — all model routing now goes through config/models.json
- Added resolveModelTier() with backward-compat literal passthrough (non-tier strings untouched) and inherit→null semantics for session-model passthrough
- Added resolveIncludes() with nesting rejection, missing-file hard-fail, and post-expansion safety check
- Wired resolveIncludes into installSubagentsClaude, installSubagentsGemini, installSubagentsCodex, and installForEditor with per-agent summary output

## Task Commits

Each task was committed atomically:

1. **Task 57-02-01: Load config/models.json and replace SUBAGENT_MODELS/getModelForAgent** - `129bd01` (feat)
2. **Task 57-02-02: Add resolveIncludes() function** - `bf858b7` (feat)
3. **Task 57-02-03: Wire resolveIncludes into pipeline and emit per-agent summary** - `423533a` (feat)

## Files Created/Modified

- `bin/install.js` — Added MODELS_CONFIG startup load, resolveModelTier(), resolveIncludes(); removed SUBAGENT_MODELS/REASONING_AGENTS/getModelForAgent; updated all three subagent install functions and installForEditor

## Decisions Made

- Captured `originalModel = frontmatter.model` before any mutation in all three subagent install functions so the summary line reflects source tier label, not resolved vendor name
- For Codex, `mdBody` for TOML `developer_instructions` uses `expandedBody` (post-include-resolution) so the inlined instructions have @include directives already expanded
- `codexModel` fallback uses `MODELS_CONFIG['codex']['enum']` when resolveModelTier returns null (inherit) — TOML always has a concrete model name since Codex requires it

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Codex frontmatter out of scope for codexModel lookup**
- **Found during:** Task 57-02-01 (call-site update for installSubagentsCodex)
- **Issue:** `codexModel` is computed outside the `if (parsed)` block but `frontmatter` is scoped inside it — direct reference would be a ReferenceError
- **Fix:** Introduced `sourceFrontmatter = null` declared before the `if (parsed)` block; assigned inside; used `sourceFrontmatter?.model` for codexModel lookup
- **Files modified:** bin/install.js
- **Verification:** Node syntax check passes; no ReferenceError
- **Committed in:** 129bd01 (Task 57-02-01)

**2. [Rule 2 - Missing Critical] Gemini inherit model handling**
- **Found during:** Task 57-02-01 (Gemini call-site update)
- **Issue:** GEMINI_STRIP_KEYS does not include 'model' — if resolvedModel is null (inherit), the model key would still appear in output using the original source value
- **Fix:** Build geminiOmitKeys dynamically: if resolvedModel is null, add 'model' to the strip list
- **Files modified:** bin/install.js
- **Verification:** Gemini omit path verified via code inspection
- **Committed in:** 129bd01 (Task 57-02-01)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 missing critical)
**Impact on plan:** Both fixes necessary for correctness. No scope creep.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- bin/install.js now supports @include directives and tier model labels
- Phase 58 can add `model: enum` / `model: reasoning` / `model: inherit` to agent frontmatter and @include directives to agent body content
- Shared content files in agents/shared/ will be inlined correctly at install time

---
*Phase: 57-include-infrastructure-tier-model-declarations*
*Completed: 2026-04-18*
