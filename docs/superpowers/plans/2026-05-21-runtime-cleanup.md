# Runtime Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove deprecated JavaScript enumeration/runtime files and generated local artifacts now that Python `scope_runtime` owns AWS enumeration.

**Architecture:** Keep Python enumeration as the source of truth. Keep JavaScript only where it still provides active non-enumeration tooling: installer, graph extraction, report/dashboard support, and the tests for those surfaces.

**Tech Stack:** Python 3.11+, boto3/Pydantic/pytest, Node.js for installer/graph/report utilities.

---

### Task 1: Remove Legacy Enumeration Surface

**Files:**
- Delete: `scripts/`
- Delete: `test/enum-*.test.js`
- Delete: `test/lib-*.test.js`
- Delete: `test/fixtures/enum/`
- Delete: `test/schema-module-envelope.test.js`
- Delete: `test/agent-prompt-coverage-instructions.test.js`
- Modify: `package.json`
- Modify: `package-lock.json`

- [ ] Remove legacy JS enumeration implementation and tests.
- [ ] Keep `test/extract-graph.test.js`, `test/hook-schema-validate.test.js`, `test/schema-audit-results.test.js`, `test/run-all.js`, and `test/fixtures/extract-graph/`.
- [ ] Update root package metadata so `npm test` only covers active JS tooling tests.
- [ ] Regenerate `package-lock.json` without AWS SDK enumeration dependencies.

### Task 2: Repair Runtime References

**Files:**
- Modify: `agents/scope-audit.md`
- Modify: `README.md`
- Modify: `ARCHITECTURE.md`
- Modify: `config/hooks/scope-artifact-check.sh`

- [ ] Replace stale `node scripts/enum/*.js` audit instructions with `uv run python -m scope_runtime audit`.
- [ ] Update docs to describe `enumerators/`, `scope_core/`, and `scope_runtime/` as the enumeration runtime.
- [ ] Update artifact checks to look under both current `runs/` layout and legacy `audit/` layout where needed.

### Task 3: Remove Ignored Local Artifacts

**Files:**
- Modify: `.gitignore`
- Remove local only: `audit/`, `agent-logs/`, `data/`, `node_modules/`, `dashboard/node_modules/`, `test/tmp/`, `.DS_Store`, `__pycache__/`, `*.pyc`

- [ ] Add ignore rules for `.venv/`, `.pytest_cache/`, `*.egg-info/`, and `*.pyo`.
- [ ] Remove ignored local runtime and dependency directories.
- [ ] Verify no tracked files were removed by local cleanup.

### Task 4: Verify

- [ ] Run `uv run pytest -q`.
- [ ] Run `npm test -- --silent`.
- [ ] Run `uv run python -m scope_runtime audit --help`.
- [ ] Run `node --check bin/extract-graph.js bin/generate-report.js bin/install.js`.
