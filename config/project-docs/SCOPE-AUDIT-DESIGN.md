# SCOPE Audit Agent Design

## Purpose

`scope-audit` is SCOPE's top-level audit orchestrator. It receives the operator target, enforces gates, invokes deterministic Python runtime enumeration, sequences attack analysis and validation, runs inline verification, writes audit findings, chains controls, and verifies required artifacts.

It should remain a top-level agent because it coordinates operator decisions and cross-agent sequencing. It should not become a subagent or skill.

## Decision

Keep `scope-audit` as the single audit entry point and clean its orchestration contract.

This pass tightens boundaries around:

- Runtime-owned enumeration and post-processing.
- Orchestrator-owned gates and downstream dispatch.
- Gate skip semantics.
- Artifact ownership.
- Prompt tool surface.
- Runtime path references.

This pass does not split `findings.md` into a skill and does not move more orchestration into Python.

## Agent Boundary

`scope-audit` owns:

- Target parsing guidance for operator input.
- Gate 1 identity check.
- Gate 2 module approval.
- Runtime command dispatch through `uv run python -m scope audit`.
- Gate 3 enumeration summary.
- Public exposure, attack analyze, attack validate, lint, and verification sequencing.
- Gate 4 attack-path approval.
- Audit-specific `findings.md`.
- Controls auto-chain after Gate 4 approval.
- Mandatory artifact checks.
- Audit knowledge load/update calls.

`scope-audit` does not own:

- Per-service enumeration logic.
- Parallel module scheduling.
- Graph extraction.
- Runtime aggregation.
- Dashboard public JSON export when runtime `--dashboard-export` succeeds.
- Attack candidate generation internals.
- Attack validation internals.
- Controls reasoning or controls artifact assembly.
- External web research.

## Runtime Contract

The Python runtime owns enumeration, aggregation, graph extraction, base `results.json`, `summary.json`, `resources.jsonl`, `graph.json`, and optional dashboard export data.

`scope-audit` invokes exactly one runtime audit command after Gate 2. It passes the approved target/service scope, `--run-dir`, `--dashboard-export`, concurrency, and optional regions.

Runtime paths are canonical:

- `$RUN_DIR/modules/<service>/<region>.json`
- `$RUN_DIR/summary.json`
- `$RUN_DIR/resources.jsonl`
- `$RUN_DIR/graph.json`
- `$RUN_DIR/results.json`
- `$RUN_DIR/manifest.json`

The prompt should not reference legacy top-level service JSON outputs such as `$RUN_DIR/s3.json` or `{service}.json not written`.

## Gate Semantics

### Gate 1

Gate 1 verifies credentials with `aws sts get-caller-identity`, loads account/SCP context, loads bounded knowledge, and auto-continues.

Gate 1 should not claim an enabled region count from runtime discovery. Runtime region discovery occurs inside `scope audit` after Gate 2. If the operator supplied explicit regions, Gate 1 may display those requested regions. Otherwise, Gate 1 should say region discovery will run during runtime dispatch.

### Gate 2

Gate 2 displays approved service scope and waits for operator approval.

The orchestrator still lets the Python runtime perform actual target resolution and region discovery. Gate 2 is an operator confirmation boundary, not a second implementation of runtime scheduling.

### Gate 3

Gate 3 summarizes enumeration artifacts and waits before attack analysis.

Gate 3 options:

- `continue`: run public exposure and attack pipeline.
- `skip`: skip public exposure, attack analysis, attack validation, Gate 4, controls, and dashboard HTML generation. Write a raw-inventory `findings.md` from runtime artifacts and verify required early-stop artifacts.
- `stop`: stop with runtime artifacts only and report the run directory.

The `skip` path must preserve `$RUN_DIR/results.json`; it must not delete runtime dashboard export files that already exist.

### Gate 4

Gate 4 summarizes validated and conditional attack paths after validation and verification.

Gate 4 options:

- `continue`: write full `findings.md`, chain controls, and generate dashboard HTML.
- `skip`: write `findings.md`, skip controls and dashboard HTML generation, keep runtime dashboard export files if they exist.
- `stop`: stop after attack analysis artifacts and report the run directory.

## Attack Pipeline Contract

`scope-audit` dispatches attack work in this order:

1. `scope-public-exposure-analysis`
2. `scope-attack-analyze`
3. candidate lint
4. `scope-attack-validate`
5. validation lint
6. inline `scope-verify` with domain-core and domain-aws

The orchestrator must stop before dependent stages when a blocking attack-stage failure occurs.

`scope-audit` passes:

- `RUN_DIR`
- `ACCOUNT_ID`
- `OWNED_ACCOUNTS` where required

It does not pass research parameters to `scope-research`; `scope-attack-analyze` owns its optional research dispatch.

## Findings Contract

Keep `findings.md` inline for this pass.

Reason:

- The report shape remains audit-specific.
- It depends on Gate 3 and Gate 4 operator choices.
- It combines runtime coverage, final attack paths, and controls next-action guidance.
- No second agent currently reuses the same report workflow.

The raw-inventory Gate 3 skip report should include:

- Account ID and target.
- Services enumerated.
- Module statuses and coverage gaps.
- Runtime findings or effective permissions available in `results.json`.
- Statement that attack analysis and controls were skipped by operator choice.
- Recommended next action to rerun `/scope:audit` and continue through attack analysis when ready.

## Tool Surface

`scope-audit` keeps `WebSearch` and `WebFetch` only because inline `scope-verify` needs documentation lookup for uncertain AWS API, CloudTrail, and MITRE claims. The orchestrator must not use web tools for audit research, target enrichment, external investigation, or research dispatch.

Needed tools:

- `Read`
- `Write`
- `Bash`
- `Grep`
- `Glob`
- `WebSearch`
- `WebFetch`

External research belongs to `scope-research`, dispatched by `scope-attack-analyze` or `scope-exploit`.

## Error Handling

Runtime module failures remain non-blocking when artifacts exist. The orchestrator surfaces coverage and error counts at Gate 3.

Blocking failures:

- Credential failure at Gate 1.
- Missing runtime artifacts required for the selected next stage.
- Public exposure failure before attack analysis.
- Candidate lint failure.
- Attack validation failure.
- Validation lint failure.

Non-blocking failures:

- Controls failure after Gate 4 continue.
- Dashboard HTML generation failure.
- Knowledge update failure.
- Mandatory artifact check warnings for artifacts outside the chosen gate path.

## Test Strategy

Use Python contract tests.

Coverage:

- `scope-audit` declares `WebSearch` and `WebFetch` only for inline `scope-verify` documentation checks.
- `scope-audit` does not use web tools for audit research or research dispatch.
- Gate 1 does not claim enabled region count from runtime discovery before runtime dispatch.
- Gate 3 `skip` has explicit raw-inventory artifact behavior and skips attack, controls, and dashboard HTML.
- Legacy top-level service JSON wording is absent.
- Runtime path references use `modules/<service>/<region>.json`.
- `scope-audit` does not dispatch `scope-research`.
- Attack pipeline order remains public exposure, analyze, candidate lint, validate, validation lint, verify.

Verification should run:

```bash
pytest tests/scope/contracts/test_attack_agent_contracts.py -q
pytest tests/scope/contracts/test_runtime_path_contracts.py -q
node --check bin/install.js
git diff --check
```

## Non-Goals

- No split of `scope-audit`.
- No `scope-findings-report` skill.
- No runtime CLI behavior change.
- No dashboard code change.
- No controls contract change.
- No attack subagent redesign.
