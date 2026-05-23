# Scope Audit Boundary Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tighten `scope-audit` as the top-level audit orchestrator by removing stale tool/path/gate contracts and making runtime-owned versus orchestrator-owned behavior explicit.

**Architecture:** Keep `scope-audit` as the top-level agent. Add contract tests for the approved boundary, update only the prompt contract, and verify existing runtime/docs tests. No Python runtime behavior changes.

**Tech Stack:** Markdown agent prompt, Python `pytest` contract tests, Node installer syntax check.

---

## File Structure

- Modify `tests/scope/contracts/test_attack_agent_contracts.py`: add prompt contract tests for `scope-audit` tools, Gate 1 region wording, Gate 3 skip behavior, runtime paths, and no `scope-research` dispatch.
- Modify `agents/scope-audit.md`: remove web tools, tighten Gate 1/Gate 3/error handling/mandatory output text, and remove legacy top-level service JSON wording.
- Verify `tests/scope/contracts/test_runtime_path_contracts.py`: no edits expected, but run it because the implementation touches runtime path wording.

## Task 1: Add Scope Audit Boundary Contract Tests

**Files:**
- Modify: `tests/scope/contracts/test_attack_agent_contracts.py`

- [ ] **Step 1: Add failing boundary test**

Append this test after `test_audit_orchestrates_attack_pipeline` in `tests/scope/contracts/test_attack_agent_contracts.py`:

```python
def test_scope_audit_boundary_contract() -> None:
    prompt = read("agents/scope-audit.md")

    assert_matches(prompt, r"^name: scope-audit$", "frontmatter name missing")
    assert "tools: Read, Write, Bash, Grep, Glob" in prompt
    assert_not_matches(prompt, r"^tools:[^\n]*(WebSearch|WebFetch)", "scope-audit should not expose web research tools")

    gate1 = section(prompt, "gate_1_credentials")
    assert "Region discovery will run during runtime dispatch." in gate1
    assert "If explicit regions were supplied, display those requested regions." in gate1
    assert "enabled regions count" not in gate1
    assert "note if fallback" not in gate1

    gate3 = section(prompt, "gate_3_enumeration_summary")
    assert "`skip`" in gate3
    assert "raw-inventory `findings.md`" in gate3
    assert "skip public exposure, attack analysis, attack validation, Gate 4, controls, and dashboard HTML generation" in gate3
    assert "Preserve `$RUN_DIR/results.json`" in gate3
    assert "Do not delete runtime dashboard export files" in gate3

    mandatory = section(prompt, "mandatory_outputs")
    assert "Gate 3 skip exception" in mandatory
    assert "$RUN_DIR/results.json" in mandatory
    assert "$RUN_DIR/findings.md" in mandatory
    assert "$RUN_DIR/agent-log.jsonl" in mandatory

    assert "scope-research" not in prompt
    assert "WebSearch" not in prompt
    assert "WebFetch" not in prompt
    assert "{service}.json not written" not in prompt
    assert "[MISSING] {service}.json not written" not in prompt
    assert "modules/<service>/<region>.json missing" in prompt
```

- [ ] **Step 2: Run the focused test and verify failure**

Run:

```bash
pytest tests/scope/contracts/test_attack_agent_contracts.py::test_scope_audit_boundary_contract -q
```

Expected: FAIL because `scope-audit` still declares `WebSearch`/`WebFetch`, Gate 1 still claims enabled region count, Gate 3 skip is underspecified, and legacy `{service}.json` wording remains.

- [ ] **Step 3: Commit the failing test**

Run:

```bash
git add tests/scope/contracts/test_attack_agent_contracts.py
git commit -m "test: add scope audit boundary contract"
```

## Task 2: Tighten Scope Audit Prompt Boundary

**Files:**
- Modify: `agents/scope-audit.md`

- [ ] **Step 1: Remove web tools from frontmatter**

Replace:

```yaml
tools: Read, Write, Bash, Grep, Glob, WebSearch, WebFetch
```

With:

```yaml
tools: Read, Write, Bash, Grep, Glob
```

- [ ] **Step 2: Replace Gate 1 region discovery wording**

In `<gate_1_credentials>`, replace:

```markdown
**Region discovery:** `scope audit` discovers enabled regions through `scope.core.regions.discover_regions()` when regional services are requested. If the operator supplies explicit regions, pass them with `--regions us-east-1,us-west-2`. If region discovery fails, stop and show the runtime error rather than guessing region coverage.

**Display Gate 1:** Identity confirmed - show caller ARN, account ID, principal type, owned-accounts count, SCPs loaded count, enabled regions count (note if fallback). Auto-continue to module approval. Do NOT pause for operator input at Gate 1.

**Knowledge preflight:** Use `skills/scope-knowledge-load/SKILL.md` with `AGENT=scope-audit`, `ACCOUNT_ID`, target, services, and enabled regions before planning findings or dispatching downstream analysis. Use the returned `KNOWLEDGE_CONTEXT` to contextualize findings, public exposure, attack paths, and coverage gaps. Do not treat knowledge as ground truth; current audit evidence wins when it conflicts with stored knowledge. Cite knowledge entries that influence decisions.
```

With:

```markdown
**Region handling:** `scope audit` discovers enabled regions through `scope.core.regions.discover_regions()` during runtime dispatch when regional services are requested. If explicit regions were supplied, display those requested regions and pass them with `--regions us-east-1,us-west-2`. If no explicit regions were supplied, display: `Region discovery will run during runtime dispatch.` If runtime region discovery fails, stop and show the runtime error rather than guessing region coverage.

**Display Gate 1:** Identity confirmed - show caller ARN, account ID, principal type, owned-accounts count, SCPs loaded count, requested regions when supplied, or the runtime-discovery message above. Auto-continue to module approval. Do NOT pause for operator input at Gate 1.

**Knowledge preflight:** Use `skills/scope-knowledge-load/SKILL.md` with `AGENT=scope-audit`, `ACCOUNT_ID`, target, services, and requested regions when supplied. If regions were not supplied, set the knowledge request region context to `runtime_discovery_pending`. Use the returned `KNOWLEDGE_CONTEXT` to contextualize findings, public exposure, attack paths, and coverage gaps. Do not treat knowledge as ground truth; current audit evidence wins when it conflicts with stored knowledge. Cite knowledge entries that influence decisions.
```

- [ ] **Step 3: Replace Gate 3 options and skip behavior**

In `<gate_3_enumeration_summary>`, replace:

```markdown
Options: `continue` (dispatch attack-paths), `skip` (raw findings only), `stop` (end session with enumeration data).

Regional failures are non-blocking - warn and continue. Wait for operator approval.
```

With:

```markdown
Options:
- `continue` - dispatch public exposure and attack-path analysis.
- `skip` - skip public exposure, attack analysis, attack validation, Gate 4, controls, and dashboard HTML generation. Write a raw-inventory `findings.md` from runtime artifacts, preserve `$RUN_DIR/results.json`, and verify Gate 3 skip mandatory artifacts.
- `stop` - stop with runtime artifacts only and report `$RUN_DIR`.

On `skip`, write `$RUN_DIR/findings.md` with account ID, target, services enumerated, module statuses, coverage gaps, runtime findings or effective permissions available in `results.json`, a statement that attack analysis and controls were skipped by operator choice, and a recommended next action to rerun `/scope:audit` and continue through attack analysis when ready. Preserve `$RUN_DIR/results.json`. Do not delete runtime dashboard export files that already exist.

Regional failures are non-blocking - warn and continue. Wait for operator approval.
```

- [ ] **Step 4: Tighten findings report intro**

In `<findings_md>`, replace:

```markdown
After Gate 4 approval, write `$RUN_DIR/findings.md` - always generated, even with 0 findings.
```

With:

```markdown
After Gate 4 approval, write `$RUN_DIR/findings.md` - always generated, even with 0 findings. If Gate 3 `skip` was selected, write the raw-inventory report described in `<gate_3_enumeration_summary>` instead and do not continue to Gate 4.
```

- [ ] **Step 5: Tighten results export ownership**

In `<results_export>`, replace:

```markdown
After findings.md is written (and Gate 4 was NOT skipped):

1. Copy `$RUN_DIR/results.json` to `dashboard/public/$RUN_ID.json`
2. Upsert this run into `dashboard/public/index.json` (match on `run_id`, newest-first) with fields: run_id, date, source ("audit"), target, risk, status, file

The Python runtime performs this automatically when invoked with `--dashboard-export`. If the export is missing, rerun the runtime command with `--dashboard-export` or copy the run into `dashboard/public/` using the same index shape.
```

With:

```markdown
The Python runtime performs dashboard public JSON export automatically when invoked with `--dashboard-export`.

After findings.md is written (and Gate 4 was NOT skipped), verify:
1. `dashboard/public/$RUN_ID.json` exists or a runtime warning explains why export failed.
2. `dashboard/public/index.json` contains this run or a runtime warning explains why index update failed.

Do not hand-build dashboard public JSON unless recovering from a runtime export failure and using the same index shape documented by `scope.runtime.post_processing.export_dashboard_results`.
```

- [ ] **Step 6: Add Gate 3 skip exception to mandatory outputs**

In `<mandatory_outputs>`, after the opening paragraph and before the Gate 4 skip exception, add:

```markdown
**Gate 3 skip exception:** If the operator said `skip` at Gate 3, `$RUN_DIR/results.json`, `$RUN_DIR/findings.md`, and `$RUN_DIR/agent-log.jsonl` remain required. Public exposure, attack analysis, validation, controls, and dashboard HTML generation are skipped. Runtime dashboard export files remain acceptable when the Python runtime already created them before Gate 3.
```

- [ ] **Step 7: Replace legacy missing subagent output wording**

In `<error_handling>`, replace:

```markdown
| Subagent no output file | Log `[MISSING] {service}.json not written`, report at Gate 3. |
```

With:

```markdown
| Runtime module artifact missing | Log `[MISSING] modules/<service>/<region>.json missing`, report at Gate 3. |
```

- [ ] **Step 8: Tighten success criteria for Gate 3 skip**

In `<success_criteria>`, replace:

```markdown
**Early stop:** If the operator says "stop" at any gate, the run is complete with partial output - only criteria up to that gate apply. Run is still indexed and existing artifacts are valid.
```

With:

```markdown
**Early stop:** If the operator says `stop` at any gate, the run is complete with partial output - only criteria up to that gate apply. Existing artifacts remain valid.

**Gate 3 skip:** If the operator says `skip` at Gate 3, the run succeeds when runtime artifacts exist, raw-inventory `findings.md` is written, `$RUN_DIR/results.json` is preserved, `$RUN_DIR/agent-log.jsonl` exists, and the skipped attack/controls/dashboard-HTML stages are reported.
```

- [ ] **Step 9: Run focused contract tests**

Run:

```bash
pytest tests/scope/contracts/test_attack_agent_contracts.py::test_scope_audit_boundary_contract -q
pytest tests/scope/contracts/test_attack_agent_contracts.py::test_audit_orchestrates_attack_pipeline -q
```

Expected: PASS.

- [ ] **Step 10: Commit prompt changes**

Run:

```bash
git add agents/scope-audit.md
git commit -m "fix: tighten scope audit orchestration contract"
```

## Task 3: Verify Runtime Path Contracts

**Files:**
- Verify only; no file changes expected.

- [ ] **Step 1: Run runtime path contract tests**

Run:

```bash
pytest tests/scope/contracts/test_runtime_path_contracts.py -q
```

Expected: PASS.

- [ ] **Step 2: Run attack contract tests**

Run:

```bash
pytest tests/scope/contracts/test_attack_agent_contracts.py -q
```

Expected: PASS.

- [ ] **Step 3: Run installer syntax check**

Run:

```bash
node --check bin/install.js
```

Expected: no output and exit code 0.

- [ ] **Step 4: Run whitespace check**

Run:

```bash
git diff --check
```

Expected: no output and exit code 0.

- [ ] **Step 5: Confirm worktree status**

Run:

```bash
git status --short
```

Expected:

```text
?? .continue-here.md
```

## Self-Review

- Spec coverage: The plan implements tool-surface cleanup, Gate 1 region wording, Gate 3 skip semantics, runtime path wording, export ownership, mandatory outputs, and contract tests from `config/project-docs/SCOPE-AUDIT-DESIGN.md`.
- Placeholder scan: No incomplete markers or vague implementation steps remain.
- Type consistency: The prompt uses `Gate 3 skip`, `Gate 4 skip`, `$RUN_DIR/results.json`, `$RUN_DIR/findings.md`, and `$RUN_DIR/agent-log.jsonl` consistently.
