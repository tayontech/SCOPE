# SCOPE LLM Context

Use this document to review or modify SCOPE without rediscovering the whole project. It complements `README.md` and `ARCHITECTURE.md`; it does not replace agent prompts, schemas, or tests.

## Audience

- Code reviewers who need to evaluate PRs, contract changes, prompts, schemas, hooks, and tests.
- Implementation agents that need enough project context to make narrow changes without breaking agent boundaries.

## Project Shape

SCOPE is a purple-team AWS security framework built from three layers:

1. Deterministic Python runtime under `scope/`.
2. Agent and skill instructions under `agents/` and `skills/`.
3. Safety, schema, dashboard, and installer tooling under `config/`, `dashboard/`, `bin/`, and `tests/`.

The Python runtime owns AWS enumeration, aggregation, graph extraction, run context, target routing, and post-processing. Agents own orchestration, reasoning, human gates, and artifact contracts. Hooks and tests enforce the boundaries.

## Fast Orientation

Primary docs:

- `README.md`: product overview, commands, install model, and high-level architecture.
- `ARCHITECTURE.md`: pipeline flow, data dependencies, verification flow, and hook layer.
- `config/project-docs/PROJECT.md`: installed platform guidance.
- `config/project-docs/LLM-CONTEXT.md`: current reviewer and implementation-agent context.
- Other `config/project-docs/*.md` files: design records or historical implementation plans. Do not treat old task steps as current source of truth.

Core runtime:

- `scope/runtime/audit.py`: audit CLI flow.
- `scope/runtime/aggregation.py`: runtime result aggregation.
- `scope/runtime/graph.py`: graph v2 extraction.
- `scope/runtime/post_processing.py`: summary, resources, graph, results, and dashboard export helpers.
- `scope/runtime/targets.py`: target parsing and service routing.
- `scope/core/`: shared AWS clients, coverage, envelope models, logging, retry, regions, and parallelism.
- `scope/enumerators/`: service-specific AWS inventory modules.

Agent surface:

- `agents/scope-audit.md`: audit orchestrator.
- `agents/scope-controls.md`: controls orchestrator.
- `agents/scope-exploit.md`: standalone red team playbook flow.
- `agents/scope-investigate.md`: tri-mode SOC investigation flow.
- `agents/subagents/`: attack, controls, investigation intake, research, and verification prompts.
- `skills/`: reusable prompt-local workflows for attack paths, evidence, exploit playbooks, investigation reports, and knowledge.

Validation and safety:

- `config/hooks/scope-safety-guard.sh`: blocks destructive AWS shell operations.
- `config/hooks/scope-schema-validate.sh`: validates `results.json` and invokes attack linter checks.
- `config/hooks/scope-spl-lint.sh`: blocks SPL anti-patterns.
- `config/hooks/scope-artifact-check.sh`: checks mandatory artifacts.
- `config/schemas/*.schema.json`: audit, controls, exploit, and module envelope schemas.
- `tests/scope/contracts/`: prompt, schema, hook, and architectural contract tests.

## Core Pipeline

Audit flow:

1. `scope-audit` receives `/scope:audit`.
2. It runs `uv run python -m scope audit`.
3. The Python runtime writes `$RUN_DIR/modules/<service>/<region>.json`, `summary.json`, `resources.jsonl`, `graph.json`, and base `results.json`.
4. `scope-public-exposure-analysis` writes `public_entrypoints[]`.
5. `scope-attack-analyze` writes `candidate_attack_paths[]` and `security_observations[]`.
6. `scope-attack-validate` writes `attack_validation[]` and promotes supported paths into final `attack_paths[]`.
7. `scope-controls` can run after approval and produces guardrails, detections, policy replacements, remediation, validation, and controls `results.json`.

Exploit flow:

1. `scope-exploit` analyzes a principal in standalone mode by default.
2. It reads audit data only when the operator passes `--audit <run-dir>`.
3. It can call `scope-research` for bounded technique context.
4. It uses `skills/scope-exploit-playbook/SKILL.md` to shape the playbook.
5. The top-level exploit agent owns gates, reasoning, artifact writes, dashboard export, `results.json`, and knowledge updates.

Investigate flow:

1. `scope-investigate` chooses mode from input: `INVESTIGATION`, `RUN`, or `INTEL`.
2. Alert, run, and intel intake live in `scope-investigate-alert`, `scope-investigate-run`, and `scope-investigate-intel`.
3. The parent agent runs the investigation loop and Splunk queries.
4. Run-guided mode reads only the operator-provided run directory.
5. The parent uses `skills/scope-investigation-report/SKILL.md` after the analyst chooses `done`.
6. Durable knowledge updates require operator-approved save.

## Ownership Boundaries

Python runtime owns:

- AWS API calls for audit enumeration.
- Module envelope layout.
- Region discovery.
- Runtime aggregation.
- Graph v2 extraction.
- Dashboard export data from audit runtime.

Top-level agents own:

- Operator gates.
- Dispatch order.
- Human-readable reports.
- Final artifact checks.
- Knowledge load and update through skills.
- Domain-specific reasoning that cannot belong to deterministic runtime.

Subagents own:

- One bounded reasoning task.
- Specific fields or artifacts documented in their prompt.
- Structured return contracts.

Skills own:

- Reusable document shapes or local reasoning rules.
- Context returned to the caller.
- No independent artifact writes unless their contract says so.

Hooks own:

- Tool-level safety.
- Schema validation.
- SPL linting.
- Artifact checks.
- AWS call logging.

## Contracts Reviewers Must Enforce

Attack path lifecycle:

- `scope-attack-analyze` creates `candidate_attack_paths[]`; it must not create, rewrite, or promote final `attack_paths[]`.
- `scope-attack-validate` owns `attack_validation[]` and final `attack_paths[]`.
- Rejected candidates must stay out of `attack_paths[]`.
- Final `attack_paths[]` entries use `validation_status` values `validated` or `conditional`.
- Downstream controls and investigations use final `attack_paths[]` as the only attack-path source of truth.

Public exposure:

- `public_entrypoints[]` must come before attack analysis.
- Only entries with `attack_path_seed: true` can start public endpoint candidates.
- Public exposure analysis must not write candidate or final attack paths.

Controls:

- Controls consume final `attack_paths[]` with `validation_status` of `validated` or `conditional`.
- Controls must not generate controls from `candidate_attack_paths[]`, rejected `attack_validation[]`, `security_observations[]`, or `public_entrypoints[]`.
- Wave 1 subagents own structured JSON artifacts: `guardrails.json`, `detections.json`, `policy-replacements.json`, and `remediation-plan.md`.
- The controls orchestrator assembles `results.json` from structured artifacts, not from markdown inference.

Exploit:

- Exploit is standalone by default.
- Audit data access requires explicit `--audit <run-dir>`.
- Exploit output must not include CloudTrail event names, GuardDuty finding types, detection likelihood, OPSEC notes, SOC recommendations, numeric confidence scores, or stealth-ordering headers.
- Persistence and post-exploitation sections require explicit operator approval.
- Exploit results expose final paths in `attack_paths[]`, not `paths[]`.

Investigate:

- Investigation mode does not read prior audit, exploit, or agent-log directories unless the operator provides a run directory.
- Run-guided mode reads the specified run directory and uses final `attack_paths[]`.
- Intel mode keeps extracted identifiers session-scoped unless the analyst approves persistence.
- Investigation reports present facts only. They must not assign severity, risk, suspicion, compromise, maliciousness, or confidence.

Knowledge:

- Top-level agents load context through `skills/scope-knowledge-load/SKILL.md`.
- Top-level agents update durable knowledge through `skills/scope-knowledge-update/SKILL.md`.
- Subagents may propose `knowledge_updates[]`, but they must not write durable knowledge directly.
- Durable knowledge must not store ARNs, account IDs, bucket names, role names, key IDs, access key IDs, secrets, session tokens, passwords, or raw credential material.
- Stored knowledge is context, not ground truth. Current evidence wins.

Runtime paths:

- Audit module artifacts live under `$RUN_DIR/modules/<service>/<region>.json`.
- Do not reintroduce legacy top-level module paths like `$AUDIT_RUN_DIR/iam.json` or `$AUDIT_RUN_DIR/$SVC.json`.
- Runtime post-processing owns `summary.json`, `resources.jsonl`, `graph.json`, and base `results.json`.

## Common Review Failures

Check for these first:

- Prompt changes that let a subagent write fields outside its ownership.
- Contract tests that assert old terminology or old paths.
- Agent prose that tells a reviewer to trust stored knowledge as evidence.
- Controls logic that maps every control to every attack path without field-level evidence.
- Exploit prose that turns playbooks into detection or OPSEC guidance.
- Investigation prose that uses legacy hunt-era command names.
- Schema changes that allow unstructured fields without contract tests.
- Runtime changes that write outside `$RUN_DIR`.
- Dashboard changes that expect a schema field not produced by runtime or controls.
- Tests added to JS for prompt or schema contracts when Python contract tests already cover that layer.

## Where To Look By Change Type

Agent prompt change:

- Read the changed prompt.
- Read related contract tests in `tests/scope/contracts/`.
- Read the corresponding schema or hook when the prompt writes files.
- Run focused contract tests before broader tests.

Python runtime change:

- Read the target module under `scope/`.
- Read tests under `tests/scope/core/`, `tests/scope/enumerators/`, or `tests/scope/runtime/`.
- Check generated artifact field names against `config/schemas/`.
- Run focused runtime tests and then `pytest -q`.

Attack path change:

- Read `scope/attack/`.
- Read `agents/subagents/scope-attack-analyze.md`, `agents/subagents/scope-attack-validate.md`, and `skills/scope-attack-path-analysis/SKILL.md`.
- Run `pytest tests/scope/attack -q` and relevant contract tests.

Controls change:

- Read `agents/scope-controls.md`.
- Read all five controls subagents.
- Read `config/schemas/controls.schema.json`.
- Run controls contract tests and schema hook tests.

Investigation change:

- Read `agents/scope-investigate.md` and the three investigation intake subagents.
- Read `skills/scope-investigation-report/SKILL.md`.
- Run runtime path and knowledge contract tests.

Dashboard change:

- Read `dashboard/src/`.
- Check expected fields against `config/schemas/` and runtime post-processing.
- Run JS tests with `npm test -- --silent` and any dashboard build command documented in the change.

Installer or hook change:

- Read `bin/install.js` or `config/hooks/*.sh`.
- Run `node --check bin/install.js` for installer changes.
- Run hook contract tests under `tests/scope/contracts/`.

## Verification Commands

Use the smallest meaningful set first, then broaden when the change touches shared contracts.

Common final checks:

```bash
pytest tests/scope/contracts -q
pytest tests/scope/attack -q
pytest -q
npm test -- --silent
node --check bin/install.js
git diff --check
```

Useful focused checks:

```bash
pytest tests/scope/contracts/test_attack_agent_contracts.py -q
pytest tests/scope/contracts/test_runtime_path_contracts.py -q
pytest tests/scope/contracts/test_knowledge_contracts.py -q
pytest tests/scope/contracts/test_repo_skills.py -q
pytest tests/scope/contracts/test_schema_hook.py -q
pytest tests/scope/contracts/test_spl_lint_hook.py -q
pytest tests/scope/runtime -q
pytest tests/scope/enumerators -q
pytest tests/scope/core -q
```

## Code Review Checklist

For every PR:

- Identify the owning layer: runtime, top-level agent, subagent, skill, hook, schema, dashboard, installer, or docs.
- Check whether the change crosses an ownership boundary.
- Check whether new fields appear in schema, producers, consumers, tests, and dashboard code.
- Check whether prompts use current runtime paths.
- Check whether tests protect the behavior and not only string presence.
- Check whether the verification commands match the blast radius.
- Check whether docs reflect the current contract.

For security-sensitive changes:

- Confirm the safety guard still blocks destructive AWS operations.
- Confirm exploit remains generate-only.
- Confirm knowledge updates redact durable identifiers.
- Confirm Splunk queries include explicit indexes and use CloudTrail field names.
- Confirm controls preserve `runtime_assumptions[]` and `coverage_caveats[]`.

## Implementation Agent Rules

Before editing:

- Read this file, `ARCHITECTURE.md`, and the prompt or runtime file you plan to change.
- Search with `rg` for every field, path, and command you plan to modify.
- Locate the focused tests before writing code.

During editing:

- Keep changes scoped to the owning layer.
- Add or update contract tests when changing agent prompts, skills, schemas, hooks, or artifact contracts.
- Add runtime tests when changing Python behavior.
- Do not use broad refactors to hide contract changes.
- Do not revert unrelated user changes.

Before finishing:

- Run focused tests for the changed layer.
- Run broader tests when shared contracts, schemas, hooks, or runtime artifacts changed.
- Report exact verification commands and any untested risk.

## Review Notes From Recent Contract Work

Recent review tightened these contracts:

- Audit dashboard export wording now matches runtime export behavior.
- Controls no longer reference legacy top-level module JSON fallbacks.
- Exploit now gates persistence and post-exploitation sections through explicit operator approval.
- Investigate prompts now use current investigation terminology and declared Splunk discovery tools.
- Investigation intake subagents no longer expose stale hunt phrasing.
- Knowledge update templates now favor generalized patterns and redact exact resource identifiers.

Keep these constraints intact when reviewing future changes.
