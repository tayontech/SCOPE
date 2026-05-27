# SCOPE LLM Context

Use this file when reviewing or modifying SCOPE. It gives implementation agents and reviewers the contracts they need before editing prompts, runtime code, schemas, hooks, dashboard code, or docs.

## Read Order

Read only the files that match the change:

- `README.md`: install flow, commands, supported runtimes, dashboard command.
- `ARCHITECTURE.md`: pipeline flow, data dependencies, verification flow, and hook layer.
- `config/project-docs/PROJECT.md`: source for generated platform instruction files.
- `config/README.md`: config ownership.
- `config/mcp-setup.md`: Splunk MCP and manual SPL mode.
- `knowledge/README.md`: durable knowledge rules and redaction boundaries.
- `tests/scope/contracts/`: prompt, schema, hook, installer, dashboard, and path contracts.

Current source files, schemas, hooks, tests, and agent prompts override historical plans.

## Project Map

| Area | Owns |
|------|------|
| `scope/runtime/` | Audit CLI flow, aggregation, graph extraction, post-processing, target routing |
| `scope/core/` | AWS clients, envelopes, retry, regions, logging, coverage, parallelism |
| `scope/enumerators/` | Service-specific AWS inventory |
| `scope/attack/` | Deterministic candidate generation and validation helpers |
| `agents/` | Top-level agent and subagent prompts |
| `skills/` | Reusable local workflows for attack paths, evidence, playbooks, detections, reports, and knowledge |
| `config/hooks/` | Safety, schema, SPL, artifact, AWS logging, and AWS output checks |
| `config/schemas/` | Audit, controls, exploit, and module envelope JSON contracts |
| `dashboard/` | React and D3 dashboard generation |

## Installer And Platform Contracts

`uv run python -m scope.install` is the canonical installer entry point.

| Runtime | Local Install Surface |
|---------|-----------------------|
| Claude Code | `.claude/skills/`, `.claude/agents/`, `.claude/settings.json` |
| Antigravity CLI | `.agents/skills/`, `.agents/hooks.json`, `.agents/mcp_config.json`, `.agents/plugins/scope/agents/` |
| Gemini CLI | `.agents/skills/`, `.gemini/agents/`, `.gemini/settings.json` |
| Codex CLI | `.agents/skills/`, `.codex/agents/`, `.codex/config.toml`, `.codex/hooks.json` |

`config/models.json` has no `enum` tier and no Antigravity model map. Enumeration runs through deterministic Python. Top-level agents inherit the active session model. Claude subagents use `opus[1m]` for the 1M context window during artifact-heavy analysis and validation. Gemini CLI uses `pro`; Codex uses `gpt-5.5` with high reasoning effort. Antigravity model choice belongs to Antigravity's model selector or `/model` command.

Google announced on May 19, 2026 that Gemini CLI stops serving requests for Google AI Pro, Ultra, and free individual users on June 18, 2026. Treat `--antigravity` as the preferred Google target. Keep `--gemini` for enterprise/API-key users and migration.

## Audit Pipeline

1. `scope-audit` receives `/scope:audit`.
2. It runs `uv run python -m scope audit`.
3. Python writes `$RUN_DIR/modules/<service>/<region>.json`, `summary.json`, `resources.jsonl`, `graph.json`, and base `results.json`.
4. `scope-public-exposure-analysis` writes `public_entrypoints[]` and `public_exposure_findings[]`.
5. `scope.attack.candidates` seeds deterministic candidates for collected assume-role, PassRole, CodeBuild StartBuild, identity issuance, event, resource-policy, and public/service-connected paths.
6. `scope-attack-analyze` preserves deterministic candidates, adds inferred candidates, and writes `security_observations[]`.
7. `scope-attack-validate` writes `attack_validation[]`, promotes supported paths into `attack_paths[]`, and writes `attack_path_groups[]`.
8. `scope-awscli-replay` can generate review-only AWS CLI replay artifacts after approval.
9. `scope-controls` can run after approval and produce org-wide issues, detections, monitoring dashboard ideas, policy replacements, remediation, validation, and controls `results.json`.

Runtime coverage spans IAM, STS, S3, KMS, Secrets Manager, Lambda, EC2, ECS, RDS, API Gateway, SNS, SQS, CodeBuild, Bedrock, CloudFront, Cognito, DynamoDB, Route 53, and SSM.

## Attack Path Rules

- `scope-attack-analyze` creates `candidate_attack_paths[]`; it does not create, rewrite, or promote final `attack_paths[]`.
- `scope-attack-analyze` preserves deterministic candidates already present in `candidate_attack_paths[]`.
- `scope-attack-validate` owns `attack_validation[]`, final `attack_paths[]`, and `attack_path_groups[]`.
- Final `attack_paths[]` entries use `validation_status` values `validated` or `conditional`.
- Downstream controls and investigations use final `attack_paths[]` as the attack-path source of truth.
- Rejected candidates stay out of `attack_paths[]`.
- Promoted attack paths end in a concrete terminal impact hop: data access, decrypt, policy mutation, compute creation, PassRole, resource-policy access, or event injection.
- `attack_path_groups[]` powers human review. Raw `attack_paths[]` remains the machine source of truth. Each group carries `leveraging_assets[]`.
- Public exposure stays separate through `public_entrypoints[]` and `public_exposure_findings[]`; promoted public exposure records link back through `promoted_attack_path_ids[]`.
- Public reachability to a backend execution role does not prove data access. Do not assume SSRF, RCE, application behavior, or response content.
- S3 object-read paths against SSE-KMS buckets and Secrets Manager reads against CMK-encrypted secrets require KMS authorization for the same principal context.
- KMS authorization can come from direct key-policy principal allow, account-root key-policy delegation plus identity `kms:Decrypt`, or a matching KMS grant.
- Permission boundaries constrain IAM hops. Boundary deny or lack of allow rejects the hop; a present boundary with no collected document creates a conditional caveat.
- External trust from `external:*` requires operator-controlled source evidence before promotion.
- Resource-policy promotion uses `resource_policy_statements[]` evidence. Generic `resource_policy_allows` graph edges supply context only.
- Resource-policy hops must match principal, action, resource, and condition context. `SourceArn`, `SourceAccount`, and `SourceOwner` conditions require matching candidate source context.
- Lambda Function URL resource-policy hops validate `lambda:FunctionUrlAuthType` and `lambda:InvokedViaFunctionUrl` against collected Function URL configuration.

## Public Exposure Rules

- `public_entrypoints[]` comes before attack analysis.
- `public_exposure_findings[]` records security-relevant public surfaces separately from attack paths.
- Only entries with `attack_path_seed: true` can start public endpoint candidates.
- Public exposure analysis does not write candidate or final attack paths.
- Public exposure findings can describe internet-facing load balancers, public security group ingress, public management ports, anonymous SNS/SQS policies, public bucket/API/Lambda surfaces, and coverage gaps.
- A public exposure finding with `attack_path_seed: false` includes `reason_not_attack_path` and `coverage_needed[]`.
- When validation promotes a public endpoint candidate, the matching public exposure finding includes `promoted_attack_path_ids[]`.

## Controls Rules

- Controls consume final `attack_paths[]` with `validation_status` of `validated` or `conditional`.
- Controls do not generate attack-path mappings from `candidate_attack_paths[]`, rejected `attack_validation[]`, `security_observations[]`, or `public_entrypoints[]`.
- Controls may consume `public_exposure_findings[]` for remediation, detections, dashboard ideas, and advisory org-wide exposure patterns.
- Controls keep public exposure IDs out of `source_attack_paths[]`; structured public exposure references belong in `source_public_exposure_findings[]`.
- Wave 1 producers write `org-wide-issues.json`, `detections.json`, `dashboards.json`, `policy-replacements.json`, and `remediation-plan.md`.
- `scope-controls-dashboards` generates monitoring dashboard ideas for security-relevant conditions that should be watched over time.
- `scope-controls-dashboards` does not build deployable dashboards, saved searches, or SIEM objects.
- The controls orchestrator assembles `results.json` from structured artifacts.

## Exploit And Investigation Rules

Exploit:

- Exploit runs standalone by default.
- Audit data access requires explicit `--audit <run-dir>`.
- Exploit output excludes CloudTrail event names, GuardDuty finding types, detection likelihood, OPSEC notes, SOC recommendations, numeric confidence scores, and stealth-ordering headers.
- Persistence and post-exploitation sections require explicit operator approval.
- Exploit results expose final paths in `attack_paths[]`, not `paths[]`.

Investigation:

- Investigation mode does not read prior audit, exploit, or agent-log directories unless the operator provides a run directory.
- Run-guided mode reads the specified run directory and uses final `attack_paths[]`.
- Intel mode keeps extracted identifiers session-scoped unless the analyst approves persistence.
- Investigation reports present facts only. They do not assign severity, risk, suspicion, compromise, maliciousness, or confidence.

## Knowledge Rules

- Top-level agents load context through `skills/scope-knowledge-load/SKILL.md`.
- Top-level agents update durable knowledge through `skills/scope-knowledge-update/SKILL.md`.
- Subagents may propose `knowledge_updates[]`; they do not write durable knowledge directly.
- Durable knowledge must not store ARNs, account IDs, bucket names, role names, key IDs, access key IDs, secrets, session tokens, passwords, raw credential material, or run-specific noise.
- Stored knowledge provides context, not ground truth. Current AWS, Splunk, audit, exploit, controls, or investigation evidence wins.

## Dashboard Rules

- Audit module artifacts live under `$RUN_DIR/modules/<service>/<region>.json`.
- Runtime post-processing owns `summary.json`, `resources.jsonl`, `graph.json`, base `results.json`, and dashboard export JSON.
- Explicit run directory basenames become canonical dashboard run IDs.
- `dashboard/public/index.json` uses a `reports[]` manifest. Each report points to one audit export and optional controls export.
- One audit workflow creates one selectable dashboard report.

## Review Checklist

For any change:

- Identify the owning layer: runtime, top-level agent, subagent, skill, hook, schema, dashboard, installer, or docs.
- Search with `rg` for every field, path, and command you plan to modify.
- Check producers, consumers, schemas, dashboard code, and tests when a field changes.
- Keep runtime paths under `$RUN_DIR`; do not reintroduce legacy top-level module paths.
- Add contract tests for prompt, schema, hook, installer, dashboard, and artifact-contract changes.
- Add runtime tests for Python behavior changes.
- Run focused tests first, then broaden when the change touches shared contracts.

Common failures:

- Subagent prompts that write fields outside their ownership.
- Controls that map every control to every attack path without field-level evidence.
- Exploit playbooks that include detection or OPSEC guidance.
- Investigation prompts that reuse legacy hunt-era commands.
- Dashboard code that expects fields no producer writes.
- Knowledge updates that persist raw identifiers.

## Verification Commands

```bash
uv run pytest tests/scope/contracts -q
uv run pytest tests/scope/attack -q
uv run pytest -q
uv run python -m scope.install --help
git diff --check
```

Focused commands:

```bash
uv run pytest tests/scope/contracts/test_attack_agent_contracts.py -q
uv run pytest tests/scope/contracts/test_runtime_path_contracts.py -q
uv run pytest tests/scope/contracts/test_knowledge_contracts.py -q
uv run pytest tests/scope/contracts/test_python_installer_contract.py -q
uv run pytest tests/scope/contracts/test_dashboard_contracts.py -q
uv run pytest tests/scope/runtime -q
uv run pytest tests/scope/enumerators -q
uv run pytest tests/scope/core -q
```
