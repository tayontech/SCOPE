# SCOPE

SCOPE is an AI agent suite for AWS purple-team security operations. Agents handle audit, exploit, controls, and investigation workflows. Run `uv run python -m scope.install` to set up your runtime.

This file is the source for generated platform instruction files such as `CLAUDE.md`, `GEMINI.md`, and `AGENTS.md`.

## Project Map

- `scope/`: deterministic Python runtime for AWS enumeration, aggregation, graph extraction, run context, and post-processing.
- `agents/`: top-level SCOPE agent workflows.
- `agents/subagents/`: bounded reasoning agents for attack analysis, controls, investigation intake, research, and verification.
- `skills/`: reusable local workflows loaded only when relevant.
- `config/hooks/`: deterministic safety, schema, SPL, artifact, logging, and AWS output checks.
- `config/schemas/`: canonical JSON contracts for audit, controls, exploit, and module envelopes.
- `dashboard/`: React and D3 dashboard generation.
- `tests/`: Python runtime and contract tests.

## Authoritative References

Use progressive disclosure. Read only the files relevant to the task.

- `README.md`: product overview, install flow, supported platforms, user-facing commands, and dashboard command.
- `ARCHITECTURE.md`: pipeline flow, data dependencies, verification flow, and hook layer.
- `docs/LLM-CONTEXT.md`: reviewer and implementation-agent orientation.
- `config/README.md`: config directory ownership and active documentation priority.
- `knowledge/README.md`: durable knowledge ownership, allowed content, and redaction rules.
- `knowledge/observations.md`: durable observations loaded through the knowledge skill when relevant.
- `agents/` and `agents/subagents/`: source prompts for top-level agents and bounded subagents.
- `skills/`: reusable workflows for knowledge load/update, attack path analysis, evidence logging, exploit playbooks, detection formatting, investigation reports, and dashboard ideas.
- `config/hooks/` and `config/schemas/`: deterministic enforcement and artifact contracts.
- `config/splunk-patterns.md` and `config/mcp-setup.md`: Splunk Cloud MCP, SPL guidance, and manual SIEM setup.
- `tests/scope/contracts/`: prompt, hook, schema, dashboard, installer, and runtime path contracts.

Current source files, schemas, hooks, tests, and agent prompts override historical implementation plans.

## Session Isolation

Keep raw run evidence, credentials, account identifiers, and operator-provided context scoped to the active session unless the operator approves a durable knowledge update.

## Agent Architecture

SCOPE agents act as software orchestrators with bounded LLM reasoning, deterministic runtime execution, explicit control flow, and operator gates. Treat prompts, context assembly, tool inputs, tool outputs, execution state, and artifact contracts as project surfaces.

- Own the context window. Pass dense, relevant context: current instructions, operator input, bounded knowledge, retrieved docs or runtime artifacts, tool results, active errors, and required output contracts.
- Keep context session-scoped. Do not carry raw ARNs, account IDs, resource names, keys, Splunk results, or prior run artifacts across sessions unless the operator provides the run directory or the knowledge loader returns distilled context.
- Use structured interfaces. Prefer JSON artifacts, schema-validated files, runtime envelopes, logs, and explicit handoff fields over prose parsing.
- Keep execution state and business state together. Run directories, `results.json`, module envelopes, `agent-log.jsonl`, validation outputs, and gate decisions define workflow state.
- Own control flow. Top-level agents decide when to dispatch subagents, pause, resume, retry, stop, or escalate. Framework defaults must not bypass SCOPE gates or safety rules.
- Compact errors into usable context. Show fatal errors to the operator, preserve recoverable errors in summaries and artifacts, and pass downstream agents only the error facts needed for reasoning.
- Use small focused agents. Audit, exploit, controls, investigation, validation, research, remediation, detection, and reporting responsibilities stay separated by clear handoff contracts.
- Design agents as stateless reducers. Given operator input, bounded context, structured state, and tool results, an agent produces the next state, next gate, next tool call, or final artifact.

## Core Operating Rules

- Reason from current evidence: real ARNs, account IDs, resource names, permissions, artifacts, API responses, graph edges, and explicit access errors.
- Treat curated notes, config files, and technique references as reasoning aids, not exhaustive boundaries.
- Every finding explains why the account's specific combination of resources and permissions matters.
- Keep public exposure separate from attack paths. Use `public_exposure_findings[]` for public-facing resources that matter but lack a validated or conditional attacker progression path.
- Seed deterministic candidates before LLM attack analysis for collected `sts:AssumeRole`, `iam:PassRole`, CodeBuild `StartBuild`, identity issuance, event paths, resource-policy paths, and public/service-connected paths that can reach concrete or coverage-caveated impact.
- Keep public endpoint reachability as exposure context unless collected AWS-level evidence proves a data flow, event source, resource-policy grant, identity issuance path, or service transition.
- Public service-connected seeds require graph evidence from the public entrypoint to an `executes_as` role or identity-provider `authenticates_to` role and a concrete IAM, Secrets Manager, S3, DynamoDB, or SSM impact.
- If backend application behavior must call the impact action, keep the path conditional through a runtime-assumption hop.
- EC2 public ingress can seed attack paths only when graph evidence connects ingress to an attached instance, instance-profile role, and concrete impact.
- RDS public endpoints and DB security-group attachments remain public exposure unless credentials, IAM auth, or another collected transition proves database access or downstream impact.
- Cognito unauthenticated identity pools can seed public attack candidates only when graph evidence shows unauthenticated credential issuance to a role and that role reaches concrete impact.
- API Gateway public service-connected seeds can use collected public endpoint state, API Gateway to Lambda `invokes` edges, and Lambda execution-role edges.
- Route 53 and CloudFront seeds can use correlated graph edges from Route 53 records to collected CloudFront distributions and from CloudFront origins to collected load balancers. Treat unresolved `external:dns:*` targets and dangling DNS candidates as exposure context until target-existence correlation exists.
- SNS, SQS, and Lambda event paths require collected subscription or event-source mapping evidence.
- Do not promote public reachability to backend role permissions by itself. Do not assume SSRF, RCE, application behavior, or response content.
- Promote attack paths only when the candidate ends in a concrete terminal impact hop.
- For SSE-KMS S3 object-read paths and CMK-encrypted Secrets Manager reads, validate KMS authorization through direct key-policy principal allow, account-root key-policy delegation plus identity `kms:Decrypt`, or a matching KMS grant.
- Treat DynamoDB table reads and SSM parameter reads as concrete data impacts only when the role policy binds to collected resource ARNs. SecureString SSM reads require KMS validation when graph evidence records a KMS dependency.
- CodeBuild `StartBuild` on a collected project can be a compute transition only when IAM allows the start action, graph evidence maps the project to its service role, and that role reaches concrete impact.
- Bedrock agents and knowledge bases require collected execution-role or data-access transitions before attack-path promotion. Posture findings such as disabled logging or custom-model presence remain findings by themselves.
- Use `attack_path_groups[]` as the human reporting layer for equivalent final paths. Keep every raw final path in `attack_paths[]` for controls, replay commands, investigations, and machine consumers. Each group must show `leveraging_assets[]`.
- Promote IAM mutation paths with the specific collected action, such as inline policy writes, managed policy attachment, policy version changes, or trust policy updates.
- Apply collected customer-managed permission boundary documents during IAM hop validation. Missing boundary documents create conditional caveats.
- Treat external trust as a candidate only when the source external principal is controlled or explicitly in scope.
- Promote resource-policy attack paths only from statement-level evidence that matches the principal, action, resource, and condition context. Generic resource-policy graph edges are context, not proof.
- SourceArn, SourceAccount, and SourceOwner conditions require matching source context.
- Treat resource-policy `Principal: "*"` as a wildcard for service, external, and account principals. Promotion still requires matching action, resource, and condition context.
- Validate Lambda Function URL resource-policy conditions against collected Function URL configuration. Missing auth context leaves the hop conditional; mismatched `lambda:FunctionUrlAuthType` rejects it.
- Controls may use `public_exposure_findings[]` for remediation, detections, dashboard ideas, and advisory org-wide exposure patterns, but must keep those IDs out of `source_attack_paths[]`.
- Present facts with lowercase severity labels in JSON and findings: `critical`, `high`, `medium`, `low`. `scope-investigate` presents facts only and lets the analyst interpret the data in context.
- Use the `external:*` node ID prefix for cross-account principals, anonymous actors, public actors, and federated identities. Examples: `external:anonymous`, `external:public`, `external:<account-id>`.
- Treat AccessDenied as signal. Record what it reveals, continue when the module can continue, and report coverage gaps.
- Stop on credential failures, fatal script errors, failed gates, or failed required artifact checks.
- Produce artifacts even when a run finds no issues.

## Safety and Gates

SCOPE workflows default to read-only AWS activity. `config/hooks/scope-safety-guard.sh` blocks destructive AWS shell operations.

- Do not deploy or mutate AWS resources from SCOPE agents. Do not delete AWS resources.
- Audit and exploit workflows may write review-only AWS CLI replay command artifacts, but agents must not execute write commands.
- Gates are mandatory pauses. Propose the next action, explain the evidence and risk, then wait for operator approval.
- The operator controls probes, disk writes, included paths, excluded paths, and cross-run data use.
- Surface unexpected errors when they occur. Retry only when the operator can see the failure and the retry reason.

## Knowledge Handling

Top-level SCOPE workflows load bounded context through `skills/scope-knowledge-load/SKILL.md` when a workflow starts. They update durable knowledge only through `skills/scope-knowledge-update/SKILL.md` after evidence review or operator-approved save.

- Subagents may propose `knowledge_updates[]`, but they must not write durable knowledge directly.
- Treat stored knowledge as context, not evidence. Current AWS, Splunk, audit, exploit, controls, or investigation evidence overrides stored observations.
- Do not store ARNs, account IDs, bucket names, role names, key IDs, access key IDs, secrets, session tokens, passwords, raw credential material, or run-specific noise in durable knowledge.
- Promote a pattern to org-wide knowledge only after evidence from at least two accounts supports it.

## Verification

Use deterministic tooling before making claims.

- Run focused tests for the changed layer, then broader tests when risk warrants it.
- Use `uv run pytest -q` for the full Python test suite.
- Use installed hooks and schemas for safety, schema validation, SPL checks, artifact checks, and AWS output checks.
- Do not ask the model to police rules that hooks, schemas, or tests can enforce.
- Confirm artifacts exist on disk before claiming a workflow wrote them.
- For explicit audit run directories, treat the directory basename as the canonical run ID across `results.json`, `dashboard/public/`, `dashboard/public/index.json`, controls `audit_runs_analyzed[]`, and generated dashboard HTML.
- Treat `dashboard/public/index.json` as a report manifest with `reports[]`. Each report selects one audit export and optional controls export; controls must attach to an audit report instead of becoming their own dashboard choice.
- If a gate check fails, stop and diagnose before proceeding.
