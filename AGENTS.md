<!-- Token budget: ~198 lines | Before: ~3000 tokens (est) | After: ~3000 tokens (est) | Phase 33 2026-03-18 -->
# SCOPE -- Cross-Platform Agent Suite

**Project:** SCOPE (Security Cloud Ops Purple Engagement) -- AI agent set for purple team security operations against AWS accounts: resource audit -> exploit playbook generation -> defensive controls with SCPs and SPL detections -> SOC alert investigation.

The audit agent is an orchestrator that dispatches enumeration subagents in parallel. Standalone agents (exploit, hunt) reference subagents at `agents/subagents/` for verification and pipeline.

## Agents

```
agents/scope-audit.md       AWS audit orchestrator — dispatches enum subagents in parallel
agents/scope-defend.md      Defensive controls generation — dispatched by orchestrator or invoked directly
agents/scope-exploit.md     Privilege escalation playbooks
agents/scope-hunt.md SOC alert investigation
```

**Subagents** (`agents/subagents/` -- dispatched by orchestrator or read inline):

```
agents/subagents/scope-enum-iam.md         IAM enumeration
agents/subagents/scope-enum-sts.md         STS/identity enumeration
agents/subagents/scope-enum-s3.md          S3 enumeration
agents/subagents/scope-enum-kms.md         KMS enumeration
agents/subagents/scope-enum-secrets.md     Secrets Manager enumeration
agents/subagents/scope-enum-lambda.md      Lambda enumeration
agents/subagents/scope-enum-ec2.md         EC2/VPC/EBS/ELB/SSM enumeration
agents/subagents/scope-enum-rds.md         RDS enumeration
agents/subagents/scope-enum-sns.md         SNS enumeration
agents/subagents/scope-enum-sqs.md         SQS enumeration
agents/subagents/scope-enum-apigateway.md  API Gateway enumeration
agents/subagents/scope-enum-codebuild.md   CodeBuild enumeration
agents/subagents/scope-attack-paths.md     Attack path reasoning from per-module JSON
agents/subagents/scope-verify.md           Unified verification -- claim ledger, AWS API validation, SPL checks (read inline)
agents/subagents/scope-pipeline.md         Post-processing middleware -- data normalization then evidence indexing (read inline)
```

**Model routing per platform** -- `install.js` assigns models during install:

| Agent Type | Claude Code | Gemini CLI | Codex |
|------------|-------------|------------|-------|
| Enum subagents | claude-haiku-4-5 | gemini-3.1-flash-lite-preview | gpt-5.4-mini |
| Attack paths, defend | claude-sonnet-4-6 | gemini-3.1-pro-preview | gpt-5.4 |

## Architecture

```
agents/               Agent .md files -- source format for all editors (flat, one file per agent)
agents/subagents/     Dispatched subagents and inline-read middleware (enum, attack-paths, verify, pipeline)
data/                 Normalized JSON output (runtime-generated, gitignored)
agent-logs/           Agent activity logs (runtime-generated, gitignored)
hunt/          Hunt artifacts (runtime-generated, gitignored)
dashboard/            React + D3 dashboard (dashboard.html)
config/               Optional pre-loaded data (accounts.json, scps/*.json)
bin/                  Tooling (install.js -- editor setup, generate-report.js -- dashboard builder)
config/hooks/         Lifecycle hooks -- safety guard, SPL lint, schema validation, artifact check, agent logger
config/schemas/       JSON Schema definitions for results.json (audit, defend, exploit)
config/settings/      Committed hook settings templates for Claude Code and Gemini CLI

# Runtime output structure (gitignored):
audit/<run-id>/           Audit run -- enum JSONs, results.json, findings.md
audit/<run-id>/defend/    Defend output nested under its parent audit run
exploit/<run-id>/         Exploit run -- playbooks, results.json
hunt/<run-id>/     Hunt artifacts
```

## Skills

Skills are `SKILL.md` files in `.agents/skills/`. Both Gemini CLI and Codex discover skills from this path.

| Location | Path |
|----------|------|
| Project  | `.agents/skills/<skill>/SKILL.md` |
| User     | `~/.agents/skills/<skill>/SKILL.md` |

## Subagents

Subagents are deployed differently per platform:

**Claude Code** — flat `.md` files in `.claude/agents/` (local) or `~/.claude/agents/` (global):
```
node bin/install.js --claude --local   # deploys to .claude/skills/ + .claude/agents/
```

**Gemini CLI** — flat `.md` files in `.gemini/agents/` (local) or `~/.gemini/agents/` (global). Requires `experimental.enableAgents: true` in `settings.json` (the installer adds this automatically via the settings template):
```
node bin/install.js --gemini --local   # deploys to .agents/skills/ + .gemini/agents/ + .gemini/settings.json
```

**Codex** — Codex uses `config.toml` for agent registration. The installer deploys stripped `.md` files to `.codex/agents/` and auto-merges `[agents]` entries into `.codex/config.toml`:
```
node bin/install.js --codex --local   # deploys to .agents/skills/ + .codex/agents/ + updates .codex/config.toml
```

## Context Isolation (Claude Code Only)

SCOPE entry-point skills (`scope-audit`, `scope-hunt`) use `context: fork` in their Claude Code skill frontmatter. When an operator invokes `/scope:audit` or `/scope:hunt`, Claude Code runs the skill in a forked subagent context: the skill content becomes the task, the forked agent gets its own isolated context window, and results summarize back to the main conversation cleanly.

**Why it exists:**
- Verbose AWS enumeration output and Splunk query result sets stay out of the main conversation window
- Long-running multi-phase operations (audit pipeline, investigation chains) get clean isolation per invocation
- The forked context cannot access pre-invocation conversation history, preventing accidental context contamination

**Claude Code only:** `context: fork` and `agent:` are Claude Code-native frontmatter fields. The installer strips both fields from Gemini CLI and Codex skill outputs (`installGemini`, `installCodex`, `installSubagentsGemini`, `installSubagentsCodex` strip lists all include `'context'` and `'agent'`).

**Functionally equivalent fallback (Gemini CLI / Codex):** SCOPE already implements sequential file-based handoff as its primary isolation mechanism. Each agent phase writes structured JSON to `$RUN_DIR/` and downstream agents read from disk -- providing the same context isolation guarantee without requiring platform-specific frontmatter:

- Enum subagents write `$RUN_DIR/{service}.json` (one file per service)
- `scope-attack-paths` reads all per-module JSON files from `$RUN_DIR/` on disk
- `scope-pipeline` normalizes results to `./data/<phase>/<run-id>.json` and validates logs to `./agent-logs/<phase>/<run-id>.json`

On Gemini CLI and Codex, this sequential file-based handoff IS the full context isolation mechanism -- no additional platform flags required.

## Invocation

| Platform   | Syntax |
|------------|--------|
| Claude Code | `/scope:audit <target>` |
| Gemini CLI  | Describe your task -- model activates the skill automatically. Or use `/skills` to select. |
| Codex       | `$scope-audit <target>` or describe task for implicit activation |

## Hooks

**Claude Code and Gemini CLI:** Lifecycle hooks enforce safety constraints at the tool level. Source scripts are in `config/hooks/` and settings templates in `config/settings/`. The installer copies hook scripts to platform-native locations (`.claude/hooks/` or `.gemini/hooks/`) and settings to `.claude/settings.json` or `.gemini/settings.json` with absolute paths.

**Codex:** No lifecycle hooks available. Safety constraints are enforced through this guidance only.

> **CODEX SAFETY NOTE:** SCOPE agents are READ-ONLY. Do not execute any AWS operation that modifies, creates, or deletes resources. All destructive operations require explicit operator approval via the approval gate pattern documented below. Exploit generates playbooks only -- it does not execute them. Never auto-apply SCPs, security group rules, or IAM policy changes. Always present the approval block and wait for explicit Y/N confirmation.

## Schema Enforcement

Canonical JSON Schema files in `config/schemas/` define required fields for each phase's `results.json`:
- `config/schemas/audit.schema.json` -- audit results
- `config/schemas/defend.schema.json` -- defend results
- `config/schemas/exploit.schema.json` -- exploit results

**Claude Code / Gemini CLI:** The `scope-schema-validate.sh` hook validates every write to `results.json` or `dashboard/public/*.json` automatically.

**Codex:** Before writing `results.json`, read the corresponding schema file and self-check that all required fields are present. If a field is missing, add it before writing.

## Output Quality Rules

These rules apply on all platforms. Codex enforces them via this guidance (no hooks available). Claude Code and Gemini CLI additionally enforce schema rules via the `scope-schema-validate.sh` hook.

### Escalation Node Connectivity

Every escalation node in the attack graph MUST have at least one incoming priv_esc edge. Before writing results.json, count escalation nodes and priv_esc edges. If any escalation node has 0 incoming priv_esc edges, go back and add them before proceeding.

### Severity Casing

severity must be exactly one of: critical, high, medium, low (lowercase). No other values. No UPPERCASE variants. No mixed-case variants.

### Edge Type Enum

edge_type must be exactly one of: priv_esc, trust, data_access, network, service, public_access, cross_account, membership. No other values.

## Commands

| Command | Description |
|---------|-------------|
| `$scope-audit <target>` | Enumerate AWS resources -- accepts ARN, service name, `--all`, `@targets.csv`, or multiple services inline. Orchestrates parallel subagent dispatch (2+ services). Auto-chains defend after audit completes. |
| `$scope-exploit <arn> [--fresh]` | Privilege escalation playbooks, persistence analysis, and exfiltration mapping for a specific principal |
| `$scope-hunt` | SOC alert investigation via Splunk -- guided queries, timeline building, IOC correlation |
| `$scope-help` | List available commands, show usage examples |

Gemini CLI operators: describe the task naturally and the model will activate the appropriate skill. The `$scope-*` prefixes above correspond to skill names in `.agents/skills/`.

## Data Layer

A single middleware agent runs automatically after audit, exploit, and defend:
- **scope-pipeline** (`agents/subagents/scope-pipeline.md`) -- Phase 1 normalizes raw artifacts to `./data/<phase>/<run-id>.json`, then Phase 2 validates `agent-log.jsonl` into envelopes at `./agent-logs/<phase>/<run-id>.json`

Invoked by the source agent after writing artifacts -- sequential and non-blocking. Investigate does not run this pipeline.

## Dashboard

All visualization is handled by the SCOPE dashboard. Agents export `results.json` to `$RUN_DIR/` and `dashboard/public/$RUN_ID.json`. Dashboard loads `index.json`, iterates the `runs[]` array, and fetches the latest entry per source phase.

**Dashboard HTML** (all environments): After exporting data to `dashboard/public/`, run `cd dashboard && npm run dashboard` to generate a self-contained `dashboard.html` with all data inlined. This file opens in any browser without a server. Agents MUST generate the dashboard after the data pipeline completes.

## AWS Credential Model

SCOPE inherits credentials from the shell environment (AWS_PROFILE, AWS_ACCESS_KEY_ID, or boto3/AWS CLI defaults). No custom credential loading. The first AWS API call (`sts:GetCallerIdentity` at Gate 1) serves as the credential check.

## Approval Gate Pattern

Standard workflows are read-only. Before ANY destructive AWS operation:
- Show approval block with action, resources, risk, reason
- Wait for explicit Y/N -- per-step, never batch
- Exploit generates playbooks with write commands but does not execute them

## Error Handling

- API throttled -> log visibly, retry once after 2-5s, report if retry fails
- Permission denied (unexpected) -> report with context
- Resource limit hit -> report and suggest cleanup
- Any AWS CLI error -> surface full error message verbatim
- Expected AccessDenied on one target is not an error -- log partial results and continue
- Middleware pipeline failures are non-blocking -- log warnings, never stop the source agent

## CloudTrail + Splunk

- CloudTrail is the only log source for Splunk (`index=cloudtrail`)
- Do not assume Splunk is available -- agents must work standalone
- CloudTrail delay: ~5-15 min after simulation before querying

## Agent Isolation

scope-hunt is standalone -- does not read audit/exploit/defend output. All other agents share data through the agent-logs/data layer.

## Configuration Files

| File | Purpose |
|------|---------|
| `config/accounts.json` | Owned AWS account IDs -- distinguishes internal vs external cross-account trusts |
| `config/scps/*.json` | Pre-loaded SCPs when caller lacks Organizations API access |
| `config/cloudtrail-classes.json` | CloudTrail event classification -- used by exploit for stealth-ordered playbooks |

All config files are optional. `accounts.json` and `scps/*.json` are gitignored. `cloudtrail-classes.json` is committed.
