# SCOPE — Claude Code

**Project:** SCOPE (Security Cloud Ops Purple Engagement) — AI agent set for purple team security operations against AWS accounts: resource audit → exploit playbook generation → defensive controls with SCPs and SPL detections → SOC alert investigation.

The audit agent is an orchestrator that dispatches enumeration subagents in parallel. Standalone agents (exploit, investigate) reference subagents at `agents/subagents/` for verification and pipeline.

## Agents

```
agents/scope-audit.md       AWS audit orchestrator (slash command) — dispatches enum subagents in parallel
agents/scope-defend.md      Defensive controls generation — dispatched by orchestrator or invoked via /scope:defend
agents/scope-exploit.md     Privilege escalation playbooks (slash command)
agents/scope-investigate.md SOC alert investigation (slash command)
```

**Subagents** (`agents/subagents/` — dispatched by orchestrator or read inline):

```
agents/subagents/scope-enum-iam.md      IAM enumeration (model: haiku)
agents/subagents/scope-enum-sts.md      STS/identity enumeration (model: haiku)
agents/subagents/scope-enum-s3.md       S3 enumeration (model: haiku)
agents/subagents/scope-enum-kms.md      KMS enumeration (model: haiku)
agents/subagents/scope-enum-secrets.md  Secrets Manager enumeration (model: haiku)
agents/subagents/scope-enum-lambda.md   Lambda enumeration (model: haiku)
agents/subagents/scope-enum-ec2.md      EC2/VPC/EBS/ELB enumeration (model: haiku)
agents/subagents/scope-attack-paths.md  Attack path reasoning from per-module JSON (model: inherit)
agents/subagents/scope-verify.md        Unified verification — claim ledger, AWS API validation, SPL checks (read inline)
agents/subagents/scope-pipeline.md      Post-processing middleware — data normalization then evidence indexing (read inline)
```

## Architecture

```
agents/               Agent .md files — source format for all editors (flat, one file per agent)
agents/subagents/     Dispatched subagents and inline-read middleware (enum, attack-paths, verify, pipeline)
data/                 Normalized JSON output (runtime-generated, gitignored)
agent-logs/           Agent activity logs (runtime-generated, gitignored)
investigate/          Investigation artifacts (runtime-generated, gitignored)
dashboard/            React + D3 dashboard (`dashboard.html`)
config/               Optional pre-loaded data (accounts.json, scps/*.json)
bin/                  Tooling (install.js — editor setup, generate-report.js — dashboard builder)
.scope/hooks/         Lifecycle hooks — safety guard, SPL lint, schema validation, artifact check, agent logger
.scope/schemas/       JSON Schema definitions for results.json (audit, defend, exploit)
```

## Hooks

SCOPE uses lifecycle hooks to enforce safety and quality constraints at the tool level. Hooks are shared scripts in `.scope/hooks/` with platform-specific configuration installed from settings templates in `.scope/settings/`.

**Settings templates:** `.scope/settings/claude.settings.json` and `.scope/settings/gemini.settings.json` are the committed sources. Run `bin/install.js --local` (or `node bin/install.js`) to copy them to `.claude/settings.json` and `.gemini/settings.json` in your working directory.

| Hook | Event | Purpose |
|------|-------|---------|
| `scope-safety-guard.sh` | PreToolUse (Bash) | Block destructive AWS operations — agents are read-only |
| `scope-spl-lint.sh` | PostToolUse (Write\|Edit) | Hard-fail on SPL anti-patterns (missing index, wrong fields, transaction in composites) |
| `scope-schema-validate.sh` | PostToolUse (Write\|Edit) | Validate results.json and dashboard JSON against phase schemas — blocks writes with missing required fields |
| `scope-artifact-check.sh` | Stop | Verify mandatory artifacts exist before agent completes |
| `scope-agent-logger.sh` | PostToolUse (Bash, async) | Auto-log AWS CLI calls to agent-log.jsonl |

Codex does not support lifecycle hooks — safety constraints are enforced through AGENTS.md guidance only.

## Slash Commands

| Command | Description |
|---------|-------------|
| `/scope:audit <target>` | Enumerate AWS resources — accepts ARN, service name, `--all`, `@targets.csv`, or multiple services inline. Orchestrates parallel subagent dispatch (2+ services) or inline execution (single service). Auto-chains defend after audit completes. |
| `/scope:exploit <arn> [--fresh]` | Privilege escalation playbooks, persistence analysis, and exfiltration mapping for a specific principal |
| `/scope:investigate` | SOC alert investigation via Splunk — guided queries, timeline building, IOC correlation |
| `/scope:help` | List available commands, show usage examples |

## Data Layer

A single middleware agent runs automatically after audit, exploit, and defend:
- **scope-pipeline** (`agents/subagents/scope-pipeline.md`) — Phase 1 normalizes raw artifacts to `./data/<phase>/<run-id>.json`, then Phase 2 validates `agent-log.jsonl` into envelopes at `./agent-logs/<phase>/<run-id>.json`

Invoked by the source agent after writing artifacts — sequential and non-blocking. Investigate does not run this pipeline.

## Dashboard

All visualization is handled by the SCOPE dashboard. Agents export `results.json` to `$RUN_DIR/` and `dashboard/public/$RUN_ID.json`. Dashboard loads `index.json`, iterates the `runs[]` array, and fetches the latest entry per source phase.

**Dashboard HTML**: `cd dashboard && npm run dashboard` — generates a self-contained `dashboard.html` with all data inlined. Opens in any browser, no server required. Agents generate this automatically after the data pipeline completes.

## AWS Credential Model

SCOPE inherits credentials from the shell environment (AWS_PROFILE, AWS_ACCESS_KEY_ID, or boto3/AWS CLI defaults). No custom credential loading. The first AWS API call (`sts:GetCallerIdentity` at Gate 1) serves as the credential check.

## Approval Gate Pattern

Standard workflows are read-only. Before ANY destructive AWS operation:
- Show approval block with action, resources, risk, reason
- Wait for explicit Y/N — per-step, never batch
- Exploit generates playbooks with write commands but does not execute them

## Error Handling

- API throttled → log visibly, retry once after 2-5s, report if retry fails
- Permission denied (unexpected) → report with context
- Resource limit hit → report and suggest cleanup
- Any AWS CLI error → surface full error message verbatim
- Expected AccessDenied on one target is not an error — log partial results and continue
- Middleware pipeline failures are non-blocking — log warnings, never stop the source agent

## CloudTrail + Splunk

- CloudTrail is the only log source for Splunk (`index=cloudtrail`)
- Do not assume Splunk is available — agents must work standalone
- CloudTrail delay: ~5-15 min after simulation before querying

## Agent Isolation

scope-investigate is standalone — does not read audit/exploit/defend output. All other agents share data through the agent-logs/data layer.

## Configuration Files

| File | Purpose |
|------|---------|
| `config/accounts.json` | Owned AWS account IDs — distinguishes internal vs external cross-account trusts |
| `config/scps/*.json` | Pre-loaded SCPs when caller lacks Organizations API access |

All config files are optional and gitignored.
