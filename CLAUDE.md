# SCOPE — Claude Code

**Project:** SCOPE (Security Cloud Ops Purple Engagement) — AI agent set for purple team security operations against AWS accounts: resource audit → exploit playbook generation → defensive controls with SCPs and SPL detections → SOC alert investigation.

Each agent file is self-contained for project context, credentials, pipeline rules, and error handling. Source agents (audit, exploit, investigate) read verification and middleware agents (`agents/scope-verify-*.md`, `agents/scope-data.md`, `agents/scope-evidence.md`) from the repo at runtime — these files must be accessible from the working directory.

## Agents

```
agents/scope-audit.md       AWS audit (slash command)
agents/scope-defend.md      Defensive controls generation (auto-called by scope-audit)
agents/scope-exploit.md     Privilege escalation playbooks (slash command)
agents/scope-investigate.md SOC alert investigation (slash command)
agents/scope-verify-core.md Core verification — claim ledger, taxonomy, cross-agent consistency (auto-called)
agents/scope-verify-aws.md  AWS verification — API, IAM, SCP/RCP, attack path satisfiability (auto-called)
agents/scope-verify-splunk.md Splunk verification — SPL lints, field validation, rerun recipes (auto-called)
agents/scope-data.md        Data normalization middleware (invoked by source agent)
agents/scope-evidence.md    Evidence provenance middleware (invoked by source agent)
```

## Architecture

```
agents/               Agent .md files — source format for all editors (flat, one file per agent)
agents/modules/       Extracted audit modules — loaded on-demand via Read (IAM, STS, S3, KMS, Secrets, Lambda, EC2, attack-paths)
commands/             Quick-reference docs for each slash command (synopsis, args, examples, artifacts)
data/                 Normalized JSON output (runtime-generated, gitignored)
evidence/             Evidence provenance data (runtime-generated, gitignored)
investigate/          Investigation artifacts (runtime-generated, gitignored)
dashboard/            React + D3 dashboard (`dashboard.html`)
config/               Optional pre-loaded data (accounts.json, scps/*.json)
bin/                  Tooling (install.js — editor setup, generate-report.js — dashboard builder)
.scope/hooks/         Lifecycle hooks — safety guard, SPL lint, schema validation, artifact check, evidence logger
.scope/schemas/       JSON Schema definitions for results.json (audit, defend, exploit)
```

## Hooks

SCOPE uses lifecycle hooks to enforce safety and quality constraints at the tool level. Hooks are shared scripts in `.scope/hooks/` with platform-specific configuration in `.claude/settings.json` and `.gemini/settings.json`.

| Hook | Event | Purpose |
|------|-------|---------|
| `scope-safety-guard.sh` | PreToolUse (Bash) | Block destructive AWS operations — agents are read-only |
| `scope-spl-lint.sh` | PostToolUse (Write\|Edit) | Hard-fail on SPL anti-patterns (missing index, wrong fields, transaction in composites) |
| `scope-schema-validate.sh` | PostToolUse (Write\|Edit) | Validate results.json and dashboard JSON against phase schemas — blocks writes with missing required fields |
| `scope-artifact-check.sh` | Stop | Verify mandatory artifacts exist before agent completes |
| `scope-evidence-logger.sh` | PostToolUse (Bash, async) | Auto-log AWS CLI calls to evidence.jsonl |

Codex does not support lifecycle hooks — safety constraints are enforced through AGENTS.md guidance only.

## Slash Commands

| Command | Description |
|---------|-------------|
| `/scope:audit <target>` | Enumerate AWS resources — accepts ARN, service name, `--all`, `@targets.csv`, or multiple services inline. Auto-chains to defensive controls generation. |
| `/scope:exploit <arn> [--fresh]` | Privilege escalation playbooks, persistence analysis, and exfiltration mapping for a specific principal |
| `/scope:investigate` | SOC alert investigation via Splunk — guided queries, timeline building, IOC correlation |
| `/scope:help` | List available commands, show usage examples |

## Data Layer

Two middleware agents run automatically after audit, exploit, and defend:
1. **scope-data** — normalizes raw artifacts to `./data/<phase>/<run-id>.json`
2. **scope-evidence** — validates `evidence.jsonl` into envelopes at `./evidence/<phase>/<run-id>.json`

Both are invoked by the source agent after writing artifacts — sequential and non-blocking. Investigate does not run this pipeline.

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

scope-investigate is standalone — does not read audit/exploit/defend output. All other agents share data through the evidence/data layer.

## Configuration Files

| File | Purpose |
|------|---------|
| `config/accounts.json` | Owned AWS account IDs — distinguishes internal vs external cross-account trusts |
| `config/scps/*.json` | Pre-loaded SCPs when caller lacks Organizations API access |

All config files are optional and gitignored.
