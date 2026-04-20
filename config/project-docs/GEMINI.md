# SCOPE — Gemini CLI

**Project:** SCOPE (Security Cloud Ops Purple Engagement) — AI agent set for purple team security operations against AWS accounts: resource audit → exploit playbook generation → defensive controls with SCPs and SPL detections → SOC alert investigation.

The audit agent is an orchestrator that dispatches enumeration subagents in parallel. Standalone agents (exploit, hunt) reference subagents at `agents/subagents/` for verification and pipeline.

## Agents

```
agents/scope-audit.md       AWS audit orchestrator (slash command) — dispatches enum subagents in parallel
agents/scope-defend.md      Defensive controls orchestrator (model: gemini-2.5-pro) — dispatches 5 subagents in 2 waves, assembles results.json. Dispatched by audit or invoked via /scope:defend
agents/scope-exploit.md     Red team operator — context-driven escalation playbooks with research integration (slash command)
agents/scope-hunt.md        SOC alert investigation, hypothesis-driven threat hunting, and threat intel parsing (slash command)
```

**Subagents** (`agents/subagents/` — dispatched by orchestrator or read inline):

```
agents/subagents/scope-hunt-investigate.md  Investigation mode intake — alert parsing, investigation_context, HYPO-01 (model: gemini-2.5-pro)
agents/subagents/scope-hunt-intel.md        Intel mode intake — URL/NL parsing, IOC/TTP extraction, INTEL-03 hypotheses (model: gemini-2.5-pro)
agents/subagents/scope-hunt-audit.md        Hunt mode intake — run-dir loading, HYPO-02/03 hypotheses from attack paths (model: gemini-2.5-pro)
agents/subagents/scope-attack-paths.md     Attack path reasoning from per-module JSON (model: gemini-2.5-pro)
agents/subagents/scope-defend-guardrails.md   Systemic pattern detection — SCPs/RCPs for widespread findings (model: gemini-2.5-pro)
agents/subagents/scope-defend-splunk.md       SPL detections mapped 1:1 to attack paths (model: gemini-2.5-pro)
agents/subagents/scope-defend-policy.md       IAM policy replacement using iam.json + staleness data (model: gemini-2.5-pro)
agents/subagents/scope-defend-remediation.md  Prioritized remediation plan with dependency mapping (model: gemini-2.5-pro)
agents/subagents/scope-defend-validate.md     Adversarial review of all generated controls (model: gemini-2.5-pro)
agents/subagents/scope-verify.md           Unified verification — claim ledger, AWS API validation, SPL checks (read inline)
agents/subagents/scope-pipeline.md         Post-processing middleware — data normalization then evidence indexing (read inline)
```

## Architecture

```
agents/               Agent .md files — source format for all editors (flat, one file per agent)
agents/subagents/     Dispatched subagents and inline-read middleware (enum, attack-paths, verify, pipeline)
data/                 Normalized JSON output (runtime-generated, gitignored)
agent-logs/           Agent activity logs (runtime-generated, gitignored)
hunt/          Hunt artifacts (runtime-generated, gitignored)
dashboard/            React + D3 dashboard (`<run-id>-dashboard.html`)
config/               Optional pre-loaded data (accounts.json, scps/*.json)
bin/                  Tooling (install.js — editor setup, generate-report.js — dashboard builder)
config/hooks/         Lifecycle hooks — safety guard, SPL lint, schema validation, artifact check, agent logger
config/schemas/       JSON Schema definitions for results.json (audit, defend, exploit)

# Runtime output structure (gitignored):
audit/<run-id>/           Audit run — enum JSONs, results.json, findings.md
audit/<run-id>/defend/          Defend output — 5 subagent artifacts, results.json, validation report
audit/<run-id>/defend/policies/ SCP/RCP JSON files from guardrails subagent
audit/<run-id>/defend/replacements/ IAM replacement policy JSON files from policy subagent
exploit/<run-id>/         Exploit run — playbooks, results.json
hunt/<run-id>/     Hunt artifacts
```

## Hooks

SCOPE uses lifecycle hooks to enforce safety and quality constraints at the tool level. Hook source scripts are in `config/hooks/` and settings templates in `config/settings/`.

**Installation:** Run `node bin/install.js` to copy hook scripts to `.gemini/hooks/` and hook settings to `.gemini/settings.json`. The installer rewrites hook paths to absolute references so hooks resolve correctly regardless of CWD.

| Hook | Event | Purpose |
|------|-------|---------|
| `scope-safety-guard.sh` | BeforeTool (run_shell_command) | Block destructive AWS operations — agents are read-only |
| `scope-aws-output-inject.sh` | BeforeTool (run_shell_command) | Auto-inject `--output json` into AWS CLI calls missing explicit output format |
| `scope-spl-lint.sh` | AfterTool (write_file\|replace) | Validates SPL against `config/index.json` allowlist, blocks anti-patterns (transaction in composites, leading wildcards, index=*, missing time bounds) |
| `scope-schema-validate.sh` | AfterTool (write_file\|replace) | Validate results.json and dashboard JSON against phase schemas — blocks writes with missing required fields |
| `scope-artifact-check.sh` | SessionEnd (all platforms) | Verify mandatory artifacts exist before agent completes |
| `scope-agent-logger.sh` | AfterTool (run_shell_command, async) | Auto-log AWS CLI calls to agent-log.jsonl |

## Slash Commands

| Command | Description |
|---------|-------------|
| `/scope:audit <target>` | Enumerate AWS resources — accepts ARN, service name, `--all`, `@targets.csv`, or multiple services inline. Orchestrates parallel subagent dispatch (2+ services) or inline execution (single service). Auto-chains defend after audit completes. |
| `/scope:defend [run-dir]` | Defensive controls orchestrator — dispatches 5 subagents (guardrails, splunk, policy, remediation, validate) against audit data. Auto-chained by audit or invoked directly with a run directory. |
| `/scope:exploit <arn> [--audit <run-dir>]` | Red team escalation playbooks — standalone context-driven probing or audit-data-driven analysis with real-world research integration |
| `/scope:hunt [input]` | SOC alert investigation, hypothesis-driven threat hunting, and threat intel parsing. Three entry points: alert/notable ID (investigation mode), audit/exploit run directory (hunt mode), or threat intel URL / natural language description (intel mode). |
| `/scope:help` | List available commands, show usage examples |

## Data Layer

A single middleware agent runs automatically after audit and defend:
- **scope-pipeline** (`agents/subagents/scope-pipeline.md`) — Phase 1 normalizes raw artifacts to `./data/<phase>/<run-id>.json`, then Phase 2 validates `agent-log.jsonl` into envelopes at `./agent-logs/<phase>/<run-id>.json`

Invoked by the source agent after writing artifacts — sequential and non-blocking. Hunt does not run this pipeline.

## Dashboard

All visualization is handled by the SCOPE dashboard. Agents export `results.json` to `$RUN_DIR/` and `dashboard/public/$RUN_ID.json`. Dashboard loads `index.json`, iterates the `runs[]` array, and fetches the latest entry per source phase.

**Dashboard HTML**: `cd dashboard && npm run dashboard` — generates a self-contained `<run-id>-dashboard.html` with all data inlined. Opens in any browser, no server required. Agents generate this automatically after the data pipeline completes.

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

- Splunk integration supports multiple indexes configured in `config/index.json` (operator-specific, gitignored)
- Agents read `config/index.json` at session start for index routing — each attack path's data source maps to the appropriate index group (`aws_api`, `identity`, `vcs`, `endpoint`, `network`, `cloud_platform`)
- First run can auto-discover indexes via the Splunk MCP `get_indexes` tool — agent filters internal indexes, reasons about groupings, and presents proposed configuration to the operator for confirmation before writing
- When `config/index.json` is absent and Splunk is unavailable, agents default to `index=cloudtrail` for backward compatibility — no breaking change for existing users
- Do not assume Splunk is available — agents must work standalone
- Agents read `config/splunk-patterns.md` for SPL query generation best practices (command selection, anti-patterns, composite detection patterns)
- CloudTrail delay: ~5-15 min after simulation before querying

## Agent Isolation

scope-hunt has three operating modes with different isolation properties:
- **Detection investigation mode** (invoked without a path, or with a Splunk alert ID): standalone — does not read audit/exploit/defend output. Isolation matches v1.8 behavior.
- **Hunt mode** (invoked with a SCOPE audit or exploit run directory path): reads `results.json`, attack path JSON, and per-module JSON from the provided run directory. Resource identifiers read in this mode are session-scoped.
- **Intel mode** (invoked with a threat intel URL or natural language threat description): fetches the URL or parses the description, extracts IOCs and TTPs, generates hypotheses beyond the report, and hunts in Splunk. Extracted identifiers are session-scoped and must not be written to persistent memory.

All other agents share data through the agent-logs/data layer.

## Configuration Files

| File | Purpose |
|------|---------|
| `config/accounts.json` | Owned AWS account IDs — distinguishes internal vs external cross-account trusts |
| `config/scps/*.json` | Pre-loaded SCPs when caller lacks Organizations API access |
| `config/cloudtrail-classes.json` | CloudTrail event classification — used by exploit for visibility tagging |
| `config/techniques.json` | Consolidated technique seed knowledge — escalation, persistence, post-exploitation vectors |
| `config/index.json` | Operator Splunk index configuration — groups indexes by data source type (gitignored, auto-discovered or copied from example) |
| `config/index.example.json` | Template with common security index groupings — copy to `config/index.json` and customize (committed) |
| `config/splunk-patterns.md` | SPL query patterns, anti-patterns, and command selection rules for detection engineering and threat hunting (committed) |

All config files are optional. `accounts.json`, `scps/*.json`, and `index.json` are gitignored. `cloudtrail-classes.json`, `index.example.json`, and `splunk-patterns.md` are committed.
