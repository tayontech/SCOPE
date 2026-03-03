# SCOPE — Project Instructions

**Project:** SCOPE — AI agent set for purple team security operations

SCOPE (Security Cloud Ops Purple Engagement) runs the full purple team loop against AWS accounts: resource audit → exploit playbook generation → defensive controls with SCPs and SPL detections → SOC alert investigation. This file contains shared project instructions for all LLM editors (Claude Code, Gemini CLI, Codex).

## Architecture

```
agents/               Agent .md files — source format for all editors (flat, one file per agent)
  scope-audit.md     Consolidated AWS audit — ARN routing, service enumeration, attack paths, results.json
  scope-defend.md    Defensive controls generation — auto-called by scope-audit after enumeration
  scope-exploit.md   Privilege escalation, persistence analysis, exfiltration mapping
  scope-investigate.md Splunk MCP threat hunting, timeline building, IOC correlation
  scope-verify-core.md   Core verification — claim ledger, output taxonomy, cross-agent consistency
  scope-verify-aws.md    AWS verification — API calls, IAM policy, SCP/RCP safety, attack path satisfiability
  scope-verify-splunk.md Splunk verification — SPL semantic lints, field validation, rerun recipes
  scope-data.md    Data normalization middleware — auto-called by agents, not a slash command
  scope-evidence.md Evidence provenance middleware — auto-called, indexes claims with provenance
commands/             Quick-reference docs for each slash command (synopsis, args, examples, artifacts)
  audit.md          /scope:audit usage (includes auto-chained defensive controls)
  exploit.md        /scope:exploit usage
  investigate.md    /scope:investigate usage
  help.md           /scope:help usage
data/                 Normalized JSON output (runtime-generated, gitignored)
  index.json        Unified run registry — machine-readable index of all runs
  audit/            Normalized audit run JSON files
  defend/           Normalized defend run JSON files
  exploit/          Normalized exploit run JSON files
evidence/             Evidence provenance data (runtime-generated, gitignored)
  index.json        Evidence run registry
  audit/            Evidence envelopes per audit run (claims, API logs, coverage)
  defend/           Evidence envelopes per defend run
  exploit/          Evidence envelopes per exploit run
investigate/          Investigation artifacts (runtime-generated, gitignored)
  context.json      Persistent environment context — network baselines, principal profiles, alert patterns, IOCs
  INDEX.md          Human-readable run index
  index.json        Machine-readable run index
  investigate-*/    Per-investigation run directories (investigation.md, evidence.jsonl)
bin/
  install.js          Deploys agents to editor config directories
```

## Slash Commands

| Command | Description |
|---------|-------------|
| `/scope:audit <target> [<target> ...]` | Enumerate AWS resources — accepts ARN, service name (`iam`, `s3`, `kms`, `secrets`, `sts`, `lambda`, `ec2`), `--all` for full account audit, `@targets.csv` for bulk targets, or multiple services inline (e.g., `iam s3 kms`). The `ec2` service includes VPC, EBS, ELB/ELBv2, SSM, and VPN enumeration. Auto-chains to defensive controls generation. |
| `/scope:exploit <arn>` | Privilege escalation playbooks, persistence analysis, and exfiltration mapping for a specific principal |
| `/scope:investigate` | SOC alert investigation via Splunk — step-by-step guided queries, timeline building, IOC correlation |
| `/scope:help` | List available commands, show usage examples, and link to documentation. Implemented by editors reading `commands/help.md` — not an agent file. |

## Data Layer

Two middleware agents run automatically as a post-processing pipeline after audit, exploit, and defend write artifacts:

1. **scope-data** — reads raw agent artifacts (prefers `results.json`, falls back to markdown), writes normalized JSON to `./data/<phase>/<run-id>.json`, maintains `./data/index.json`
2. **scope-evidence** — reads `$RUN_DIR/evidence.jsonl`, validates provenance chains, writes evidence envelopes to `./evidence/<phase>/<run-id>.json`, maintains `./evidence/index.json`

Neither is a slash command. Both are auto-called, sequential, and non-blocking (failures log warnings but don't stop the source agent). **Investigate does not run this pipeline** — if the analyst chooses to save, it writes `investigation.md` and `evidence.jsonl` to the run directory (no middleware normalization). `./investigate/context.json` is always updated for cross-investigation learning, regardless of save choice. All visualization is handled by the SCOPE dashboard at `http://localhost:3000`.

**Audit → Defend auto-chain:** After scope-audit completes its audit and middleware pipeline, it automatically invokes scope-defend with the current run's findings. Defend chains after any non-stopped audit completion — including when the operator skips export at Gate 4 (defend reads findings.md and enumeration data, not results.json). Defend runs autonomously — no enumeration gates (Gates 2-4) since it only reads audit output and writes remediation artifacts, never makes AWS API calls. It produces its own artifacts in `./defend/`. The middleware pipeline then runs again for the defend output.

### Pipeline Observability

The middleware pipeline is designed to fail gracefully — each step logs warnings but never blocks the source agent. This means:

- If scope-data fails: no normalized JSON. Downstream agents fall back to raw markdown parsing.
- If scope-evidence fails: no provenance envelopes. Downstream agents use normalized JSON or raw artifacts.

**Detecting failures:** After an audit, exploit, or defend run, check for expected output files. `$RUN_DIR/results.json` is produced by the source agent (audit/exploit/defend), not the pipeline. If it's missing, check the run context before assuming failure — some agents have intentional no-export paths:
- **Exploit:** Zero-path results stop at Gate 3 with no playbook or results export. The operator can also say "stop" at Gate 4 to end before writing, or "skip" to display without saving. All three are intentional no-export paths. Check for `playbook.md` — if absent, check whether the run stopped at Gate 3 (zero findings) or Gate 4 (operator declined).
- **Audit:** If the operator says "skip" at Gate 4, the findings.md report is written but results.json and dashboard export are intentionally skipped. The defend auto-chain still runs (it reads findings.md, not results.json). Check for `findings.md` to confirm the audit itself completed.
- **Defend:** Always produces results.json on successful completion. If missing, the agent failed.

If `./data/<phase>/<run-id>.json` or `./evidence/<phase>/<run-id>.json` is missing, check pipeline warnings — the middleware failed. Re-run the pipeline manually by reading the middleware agents with the same PHASE and RUN_DIR. (Investigate runs do not produce `results.json` — check for `investigation.md` instead.)

**Fallback hierarchy:** Downstream agents (defend, exploit) implement a three-tier fallback: evidence → normalized data → raw files. The agent always works, but fidelity decreases at each fallback level.

## Evidence Layer

Downstream agents consume upstream output in this priority order:

1. `./evidence/` — **Highest fidelity.** Claim-level provenance, coverage manifests, policy evaluation chains. Use when you need to understand WHY a claim was made and what evidence supports it.
2. `./data/` — **Structured report data.** Summaries, graph structures, attack path lists. Use when you need WHAT was found but don't need provenance.
3. `$RUN_DIR/` — **Raw artifacts.** Markdown reports, results.json, raw JSON. Fallback when normalized data is unavailable. Requires regex parsing.

Audit, exploit, and defend write `$RUN_DIR/evidence.jsonl` during execution — one JSON line per evidence event (API calls, policy evaluations, claims, coverage checks). scope-evidence validates and indexes these into structured envelopes. Investigate accumulates evidence in memory and flushes to disk only when the analyst saves.

## Dashboard

All visualization is handled by the **SCOPE dashboard** — a React + D3 application at `http://localhost:3000`.

Three agents (audit, exploit, defend) export data as `results.json` to two locations:
1. **`$RUN_DIR/results.json`** — archived with run artifacts
2. **`dashboard/public/$RUN_ID.json`** — served to the SCOPE dashboard

Investigate does not export results.json — it produces a markdown determination (`investigation.md`) only.

The dashboard reads `dashboard/public/index.json` to find the latest run and renders it. If `index.json` is missing or has no `latest` entry, the dashboard falls back to loading `dashboard/public/results.json` directly. The index tracks `source` (audit/exploit/defend) per run. The dashboard auto-detects the phase and renders the appropriate view.

**Dashboard features:** Phase tab bar (Audit, Exploit, Defend) with auto-detection from data source. **Audit/Exploit view:** severity filter toggles, category filter toggles (9 categories), search bar, sort (severity/steps/name), clickable stat cards with slide-out detail panel, attack graph with edge highlighting, node detail panel, copy-to-clipboard. **Defend view:** policy viewer (collapsible SCP/RCP cards with JSON syntax coloring, blast-radius badges, impact analysis), detection rules list (grouped by category with MITRE links), controls matrix (card grid with priority/effort badges), prioritization sidebar. **Run history:** phase-colored badges, auto-phase-switch on run selection, backwards compatibility (missing `source` defaults to "audit").

**Results schema:** `results.json` includes `summary` (with `paths_by_category` counts), `graph` (nodes + edges), `attack_paths` (each with `category` field), `principals` (user/role array with MFA, policies, risk flags), and `trust_relationships` (per-trust with wildcard/external ID/MFA checks). Old results.json without new fields renders gracefully (empty arrays).

**No standalone HTML files are generated.** Agents do not produce `attack-graph.html` or `dashboard.html` — all rendering is done by the SCOPE dashboard.

## Agent Isolation

**scope-investigate is standalone by design.** It does not read from `./audit/`, `./exploit/`, `./evidence/`, or any other agent's output. This is intentional:

- Investigation is SOC-focused: the analyst brings an alert and investigates it in Splunk.
- Audit/exploit data is pentesting-focused: different context, different audience, different trust model.
- Cross-contamination between pentest findings and SOC investigations would confuse workflows.

**Environment context exception:** scope-investigate reads `./investigate/context.json` at startup. This file contains distilled environmental knowledge (network baselines, principal behavior profiles, alert pattern statistics) — not raw investigation artifacts. The prohibition on reading other `./investigate/` subdirectories and all audit/exploit/defend data remains.

If you need to correlate investigation results with audit findings, run both independently and compare artifacts manually.

**All other agents share data through the evidence/data layer:**
- Defend reads the current audit run in autonomous mode (auto-chained from audit) or all audit runs when invoked manually.
- Exploit reads audit data (optional) or enumerates fresh.
- All share the same verification protocol.

## Engagement Context

Agents can optionally run inside an engagement directory (`./engagements/<name>/`). When an engagement directory exists:
- Audit writes to `./engagements/<name>/audit/$RUN_ID/` instead of `./audit/$RUN_ID/`
- Defend and exploit follow the same pattern
- Investigate is unaffected (standalone by design)

Engagement directories are created manually by the operator before running agents. There is no engagement manifest or automated creation — v2 will add engagement orchestration.

## Configuration Files

The `config/` directory holds optional pre-loaded data that agents use when live enumeration is unavailable or incomplete.

| File | Purpose | Consuming Agent |
|------|---------|-----------------|
| `config/accounts.json` | Owned AWS account IDs — distinguishes internal cross-account trusts from external ones. Copy `accounts.example.json` and fill in real IDs. | scope-audit |
| `config/scps/*.json` | Pre-loaded Service Control Policies — provides SCP data when the caller lacks Organizations API access. Files prefixed with `_` are templates (skipped by loader). | scope-audit (loading + merge), scope-verify-aws (validation) |

All config files are optional and gitignored (they contain environment-specific data). Example/template files are tracked. Without config files, agents fall back to live enumeration only (with reduced confidence where data is missing). See `config/scps/README.md` for SCP file format and sourcing instructions.

## v2 Deferred

Full engagement orchestration (engage, detect, teardown, status) is planned for v2. See project roadmap for details.

## AWS Credential Model

SCOPE inherits credentials from the shell environment — AWS_PROFILE, AWS_ACCESS_KEY_ID, or any mechanism boto3/AWS CLI picks up. No custom credential loading.

Do NOT add a separate credential validation step before the workflow begins. The first AWS API call (`sts:GetCallerIdentity`, run during audit's Gate 1 — the auto-continue identity verification step) serves as the credential check. On failure, output this template:

```
AWS credential error: [error message]

To fix:
  Option 1: export AWS_PROFILE=<profile-name>
  Option 2: export AWS_ACCESS_KEY_ID=<key> AWS_SECRET_ACCESS_KEY=<secret>
  Option 3: aws sso login --profile <profile-name>
```

## Approval Gate Pattern

Standard SCOPE agent workflows (audit, defend, investigate, exploit) are read-only — they enumerate, analyze, and generate artifacts but do not create, modify, or delete AWS resources. The approval gate below applies only when an operator explicitly directs a write operation (e.g., deploying a generated SCP). Exploit generates playbooks with write commands but does not execute them.

Before ANY destructive AWS operation (resource creation, modification, or deletion):

```
APPROVAL REQUIRED
Action: [what will happen]
Resources: [list of AWS resources affected]
Risk: [LOW / MEDIUM / HIGH]
Reason: [why this step is needed]

Proceed? (Y/N):
```

Rules:
- Show this block and wait for explicit Y/N before proceeding
- Per-step approval — never batch multiple destructive operations
- On N: log "Skipped: [action] — denied by user" and continue with next step
- On Y: proceed, then log the action and CloudTrail events to expect
- **Agent-specific override:** scope-exploit prohibits CloudTrail event names in all output (detection analysis belongs to scope-defend and scope-investigate). This override takes precedence — exploit does not log expected CloudTrail events even for approved operations.

## Key Pitfalls to Avoid

- **Do not batch approvals** — each destructive operation needs individual Y/N
- **Do not add credential validation steps outside Gate 1** — Gate 1's sts:GetCallerIdentity IS the first API call
- **Do not use context:fork for inline agents** — agents are standalone prompt files
- **Do not silently skip failures** — source agents stop and report on AWS API errors (throttling, permission denied, resource limits). Exception: middleware pipeline steps (scope-data, scope-evidence) are non-blocking — they log warnings but never stop the source agent.
- **Do not assume Splunk is available** — it's optional. Agents must work standalone without Splunk MCP.

## CloudTrail + Splunk

- CloudTrail is the only log source flowing to Splunk
- All SPL detections are built against CloudTrail events in `index=cloudtrail`
- Before generating detections: reason about which AWS API calls generate which CloudTrail events
- If Splunk MCP is available: use it to verify detections fire after simulation
- After running simulations: wait for user go-ahead before querying Splunk (CloudTrail delay: ~5-15 min)

## Error Handling

Stop and report on unexpected AWS errors:
- API throttled → log the error visibly, retry once after 2-5 seconds. If the retry also fails, report and continue with partial results. Never retry silently — the operator must see every throttle event.
- Permission denied (unexpected) → report with context (what was attempted, what permission is needed)
- Resource limit hit → report and suggest cleanup
- Any AWS CLI error → surface full error message, not just a summary

**Expected access denials are not errors.** When auditing multiple targets, AccessDenied on one target is expected — log partial results and continue with remaining targets. Only stop the entire run for systemic failures (credential expiration, account-wide blocks).
