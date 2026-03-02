# SCOPE — Project Instructions

**Project:** SCOPE — AI agent set for purple team security operations

SCOPE (Security Cloud Ops Purple Engagement) runs the full purple team loop against AWS accounts: resource audit → exploit playbook generation → remediation with SCPs and SPL detections → SOC alert investigation. This file contains shared project instructions for all LLM editors (Claude Code, Gemini CLI, Codex).

## Architecture

```
agents/               Agent .md files — source format for all editors (flat, one file per agent)
  scope-audit.md     Consolidated AWS audit — ARN routing, service enumeration, attack paths, HTML graph
  scope-remediate.md Enterprise-scale SCPs, security controls, detection suggestions
  scope-exploit.md   Privilege escalation policy generator, control circumvention advisor
  scope-investigate.md Splunk MCP threat hunting, timeline building, IOC correlation
  scope-verify-core.md   Core verification — claim ledger, output taxonomy, cross-agent consistency
  scope-verify-aws.md    AWS verification — API calls, IAM policy, SCP/RCP safety, attack path satisfiability
  scope-verify-splunk.md Splunk verification — SPL semantic lints, field validation, rerun recipes
  scope-data.md    Data normalization middleware — auto-called by agents, not a slash command
  scope-evidence.md Evidence provenance middleware — auto-called, indexes claims with provenance
  scope-render.md  Dashboard rendering middleware — auto-called, generates HTML from normalized data
commands/             Quick-reference docs for each slash command (synopsis, args, examples, artifacts)
  audit.md          /scope:audit usage
  remediate.md      /scope:remediate usage
  exploit.md        /scope:exploit usage
  investigate.md    /scope:investigate usage
  verify.md         /scope:verify usage
data/                 Normalized JSON output (runtime-generated, gitignored)
  index.json        Unified run registry — machine-readable index of all runs
  audit/            Normalized audit run JSON files
  remediate/        Normalized remediate run JSON files
  exploit/          Normalized exploit run JSON files
  investigate/      Normalized investigate run JSON files
evidence/             Evidence provenance data (runtime-generated, gitignored)
  index.json        Evidence run registry
  audit/            Evidence envelopes per audit run (claims, API logs, coverage)
  remediate/        Evidence envelopes per remediate run
  exploit/          Evidence envelopes per exploit run
  investigate/      Evidence envelopes per investigate run
bin/
  install.js          Deploys agents to editor config directories
```

## Slash Commands

| Command | Description |
|---------|-------------|
| `/scope:audit <target>` | Enumerate AWS resources — accepts ARN, service name (iam/s3/kms/secrets/sts/lambda/ec2), `--all` for full account audit, or `@targets.csv` for bulk targets. Produces layered output + interactive HTML attack graph. |
| `/scope:remediate` | Generate enterprise-scale SCPs, security controls, and detection suggestions from audit findings |
| `/scope:investigate` | Splunk MCP threat hunting — timeline building, IOC correlation, detection verification |
| `/scope:exploit` | Privilege escalation policy generator, control circumvention advisor for assessments and CTFs |
| `/scope:verify` | Verification protocol — auto-called by agents to enforce claim accuracy, reproducibility, and safety |

## Data Layer

Three middleware agents run automatically as a post-processing pipeline after each source agent writes artifacts:

1. **scope-data** — reads raw markdown/HTML artifacts, writes normalized JSON to `./data/<phase>/<run-id>.json`, maintains `./data/index.json`
2. **scope-evidence** — reads `$RUN_DIR/evidence.jsonl`, validates provenance chains, writes evidence envelopes to `./evidence/<phase>/<run-id>.json`, maintains `./evidence/index.json`
3. **scope-render** — reads normalized JSON from `./data/`, generates self-contained HTML dashboards in `$RUN_DIR/`

None are slash commands. All are auto-called, sequential, and non-blocking (failures log warnings but don't stop the source agent).

### Pipeline Observability

The middleware pipeline is designed to fail gracefully — each step logs warnings but never blocks the source agent. This means:

- If scope-data fails: no normalized JSON. Downstream agents fall back to raw markdown parsing.
- If scope-evidence fails: no provenance envelopes. Downstream agents use normalized JSON or raw artifacts.
- If scope-render fails: no HTML dashboards. Raw artifacts and normalized data are still available.

**Detecting failures:** After each run, check for expected output files. If `$RUN_DIR/attack-graph.html` or `$RUN_DIR/dashboard.html` is missing, the pipeline logged a warning during execution. Re-run the pipeline manually by reading the three middleware agents with the same PHASE and RUN_DIR.

**Fallback hierarchy:** Every downstream agent (remediate, exploit) implements a three-tier fallback: evidence → normalized data → raw files. The agent always works, but fidelity decreases at each fallback level.

## Evidence Layer

Downstream agents consume upstream output in this priority order:

1. `./evidence/` — **Highest fidelity.** Claim-level provenance, coverage manifests, policy evaluation chains. Use when you need to understand WHY a claim was made and what evidence supports it.
2. `./data/` — **Structured report data.** Summaries, graph structures, attack path lists. Use when you need WHAT was found but don't need provenance.
3. `$RUN_DIR/` — **Raw artifacts.** Markdown reports, HTML dashboards, raw JSON. Fallback when normalized data is unavailable. Requires regex parsing.

Source agents write `$RUN_DIR/evidence.jsonl` during execution — one JSON line per evidence event (API calls, policy evaluations, claims, coverage checks). scope-evidence validates and indexes these into structured envelopes.

## Dashboards

Dashboard HTML is generated by `scope-render` as the last step of the post-processing pipeline:
- scope-audit: `$RUN_DIR/attack-graph.html` — interactive D3 force-directed attack graph
- scope-remediate: `$RUN_DIR/dashboard.html` — risk matrix, policy coverage, MITRE heatmap
- scope-exploit: `$RUN_DIR/dashboard.html` — escalation path timelines, circumvention analysis
- scope-investigate: `$RUN_DIR/dashboard.html` — event timeline, query log (only when analyst saves)

Dashboards are self-contained HTML with inline CSS/JS and D3.js from CDN. Dark theme and severity colors are consistent across all agents. Data is embedded as a JS literal — no server required. Template and rendering logic live in `agents/scope-render.md` — source agents do not generate HTML inline.

## Agent Isolation

**scope-investigate is standalone by design.** It does not read from `./audit/`, `./exploit/`, `./evidence/`, or any other agent's output. This is intentional:

- Investigation is SOC-focused: the analyst brings an alert and investigates it in Splunk.
- Audit/exploit data is pentesting-focused: different context, different audience, different trust model.
- Cross-contamination between pentest findings and SOC investigations would confuse workflows.

If you need to correlate investigation results with audit findings, run both independently and compare artifacts manually.

**All other agents share data through the evidence/data layer:**
- Remediate reads all audit runs to generate remediations.
- Exploit reads audit data (optional) or enumerates fresh.
- All share the same verification protocol.

## Engagement Context

Agents can optionally run inside an engagement directory (`./engagements/<name>/`). When an engagement directory exists:
- Audit writes to `./engagements/<name>/audit/$RUN_ID/` instead of `./audit/$RUN_ID/`
- Remediate and exploit follow the same pattern
- Investigate is unaffected (standalone by design)

Engagement directories are created manually by the operator before running agents. There is no engagement manifest or automated creation — v2 will add engagement orchestration.

## v2 Deferred

Full engagement orchestration (engage, detect, teardown, status) is planned for v2. See project roadmap for details.

## AWS Credential Model

SCOPE inherits credentials from the shell environment — AWS_PROFILE, AWS_ACCESS_KEY_ID, or any mechanism boto3/AWS CLI picks up. No custom credential loading.

Do NOT pre-validate credentials at agent startup. Check on first actual AWS API call. On failure, output this template:

```
AWS credential error: [error message]

To fix:
  Option 1: export AWS_PROFILE=<profile-name>
  Option 2: export AWS_ACCESS_KEY_ID=<key> AWS_SECRET_ACCESS_KEY=<secret>
  Option 3: aws sso login --profile <profile-name>
```

## Approval Gate Pattern

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

## Key Pitfalls to Avoid

- **Do not batch approvals** — each destructive operation needs individual Y/N
- **Do not pre-validate credentials** — check only on first API call
- **Do not use context:fork for inline agents** — agents are standalone prompt files
- **Do not silently skip failures** — stop and report on API errors (throttling, permission denied, resource limits)
- **Do not auto-remediate** — SCOPE is offensive/detective, not audit/compliance. Report and recommend.
- **Do not assume Splunk is available** — it's optional. Agents must work standalone without Splunk MCP.

## CloudTrail + Splunk

- CloudTrail is the only log source flowing to Splunk
- All SPL detections are built against CloudTrail events in `index=cloudtrail`
- Before generating detections: reason about which AWS API calls generate which CloudTrail events
- If Splunk MCP is available: use it to verify detections fire after simulation
- After running simulations: wait for user go-ahead before querying Splunk (CloudTrail delay: ~5-15 min)

## Error Handling

Stop and report on any failure:
- API throttled → report, do not retry silently
- Permission denied → report with context (what was attempted, what permission is needed)
- Resource limit hit → report and suggest cleanup
- Any AWS CLI error → surface full error message, not just a summary
