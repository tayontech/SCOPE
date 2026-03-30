# SCOPE Architecture

Agent communication diagram for the SCOPE pipeline orchestration system.

## Agent Overview

**Orchestrator agent** (slash command — operator-triggered):
- `scope-audit` — AWS resource enumeration orchestrator: dispatches enum subagents in parallel, runs attack-paths analysis, auto-chains defend

**Standalone agents** (slash commands — operator-triggered):
- `scope-exploit` — Privilege escalation playbooks, persistence analysis, exfiltration mapping
- `scope-investigate` — SOC alert investigation via Splunk

**Operator-invoked or orchestrator-dispatched:**
- `scope-defend` — Defensive controls generation — dispatched automatically by scope-audit after Gate 4, or invoked by operator via `/scope:defend [run-dir]`

**Enumeration subagents** (dispatched in parallel by scope-audit, model: haiku):
- `scope-enum-iam`, `scope-enum-sts`, `scope-enum-s3`, `scope-enum-kms`, `scope-enum-secrets`, `scope-enum-lambda`, `scope-enum-ec2`, `scope-enum-rds`, `scope-enum-sns`, `scope-enum-sqs`, `scope-enum-apigateway`, `scope-enum-codebuild`

**Analysis subagent** (dispatched as fresh-context by scope-audit, model: inherit):
- `scope-attack-paths` — Reads per-module JSON from disk, performs cross-service attack path analysis

**Verification agent** (read inline during execution):
- `scope-verify` — Unified verification: claim ledger, taxonomy, AWS API validation, SPL lints (domain sections dispatched by caller)

**Middleware agent** (read inline, sequential pipeline after artifacts are written):
- `scope-pipeline` — Phase 1: raw artifacts → normalized JSON in `./data/`; Phase 2: `agent-log.jsonl` → provenance envelopes in `./agent-logs/`

## System Flow

```
  Operator
    │
    ├── /scope:audit ─────────────────────────────────────────────────┐
    │                                                                  │
    │                               ┌──────────────────────────────────┤
    │                               │   scope-audit (Orchestrator)      │
    │                               │                                   │
    │                               │  Gate 1: credential check         │
    │                               │  Gate 2: batch dispatch approval  │
    │                               │                                   │
    │                               │  Parallel subagent dispatch:      │
    │                               │  ┌──────────────────────────┐    │
    │                               │  │ 12 enum subagents (haiku)│    │
    │                               │  │ iam, sts, s3, kms,       │    │
    │                               │  │ secrets, lambda, ec2,    │    │
    │                               │  │ rds, sns, sqs,           │    │
    │                               │  │ apigateway, codebuild    │    │
    │                               │  └──────────────────────────┘    │
    │                               │       │ writes $RUN_DIR/*.json    │
    │                               │       ▼                           │
    │                               │  scope-attack-paths (sonnet)      │
    │                               │  (fresh-context, reads from disk) │
    │                               │       │                           │
    │                               │  Gate 3: results                  │
    │                               │  Gate 4: scope-defend approval    │
    │                               │       │                           │
    │                               │       ▼                           │
    │                               │  scope-defend (auto-chained)      │
    │                               │  scope-verify (inline)            │
    │                               │  scope-pipeline (inline)          │
    │                               └──────────────────────────────────┘
    │
    ├── /scope:exploit ────────────►┌──────────────────────────────────┐
    │                               │  scope-exploit (standalone)       │
    │                               │                                   │
    │                               │  1. Enumerate / Analyze           │
    │                               │  2. Read scope-verify inline      │
    │                               │  3. Write artifacts               │
    │                               │  4. Read scope-pipeline inline    │
    │                               └──────────────────────────────────┘
    │
    ├── /scope:defend [run-dir] ───►┌──────────────────────────────────┐
    │   (operator-invoked after     │  scope-defend                     │
    │    audit completes)           │  Reads audit run,                 │
    │                               │  generates SCPs/RCPs,             │
    │                               │  detections, controls             │
    │                               └──────────────────────────────────┘
    │
    └── /scope:investigate ────────►┌──────────────────────────────────┐
                                    │  Standalone Agent                 │
                                    │                                   │
                                    │  1. Load context.json             │
                                    │  2. Query Splunk                  │
                                    │  3. Write artifacts               │
                                    │  4. Update context.json           │
                                    │                                   │
                                    │  (no post-processing              │
                                    │   pipeline)                       │
                                    └──────────────────────────────────┘
```

## Post-Processing Pipeline

Source agents (audit, exploit, defend) trigger this pipeline after writing artifacts. Investigate is standalone and does not run the post-processing pipeline — if the analyst saves, it writes `investigation.md` and `agent-log.jsonl` to the run directory. `./investigate/context.json` is always updated regardless of save choice.

```
  $RUN_DIR/findings.md          ./data/$PHASE/$RUN_ID.json
  $RUN_DIR/playbook.md     ┌──►  ./data/index.json
  $RUN_DIR/policies/*.json │
           │               │
           ▼               │
    ┌──────────────────┐   │
    │  scope-pipeline  │───┘
    │  Phase 1: data   │
    └──────────────────┘
           │ params: PHASE, RUN_DIR
           ▼
    ┌──────────────────┐   ./agent-logs/$PHASE/$RUN_ID.json
    │  Phase 2:        │──► ./agent-logs/index.json
    │  agent-log       │
    └──────────────────┘
           reads: $RUN_DIR/agent-log.jsonl
                  ./data/$PHASE/$RUN_ID.json

    Visualization: SCOPE dashboard (`dashboard/dashboard.html`, generated via `cd dashboard && npm run dashboard`)
                   reads dashboard/public/index.json + $RUN_ID.json
```

Failures are non-blocking — each step logs warnings but never stops the source agent.

## Verification Flow

`scope-verify` is read inline during source agent execution. The caller specifies which XML domain sections to activate:

```
  Source Agent (audit / defend / exploit / investigate)
       │
       │  inline read with domain spec
       │  e.g., audit: domain-core + domain-aws
       │         investigate: domain-core + domain-splunk
       ▼
  ┌──────────────────────────┐
  │       scope-verify       │
  │                          │
  │  <domain-core>           │
  │  • Claim ledger          │
  │  • MITRE IDs             │
  │  • Cross-agent           │
  │    consistency           │
  │  </domain-core>          │
  │                          │
  │  <domain-aws>            │
  │  • API call validation   │
  │  • IAM policy syntax     │
  │  • SCP/RCP safety        │
  │  • Attack path paths     │
  │  </domain-aws>           │
  │                          │
  │  <domain-splunk>         │
  │  • SPL semantic lints    │
  │  • Field name validation │
  │  • CloudTrail schema     │
  │  • Rerun recipes         │
  │  </domain-splunk>        │
  └──────────────────────────┘
            │ returns corrected claims
            ▼
      Source Agent continues
```

Verification results are in-memory — scope-verify returns corrections to the calling agent, not to disk.

## Cross-Agent Data Dependencies

```
                   ┌───────────────────────────────────┐
                   │           scope-audit              │
                   │  (orchestrator — dispatches        │
                   │   12 enum subagents + attack-paths) │
                   └──────────┬────────────────────────┘
                              │ writes ./audit/
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               │
  ┌───────────────┐ ┌────────────────┐        │
  │ scope-defend  │ │ scope-exploit  │        │
  │               │ │                │        │
  │reads specified│ │reads audit data│        │
  │audit run dir  │ │(optional, skip │        │
  │(auto-chained  │ │with --fresh)   │        │
  │or operator)   │ └────────────────┘        │
  └───────────────┘                           │
                                              │
  ┌───────────────────────────────────────────┘
  │
  │   scope-investigate is STANDALONE
  │   • No reads from ./audit/, ./exploit/, ./agent-logs/
  │   • Reads ./investigate/context.json (environment knowledge)
  │   • Analyst brings alert context, queries Splunk
  │   • Intentional isolation: SOC ≠ pentest
  └──────────────────────────────────────────────────
```

## Data Hierarchy

Downstream agents consume upstream output in this priority order:

```
  ┌─────────────────────────────────────────────┐
  │ 1. ./agent-logs/$PHASE/$RUN_ID.json         │  Highest fidelity
  │    Claim-level provenance, coverage,        │  WHY a claim was made
  │    policy evaluation chains                 │
  ├─────────────────────────────────────────────┤
  │ 2. ./data/$PHASE/$RUN_ID.json               │  Structured data
  │    Summaries, graphs, attack paths          │  WHAT was found
  ├─────────────────────────────────────────────┤
  │ 3. $RUN_DIR/ (raw artifacts)                │  Fallback
  │    Markdown, raw JSON                       │  Requires regex parsing
  └─────────────────────────────────────────────┘

  Fallback: if agent-logs missing → use data → if data missing → parse raw
```

## Communication Matrix

| Agent | Trigger | Reads | Writes | Calls |
|-------|---------|-------|--------|-------|
| **audit** | `/scope:audit` | AWS APIs | `$RUN_DIR/findings.md`, `results.json`, `agent-log.jsonl`, per-module JSON | dispatches 12 enum subagents + attack-paths + defend |
| **defend** | orchestrator dispatch or `/scope:defend [run-dir]` (operator) | `$AUDIT_RUN_DIR` (specified run) or `./audit/` (all runs, manual) | `$RUN_DIR/executive-summary.md`, `technical-remediation.md`, `policies/{scp,rcp}-*.json`, `results.json`, `agent-log.jsonl` | scope-verify → scope-pipeline |
| **exploit** | `/scope:exploit` | `./audit/` (optional), AWS APIs | `$RUN_DIR/playbook.md`, `results.json`, `agent-log.jsonl` | scope-verify → scope-pipeline |
| **investigate** | `/scope:investigate` | Splunk MCP, `./investigate/context.json` | `$RUN_DIR/investigation.md`, `$RUN_DIR/agent-log.jsonl` (if saved), `./investigate/context.json` | scope-verify (standalone — no post-processing pipeline) |
| **scope-verify** | Read inline by source agents | Agent claims (in-memory) | Corrected claims (in-memory) | — (domains dispatched internally by XML section) |
| **scope-pipeline** | Read inline after artifacts | `$RUN_DIR/` raw artifacts (Phase 1), `$RUN_DIR/agent-log.jsonl` + `./data/` (Phase 2) | `./data/$PHASE/$RUN_ID.json`, `./data/index.json` (Phase 1); `./agent-logs/$PHASE/$RUN_ID.json`, `./agent-logs/index.json` (Phase 2) | — |

## Enforcement Layer

Lifecycle hooks enforce safety and quality constraints at the tool level. Shared scripts live in `config/hooks/` with editor-specific configuration.

```
config/hooks/
  scope-safety-guard.sh      Block destructive AWS operations (read-only enforcement)
  scope-spl-lint.sh          Hard-fail on SPL anti-patterns (missing index, wrong fields)
  scope-schema-validate.sh   Validate results.json against phase schemas
  scope-artifact-check.sh    Verify mandatory artifacts exist before agent completes
  scope-agent-logger.sh      Auto-log AWS CLI calls to agent-log.jsonl (async)

config/schemas/
  audit.schema.json          Required fields for audit results.json
  defend.schema.json         Required fields for defend results.json
  exploit.schema.json        Required fields for exploit results.json
```

Editor-specific hook configuration:
- **Claude Code:** `.claude/settings.json` — PreToolUse / PostToolUse / Stop events
- **Gemini CLI:** `.gemini/settings.json` — BeforeTool / AfterTool / AfterAgent events
- **Codex:** No hook support — safety enforced through AGENTS.md guidance; schema compliance is self-checked
