# SCOPE Architecture

Agent communication diagram for the SCOPE pipeline orchestration system.

## Agent Overview

**Orchestrator agent** (slash command — operator-triggered):
- `scope-audit` — AWS resource enumeration orchestrator: runs `python -m scope audit`, dispatches attack-path analysis, auto-chains defend

**Standalone agents** (slash commands — operator-triggered):
- `scope-exploit` — Privilege escalation playbooks, persistence analysis, exfiltration mapping
- `scope-hunt` — SOC alert investigation, hypothesis-driven threat hunting, and threat intel parsing (tri-mode: investigation, hunt, intel)

**Operator-invoked or orchestrator-dispatched:**
- `scope-defend` — Defensive controls generation — dispatched automatically by scope-audit after Gate 4, or invoked by operator via `/scope:defend [run-dir]`

**Enumeration runtime** (invoked by scope-audit, model: none — deterministic Python):
- `scope audit` orchestrates Python boto3 enumerators from `scope/enumerators/`
- `scope.core` owns AWS clients, coverage, envelope models, retry, and region discovery

**Attack path analysis** (fresh-context subagent dispatched by scope-audit):
- `scope.runtime.graph` — deterministic graph v2 extraction from per-module JSON (Python, no AI model)
- `scope-attack-analyze` — cross-service attack path analysis over `results.json`, `resources.jsonl`, `graph.json`, and module envelopes

**Verification agent** (read inline during execution):
- `scope-verify` — Unified verification: claim ledger, taxonomy, AWS API validation, SPL lints (domain sections dispatched by caller)

**Runtime post-processing**:
- `scope.runtime` writes `summary.json`, `resources.jsonl`, `graph.json`, and base `results.json` during audit execution

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
    │                               │  Enumeration (Python runtime):     │
    │                               │  ┌──────────────────────────┐    │
    │                               │  │ scope audit      │    │
    │                               │  │ iam, sts, s3, kms,       │    │
    │                               │  │ secrets, lambda, ec2,    │    │
    │                               │  │ rds, sns, sqs,           │    │
    │                               │  │ apigateway, codebuild,   │    │
    │                               │  │ bedrock, cognito,        │    │
    │                               │  │ dynamodb, ssm            │    │
    │                               │  └──────────────────────────┘    │
    │                               │       │ writes modules/*/*.json    │
    │                               │       ▼                           │
    │                               │  Runtime graph extraction:             │
    │                               │  ┌──────────────────────────────┐    │
    │                               │  │ scope.runtime.graph          │    │
    │                               │  │ graph v2 + evidence          │    │
    │                               │  └──────────┬───────────────────┘    │
    │                               │             ▼                         │
    │                               │  ┌──────────────────────────────┐    │
    │                               │  │ scope-attack-analyze         │    │
    │                               │  │ (cross-service paths)        │    │
    │                               │  └──────────────────────────────┘    │
    │                               │       │                           │
    │                               │  Gate 3: results                  │
    │                               │  Gate 4: scope-defend approval    │
    │                               │       │                           │
    │                               │       ▼                           │
    │                               │  scope-defend (auto-chained)      │
    │                               │  scope-synthesizer                │
    │                               │  (engagement-report.md)           │
    │                               │  scope-verify (inline)            │
    │                               │  runtime post-processing          │
    │                               └──────────────────────────────────┘
    │
    ├── /scope:exploit ────────────►┌──────────────────────────────────┐
    │                               │  scope-exploit (standalone)       │
    │                               │                                   │
    │                               │  1. Enumerate / Analyze           │
    │                               │  2. Dispatch scope-research       │
    │                               │     (real-world technique lookup) │
    │                               │  3. Read scope-verify inline      │
    │                               │  4. Write artifacts               │
    │                               │  5. Write artifacts               │
    │                               └──────────────────────────────────┘
    │
    ├── /scope:defend [run-dir] ───►┌──────────────────────────────────┐
    │   (operator-invoked after     │  scope-defend                     │
    │    audit completes)           │  Reads audit run                  │
    │                               │                                   │
    │                               │  Wave 1 (parallel):               │
    │                               │  ├─ scope-defend-guardrails       │
    │                               │  ├─ scope-defend-splunk           │
    │                               │  ├─ scope-defend-policy           │
    │                               │  └─ scope-defend-remediation      │
    │                               │       │                           │
    │                               │       ▼                           │
    │                               │  Wave 2:                          │
    │                               │  └─ scope-defend-validate         │
    │                               │     (reviews Wave 1 output)       │
    │                               │       │                           │
    │                               │       ▼                           │
    │                               │  Assembly: results.json           │
    │                               └──────────────────────────────────┘
    │
    └── /scope:hunt [input] ──►┌──────────────────────────────────┐
                                    │  scope-hunt (tri-mode)            │
                                    │                                   │
                                    │  Entry point detection:           │
                                    │  ├─ Empty / notable_id=*          │
                                    │  │    → MODE=INVESTIGATION        │
                                    │  ├─ path-like (dir exists)        │
                                    │  │    → MODE=HUNT                 │
                                    │  ├─ http(s)://                    │
                                    │  │    → MODE=INTEL, TYPE=URL      │
                                    │  ├─ NL heuristic match            │
                                    │  │    → MODE=INTEL, TYPE=NL       │
                                    │  └─ anything else                 │
                                    │       → MODE=INVESTIGATION        │
                                    │                                   │
                                    │  Hunt mode (run dir provided):    │
                                    │  1. Load context.json             │
                                    │  2. Read run directory            │
                                    │     results.json, attack paths,   │
                                    │     per-module JSON               │
                                    │  3. Generate hypotheses           │
                                    │  4. Query Splunk (optional)       │
                                    │  5. Write artifacts               │
                                    │  6. Update context.json           │
                                    │                                   │
                                    │  Investigation mode (no input):   │
                                    │  1. Load context.json             │
                                    │  2. Query Splunk                  │
                                    │  3. Write artifacts               │
                                    │  4. Update context.json           │
                                    │                                   │
                                    │  Intel mode (URL / NL input):     │
                                    │  1. Load context.json             │
                                    │  2. Fetch URL (WebFetch) or       │
                                    │     parse NL description          │
                                    │  3. Extract IOCs + TTPs           │
                                    │  4. Generate threat_intel and     │
                                    │     intel_reasoning hypotheses    │
                                    │  5. Query Splunk                  │
                                    │  6. Write artifacts               │
                                    │  7. Update context.json           │
                                    │                                   │
                                    │  (no post-processing pipeline     │
                                    │   in any mode)                    │
                                    └──────────────────────────────────┘
```

## Runtime Post-Processing

`scope audit` performs deterministic post-processing immediately after enumeration. Hunt does not run post-processing in any mode; if the analyst saves, it writes `investigation.md` and `agent-log.jsonl` to the run directory. `./hunt/context.json` is always updated regardless of save choice. In hunt mode, scope-hunt reads from an existing audit or exploit run directory but does not write back to it. In intel mode, extracted IOCs and TTPs are session-scoped and written only to `context.json`.

```
  $RUN_DIR/modules/<service>/<region>.json
           │
           ▼
    ┌──────────────────┐
    │  scope.runtime   │──► $RUN_DIR/summary.json
    │  post-processing │    $RUN_DIR/resources.jsonl
    │                  │    $RUN_DIR/graph.json
    │                  │    $RUN_DIR/results.json
    └──────────────────┘

    Visualization: SCOPE dashboard (`dashboard/<run-id>-dashboard.html`, generated via `cd dashboard && npm run dashboard`)
                   reads dashboard/public/index.json + $RUN_ID.json
```

Failures are non-blocking — each step logs warnings but never stops the source agent.

## Verification Flow

`scope-verify` is read inline during source agent execution. The caller specifies which XML domain sections to activate:

```
  Source Agent (audit / defend / exploit / hunt)
       │
       │  inline read with domain spec
       │  e.g., audit: domain-core + domain-aws
       │         hunt: domain-core + domain-splunk
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
                   │  (orchestrator — runs Python       │
                   │   runtime + attack analysis)        │
                   └──────────┬────────────────────────┘
                              │ writes ./runs/ or explicit RUN_DIR
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
  │   scope-hunt — tri-mode isolation
  │
  │   Detection investigation mode (no path argument):
  │   • No reads from ./runs/, ./exploit/, ./agent-logs/
  │   • Reads ./hunt/context.json (environment knowledge)
  │   • Analyst brings alert context, queries Splunk
  │   • Intentional isolation: SOC ≠ pentest
  │
  │   Hunt mode (audit/exploit run directory provided):
  │   • Reads $HUNT_RUN_DIR/results.json, attack-paths JSON,
  │     per-module JSON from the provided run directory
  │   • Reads ./hunt/context.json (environment knowledge)
  │   • Generates hypotheses from findings, queries Splunk
  │   • Resource identifiers are session-scoped — not written to MEMORY.md
  │
  │   Intel mode (threat intel URL or natural language input):
  │   • No reads from ./runs/, ./exploit/, ./agent-logs/
  │   • Reads ./hunt/context.json (environment knowledge)
  │   • Fetches URL (WebFetch) or parses NL description
  │   • Extracts IOCs (IPs, ARNs, hashes) and TTPs (MITRE IDs, eventNames)
  │   • Generates threat_intel hypotheses (from report) and
  │     intel_reasoning hypotheses (kill chain beyond the report)
  │   • Extracted identifiers are session-scoped — not written to MEMORY.md
  └──────────────────────────────────────────────────
```

## Data Hierarchy

Downstream agents consume upstream output in this priority order:

```
  ┌─────────────────────────────────────────────┐
  │ 1. $RUN_DIR/results.json                    │  Highest fidelity
  │    Runtime inventory plus attack paths      │  WHAT was found
  ├─────────────────────────────────────────────┤
  │ 2. $RUN_DIR/summary.json + resources.jsonl  │  Structured facts
  │    Module status, resources, errors         │  WHY scope is complete/partial
  ├─────────────────────────────────────────────┤
  │ 3. $RUN_DIR/modules/**                      │  Fallback
  │    Raw module envelopes                     │  Service-level facts
  └─────────────────────────────────────────────┘
```

## Communication Matrix

| Agent | Trigger | Reads | Writes | Calls |
|-------|---------|-------|--------|-------|
| **audit** | `/scope:audit` | AWS APIs through `scope.runtime` | `$RUN_DIR/findings.md`, `results.json`, `summary.json`, `resources.jsonl`, `graph.json`, per-module JSON | runs `python -m scope audit` + scope-attack-analyze + defend + synthesizer |
| **defend** | orchestrator dispatch or `/scope:defend [run-dir]` (operator) | `$AUDIT_RUN_DIR` (specified run) or `./runs/` (all runs, manual) | `$RUN_DIR/executive-summary.md`, `technical-remediation.md`, `policies/{scp,rcp}-*.json`, `results.json`, `agent-log.jsonl` | scope-verify |
| **exploit** | `/scope:exploit` | `./runs/` (optional), AWS APIs | `$RUN_DIR/playbook.md`, `results.json`, `agent-log.jsonl` | scope-verify |
| **hunt** | `/scope:hunt [input]` | Hunt mode: `$HUNT_RUN_DIR/results.json`, attack-paths JSON, per-module JSON, `./hunt/context.json`, Splunk MCP (optional). Investigation mode: Splunk MCP, `./hunt/context.json`. Intel mode: WebFetch (URL) or NL parse, `./hunt/context.json`, Splunk MCP (optional) | `$RUN_DIR/investigation.md`, `$RUN_DIR/agent-log.jsonl` (if saved), `./hunt/context.json` | scope-verify (no post-processing pipeline in any mode) |
| **scope-research** | Dispatched by exploit and attack-paths | WebSearch, external technique references | Research findings (in-memory, consumed by caller) | — |
| **scope-synthesizer** | Dispatched by audit after defend | `$RUN_DIR/`, defend artifacts | `$RUN_DIR/engagement-report.md` | — |
| **scope-verify** | Read inline by source agents | Agent claims (in-memory) | Corrected claims (in-memory) | — (domains dispatched internally by XML section) |

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
- **Codex:** `.codex/hooks.json` — PreToolUse / PostToolUse events
