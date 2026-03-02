# SCOPE Architecture

Agent communication diagram for the 10-agent SCOPE system.

## Agent Overview

**Source agents** (slash commands — operator-triggered):
- `scope-audit` — AWS resource enumeration, attack path discovery
- `scope-remediate` — SCP/RCP generation (auto-called by audit)
- `scope-exploit` — Privilege escalation playbooks, persistence analysis, exfiltration mapping
- `scope-investigate` — SOC alert investigation via Splunk

**Verification agents** (auto-called during source agent execution):
- `scope-verify-core` — Claim ledger, taxonomy, cross-agent consistency
- `scope-verify-aws` — AWS API, IAM policy, SCP/RCP, attack path validation
- `scope-verify-splunk` — SPL semantic lints, field validation, rerun recipes

**Middleware agents** (auto-called sequential pipeline after artifacts are written):
- `scope-data` — Raw artifacts → normalized JSON in `./data/`
- `scope-evidence` — `evidence.jsonl` → provenance envelopes in `./evidence/`

## System Flow

```
  Operator
    │
    ├── /scope:audit ─────────┐  (auto-chains → remediate)
    ├── /scope:exploit ───────┤     ┌──────────────────────┐
    └── /scope:investigate ───┼────►│   Source Agent        │
                              │     │                      │
                              │     │  1. Enumerate / Analyze
                              │     │  2. Call verify-core ─┼──► Verification
                              │     │  3. Write artifacts   │    (see below)
                              │     │  4. Write evidence.jsonl
                              │     └──────────┬───────────┘
                              │                │
                              │                ▼
                              │     ┌──────────────────────┐
                              │     │  Post-Processing      │
                              │     │  Pipeline (sequential) │
                              │     │                      │
                              │     │  scope-data           │
                              │     │       │               │
                              │     │       ▼               │
                              │     │  scope-evidence       │
                              │     └──────────────────────┘
```

## Post-Processing Pipeline

Every source agent triggers this chain after writing artifacts:

```
  $RUN_DIR/findings.md          ./data/$PHASE/$RUN_ID.json
  $RUN_DIR/playbook.md     ┌──►  ./data/index.json
  $RUN_DIR/investigation.md│
  $RUN_DIR/policies/*.json │
           │               │
           ▼               │
    ┌─────────────┐        │
    │ scope-data  │────────┘
    └─────────────┘
           │ params: PHASE, RUN_DIR
           ▼
    ┌──────────────┐       ./evidence/$PHASE/$RUN_ID.json
    │scope-evidence│──────► ./evidence/index.json
    └──────────────┘
           reads: $RUN_DIR/evidence.jsonl
                  ./data/$PHASE/$RUN_ID.json

    Visualization: SCOPE dashboard at http://localhost:3000
                   reads ./data/ and results.json
```

Failures are non-blocking — each step logs warnings but never stops the source agent.

## Verification Flow

`scope-verify-core` is called inline during source agent execution and dispatches to domain verifiers:

```
  Source Agent (audit / remediate / exploit / investigate)
       │
       │  inline call
       ▼
  ┌─────────────────┐
  │ scope-verify-core│
  │                 │
  │ • Claim ledger  │
  │ • MITRE IDs     │
  │ • Cross-agent   │
  │   consistency   │
  └───────┬─────────┘
          │
     ┌────┴────┐
     │         │
     ▼         ▼
┌──────────┐ ┌───────────────┐
│verify-aws│ │verify-splunk  │
│          │ │               │
│• API calls│ │• SPL lints    │
│• IAM eval │ │• Field names  │
│• SCP/RCP  │ │• CloudTrail   │
│• Attack   │ │  schema       │
│  paths    │ │• Rerun recipes│
└──────────┘ └───────────────┘
     │              │
     └──────┬───────┘
            │ returns corrected claims
            ▼
      Source Agent continues
```

Verification results are in-memory — verifiers return corrections to the calling agent, not to disk.

## Cross-Agent Data Dependencies

```
                   ┌───────────────────────────────────┐
                   │           scope-audit              │
                   │  (independent — reads AWS only)    │
                   └──────────┬────────────────────────┘
                              │ writes ./audit/
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               │
  ┌───────────────┐ ┌────────────────┐        │
  │scope-remediate│ │ scope-exploit  │        │
  │               │ │                │        │
  │reads ALL audit│ │reads audit data│        │
  │runs from      │ │(optional, skip │        │
  │./audit/       │ │with --fresh)   │        │
  └───────────────┘ └────────────────┘        │
                                              │
  ┌───────────────────────────────────────────┘
  │
  │   scope-investigate is STANDALONE
  │   • No reads from ./audit/, ./exploit/, ./evidence/
  │   • Analyst brings alert context, queries Splunk
  │   • Intentional isolation: SOC ≠ pentest
  └──────────────────────────────────────────────────
```

## Data Hierarchy

Downstream agents consume upstream output in this priority order:

```
  ┌─────────────────────────────────────────────┐
  │ 1. ./evidence/$PHASE/$RUN_ID.json           │  Highest fidelity
  │    Claim-level provenance, coverage,        │  WHY a claim was made
  │    policy evaluation chains                 │
  ├─────────────────────────────────────────────┤
  │ 2. ./data/$PHASE/$RUN_ID.json               │  Structured data
  │    Summaries, graphs, attack paths          │  WHAT was found
  ├─────────────────────────────────────────────┤
  │ 3. $RUN_DIR/ (raw artifacts)                │  Fallback
  │    Markdown, HTML, raw JSON                 │  Requires regex parsing
  └─────────────────────────────────────────────┘

  Fallback: if evidence missing → use data → if data missing → parse raw
```

## Communication Matrix

| Agent | Trigger | Reads | Writes | Calls |
|-------|---------|-------|--------|-------|
| **audit** | `/scope:audit` | AWS APIs | `$RUN_DIR/findings.md`, `evidence.jsonl` | verify-core → data → evidence |
| **remediate** | Auto-called by audit | `$AUDIT_RUN_DIR` (current run) | `$RUN_DIR/executive-summary.md`, `technical-remediation.md`, `policies/*.json`, `evidence.jsonl` | verify-core → data → evidence |
| **exploit** | `/scope:exploit` | `./audit/` (optional), AWS APIs | `$RUN_DIR/playbook.md`, `results.json`, `evidence.jsonl` | verify-core → data → evidence |
| **investigate** | `/scope:investigate` | Splunk MCP only | `$RUN_DIR/investigation.md`, `evidence.jsonl` | verify-core → data → evidence |
| **verify-core** | Called by source agents | Agent claims (in-memory) | Corrected claims (in-memory) | verify-aws, verify-splunk |
| **verify-aws** | Called by verify-core | AWS claims (in-memory) | Validation results (in-memory) | — |
| **verify-splunk** | Called by verify-core | SPL queries (in-memory) | Validation results (in-memory) | — |
| **data** | Auto after artifacts | `$RUN_DIR/` raw artifacts | `./data/$PHASE/$RUN_ID.json`, `./data/index.json` | — |
| **evidence** | Auto after data | `$RUN_DIR/evidence.jsonl`, `./data/` | `./evidence/$PHASE/$RUN_ID.json`, `./evidence/index.json` | — |
