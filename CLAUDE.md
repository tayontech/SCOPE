# SCOPE — Claude Code

Read and follow all instructions in `INSTRUCTIONS.md` in this repository root. That file contains the shared project context, architecture, slash commands, credential model, approval gates, and error handling rules.

## Agents

```
agents/scope-audit.md       AWS audit (slash command)
agents/scope-defend.md      Defensive controls generation (auto-called by scope-audit)
agents/scope-exploit.md     Privilege escalation playbooks (slash command)
agents/scope-investigate.md SOC alert investigation (slash command)
agents/scope-verify-core.md Core verification — claim ledger, taxonomy, cross-agent consistency (auto-called)
agents/scope-verify-aws.md  AWS verification — API, IAM, SCP/RCP, attack path satisfiability (auto-called)
agents/scope-verify-splunk.md Splunk verification — SPL lints, field validation, rerun recipes (auto-called)
agents/scope-data.md        Data normalization middleware (auto-called)
agents/scope-evidence.md    Evidence provenance middleware (auto-called)
```

`scope-data` normalizes raw agent artifacts into structured JSON in `./data/`. `scope-evidence` validates and indexes `evidence.jsonl` into provenance envelopes in `./evidence/`. Both run automatically as a sequential pipeline after audit, exploit, and defend runs — no operator interaction. All visualization is handled by the SCOPE dashboard at `http://localhost:3000`.
