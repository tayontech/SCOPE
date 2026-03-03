# /scope:investigate

SOC alert investigation assistant. Guides analysts through CloudTrail-based alert investigation in Splunk. Learns from the environment over time — builds network baselines, principal behavior profiles, alert pattern statistics, and IOC databases across investigations.

## Synopsis

```
/scope:investigate
```

## Arguments

None. The analyst provides the alert context conversationally or pulls from the Splunk alert queue (CONNECTED mode only).

## Alert Intake

| Mode | Options |
|------|---------|
| CONNECTED | 1. Paste alert details (Modes A/B/C) — 2. Pull from Splunk alert queue (Mode D) |
| MANUAL | Paste alert details only (Modes A/B/C) |

**Mode A — Alert metadata:** alert type, user ARN, source IP, time (structured key fields)
**Mode B — Notable event ID:** `notable_id=<id>` — auto-lookups in CONNECTED, manual paste in MANUAL
**Mode C — Natural language:** free-form description, parsed and confirmed with analyst
**Mode D — Splunk alert queue:** pulls latest unacknowledged notable event (CONNECTED only)

## Examples

```
/scope:investigate
> I have a CreateAccessKey alert for user alice from IP 198.51.100.42
```

```
/scope:investigate
> 2 (pull from Splunk alert queue)
```

## Environment Context

The agent maintains `./investigate/context.json` — a persistent knowledge base that grows across investigations.

| Data | What It Tracks |
|------|---------------|
| Network | Known CIDRs, VPN ranges, external IPs with classifications |
| Principals | Service account baselines, user behavior profiles (typical IPs, actions, hours, regions) |
| Accounts | Known accounts with normal regions/services, cross-account trusts |
| Alert patterns | Per-alert-type FP/TP rates, common false positive patterns, effective investigation approaches |
| IOCs | Confirmed-malicious/suspicious IPs, user agents, ARNs |

**First run:** No context file exists — agent operates with empty knowledge base and reference patterns only.
**Subsequent runs:** Context is loaded at startup and displayed as a summary. Entities in the alert are matched against context entries and displayed in the confirmation block.

Context is updated via the post-investigation learning pipeline after each completed investigation (regardless of whether artifacts are saved).

## Operating Modes

| Mode | Description |
|------|-------------|
| CONNECTED | Splunk MCP available — queries execute directly after analyst approval. Alert queue intake available. |
| MANUAL | No MCP — displays SPL for analyst to paste into Splunk and return results. Learning still works. |

## Reasoning Framework

The agent selects investigation steps autonomously using a priority hierarchy instead of following fixed playbook sequences:

1. **IOC match** — entity matches known IOC from context
2. **Baseline deviation** — known principal acting outside baseline
3. **Novel entity** — unknown entity, establish novelty
4. **FP pattern check** — high FP-rate alert type, check known patterns first
5. **Reference pattern** — fall back to former playbook investigation angles

Each step includes a structured reasoning block citing alert context, environment knowledge, reference pattern (if any), and independent reasoning.

## Gate Flow

Each investigation step follows the same pattern:
1. Propose next step with structured reasoning block
2. Show complete SPL
3. Wait for analyst: approve / skip / pivot
4. Show results and note findings
5. Repeat

At completion:
- Analyst says "done" → summary generated (with context annotations if context was loaded)
- Analyst asked to save artifacts (Y/N)
- Post-investigation learning runs (analyst can review/correct before context write)

Artifacts are only written when the analyst opts to save. Context learning runs regardless.

## Output Artifacts

Only created when analyst chooses to save:

| Artifact | Path | Written by | Description |
|----------|------|-----------|-------------|
| Investigation summary | `$RUN_DIR/investigation.md` | scope-investigate | Narrative + event table + context annotations + queries run |
| Evidence log | `$RUN_DIR/evidence.jsonl` | scope-investigate | Structured evidence log (claims, query results, coverage) |

Always updated (regardless of save choice):

| Artifact | Path | Description |
|----------|------|-------------|
| Environment context | `./investigate/context.json` | Persistent knowledge base — updated via post-investigation learning |

Investigate does not export results.json or dashboard data — it produces a markdown determination only.

## Prerequisites

- Splunk MCP (optional — works in manual mode without it)
- An alert to investigate
