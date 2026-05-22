---
name: scope-knowledge-update
description: Use after SCOPE evidence review, final disposition, or operator-approved save to update durable environment knowledge, observations, observables, baselines, and coverage gaps.
---

# SCOPE Knowledge Update

Use this skill after a top-level agent has evidence-backed results and the operator-approved workflow allows persistence.

Subagents may propose `knowledge_updates[]`, but only the top-level orchestrator applies updates through this skill.

## Inputs

The caller provides:

- `ACCOUNT_ID`
- `AGENT`: `scope-audit`, `scope-controls`, `scope-exploit`, or `scope-investigate`
- `RUN_DIR` or evidence file path when available
- Final disposition or outcome
- Evidence-backed candidate updates

## Files To Update

Create files from the templates in `knowledge/` when missing.

- `config/observations.md`: concise human-readable operational notes
- `knowledge/observables.jsonl`: structured entities, indicators, TTPs, and AWS actions
- `knowledge/baselines.json`: known-normal relationships, source IPs, user agents, roles, and expected behavior
- `knowledge/coverage-gaps.md`: missing indexes, fields, logs, denied AWS coverage, and blind spots
- `knowledge/investigations/INV-*.md`: saved investigation records
- `knowledge/research/R-*.md`: saved threat-intel or news research records

## Update Status Values

Every durable update must use one of:

- `confirmed`
- `likely_normal`
- `suspicious`
- `false_positive`
- `coverage_gap`
- `needs_review`

## Safety Rules

- Do not write secrets, access keys, session tokens, passwords, raw credential material, or private keys.
- Do not write unsupported claims.
- Do not write run-specific noise unless it will help future investigations.
- Do not promote a pattern to org-wide unless at least two distinct account sections support it.
- Do not overwrite existing knowledge. Append or merge.
- Dedupe before appending.
- Every update must cite evidence: run directory, report path, query ID, event ID, finding ID, or analyst-approved note.
- If an update contains an account ID, place it under that account or include the `account_id` field.
- Use dates in `YYYY-MM-DD` format.

## Routing Rules

Route updates by type:

- Normal automation, known-good role chains, false positives, detection tuning notes -> `config/observations.md`
- IOCs, principals, roles, user agents, source IPs, AWS actions, TTPs -> `knowledge/observables.jsonl`
- Known-normal AssumeRole chains, expected event volume, service-account behavior -> `knowledge/baselines.json`
- Missing indexes, missing fields, logging disabled, AWS access denied, no data-event coverage -> `knowledge/coverage-gaps.md`
- Completed investigations -> `knowledge/investigations/INV-*.md`
- Threat intel/news article research -> `knowledge/research/R-*.md`

## Required Output

After applying updates, return:

```text
KNOWLEDGE_UPDATE
  status: complete|skipped|error
  files_updated:
    - path
  entries_added: 0
  entries_merged: 0
  entries_skipped: 0
  skipped_reasons:
    - ...
  operator_review_needed:
    - ...
```

Use `skipped` when the operator did not approve persistence or no evidence-backed updates exist.
