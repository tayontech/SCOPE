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

Create files from the templates in `knowledge/` when missing. For `config/observations.md`, use `config/observations.example.md` when present.

- `config/observations.md`: concise human-readable operational notes
- `knowledge/observables.jsonl`: structured indicator or TTP patterns with resource identifiers removed or generalized
- `knowledge/baselines.json`: known-normal behavioral patterns with resource identifiers removed or generalized
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
- Do not write ARNs, account IDs, bucket names, role names, key IDs, or access key IDs. Resource identifiers are session-scoped.
- Do not write unsupported claims.
- Do not write run-specific noise unless it will help future investigations.
- Do not promote a pattern to org-wide unless at least two distinct account sections support it.
- Do not overwrite existing knowledge. Append or merge.
- Dedupe before appending.
- Every update must cite evidence: run directory, report path, query ID, event ID, finding ID, or analyst-approved note.
- Generalize resource-specific evidence before persistence. Use service names, control categories, event patterns, and behavior classes instead of exact identifiers.
- Before writing, scan candidate entries for exact identifier patterns: `arn:aws:`, 12-digit account IDs, access key IDs, key IDs, role names, user names, bucket names, and secret names. Redact or generalize the value. If the value cannot be generalized without losing meaning, skip it and report the skip reason.
- Evidence citations may point to run directories, reports, query IDs, event IDs, or finding IDs. Do not copy raw resource identifiers into the durable knowledge entry.
- Use dates in `YYYY-MM-DD` format.

## Routing Rules

Route updates by type:

- Normal automation classes, false positives, detection tuning notes -> `config/observations.md`
- Generalized IOCs, user-agent families, event-name patterns, TTPs -> `knowledge/observables.jsonl`
- Expected event volume, service-account behavior classes, approved automation patterns -> `knowledge/baselines.json`
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
