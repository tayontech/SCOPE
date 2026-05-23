---
name: scope-knowledge-load
description: Use when a SCOPE top-level agent starts a run and needs bounded environment knowledge, prior investigation lessons, known-good baselines, observables, and coverage gaps before planning.
---

# SCOPE Knowledge Load

Use this skill at the start of top-level agents before planning, dispatching subagents, writing detections, building controls, or forming investigation hypotheses.

## Inputs

The caller provides any known selectors:

- `ACCOUNT_ID`
- `AGENT`: `scope-audit`, `scope-controls`, `scope-exploit`, or `scope-investigate`
- `ENTITY`: role, user, IP, bucket, key, account, repo, domain, or alert identifier when known
- `TOPIC`: service, TTP, threat actor, alert type, AWS action, or investigation theme when known
- `TIMEFRAME`: the investigation or run window when known

## Files To Read

Read these files when present. Missing files are normal on first use.

- `knowledge/environment.md`
- `knowledge/observables.jsonl`
- `knowledge/baselines.json`
- `knowledge/coverage-gaps.md`
- `knowledge/investigations/*.md`
- `knowledge/research/*.md`
- `config/observations.md`
- `config/index.json`
- `config/splunk-patterns.md`
- `config/hunt-techniques.json`
- `config/hunt-reference-patterns.json`

## Selection Rules

Return a bounded `KNOWLEDGE_CONTEXT` instead of dumping full files.

Prioritize entries that match:

1. Exact account ID
2. Exact entity
3. Same AWS service or log source
4. Same TTP, event name, alert type, IOC type, or threat actor
5. Recent confirmed or likely-normal baseline
6. Known coverage gaps that affect the current task

If more than 10 entries match, return the 10 most relevant. Prefer recent, evidence-backed, confirmed entries over stale or needs-review entries.

## Interpretation Rules

- Resource identifiers are session-scoped. Do not treat durable knowledge as a source of ARNs, account IDs, bucket names, role names, key IDs, or access key IDs.
- Treat knowledge as context, not ground truth.
- Cite which knowledge entries influenced decisions.
- If live evidence contradicts stored knowledge, trust live evidence and mark the stored knowledge as stale in proposed updates.
- Do not use a knowledge entry as the only evidence for a finding, attack path, detection, remediation, or exploit path.
- Do not broaden scope based only on stored knowledge. Ask the top-level agent to confirm or gather evidence.

## Output

Return this structure to the calling agent:

```text
KNOWLEDGE_CONTEXT
  files_read:
    - path
  relevant_observations:
    - id_or_source: ...
      status: confirmed|likely_normal|suspicious|false_positive|coverage_gap|needs_review
      summary: ...
      evidence: ...
  baselines:
    - entity: ...
      normal_pattern: ...
      source: ...
  observables:
    - type: user_agent_family|event_name|repo|domain|threat_actor|ttp|indicator_pattern
      value: ...
      status: confirmed|likely_normal|suspicious|false_positive|coverage_gap|needs_review
      evidence: ...
  coverage_gaps:
    - gap: ...
      affected_sources: ...
      implication: ...
  constraints:
    - ...
  stale_or_conflicting_knowledge:
    - ...
```

If no useful knowledge exists, return:

```text
KNOWLEDGE_CONTEXT
  files_read: []
  relevant_observations: []
  baselines: []
  observables: []
  coverage_gaps: []
  constraints: []
  stale_or_conflicting_knowledge: []
```
