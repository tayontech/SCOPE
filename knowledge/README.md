# SCOPE Knowledge

This directory stores durable environment knowledge used by SCOPE agents.

Knowledge is context, not ground truth. Agents must verify stored knowledge against current evidence before making findings, attack paths, controls, detections, exploit paths, or investigation dispositions.

## Files

- `environment.md`: SIEM, cloud, identity, account, and data-source context.
- `observables.jsonl`: structured entities and indicators observed during investigations, audits, controls, and exploit runs.
- `baselines.json`: known-normal behavior and expected relationships.
- `coverage-gaps.md`: telemetry, index, field, and AWS collection gaps.
- `investigations/`: completed investigation records.
- `research/`: threat-intel and news research records.

## Ownership

Top-level agents read knowledge through `skills/scope-knowledge-load/SKILL.md`.

Top-level agents update knowledge through `skills/scope-knowledge-update/SKILL.md` only after evidence review, final disposition, or operator-approved save.

Subagents may propose knowledge updates, but they must not write durable knowledge directly.
