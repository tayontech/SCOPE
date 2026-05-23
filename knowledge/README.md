# SCOPE Knowledge

This directory stores durable environment knowledge used by SCOPE agents.

Knowledge is context, not ground truth. Agents must verify stored knowledge against current evidence before making findings, attack paths, controls, detections, exploit paths, or investigation dispositions.

## Files

- `environment.md`: stable operator-supplied environment context only: high-level org/accounts, identity/access model, known constraints, approved exceptions, and review cadence.
- `observations.md`: durable lessons, baselines, false positives, known-good patterns, deployed controls, automation notes, and org-wide patterns.
- `coverage-gaps.md`: telemetry gaps plus AWS audit, enumeration, and authorization gaps such as access denied, uncovered accounts/regions/services, missing permissions, no data-event coverage, or unavailable MCP/SIEM access.
- `exploit-reasoning-notes.md`: curated expert reasoning notes for exploit analysis.
- `hunt-reasoning-notes.md`: curated expert reasoning notes for investigations and hunts.

Do not store SIEM indexes, sourcetypes, retention, or data-source inventories in durable knowledge. MCP/server discovery and agent learning provide that context over time.

## Ownership

Top-level agents read knowledge through `skills/scope-knowledge-load/SKILL.md`.

Top-level agents update knowledge through `skills/scope-knowledge-update/SKILL.md` only after evidence review, final disposition, or operator-approved save.

Subagents may propose knowledge updates, but they must not write durable knowledge directly.
