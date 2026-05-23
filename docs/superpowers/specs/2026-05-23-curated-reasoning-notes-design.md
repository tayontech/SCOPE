# Curated Reasoning Notes Design

## Goal

Replace broad, obvious JSON catalogues with small Markdown expert-note files that improve agent reasoning without turning into checklists.

The notes should help agents reason through complex exploit paths and hunts by surfacing judgment calls, edge cases, validation pivots, false-positive traps, and visibility gaps that a capable model might miss under time pressure.

## Current Problems

`config/techniques.json` contains many basic AWS privilege escalation and post-exploitation entries. Most entries map directly from a permission to a known action. `scope-exploit` should infer those paths from IAM semantics, discovered permissions, service behavior, and optional research.

`config/hunt-reference-patterns.json` contains generic alert playbooks. Patterns such as actor timelines, IAM change pivots, and triggering-event searches belong in the investigation loop or prompt. They do not justify a separate maintained catalogue unless they add expert nuance.

`config/cloudtrail-classes.json` duplicates generic AWS knowledge and can overstate visibility. A static action catalogue can go stale, miss newer data-event sources, and push exploit output toward detection guidance. Most environments do not ingest CloudTrail data events, so visibility belongs in controls, investigation, and curated reasoning caveats rather than an exploit playbook tag table.

## Design

Create two Markdown files:

- `knowledge/exploit-reasoning-notes.md`
- `knowledge/hunt-reasoning-notes.md`

Remove or deprecate:

- `config/techniques.json`
- `config/hunt-reference-patterns.json`

Keep `config/hunt-techniques.json` for structured hunt hypothesis patterns for now. Reassess it after the first note migration, because it may also contain content that belongs in curated notes or prompt logic.

Remove `config/cloudtrail-classes.json`. Do not replace it with another static CloudTrail action catalogue.

## Agent Behavior

`scope-exploit` loads `knowledge/exploit-reasoning-notes.md` after permission discovery if the file exists. The agent treats notes as optional expert context. Missing notes should warn and continue.

`scope-investigate` loads `knowledge/hunt-reasoning-notes.md` during hypothesis testing if the file exists. The agent treats notes as optional expert context. Missing notes should warn and continue.

Agents must not treat notes as exhaustive catalogues, required checklists, or deterministic decision rules. Current environment evidence, AWS semantics, and live query results outrank notes.

`scope-exploit` must not tag playbook steps with static CloudTrail visibility labels such as `[MGT]`, `[DATA]`, or `[NONE]`. Detection and visibility analysis belongs to `scope-controls` and `scope-investigate`. Exploit may mention telemetry only through approved reasoning caveats when they affect validation confidence, not as playbook step metadata.

## Content Standard

Each note should answer these questions:

- What subtle reasoning problem does this address?
- Which preconditions decide whether it matters?
- Which evidence confirms or refutes the idea?
- Which false positive, bad assumption, or shallow conclusion should the agent avoid?
- Which CloudTrail, Splunk, or MCP visibility gap changes confidence?

Suggested Markdown shape:

```md
## PassRole Requires Execution Control

Applies to: iam:PassRole, lambda:CreateFunction, ecs:RunTask, ec2:RunInstances

Why it matters:
PassRole does not create escalation by itself. Exploitability depends on service trust, resource scope, conditions, and whether the principal can cause the trusted service to execute attacker-controlled code or configuration.

Reasoning prompts:
- Can the principal pass a role to a service that the role trusts?
- Can the principal create, update, or trigger the service resource?
- Does the role expose credentials, data, or privilege-changing APIs?

Validation pivots:
- Inspect the target role trust policy.
- Check `iam:PassedToService` and resource constraints.
- Confirm create/update/invoke permissions for the execution service.

Avoid:
- Calling every broad PassRole permission exploitable without proving execution control.
```

## Initial Note Themes

Exploit notes should focus on:

- PassRole exploitability versus execution control.
- Permission boundaries, SCPs, RCPs, session policies, and resource policies as constraints, not footnotes.
- Service-linked role and trust-policy edge cases.
- Cross-account assumptions where resource policy, trust policy, and identity policy must align.
- Data-event blind spots for post-exploitation claims.
- Bedrock and AI-service abuse paths where CloudTrail coverage, runtime invocation, and data exposure vary.
- Validation pivots that distinguish possible, conditional, and proven paths.
- Data-event uncertainty as a confidence caveat, not a static step tag.

Hunt notes should focus on:

- Identity resolution traps across assumed roles, access keys, federated identities, and service principals.
- Confirm/refute query ladders for suspicious but ambiguous behavior.
- Time-window selection traps, including delayed use of newly created credentials.
- Benign explanations for IAM, CloudTrail, S3, Lambda, and STS activity.
- Data-event absence as a visibility caveat rather than proof of no activity.
- Dashboard-worthy monitoring cases where a detection may create too much noise.
- Splunk Cloud constraints and MCP query execution assumptions.

## Verification

Implementation should include:

- Prompt contract tests proving agents load the new Markdown notes.
- Contract tests proving stale required loads for `techniques.json` and `hunt-reference-patterns.json` no longer exist.
- Config README updates documenting the new files.
- JSON validity checks only for remaining JSON files.
- Hook or lint updates only if existing checks reference removed files.
- Contract tests proving `scope-exploit` no longer loads `cloudtrail-classes.json` or emits static `[MGT]`, `[DATA]`, `[NONE]` step tags.

## Non-Goals

Do not build a large playbook database.

Do not convert notes back into structured JSON unless runtime code needs deterministic lookup.

Do not make these notes authoritative over audit evidence, exploit validation, Splunk results, or AWS documentation.

Do not block exploit or investigation workflows when note files are absent.

Do not maintain static AWS action-to-CloudTrail catalogues in config unless future runtime code needs a deterministic, source-verified contract.
