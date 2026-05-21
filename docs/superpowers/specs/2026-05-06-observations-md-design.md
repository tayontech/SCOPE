# observations.md — Environmental Learning Implementation

**Date:** 2026-05-06
**Scope:** Define format for config/observations.md, add read/write instructions to 4 boundary agents, create example template
**Approach:** Single flat markdown file, agent-appended, gitignored

---

## Problem Statement

`config/observations.md` is designed as cross-run environmental memory — agents get smarter about an AWS environment over repeated runs. The mandate exists in `agents/shared/agent-preamble.md` (line 15) and `config/project-docs/PROJECT.md` (lines 27-39), but no agent implements reading or writing. The format is undefined, so even if agents tried, output would be inconsistent.

---

## Design

### File Format

**Location:** `config/observations.md` (gitignored, operator-local)

**Structure:**

```markdown
# SCOPE Environment Observations

## Org-Wide Patterns
<!-- Patterns observed across 2+ accounts -->
- 2026-05-06: All accounts use {service}-{env}-{purpose} role naming convention
- 2026-05-06: No accounts enforce MFA on IAM users

## Account: 123456789012
### Naming & Structure
- 2026-05-06: S3 buckets follow {org}-{region}-{purpose} pattern
### Recurring Gaps
- 2026-05-06: Lambda exec roles consistently have SecretsManager read access
### Known-Good Trusts
- 2026-05-06: Cross-account trust to 987654321098 is expected (shared services)

## Account: 987654321098
### Naming & Structure
### Recurring Gaps
### Known-Good Trusts

## Investigation Baselines
<!-- Hunt-specific: principal behavior baselines, known FP patterns -->
- 2026-05-06: Principal alice (IAMUser) — baseline: office IP 203.0.113.0/24, business hours

## Deployed Controls
<!-- Defend-specific: SCPs/detections deployed, effectiveness notes -->
- 2026-05-06: SCP block-s3-public-access deployed to account 123456789012
```

### Entry Rules

1. Each entry is one line, prefixed with ISO date (`YYYY-MM-DD`)
2. Account-specific observations go under `## Account: {12-digit ID}` with the appropriate subsection
3. If an account section doesn't exist, create it with the three subsections (Naming & Structure, Recurring Gaps, Known-Good Trusts)
4. Org-Wide patterns require the same observation in 2+ accounts before promotion
5. Never delete or overwrite existing entries — append only
6. Maximum 5 observations per agent per run (prevents bloat)
7. Observations are patterns, not findings. "Lambda roles have SecretsManager access" is an observation. "role:lambda-exec can read secret:db-password" is a finding (belongs in results.json)

### Agent Integration

**Four boundary agents read and write. Internal agents (synthesizer, domain sub-agents) do not.**

#### scope-audit.md

**Read:** At Gate 1, after credential check, before displaying module approval.

Add after the credential verification block and before region discovery:

```markdown
**Load environment observations:** Read `config/observations.md` if it exists. Note account-specific patterns and org-wide observations. Use these to contextualize findings during the run — flag when new findings match or contradict prior observations. Do not treat observations as ground truth (the environment may have changed since the last run).
```

**Write:** After the full pipeline completes (post-Gate 5, after dashboard export, before the final status report).

Add before the Return section:

```markdown
**Update environment observations:** Before finishing, append up to 5 concise observations to `config/observations.md`. Write to the `## Account: {ACCOUNT_ID}` section (create it if missing, with subsections: Naming & Structure, Recurring Gaps, Known-Good Trusts). Promote a pattern to `## Org-Wide Patterns` only if observed in 2+ accounts across runs. Prefix each entry with today's date (YYYY-MM-DD). Never delete or overwrite existing entries.

Focus on: naming conventions, role structure patterns, service usage patterns, severity trends vs prior observations, new finding categories not previously observed.
```

#### scope-exploit.md

**Read:** At Gate 1, after credential check / self-target discovery.

Add after identity discovery:

```markdown
**Load environment observations:** Read `config/observations.md` if it exists. Use account-specific patterns to contextualize discovered permissions — note when capabilities match or deviate from prior baselines. Do not treat observations as ground truth.
```

**Write:** After playbook generation, before the final return.

Add before the Return section:

```markdown
**Update environment observations:** Before finishing, append up to 5 concise observations to `config/observations.md` under the appropriate account section. Focus on: permission baselines for this principal type, novel escalation paths not in techniques.json, persistence mechanisms discovered. Prefix each entry with today's date. Never delete or overwrite existing entries.
```

#### scope-defend.md

**Read:** After intake validation, before Wave 1 subagent dispatch.

Add after the audit run directory validation:

```markdown
**Load environment observations:** Read `config/observations.md` if it exists. Use to understand: what controls are already deployed in this account, what remediation has been attempted before, detection FP rates. Avoid re-recommending controls already noted as deployed.
```

**Write:** After Wave 2 validation completes, before results assembly.

Add before the results_assembly section:

```markdown
**Update environment observations:** Before finishing, append up to 5 concise observations to `config/observations.md` under the appropriate account section and `## Deployed Controls`. Focus on: new controls deployed, remediation blockers, detection effectiveness. Prefix each entry with today's date. Never delete or overwrite existing entries.
```

#### scope-hunt.md

**Read:** During context loading, before hypothesis generation.

Add after the context loading phase:

```markdown
**Load environment observations:** Read `config/observations.md` if it exists. Use investigation baselines and account patterns to contextualize the current alert — recognize repeat actors, known-good trusts, and prior false positive patterns. Do not treat observations as ground truth.
```

**Write:** After investigation completes, at save time.

Add before the final return:

```markdown
**Update environment observations:** Before finishing, append up to 5 concise observations to `config/observations.md` under `## Investigation Baselines` and the appropriate account section. Focus on: principal behavior baselines, new IOCs, detection blind spots, false positive patterns. Prefix each entry with today's date. Never delete or overwrite existing entries.
```

### Example Template

Create `config/observations.example.md` (committed to repo) as a reference for the format:

```markdown
# SCOPE Environment Observations

## Org-Wide Patterns
<!-- Patterns observed across 2+ accounts. Promote here only after seeing in multiple accounts. -->

## Account: REPLACE_WITH_ACCOUNT_ID
### Naming & Structure
### Recurring Gaps
### Known-Good Trusts

## Investigation Baselines
<!-- Hunt-specific: principal behavior baselines, known FP patterns -->

## Deployed Controls
<!-- Defend-specific: SCPs/detections deployed, effectiveness notes -->
```

---

## Files Modified

| File | Change |
|------|--------|
| `agents/scope-audit.md` | Add read instruction after Gate 1, write instruction after Gate 5 |
| `agents/scope-exploit.md` | Add read instruction after Gate 1, write instruction after playbook |
| `agents/scope-defend.md` | Add read instruction after intake, write instruction after Wave 2 |
| `agents/scope-hunt.md` | Add read instruction during context load, write instruction at save |
| `config/observations.example.md` | New file — format template |

## Files Not Modified

| File | Reason |
|------|--------|
| `agents/shared/agent-preamble.md` | Already has the mandate (line 15) — no change needed |
| `config/project-docs/PROJECT.md` | Already defines the principle (lines 27-39) — no change needed |
| `agents/subagents/scope-attack-synthesizer.md` | Pure data transform — no environmental context needed |
| `agents/shared/attack-domain-template.md` | Domain sub-agents receive context from orchestrator, don't read directly |

## Success Criteria

1. After an audit run, `config/observations.md` exists with at least one account section and entries
2. On a second run against the same account, agents read prior observations and reference them in reasoning
3. On a run against a different account, a new account section is created without disturbing the first
4. Entries are concise (one line each), dated, and append-only
5. No agent writes more than 5 observations per run
6. File stays under 100 lines after 10 runs across 3 accounts
