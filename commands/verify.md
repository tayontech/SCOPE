# /scope:verify

Verification protocol — enforces claim accuracy, reproducibility, and safety across all agent output.

## Synopsis

```
/scope:verify
/scope:verify <run-dir>
```

Auto-called by other agents during execution. Can also be invoked manually to re-verify existing artifacts.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `<run-dir>` | No | Path to a run directory to re-verify (e.g., `./audit/audit-20260301-143022-all/`). If omitted, verifies the most recent run across all phases. |

## Manual Invocation

When called manually, scope-verify reads the artifacts in the given run directory and applies the full verification protocol:

1. Detect the phase from the run directory path (audit/, remediate/, exploit/, investigate/)
2. Read `agents/scope-verify-core.md` — apply claim ledger, output taxonomy, cross-agent consistency
3. Read `agents/scope-verify-aws.md` — validate AWS API calls, IAM policies, SCP/RCP safety, attack paths
4. Read `agents/scope-verify-splunk.md` — lint SPL queries, validate CloudTrail fields, check rerun recipes
5. Report findings: each claim gets `PASS`, `STRIP`, or `CONDITIONALIZE`

## Architecture

The verification system is split into three specialized agents:

| Agent | Domain | Responsibility |
|-------|--------|---------------|
| `scope-verify-core` | Cross-domain | Claim ledger, output taxonomy, MITRE ATT&CK, cross-agent consistency, correction rules |
| `scope-verify-aws` | AWS | API call validation, CloudTrail events, IAM policy syntax, SCP/RCP safety, attack path satisfiability |
| `scope-verify-splunk` | Splunk | SPL semantic lints, CloudTrail field validation, time bounds, rerun recipes |

`scope-verify-core` is the entry point. It dispatches to `scope-verify-aws` and `scope-verify-splunk` for domain-specific checks.

## What It Checks

- **Claim accuracy** — every factual claim traced to evidence (AWS API output, Splunk query result)
- **SPL semantic lints** — field existence, time bounds, no backtick macros, raw `index=cloudtrail` only
- **Attack path satisfiability** — per-step permission verification against effective access
- **Remediation safety** — SCP/RCP blast radius, exemption presence, known footgun detection

## Output

Structured verification artifacts — not prose. Each claim gets an action: `PASS`, `STRIP`, or `CONDITIONALIZE`.
