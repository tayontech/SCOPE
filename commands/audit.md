# /scope:audit

Enumerate AWS resources, map permissions, and discover attack paths.

## Synopsis

```
/scope:audit <target>
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `<target>` | Yes | ARN, service name (`iam`, `s3`, `kms`, `secrets`, `sts`, `lambda`, `ec2`), `--all`, or `@targets.csv` |

## Examples

```
/scope:audit --all                                    # Full account audit
/scope:audit iam                                      # All IAM principals
/scope:audit arn:aws:iam::123456789012:user/alice     # Specific principal
/scope:audit @targets.csv                             # Bulk targets from CSV
```

## Gate Flow

1. **Gate 1** — Identity display (auto-continues, no pause)
2. **Gate 2** — Pre-module enumeration approval (per module)
3. **Gate 3** — Enumeration complete, confirm analysis
4. **Gate 4** — Analysis complete, confirm graph generation

## Remediation Auto-Chain

After the audit completes (findings, attack graph, results.json), the remediation workflow runs automatically:

- **Fully autonomous** — no operator gates, no pauses
- Reads only the current audit run's findings (not all prior runs)
- Generates SCPs/RCPs, security control recommendations, SPL detections, and prioritized remediation plans
- Writes all remediate artifacts to `./remediate/remediate-{timestamp}/`
- Runs the middleware pipeline (scope-data → scope-evidence) for remediate output

The operator reviews the final combined output (audit findings + remediation plan) after both complete.

## Output Artifacts

### Audit Artifacts

| Artifact | Path | Written by | Description |
|----------|------|-----------|-------------|
| Findings report | `$AUDIT_RUN_DIR/findings.md` | scope-audit | Three-layer output: risk summary, permission details, attack path narratives |
| Evidence log | `$AUDIT_RUN_DIR/evidence.jsonl` | scope-audit | Structured evidence log (API calls, policy evals, claims, coverage) |
| Results JSON | `$AUDIT_RUN_DIR/results.json` | scope-audit | Structured data for SCOPE dashboard (also written to dashboard/public/) |

### Remediate Artifacts (auto-generated)

| Artifact | Path | Written by | Description |
|----------|------|-----------|-------------|
| Executive summary | `$REMEDIATE_RUN_DIR/executive-summary.md` | scope-remediate | Leadership risk scorecard + top quick wins |
| Technical remediation | `$REMEDIATE_RUN_DIR/technical-remediation.md` | scope-remediate | Full engineer-facing plan with SCP/RCP, controls, detections |
| SCP policies | `$REMEDIATE_RUN_DIR/policies/scp-*.json` | scope-remediate | Deployable SCP JSON files |
| RCP policies | `$REMEDIATE_RUN_DIR/policies/rcp-*.json` | scope-remediate | Deployable RCP JSON files |
| Evidence log | `$REMEDIATE_RUN_DIR/evidence.jsonl` | scope-remediate | Structured evidence log (claims, coverage) |

All visualization is handled by the SCOPE dashboard at `http://localhost:3000`. No standalone HTML files are generated.

## Prerequisites

- AWS credentials configured in environment
- AWS CLI v2
