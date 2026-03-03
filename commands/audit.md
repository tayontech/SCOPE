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
4. **Gate 4** — Analysis complete, confirm results export (skip = text-only output)

The operator can say "stop" at any gate to end the session early. A stopped run produces partial output — whatever was collected up to that point. The defend auto-chain only runs after a full (non-stopped) completion.

## Defend Auto-Chain

After the audit completes (findings, attack graph, results.json), the defend workflow runs automatically:

- **Fully autonomous** — no operator gates, no pauses
- Reads only the current audit run's findings (not all prior runs)
- Generates SCPs/RCPs, security control recommendations, SPL detections, and prioritized defensive plans
- Writes all defend artifacts to `./defend/defend-{timestamp}/`
- Runs the middleware pipeline (scope-data → scope-evidence) for defend output

The operator reviews the final combined output (audit findings + defensive plan) after both complete.

## Output Artifacts

### Audit Artifacts

| Artifact | Path | Written by | Description |
|----------|------|-----------|-------------|
| Findings report | `$AUDIT_RUN_DIR/findings.md` | scope-audit | Three-layer output: risk summary, permission details, categorized attack path narratives across 9 categories |
| Evidence log | `$AUDIT_RUN_DIR/evidence.jsonl` | scope-audit | Structured evidence log (API calls, policy evals, claims, coverage) |
| Results JSON | `$AUDIT_RUN_DIR/results.json` | scope-audit | Structured data for SCOPE dashboard — includes `summary` (with `paths_by_category`), `graph`, `attack_paths` (with `category` field), `principals`, `trust_relationships` |

### Defend Artifacts (auto-generated)

| Artifact | Path | Written by | Description |
|----------|------|-----------|-------------|
| Executive summary | `$DEFEND_RUN_DIR/executive-summary.md` | scope-defend | Leadership risk scorecard + top quick wins |
| Technical remediation | `$DEFEND_RUN_DIR/technical-remediation.md` | scope-defend | Full engineer-facing plan with SCP/RCP, controls, detections |
| SCP policies | `$DEFEND_RUN_DIR/policies/scp-*.json` | scope-defend | Deployable SCP JSON files |
| RCP policies | `$DEFEND_RUN_DIR/policies/rcp-*.json` | scope-defend | Deployable RCP JSON files |
| Evidence log | `$DEFEND_RUN_DIR/evidence.jsonl` | scope-defend | Structured evidence log (claims, coverage) |

All visualization is handled by the SCOPE dashboard at `http://localhost:3000`. No standalone HTML files are generated.

## Attack Path Categories

Audit discovers attack paths across 9 categories:

| Category | What it covers |
|----------|---------------|
| `privilege_escalation` | IAM manipulation, role chaining, PassRole abuse (50+ escalation methods + chains) |
| `trust_misconfiguration` | Wildcard trust policies, overly broad cross-account trusts, missing external ID |
| `data_exposure` | Public S3 buckets, unencrypted secrets, public EBS/RDS snapshots |
| `credential_risk` | Console users without MFA, stale access keys, unused active keys |
| `excessive_permission` | Admin-equivalent on non-admin entities, wildcard permissions, overly permissive policies |
| `network_exposure` | Internet-facing EC2 with sensitive IAM roles, broad security group ingress |
| `persistence` | 41 techniques across 8 services (IAM, STS, EC2, Lambda, S3, KMS, Secrets Manager, SSM) |
| `post_exploitation` | Data exfiltration vectors, destructive actions, resource manipulation |
| `lateral_movement` | Cross-account role chaining, SSM pivots, Lambda-to-service pivots, EC2 IMDS exploitation |

## Prerequisites

- AWS credentials configured in environment
- AWS CLI v2
