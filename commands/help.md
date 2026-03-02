# /scope:help

Show available SCOPE commands and usage.

## Synopsis

```
/scope:help
```

## Output

Display this command reference:

```
SCOPE — Security Cloud Ops Purple Engagement

Available commands:

  /scope:audit <target>     Enumerate AWS resources and discover attack paths
                            Accepts: ARN, service name, --all, @targets.csv
                            Auto-generates remediation (SCPs, detections, prioritized plan)

  /scope:exploit <arn>      Generate privilege escalation playbooks
                            Tests exploitability of audit findings for a specific principal

  /scope:investigate        SOC alert investigation via Splunk
                            Timeline building, IOC correlation, detection verification

  /scope:help               Show this command reference

Examples:
  /scope:audit --all                                    Full account audit
  /scope:audit iam                                      All IAM principals
  /scope:audit arn:aws:iam::123456789012:user/alice     Specific principal
  /scope:audit @targets.csv                             Bulk targets from CSV
  /scope:exploit arn:aws:iam::123456789012:user/alice   Escalation playbook
  /scope:investigate                                    Start SOC investigation

Dashboard:
  The SCOPE dashboard runs at http://localhost:3000
  Start it: cd dashboard && npm run dev
  Audit results are automatically exported to the dashboard after each run.

Auto-called agents (not user-invocable):
  scope-remediate    Remediation generation — auto-called by audit
  scope-verify-*     Verification protocol — auto-called during execution
  scope-data         Data normalization middleware
  scope-evidence     Evidence provenance middleware
```
