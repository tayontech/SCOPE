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

  /scope:audit <target> [<target> ...]
                            Enumerate AWS resources and discover attack paths
                            Accepts: ARN, service name, --all, @targets.csv, or multiple services inline
                            Auto-generates defensive controls (SCPs, detections, prioritized plan)

  /scope:exploit <arn> [--fresh]
                            Generate privilege escalation playbooks
                            Tests exploitability of audit findings for a specific principal
                            --fresh forces fresh permission enumeration, ignoring existing audit data

  /scope:investigate        SOC alert investigation via Splunk
                            Timeline building, IOC correlation, detection verification

  /scope:help               Show this command reference

Examples:
  /scope:audit --all                                    Full account audit
  /scope:audit iam                                      All IAM principals
  /scope:audit arn:aws:iam::123456789012:user/alice     Specific principal
  /scope:audit @targets.csv                             Bulk targets from CSV
  /scope:exploit arn:aws:iam::123456789012:user/alice   Escalation playbook
  /scope:exploit arn:aws:iam::123456789012:user/alice --fresh  Fresh enumeration
  /scope:investigate                                    Start SOC investigation

Dashboard:
  Generate: cd dashboard && npm run dashboard
  Open dashboard/dashboard.html in any browser.
  Audit, exploit, and defend export results to the dashboard.
  Investigate is standalone — it produces markdown only (no dashboard export).

Auto-called agents (not user-invocable):
  scope-defend       Defensive controls generation — auto-called by audit
  scope-verify-*     Verification protocol — auto-called during execution
  scope-data         Data normalization middleware
  scope-evidence     Evidence provenance middleware
```
