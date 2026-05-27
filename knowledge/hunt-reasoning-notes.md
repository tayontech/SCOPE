# Hunt Reasoning Notes

Purpose: curated expert context for `scope-investigate`. These notes are not a checklist, not exhaustive, and not authoritative over current environment evidence, Splunk results, or analyst-provided context.

## Resolve The Actual Actor Before Query Expansion

Applies to: assumed roles, access keys, federated users, service principals, IAM Identity Center

Why it matters:
CloudTrail often shows the session identity, not the human or workload that initiated the chain. Expanding queries from the wrong identity creates false timelines.

Reasoning prompts:
- Is `userIdentity.arn` an assumed-role session, long-term IAM principal, AWS service, or federated identity?
- Does `userIdentity.sessionContext.sessionIssuer.arn` point to the stable role?
- Does the access key ID connect the event to a different principal or session?

Validation pivots:
- Build one timeline by session ARN and one by session issuer ARN.
- Pivot through `accessKeyId`, `sourceIPAddress`, `userAgent`, and `principalId`.
- Separate service-initiated actions from direct principal actions.

Avoid:
- Treating an assumed-role session name as a stable human identity.

## Absence Of Data Events Does Not Refute Activity

Applies to: S3 object access, Lambda invoke, DynamoDB item access, SQS message reads, Bedrock runtime

Why it matters:
Many high-impact actions require CloudTrail data events or service-specific telemetry. Most environments do not ingest those sources broadly.

Reasoning prompts:
- Does the hypothesis depend on a data-plane action?
- Does the SIEM contain that data-event source for the resource?
- Are there management-plane precursors that still support or weaken the hypothesis?

Validation pivots:
- Query for event selector changes and known data-event source indexes.
- Look for precursor actions such as permission changes, role assumptions, function updates, or bucket policy changes.
- Record telemetry gaps separately from refuting evidence.

Avoid:
- Closing a hypothesis because the SIEM lacks the data source needed to observe it.

## IAM Changes Need Delayed-Use Windows

Applies to: `CreateAccessKey`, `Attach*Policy`, `Put*Policy`, `CreatePolicyVersion`, `UpdateAssumeRolePolicy`

Why it matters:
Attackers may create access or change policy and wait before using it. A narrow two-hour window can miss delayed exploitation.

Reasoning prompts:
- Does the change create durable access or only immediate execution?
- What later activity would prove the new access got used?
- Does a business workflow explain the delay?

Validation pivots:
- Search immediate, 24-hour, and 7-day windows when retention allows.
- Pivot by target principal, actor principal, access key, and changed role.
- Compare post-change services against the target's historical baseline.

Avoid:
- Marking policy changes benign only because no immediate follow-on action exists.

## Prefer Dashboard Monitoring For High-Volume Ambiguity

Applies to: enumeration bursts, common CI/CD role activity, repeated denied API calls, broad read-only access

Why it matters:
Some patterns deserve visibility but make poor alerts without environment baselines. Dashboards can show drift and concentration without creating noisy detections.

Reasoning prompts:
- Would this fire often for normal automation?
- Does the signal need threshold tuning or owner context before alerting?
- Would a dashboard reveal trend, outlier, or coverage gaps better than a detection?

Validation pivots:
- Aggregate by actor, account, service, event, and user agent.
- Compare recent activity to prior periods.
- Recommend dashboard monitoring when alert promotion lacks stable precision.

Avoid:
- Forcing every useful hunt insight into a detection rule.
