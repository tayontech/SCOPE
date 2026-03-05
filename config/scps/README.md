# config/scps/ — Pre-loaded SCP Data

Pre-load Service Control Policy data for environments where the audit caller lacks AWS Organizations API access. Without SCPs, attack path confidence drops to "SCP status unknown." Pre-loading closes this gap.

## When to Use

- **No Organizations access** — caller credentials don't have `organizations:List*`/`organizations:Describe*` permissions
- **Cross-OU visibility** — you want to include SCPs from OUs outside the caller's direct hierarchy
- **Offline / air-gapped analysis** — running audits without live AWS API access to the management account

## File Format

- One JSON file per SCP
- Files prefixed with `_` are skipped by the loader (e.g., `_example.json` is a template)
- Required fields: `PolicyId`, `PolicyDocument`
- Recommended fields: `PolicyName`, `Description`, `Targets`

### Schema

```json
{
  "PolicyId": "p-xxxx",
  "PolicyName": "Human-readable name",
  "Description": "What this SCP does",
  "PolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [...]
  },
  "Targets": [
    { "TargetId": "ou-xxxx-xxxxxxxx", "Name": "Production", "Type": "ORGANIZATIONAL_UNIT" },
    { "TargetId": "123456789012", "Name": "prod-workload", "Type": "ACCOUNT" }
  ]
}
```

## Sourcing SCPs

### From AWS CLI (management account)

```bash
# List all SCPs
aws organizations list-policies --filter SERVICE_CONTROL_POLICY --output json

# Export each SCP to a file
for id in $(aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[].Id' --output text); do
  aws organizations describe-policy --policy-id "$id" --output json | jq '.Policy.PolicySummary + {PolicyDocument: (.Policy.Content | fromjson), Targets: []}' > "config/scps/${id}.json"
  # Optionally populate Targets:
  targets=$(aws organizations list-targets-for-policy --policy-id "$id" --output json | jq '.Targets')
  jq --argjson t "$targets" '.Targets = $t' "config/scps/${id}.json" > tmp && mv tmp "config/scps/${id}.json"
done
```

### From scope-defend output

Wrap defend-generated SCP files with the required schema fields:

```bash
# defend writes SCPs to ./defend/defend-*/policies/scp-*.json
# Those are raw PolicyDocument objects — wrap them:
jq '{PolicyId: "p-custom-001", PolicyName: "defend-generated", PolicyDocument: ., Targets: []}' \
  ./defend/defend-*/policies/scp-deny-root.json > config/scps/deny-root.json
```

## Merge Behavior

When the audit runs, it unions live-enumerated SCPs with config SCPs:

- **Live succeeds:** Config SCPs are merged in. On `PolicyId` collision, the live version wins.
- **Live denied:** Config SCPs are used as the full dataset.
- **No config, no live:** Attack paths report "SCP status unknown" with reduced confidence.

Each SCP in the merged set is tagged with `_source: "live"`, `"config"`, or `"config+live"` (collision where live won) for traceability.
