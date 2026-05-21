# Target-Scoped Audit Runtime Design

## Goal

Add target-scoped audit support to the Python runtime so `scope-audit` can honestly support specific resources without falling back to broad `--all` scans.

The runtime must support:

- `--target <arn>`
- `--target-file <path>`
- ARN parsing
- resource selectors
- per-resource enumeration paths where practical
- post-filtered target output with explicit coverage notes where a service does not yet have a native per-resource path

## Current State

`scope_runtime audit` currently supports only:

```bash
uv run python -m scope_runtime audit --all
uv run python -m scope_runtime audit --services iam,s3,lambda
uv run python -m scope_runtime audit --services ec2 --regions us-east-1,us-west-2
```

The current CLI has no `--target`, `--target-file`, ARN parser, target planner, resource selector, or per-resource enumeration API. `scope-audit` should not claim resource-targeted audit support until runtime support exists.

## Target Input Contract

### Single Target

```bash
uv run python -m scope_runtime audit \
  --target arn:aws:lambda:us-east-1:123456789012:function:my-func
```

### Target File

```bash
uv run python -m scope_runtime audit --target-file targets.txt
```

`targets.txt` is newline-delimited:

```text
# comments are ignored
arn:aws:iam::123456789012:role/Admin
arn:aws:s3:::my-bucket
arn:aws:lambda:us-east-1:123456789012:function:my-func
```

Rules:

- One target per line.
- Blank lines are ignored.
- Lines beginning with `#` are ignored.
- v1 supports ARNs only.
- A non-ARN line is a hard input error before any AWS calls are made.
- Multiple targets produce one combined run directory.

## Supported Services

Target mode v1 must support every current SCOPE service:

- `apigateway`
- `bedrock`
- `codebuild`
- `cognito`
- `dynamodb`
- `ec2`
- `iam`
- `kms`
- `lambda`
- `rds`
- `s3`
- `secrets`
- `sns`
- `sqs`
- `ssm`
- `sts`

Unsupported ARN services fail before execution with a clear error. The runtime must not silently run `--all`.

## Target Scope Semantics

Target-scoped audit output includes:

1. The exact target resources requested.
2. Required context resources needed to understand the targets.
3. No unrelated inventory.

Examples of context resources:

- IAM roles attached to Lambda, EC2, Bedrock, and CodeBuild targets.
- IAM policies attached to target principals or target execution roles.
- Trust policies, OIDC providers, and identity relationships related to target principals.
- Resource policies attached to target resources.
- KMS keys referenced by target S3, Secrets Manager, RDS, DynamoDB, Lambda, or SSM resources.

Target mode should filter output down to matching target resources where possible. If the current enumerator can only list broadly, the runtime may run the minimum service/region and post-filter emitted resources. That module must record a coverage note indicating that target selection used post-filtering.

## Region Planning

Regional target:

- Run the target service only in the ARN region.
- Include global context services when relevant.

Global target:

- Run the global service path.
- Include related context services when relevant.

No-region target:

- Use service-specific rules:
  - S3 bucket ARN -> `s3/global`
  - IAM ARN -> `iam/global`
  - STS ARN -> `sts/global`
- If the service requires a region and the target lacks one, fail with a clear input error.

The runtime must not discover and scan every enabled region for target mode unless a later design explicitly introduces that behavior.

## Data Model

### TargetScope

Runtime target parsing should produce a structured object:

```python
@dataclass(frozen=True)
class TargetScope:
    raw: str
    arn: str
    partition: str
    service: str
    region: str | None
    account_id: str | None
    resource_type: str
    resource_id: str
```

Each service parser may add normalized fields internally, but the public planner contract should keep this shape stable.

### Run Scope

`manifest.json`, `summary.json`, and `results.json` should include:

```json
{
  "scope": {
    "mode": "target",
    "targets": [
      "arn:aws:lambda:us-east-1:123456789012:function:my-func"
    ]
  }
}
```

Existing service and full-account runs should use:

```json
{
  "scope": {
    "mode": "service",
    "targets": []
  }
}
```

or:

```json
{
  "scope": {
    "mode": "all",
    "targets": []
  }
}
```

### Resource Scope Metadata

Every resource emitted during target mode must include:

```json
{
  "scope_match": "target",
  "scope_source": "arn:aws:lambda:us-east-1:123456789012:function:my-func"
}
```

or:

```json
{
  "scope_match": "context",
  "scope_source": "arn:aws:lambda:us-east-1:123456789012:function:my-func"
}
```

`scope_match = "target"` means the resource directly matched a requested target. `scope_match = "context"` means the resource was included because it explains or relates to a requested target.

## Status Semantics

For target mode:

- All targets resolved -> `complete`.
- One or more targets fail in a multi-target run -> `partial`.
- All targets fail or are not found -> `error`.
- Optional context failure does not automatically make the run `partial`, but it must be represented in `coverage[]`, `errors[]`, or `coverage_gaps`.

Failure categories:

- `not_found`: target ARN parsed successfully but the resource does not exist in the selected account/region.
- `access_denied`: target lookup or required detail call was denied.
- `unsupported`: ARN parsed but service/resource shape is not supported by target mode.
- `error`: unexpected runtime or AWS API error.

## Planner Rules

The audit planner maps targets to work items:

- IAM role/user/group/policy -> `iam/global`, plus `sts/global`.
- STS caller/account/org target -> `sts/global`.
- S3 bucket -> `s3/global`, plus IAM/KMS context when discovered.
- Lambda function -> `lambda/<region>`, plus `iam/global`, plus KMS context when discovered.
- EC2 instance/security group/VPC/snapshot/load balancer -> `ec2/<region>`, plus `iam/global` for instance profile context when discovered.
- KMS key -> `kms/<region>`, plus `iam/global`.
- Secrets Manager secret -> `secrets/<region>`, plus KMS/IAM context when discovered.
- RDS instance/snapshot -> `rds/<region>`, plus KMS/IAM context when discovered.
- SNS topic -> `sns/<region>`, plus IAM context.
- SQS queue -> `sqs/<region>`, plus IAM context.
- API Gateway API -> `apigateway/<region>`, plus Lambda/IAM context when integrations are discovered.
- CodeBuild project -> `codebuild/<region>`, plus IAM context for service roles.
- Bedrock agent/model/knowledge base/guardrail -> `bedrock/<region>`, plus IAM/S3 context when referenced.
- Cognito identity pool/user pool/client -> `cognito/<region>`, plus IAM context for identity roles.
- DynamoDB table -> `dynamodb/<region>`, plus KMS/IAM context when discovered.
- SSM parameter/document/instance association -> `ssm/<region>`, plus KMS/IAM context when discovered.

Context expansion should be conservative in v1. It should include directly referenced resources only, not recursively expand into a full-account audit.

## Enumerator API

Target mode needs a selector-aware enumerator contract. The planner should pass an optional selector to each module:

```python
def run(factory: ClientFactory, region: str, selector: ResourceSelector | None = None) -> ModuleEnvelope:
    ...
```

`ResourceSelector` should include:

```python
@dataclass(frozen=True)
class ResourceSelector:
    mode: Literal["all", "target"]
    targets: tuple[TargetScope, ...]
```

Existing enumerators should continue to work when `selector is None` or `selector.mode == "all"`.

For services without native target lookup yet, the enumerator may list the minimum scope and filter resources before writing the envelope. It must record target filter method in coverage:

```json
{
  "check": "target_filter",
  "scope": "module_wide",
  "status": "complete",
  "succeeded": 1,
  "failed": 0,
  "skipped": 0,
  "reasons": [
    {
      "code": "post_filter",
      "count": 1,
      "sample_resource": "arn:aws:lambda:us-east-1:123456789012:function:my-func"
    }
  ]
}
```

## Output Layout

Target runs use the same run layout as service/all runs:

```text
audit/<account-name>-<timestamp>/
  manifest.json
  summary.json
  resources.jsonl
  graph.json
  results.json
  modules/
    iam/global.json
    sts/global.json
    lambda/us-east-1.json
```

This preserves downstream compatibility for `scope-attack-analyze`, `scope-defend`, `scope-hunt-audit`, dashboard export, and post-processing.

## Scope-Audit Impact

After runtime target support exists, `scope-audit` should support:

- `/scope:audit --all`
- `/scope:audit iam s3 lambda`
- `/scope:audit arn:aws:lambda:us-east-1:123456789012:function:my-func`
- `/scope:audit @targets.txt`

The agent should confirm target scope at Gate 2, then call the runtime. It should not parse ARN internals itself except to display a human-readable preflight summary.

## Out Of Scope

- CSV target files.
- Non-ARN target strings.
- Recursive relationship expansion beyond directly referenced context.
- Full precision per-resource API implementation for every service in the first commit.
- Dashboard redesign.
- Agent prompt rewrite beyond consuming the eventual runtime contract.

## Validation

Implementation should add tests for:

- `--target` and `--target-file` CLI parsing.
- Newline target-file parsing with comments and blank lines.
- ARN parsing for every supported SCOPE service.
- Planner work item generation for regional/global/no-region targets.
- Target scope metadata in `manifest.json`, `summary.json`, `results.json`, and resource rows.
- Target failure status semantics: partial for one failed target, error for all failed targets.
- Backward compatibility for existing `--all` and `--services` runs.
