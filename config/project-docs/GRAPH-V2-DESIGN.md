# Graph V2 Design

## Goal

Graph v2 gives SCOPE a deterministic, traceable relationship graph from Python inventory artifacts. `scope-attack-analyze` will consume this graph before controls design starts.

This phase updates the graph contract and moves graph extraction into the Python runtime. It does not change attack-path reasoning, controls generation, agent names, or skill packaging.

## Current Inputs

Python runtime writes these artifacts before graph extraction:

```text
runs/audit-.../
  modules/<service>/<region>.json
  summary.json
  resources.jsonl
```

`scope.runtime.post_processing.build_graph()` calls Python graph extraction code in `scope/runtime/graph.py`.

The Python graph builder writes `graph.json`. `build_results()` embeds the same graph into base `results.json`.

## Current Gaps

Current graph output comes from `bin/extract-graph.js`. It supports dashboard rendering but loses reasoning evidence:

- Nodes lack ARN, account ID, service, region, resource type, and source path.
- Edges lack stable IDs.
- Edges lack evidence pointers back to module envelopes.
- The graph has no schema version.
- Resource-policy relationships do not become graph edges.
- KMS dependency relationships do not become graph edges.
- EC2 instance profile edges can point to the profile name instead of the role name.
- Attack analysis cannot cite a specific relationship without reconstructing it from source and target fields.
- Core audit runtime shells out to Node even though Python now owns inventory, aggregation, post-processing, and `results.json`.

## Runtime Ownership

Python owns graph extraction.

New module:

```text
scope/runtime/graph.py
```

Responsibilities:

- read `modules/<service>/<region>.json`
- validate module envelopes with `ModuleEnvelope`
- extract graph v2 nodes and edges
- attach source-path evidence
- write `graph.json`
- return the graph dictionary to `scope.runtime.post_processing`

`bin/extract-graph.js` becomes obsolete. The implementation should remove the Node graph subprocess after Python parity passes. Node remains for dashboard/report generation and installer tooling.

## Graph V2 Shape

```json
{
  "schema_version": "2.0",
  "metadata": {
    "source": "scope-runtime",
    "relationship_extractors": ["iam", "lambda", "ec2", "codebuild", "apigateway", "cognito", "bedrock", "resource_policy", "kms_dependency"]
  },
  "nodes": [],
  "edges": []
}
```

The graph keeps `nodes` and `edges` as arrays for dashboard compatibility. Consumers must tolerate unknown fields.

## Node Contract

Required node fields:

```json
{
  "id": "role:AppRole",
  "label": "AppRole",
  "type": "role",
  "_source": "api"
}
```

Graph v2 adds:

```json
{
  "resource_type": "iam_role",
  "arn": "arn:aws:iam::123456789012:role/AppRole",
  "service": "iam",
  "region": "global",
  "account_id": "123456789012",
  "source_path": "modules/iam/global.json"
}
```

Node IDs keep the existing prefix model:

```text
user:<name>
role:<name>
group:<name>
svc:<principal>
external:<principal>
oidc:<url>
compute:lambda:<function-name>
compute:ec2:<instance-id>
compute:codebuild:<project-name>
gateway:apigw:<api-id>
messaging:sns:<topic-arn>
messaging:sqs:<queue-url>
ai:bedrock:<resource-id>
idp:cognito:<pool-id>
data:s3:<bucket-name>
data:kms:<key-id>
data:secrets:<secret-name>
data:rds:<db-id>
data:dynamodb:<table-name>
data:ssm:<parameter-name>
```

## Edge Contract

Required edge fields:

```json
{
  "id": "edge:executes_as:compute:lambda:api->role:AppRole",
  "source": "compute:lambda:api",
  "target": "role:AppRole",
  "edge_type": "executes_as",
  "label": "executes_as",
  "_source": "api"
}
```

Graph v2 adds:

```json
{
  "relationship": "lambda_function_executes_as_iam_role",
  "service": "lambda",
  "region": "us-east-1",
  "account_id": "123456789012",
  "evidence": [
    {
      "source_path": "modules/lambda/us-east-1.json",
      "resource_type": "lambda_function",
      "resource_id": "api",
      "arn": "arn:aws:lambda:us-east-1:123456789012:function:api",
      "field": "role"
    }
  ]
}
```

Edge IDs use deterministic string assembly:

```text
edge:<edge_type>:<source>-><target>
```

If multiple fields produce the same edge, the extractor merges them into one edge and appends evidence records.

## Relationship Types

Graph v2 keeps current `edge_type` values and adds two concrete relationship categories.

| Edge Type | Relationship Examples |
|---|---|
| `trust` | IAM role trusts same-account, cross-account, wildcard, or federated principal |
| `service` | AWS service principal can assume IAM role |
| `membership` | IAM user belongs to IAM group |
| `executes_as` | Lambda, EC2, CodeBuild, Bedrock agent, or Bedrock knowledge base uses IAM role |
| `invokes` | API Gateway invokes Lambda |
| `authenticates_to` | Cognito identity pool or OIDC provider authenticates to IAM role |
| `resource_policy_allows` | Resource policy grants principal access to S3, KMS, Secrets, Lambda, SNS, SQS, DynamoDB, or SSM resource |
| `encrypted_by` | Resource uses KMS key |

## Resource Relationship Mapping

### IAM

From `iam_role.trust_relationships[]`:

- service trust: `svc:<principal>` to `role:<role-name>`, `edge_type: "service"`
- same-account user trust: `user:<name>` to `role:<role-name>`, `edge_type: "trust"`
- same-account role trust: `role:<name>` to `role:<role-name>`, `edge_type: "trust"`
- cross-account, wildcard, and federated trust: `external:<principal>` to `role:<role-name>`, `edge_type: "trust"`

From `iam_user.groups[]`:

- `user:<name>` to `group:<name>`, `edge_type: "membership"`

From `oidc_provider.assumed_role_arns[]`:

- `oidc:<url>` to `role:<role-name>`, `edge_type: "authenticates_to"`

### Compute and AI Execution

- `lambda_function.role` creates `compute:lambda:<name>` to `role:<role-name>`.
- `codebuild_project.service_role` creates `compute:codebuild:<name>` to `role:<role-name>`.
- `bedrock_agent.execution_role_arn` creates `ai:bedrock:<agent-id>` to `role:<role-name>`.
- `bedrock_knowledge_base.role_arn` creates `ai:bedrock:<kb-id>` to `role:<role-name>`.
- `ec2_instance` creates `compute:ec2:<instance-id>` to `role:<role-name>` only when runtime inventory exposes a role ARN or role name.

If EC2 only exposes an instance profile ARN, graph v2 skips the edge and records an omission in `metadata.omissions[]`.

### Invocation

- `apigateway_*_api.lambda_integrations[]` creates `gateway:apigw:<api-id>` to `compute:lambda:<function-name>`, `edge_type: "invokes"`.

### Identity Providers

- `cognito_identity_pool.authenticated_role_arn` creates `idp:cognito:<pool-id>` to `role:<role-name>`.
- `cognito_identity_pool.unauthenticated_role_arn` creates `idp:cognito:<pool-id>` to `role:<role-name>`.

### Resource Policies

For resources with policy principals:

- source: principal node
- target: resource node
- edge type: `resource_policy_allows`

Resource types:

```text
s3_bucket.policy
kms_key.policy_principals
secrets_secret.resource_policy_principals
lambda_function.resource_policy_principals
sns_topic.resource_policy.principals
sqs_queue.resource_policy.principals
dynamodb_table.resource_policy
ssm_parameter.resource_policy
```

The extractor must parse full policy documents when present and use principal arrays when only extracted principals exist.

### KMS Dependencies

For resources with KMS key fields:

- source: resource node
- target: `data:kms:<key-id>`
- edge type: `encrypted_by`

Fields include:

```text
s3_bucket.encryption
secrets_secret.kms_key_id
rds_instance.kms_key_id
rds_snapshot.kms_key_id
dynamodb_table.kms_key_id
sns_topic.kms_key_id
sqs_queue.kms_key_id
ssm_parameter.kms_key_id
codebuild_project.encryption_key
```

## IAM Capability Edges

Graph v2 does not emit IAM action capability edges.

Capability edges require policy evaluation:

- `Action` and `NotAction`
- `Resource` and `NotResource`
- explicit deny
- permission boundaries
- SCPs
- conditions
- group policy inheritance
- absent AWS-managed policy documents

Those semantics belong in a separate capability graph phase. That phase should emit conditional edges with confidence and constraint metadata.

Example future edge:

```json
{
  "id": "cap:role:Dev->role:LambdaExec:iam:PassRole",
  "source": "role:Dev",
  "target": "role:LambdaExec",
  "edge_type": "capability",
  "action": "iam:PassRole",
  "effect": "Allow",
  "condition_state": "present",
  "confidence": "conditional",
  "constraints": {
    "iam:PassedToService": ["lambda.amazonaws.com"]
  },
  "evidence": []
}
```

## Acceptance Criteria

- `graph.json` includes `schema_version: "2.0"`.
- Every node preserves current `id`, `label`, `type`, and `_source` fields.
- Every edge preserves current `source`, `target`, `edge_type`, `label`, and `_source` fields.
- Every edge has a stable `id`.
- Every edge has at least one evidence record unless the extractor inferred the endpoint node only.
- Every graph edge endpoint has a corresponding node.
- The extractor reads `modules/<service>/<region>.json`.
- The extractor keeps legacy top-level `<service>.json` support for archived fixtures.
- EC2 instance profile edges stop using profile name as role name.
- Tests cover resource-policy and KMS dependency edges.
- Attack analysis can cite edge IDs and evidence source paths from graph v2.

## Out Of Scope

- Attack path generation changes.
- Controls generation changes.
- Top-level agent rewrites.
- Skill extraction.
- IAM policy capability graph.
- Dashboard UI redesign.
