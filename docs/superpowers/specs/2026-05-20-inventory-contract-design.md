# Inventory Contract Design

## Goal

Rework SCOPE enumeration output into a strict factual inventory contract. Enumeration scripts collect AWS resources, observed configuration, local relationships, coverage, and errors. They do not emit security judgments. Deterministic Python graph extraction builds cross-service relationships from the inventory. AI agents consume `resources + graph` to produce findings, attack paths, severity, narrative, and recommendations.

## Non-Goals

- Dashboard rewrite. The dashboard will be revisited after inventory and graph output are stable.
- Attack-path scoring in enumerators.
- Remediation advice in enumerators.
- Fetching AWS-managed IAM policy documents.
- Retiring legacy JavaScript paths in this spec. Retirement happens after the new contract is implemented and verified.

## Contract Principles

1. Enumerators emit facts only.
2. Resource inventory records use `resources`, not `findings`.
3. Enumerators may emit observed state and factual derived booleans.
4. Enumerators must not emit severity, risk labels, exploitability, remediation, or attack-path conclusions.
5. Missing data must distinguish absent, denied, skipped, unsupported, and error states when that distinction matters.
6. Relationships include evidence so agents can explain why an edge exists.
7. Graph building is deterministic Python logic, not AI inference.

## Envelope Shape

```json
{
  "module": "iam",
  "account_id": "123456789012",
  "region": "global",
  "status": "complete",
  "timestamp": "2026-05-20T00:00:00Z",
  "resources": [],
  "coverage": [],
  "errors": []
}
```

The Python contract should emit `resources`. Because the Python enumeration path is still under migration, prefer a clean contract change over a long-lived compatibility bridge. Existing consumers must be updated to read `resources`.

## Resource Base Shape

Every resource should include these fields when applicable:

```json
{
  "resource_type": "iam_role",
  "resource_id": "DeployRole",
  "arn": "arn:aws:iam::123456789012:role/DeployRole",
  "account_id": "123456789012",
  "region": "global",
  "name": "DeployRole",
  "relationships": []
}
```

Optional sections are factual and service-specific:

```json
{
  "configuration": {},
  "identity": {},
  "network": {},
  "policy": {},
  "encryption": {},
  "logging": {},
  "status": {}
}
```

Do not include nested `findings`.

## Prohibited Enumerator Fields

Enumerators must not output:

- `findings`
- `severity`
- `risk`
- `attack_path`
- exploit language such as credential theft, defense evasion, privilege escalation, or attack surface
- remediation guidance
- narrative conclusions that a state is good or bad

Factual derived fields are allowed when they are deterministic observations:

- `mfa_enabled`
- `has_console_access`
- `is_wildcard`
- `has_external_id`
- `has_mfa_condition`
- `logging_enabled`
- `public_ip`
- `imds_http_tokens`
- `is_stale`
- `stale_days`

If a field is derived, it must be based only on collected facts and must not include a risk interpretation.

## Status Semantics

Use explicit status fields where `null` would be ambiguous:

```json
{
  "resource_policy": null,
  "resource_policy_status": "access_denied"
}
```

Recommended status values:

- `present`
- `absent`
- `access_denied`
- `unsupported`
- `skipped`
- `error`
- `not_applicable`

`coverage[]` remains the module-level explanation of what checks succeeded, failed, or were skipped.

## Relationship Shape

Enumerators emit directly observed local relationships. The graph builder emits normalized graph edges. Both use the same general edge shape:

```json
{
  "type": "uses_role",
  "source_arn": "arn:aws:lambda:us-east-1:123456789012:function:fn",
  "source_type": "lambda_function",
  "target_arn": "arn:aws:iam::123456789012:role/fn-role",
  "target_type": "iam_role",
  "direction": "outbound",
  "evidence": {
    "source": "lambda.GetFunctionConfiguration",
    "field": "Role"
  },
  "conditions": {},
  "actions": [],
  "effect": null,
  "principal": null,
  "status": "observed",
  "confidence": "exact"
}
```

Required edge fields:

- `type`
- source identifier (`source_arn` preferred, `source_id` when ARN is not available)
- `source_type`
- target identifier (`target_arn` preferred, `target_id` when ARN is not available)
- `target_type`
- `evidence`
- `status`

Optional edge fields:

- `direction`
- `conditions`
- `actions`
- `effect`
- `principal`
- `confidence`

Allowed deterministic confidence values:

- `exact`
- `pattern`
- `unresolved`

## Relationship Types

Identity and IAM:

- `member_of`
- `has_attached_policy`
- `has_inline_policy`
- `trusts_principal`
- `can_assume_role`
- `can_pass_role`
- `federates_with`
- `has_permission_boundary`

Compute:

- `uses_role`
- `uses_instance_profile`
- `invokes`
- `runs_in_vpc`
- `attached_to_security_group`

Network:

- `allows_ingress_from`
- `allows_egress_to`
- `routes_to`
- `exposes_endpoint`

Data and KMS:

- `uses_kms_key`
- `has_resource_policy`
- `allows_principal`
- `replicates_to`

Messaging and eventing:

- `subscribes_to`
- `publishes_to`
- `dead_letters_to`
- `event_source_for`

Service-specific:

- `integrates_with`
- `authorizes_with`
- `backs_knowledge_base`
- `executes_with_role`

This list is extensible, but new edge types must remain factual and evidence-backed.

## Graph Builder

Add deterministic graph extraction in Python:

```text
scope_core/graph.py
scope_runtime/extract_graph.py
```

The graph builder reads:

```text
<run_dir>/modules/<module>/<region>.json
```

It writes:

```text
<run_dir>/graph.json
```

Graph output shape:

```json
{
  "account_id": "123456789012",
  "nodes": [],
  "edges": []
}
```

Responsibilities:

- load all module resources
- normalize resource identity into graph nodes
- preserve local relationships emitted by enumerators
- derive cross-service relationships from policies, trust policies, resource policies, and config references
- dedupe nodes and edges
- preserve evidence for every edge

The graph builder may derive relationships from:

- direct config references
- IAM identity policies
- IAM trust policies
- resource policies
- KMS key policies
- API integration URIs
- messaging subscriptions and DLQ configuration
- network attachment fields

The graph builder must not assign severity, risk, exploitability, or recommendations.

## IAM Contract

IAM is the reference module for the new contract.

IAM resources:

- `iam_user`
- `iam_group`
- `iam_role`
- `oidc_provider`
- optional `iam_policy` only for customer-managed policies if a standalone policy inventory is later needed

Rules:

- Exclude service-linked roles by default.
- Exclude roles named `AWSServiceRoleFor*`.
- Keep attached policies on users, groups, and roles.
- Keep inline policies on users, groups, and roles.
- Fetch inline policy documents.
- Fetch customer-managed attached policy default-version documents.
- Do not fetch AWS-managed policy documents.
- Preserve AWS-managed policy ARN/name with `document: null`.
- Preserve trust policy principals and conditions.
- Preserve OIDC provider URL, client IDs, thumbprints, and role associations.
- Remove derived `risk` from trust relationships.
- Keep factual trust booleans such as `is_wildcard`, `has_external_id`, and `has_mfa_condition`.

Example IAM role:

```json
{
  "resource_type": "iam_role",
  "resource_id": "DeployRole",
  "arn": "arn:aws:iam::123456789012:role/DeployRole",
  "account_id": "123456789012",
  "region": "global",
  "trust_relationships": [
    {
      "principal": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
      "trust_type": "federated",
      "is_wildcard": false,
      "has_external_id": false,
      "has_mfa_condition": false,
      "conditions": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:org/repo:*"
        }
      }
    }
  ],
  "attached_policies": [
    {
      "arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
      "name": "ReadOnlyAccess",
      "document": null
    }
  ],
  "inline_policies": [],
  "relationships": []
}
```

## Service Contract Notes

S3:

- Buckets, encryption, versioning, public access block, policy, ACL, logging, website config.
- Relationship examples: `uses_kms_key`, `has_resource_policy`, `allows_principal`.

EC2:

- Instances, VPCs, security groups, snapshots, load balancers.
- Relationship examples: `uses_instance_profile`, `attached_to_security_group`, `allows_ingress_from`, `allows_egress_to`.

Lambda:

- Functions, runtime, role ARN, VPC config, URL config, resource policy.
- Relationship examples: `uses_role`, `runs_in_vpc`, `uses_kms_key`.

KMS:

- Keys, aliases, rotation, grants, key policy.
- Relationship examples: `has_resource_policy`, `allows_principal`.

RDS:

- Instances, snapshots, encryption, public accessibility, subnet/security groups.
- Relationship examples: `uses_kms_key`, `attached_to_security_group`, `runs_in_vpc`.

SNS and SQS:

- Topics, queues, policies, encryption, subscriptions, DLQs.
- Relationship examples: `subscribes_to`, `publishes_to`, `dead_letters_to`, `uses_kms_key`.

API Gateway:

- APIs, stages, authorizers, integrations, resource policies.
- Relationship examples: `integrates_with`, `invokes`, `authorizes_with`.

Cognito:

- User pools, identity pools, clients, federation configuration.
- Relationship examples: `federates_with`, `authorizes_with`.

Bedrock:

- Foundation models available, agents, knowledge bases, guardrails, logging configuration.
- Relationship examples: `executes_with_role`, `backs_knowledge_base`.

DynamoDB:

- Tables, encryption, PITR, streams, resource policies.
- Relationship examples: `uses_kms_key`, `has_resource_policy`, `event_source_for`.

SSM, Secrets Manager, CodeBuild:

- Parameters, secrets, projects, roles, encryption, resource policies where supported.
- Relationship examples: `uses_kms_key`, `uses_role`, `has_resource_policy`.

## Consumer Changes

Agents should consume:

```text
resources + graph + coverage + errors
```

Agents own:

- security findings
- attack path selection
- severity
- exploitability
- remediation
- narrative reporting

Data-normalization agents should be retired or rewritten as validators/consumers after the Python inventory and graph layers are stable.

## Verification

Implementation must include:

- model/schema tests proving `resources` is required and `findings` is not emitted
- per-enumerator tests proving no nested `findings`, `severity`, or `risk`
- IAM tests for service-linked role exclusion
- IAM tests for AWS-managed policy document retention as `null`
- IAM tests for customer-managed and inline policy documents
- IAM tests for OIDC trust conditions
- graph builder tests for representative local and cross-service relationships
- real AWS smoke run in one region
- real AWS all-enabled-region run

