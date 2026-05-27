---
name: scope-attack-path-analysis
description: Use when constructing SCOPE attack candidate chains from audit artifacts and rejecting facts that do not form attacker progressions.
---

# SCOPE Attack Path Analysis

Use this skill inside `scope-attack-analyze` to build `candidate_attack_paths[]`. This skill does not validate or promote final paths. Do not write final `attack_paths[]`; `scope-attack-validate` owns promotion after validation.

## Chain Quality Bar

A candidate path must satisfy this bar:

`entry point -> new execution context -> new permission set -> impact`

Each hop must change position, principal context, capability, reachable resource, permission set, execution context, or impact. A hop can represent role chaining, lateral movement between principals/resources, a policy-controlled transition, or a resource access transition, but it must move the attacker forward.

When `public_entrypoints[]` exists, treat it as the source of public-start candidates. Only records with `attack_path_seed: true` can start `starting_position.type: "public_endpoint"` candidates. Set `starting_position.id` to the exact `public_entrypoints[].id`. Keep `attack_path_seed: false` records as exposure context unless another collected graph, IAM, or resource-policy fact creates a separate attacker-controlled transition.

## Accept As Candidate Chains

- Public endpoint with AWS-level proof: a `public_entrypoints[]` seed reaches compute or a service integration, and collected AWS evidence proves a resource-policy grant, event source, identity issuance path, or concrete data transition. Do not treat backend role permissions alone as public caller access.
- Public service-connected role path: graph evidence reaches an `executes_as` role from the public entrypoint and the role can reach a concrete impact. Keep backend application behavior as a runtime assumption when the run does not prove the application calls the impact action.
- EC2 public ingress role path: graph evidence connects public security group ingress to an attached EC2 instance and instance-profile role with concrete impact. Standalone open ports remain exposure observations.
- DNS/CDN service path: Route 53 or CloudFront can participate in a candidate only when graph evidence correlates DNS/CDN targets to collected AWS resources. Unresolved DNS targets remain exposure observations.
- Assume-role then stronger action: the starting principal can assume another role, and the resulting role has a stronger action that changes the permission set or reachable resource set.
- Pass-role into compute: the principal can pass a role into a compute or execution service, creating a new execution context with that role's permissions.
- Existing CodeBuild project execution: the principal can start a collected CodeBuild project, graph evidence maps the project to a service role, and that role reaches concrete impact.
- Identity issuance: a collected identity provider such as an unauthenticated Cognito identity pool can issue AWS credentials for a role, and the role reaches concrete impact.
- Concrete data impact: a reachable role can read collected Secrets Manager, S3, DynamoDB, or SSM resource ARNs. SecureString SSM, SSE-KMS S3, and CMK-encrypted Secrets Manager reads need KMS evidence when graph edges record a key dependency.
- Resource policy external access to impact: a bucket, queue, key, secret, function, or other resource policy grants external access that leads to a concrete impact action on a target resource.
- Event-source policy access: a resource such as S3 emits an event through a service principal and the target resource policy allows that service principal with matching `SourceArn`, `SourceAccount`, or `SourceOwner` context.
- SNS/SQS event-source path: graph evidence shows a collected SNS subscription or Lambda event source mapping from the source queue/topic to the consumer.
- Wildcard-principal resource policy access: `Principal: "*"` grants the service, external, or account principal only when action, resource, and conditions match the candidate context.
- Lambda Function URL policy access: a function policy grants `lambda:InvokeFunctionUrl` and collected Function URL configuration satisfies `lambda:FunctionUrlAuthType` or `lambda:InvokedViaFunctionUrl` conditions.
- KMS-protected data access: the path reaches SSE-KMS S3 data or a CMK-encrypted secret, and KMS authorization exists through direct key-policy principal allow, account-root delegation plus identity `kms:Decrypt`, or a matching KMS grant.

Prefer chains that connect collected graph edges, IAM policy facts, trust policy facts, and module resources. Role chaining and lateral movement count when the next principal/resource context can reach capabilities the prior context could not.

## Reject As Security Observations

Reject these from `candidate_attack_paths[]` and place attack-relevant facts in `security_observations[]`:

- Single posture facts that do not show attacker progress.
- Permission lists without context change.
- Missing required hop between entry, execution context, permission set, and impact.
- Data claims without target resource/action.
- External trust relationships where the source external principal is not operator-controlled.
- Anonymous or public resource-policy access when the matching statement only allows a different source resource through `SourceArn`, `SourceAccount`, or `SourceOwner`.
- Lambda Function URL access when collected Function URL auth type contradicts the policy condition, or when invocation is the only concrete action.
- Public entrypoint records where `attack_path_seed` is false and no separate transition evidence exists.
- Public endpoint facts whose only concrete action is invocation, TCP reachability, or DNS resolution.
- Public security group ingress with no attached compute role and concrete impact.
- Public RDS endpoint or open database port with no collected credential, IAM-auth, or downstream transition evidence.
- Cognito user-pool weakness without identity-pool credential issuance, backend invocation, or resource access evidence.
- SNS/SQS consumer claims without collected subscription or event-source mapping evidence.

Examples include broad permissions with no reachable principal, public configuration with no action path, a trust policy with no assumable starting context, or data sensitivity claims that omit the resource ARN and AWS action.

## Output Rules

- Write structured `hops[]` on every `candidate_attack_paths[]` entry.
- Send non-chain facts to `security_observations[]` with `reason_not_path`.
- Model runtime-only behavior as `runtime_assumption`.
- Model missing enumeration or unknown fields as `coverage_caveat`.
- Keep customer-managed permission boundary evidence separate from identity policies. A boundary may reduce or block an otherwise allowed IAM hop.
- Keep KMS key policies and grants separate from identity policies. They represent KMS authorization evidence, not normal IAM identity policy evidence.
- Do not create, rewrite, or promote final `attack_paths[]`.
- Do not call AWS APIs.

Each hop should name `transition`, `from_context`, `action`, `target`, `resulting_context`, `capability_gained`, `validation_type`, and evidence handles. Use concrete ARNs, graph IDs, module source paths, and policy document handles from the run directory.
