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

- Public endpoint to compute role: a `public_entrypoints[]` seed reaches compute, the compute service executes as a role, and that role can perform an impact action.
- Assume-role then stronger action: the starting principal can assume another role, and the resulting role has a stronger action that changes the permission set or reachable resource set.
- Pass-role into compute: the principal can pass a role into a compute or execution service, creating a new execution context with that role's permissions.
- Resource policy external access to impact: a bucket, queue, key, secret, function, or other resource policy grants external access that leads to a concrete impact action on a target resource.

Prefer chains that connect collected graph edges, IAM policy facts, trust policy facts, and module resources. Role chaining and lateral movement count when the next principal/resource context can reach capabilities the prior context could not.

## Reject As Security Observations

Reject these from `candidate_attack_paths[]` and place attack-relevant facts in `security_observations[]`:

- Single posture facts that do not show attacker progress.
- Permission lists without context change.
- Missing required hop between entry, execution context, permission set, and impact.
- Data claims without target resource/action.
- Public entrypoint records where `attack_path_seed` is false and no separate transition evidence exists.
- Public endpoint facts whose only concrete action is invocation, TCP reachability, or DNS resolution.

Examples include broad permissions with no reachable principal, public configuration with no action path, a trust policy with no assumable starting context, or data sensitivity claims that omit the resource ARN and AWS action.

## Output Rules

- Write structured `hops[]` on every `candidate_attack_paths[]` entry.
- Send non-chain facts to `security_observations[]` with `reason_not_path`.
- Model runtime-only behavior as `runtime_assumption`.
- Model missing enumeration or unknown fields as `coverage_caveat`.
- Do not create, rewrite, or promote final `attack_paths[]`.
- Do not call AWS APIs.

Each hop should name `from_context`, `action`, `target`, `resulting_context`, `capability_gained`, `validation_type`, and evidence handles. Use concrete ARNs, graph IDs, module source paths, and policy document handles from the run directory.
