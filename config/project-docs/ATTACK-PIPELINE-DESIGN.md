# SCOPE Attack Pipeline Design

## Purpose

SCOPE needs attack paths that model real attacker progression, not lists of posture issues. The attack pipeline separates red-team path generation from deterministic fact checking so downstream controls, exploit playbooks, findings, and dashboards consume structured paths with explicit validation status.

## Pipeline

```text
scope-audit
  -> Python runtime inventory
  -> graph v2
  -> scope-attack-analyze
  -> attack contract linter
  -> scope-attack-validate
  -> attack contract linter
  -> scope-verify
  -> findings report skill
  -> scope-controls
  -> scope-synthesizer
  -> dashboard
```

`scope-audit` owns orchestration, gates, run directory state, and operator decisions. Attack subagents own narrow parts of the attack reasoning pipeline.

## Agent Boundaries

### scope-attack-analyze

`scope-attack-analyze` generates candidate attack paths. It thinks like a red teamer and expands from reachable starting positions through graph relationships, IAM capabilities, resource policies, and service-specific pivots.

It writes:

```json
{
  "candidate_attack_paths": [],
  "security_observations": []
}
```

It does not write final `attack_paths[]` except preserving an empty array from the runtime base envelope.

Responsibilities:

- Identify starting positions: public endpoints, external trusted principals, wildcard resource policies, compromised principal context, federated identity, event-driven entry points.
- Build multi-hop chains where each hop changes attacker position, principal context, capability, reachable resource, or final impact.
- Model role chaining, lateral movement, service pivots, resource-policy access, data access, decrypt paths, persistence, and privilege escalation.
- Reject trivial posture issues that do not form a chain.
- Mark runtime assumptions where control-plane data cannot prove application behavior.
- Cite graph edges, module paths, ARNs, resource IDs, and policy documents for every hop.

### scope-attack-validate

`scope-attack-validate` fact-checks candidate paths. It validates each hop in sequence and updates attacker state as the path progresses.

It writes:

```json
{
  "attack_validation": [],
  "attack_paths": []
}
```

Responsibilities:

- Verify referenced graph edges exist.
- Verify source and target resources exist in runtime artifacts.
- Evaluate IAM action/resource permissions from collected inline and customer-managed policy documents.
- Track current principal context after assume-role, execute-as, pass-role, and create-compute transitions.
- Detect collected explicit denies.
- Surface permission boundary, SCP, resource policy, and coverage caveats.
- Mark runtime-dependent hops as assumptions.
- Promote only validated or conditional paths to final `attack_paths[]`.

AWS IAM Policy Simulator does not run by default. A later opt-in mode may add live simulation for high-impact or ambiguous paths, but default validation must work from collected artifacts.

### scope-verify

`scope-verify` checks artifact integrity and claim discipline after attack validation. It does not duplicate IAM or path validation.

Responsibilities:

- Confirm final `attack_paths[]` entries reference validation records.
- Confirm rejected candidates do not appear in final attack paths.
- Confirm evidence handles resolve to actual graph edges, module files, ARNs, or resources.
- Strip or block unsupported final report claims.
- Check AWS action names, MITRE IDs, and artifact consistency.

## State Model

Each candidate path models attacker state transitions:

```json
{
  "position": "external:arn:aws:iam::999999999999:root",
  "principal_context": null,
  "capabilities": ["invoke_public_api"],
  "reachable_resources": []
}
```

Each hop transforms state:

```json
{
  "id": "cap-001-hop-002",
  "transition": "assume_role",
  "from_context": "role:AuditRole",
  "action": "sts:AssumeRole",
  "target": "role:DevOpsRole",
  "resulting_context": "role:DevOpsRole",
  "capability_gained": "DevOpsRole permissions"
}
```

The validator evaluates hops sequentially. After a successful `assume_role` hop, the next hop evaluates policies attached to the assumed role, not the original principal.

## Candidate Contract

`candidate_attack_paths[]` entries use structured hops:

```json
{
  "id": "cap-001",
  "name": "Public API invokes Lambda role with S3 read access",
  "category": "data_exposure",
  "severity": "high",
  "starting_position": {
    "type": "external|principal|resource|public_endpoint",
    "id": "gateway:apigw:api-id",
    "arn": "arn:aws:execute-api:us-east-1:123456789012:api-id/*/*/*"
  },
  "initial_context": {
    "principal": null,
    "capabilities": ["invoke_public_api"]
  },
  "hops": [
    {
      "id": "cap-001-hop-001",
      "transition": "invoke",
      "from_context": "external:*",
      "action": "execute-api:Invoke",
      "target": "compute:lambda:handler",
      "resulting_context": "compute:lambda:handler",
      "capability_gained": "Attacker can trigger Lambda execution",
      "required": true,
      "validation_type": "graph",
      "evidence": [
        {
          "type": "graph_edge",
          "id": "edge:invokes:gateway:apigw:api-id->compute:lambda:handler",
          "source_path": "modules/apigateway/us-east-1.json"
        }
      ],
      "assumptions": []
    }
  ],
  "impact": {
    "type": "admin_access|data_access|persistence|lateral_movement|exfiltration|defense_evasion",
    "resource": "arn:aws:s3:::sensitive-bucket/*",
    "action": "s3:GetObject"
  },
  "affected_resources": ["arn:aws:s3:::sensitive-bucket"],
  "detection_opportunities": ["Invoke", "GetObject"],
  "mitre_techniques": ["T1078.004"],
  "remediation": ["Restrict public API reachability or remove RoleA S3 access"]
}
```

Allowed hop `transition` values:

- `invoke`
- `execute_as`
- `assume_role`
- `pass_role`
- `create_compute`
- `mutate_policy`
- `resource_policy_access`
- `data_access`
- `decrypt`
- `event_injection`

Allowed `validation_type` values:

- `graph`
- `iam`
- `resource_policy`
- `runtime_assumption`
- `coverage_caveat`

## Validation Contract

`attack_validation[]` records the validator result for each candidate:

```json
{
  "candidate_id": "cap-001",
  "status": "validated",
  "promotion_decision": "promote",
  "reason": "Collected artifacts validate each authorization hop.",
  "validated_hops": ["cap-001-hop-001", "cap-001-hop-002"],
  "conditional_hops": [],
  "failed_hops": [],
  "untested_hops": [],
  "runtime_assumptions": [],
  "coverage_caveats": [],
  "final_context": "role:RoleA",
  "validated_impact": {
    "type": "data_access",
    "resource": "arn:aws:s3:::sensitive-bucket/*",
    "action": "s3:GetObject"
  }
}
```

Allowed validation `status` values:

- `validated`: collected artifacts support the full authorization chain.
- `conditional`: collected artifacts support the control-plane chain, but runtime behavior or missing context remains.
- `rejected`: a required hop failed.

Allowed `promotion_decision` values:

- `promote`
- `observe`
- `drop`

## Final Attack Path Contract

`attack_paths[]` contains only promoted paths:

```json
{
  "id": "ap-001",
  "source_candidate_id": "cap-001",
  "validation_status": "conditional",
  "name": "Public API can trigger Lambda role with S3 read access",
  "severity": "high",
  "category": "data_exposure",
  "description": "A public API route can invoke Lambda code running as RoleA, and RoleA can read sensitive-bucket objects.",
  "hops": [],
  "runtime_assumptions": [
    "Lambda code must read from arn:aws:s3:::sensitive-bucket/* on an attacker-reachable request path."
  ],
  "coverage_caveats": [],
  "affected_resources": ["arn:aws:s3:::sensitive-bucket"],
  "detection_opportunities": ["Invoke", "GetObject"],
  "mitre_techniques": ["T1078.004"],
  "remediation": ["Restrict public API reachability or remove RoleA S3 access"]
}
```

Allowed final `validation_status` values:

- `validated`
- `conditional`

Final attack paths do not use confidence tiers or confidence percentages.

## Promotion Rules

- Promote `validated` candidates with meaningful impact.
- Promote `conditional` candidates with meaningful impact and explicit runtime assumptions or coverage caveats.
- Drop `rejected` candidates from final `attack_paths[]`.
- Keep rejected candidates only in `attack_validation[]` diagnostics.
- Move non-chain facts into `security_observations[]`.
- Require every promoted path to reference `source_candidate_id`.
- Require every promoted path to include structured hops and evidence.

## Chain Quality Bar

A candidate is an attack path only when each hop changes attacker state:

```text
entry point -> new execution context -> new permission set -> impact
```

Accept examples:

- External principal assumes RoleA, RoleA assumes RoleB, RoleB passes RoleC to Lambda, RoleC reads Secrets Manager.
- Public API invokes Lambda, Lambda executes as RoleA, RoleA can read sensitive S3 data, Lambda code behavior remains a runtime assumption.
- CodeBuild trigger executes as BuildRole, BuildRole creates CloudFormation stack with passed role, stack creates privileged compute.

Reject examples:

- A single encrypted-disabled finding with no attacker path.
- A list of related permissions that never changes attacker context.
- A theoretical role chain where the required `sts:AssumeRole` permission is absent.
- A data access claim where the target resource does not exist in artifacts.

## Linting Gates

The hook-backed Python linter enforces field contracts between chained agents.

After `scope-attack-analyze`:

- `candidate_attack_paths[]` exists.
- Candidate IDs are unique.
- Hops are structured objects.
- Hop IDs are unique.
- Required hop fields exist.
- `attack_paths[]` stays empty.
- Evidence entries have valid types and source handles.
- Enum values match the schema.

After `scope-attack-validate`:

- `attack_validation[]` exists.
- Every validation references a known candidate ID.
- Every final attack path references a promoted validation record.
- `rejected` candidates do not appear in final `attack_paths[]`.
- Final `validation_status` is `validated` or `conditional`.
- Conditional paths include runtime assumptions or coverage caveats.
- Evidence handles still resolve.

The linter does not decide whether a path is real. It enforces structure, evidence handles, and promotion consistency.

## Downstream Rules

`scope-controls` consumes final `attack_paths[]` where `validation_status` is `validated` or `conditional`.

For validated paths, controls may generate prevention, detection, remediation, and stronger language.

For conditional paths, controls still generate detections and remediation, but they must preserve runtime assumptions and avoid claiming confirmed exploitation. Broad SCP/RCP guardrails should require a shared root cause across multiple paths or a validated authorization issue.

`scope-exploit` consumes final attack paths when an audit run exists. If no attack paths exist, it may invoke attack analysis and validation before playbook generation.

`scope-findings-report` reads final `attack_paths[]`, `attack_validation[]`, `security_observations[]`, and coverage data. It reports validation status instead of confidence.

## Skills

First-wave repo skills:

- `skills/scope-attack-path-analysis/SKILL.md`: candidate path generation, state transitions, chain quality, rejection rules.
- `skills/scope-evidence-logging/SKILL.md`: citation rules for graph edges, module files, resource ARNs, policy documents, and fact-vs-inference labeling.

Later repo skill:

- `skills/scope-findings-report/SKILL.md`: findings report structure, clean-run handling, coverage gap wording, and validation status wording.

No standalone confidence skill. No validation skill. Validation belongs to `scope-attack-validate` plus deterministic Python helpers.

## Python Components

Implementation should add Python modules under `scope/attack/`:

- `schema.py`: typed contracts or schema helpers for candidates, validation records, final paths, hops, and evidence.
- `lint.py`: stage-aware linter CLI for `--stage candidates` and `--stage validation`.
- `policy_eval.py`: offline IAM allow/deny checks for collected policy documents.
- `validate_graph.py`: graph edge and resource existence checks.
- `validate_paths.py`: stateful hop validation and promotion helpers.

The agent prompts should call these helpers rather than hand-validating every rule in prose.

## Open Implementation Notes

- The first implementation can validate a focused set of IAM transitions: `sts:AssumeRole`, `iam:PassRole`, `lambda:InvokeFunction`, `execute-api:Invoke`, `s3:GetObject`, `secretsmanager:GetSecretValue`, `kms:Decrypt`, and policy mutation actions.
- AWS-managed policy documents that the runtime did not collect create a coverage caveat unless live simulation gets added later.
- Permission boundaries and SCPs should block a path only when collected artifacts prove the deny. Missing boundary or SCP context creates a conditional caveat.
- Runtime behavior stays explicit. Inventory can validate authorization chains; it cannot prove application code returns sensitive data without code or runtime testing.
