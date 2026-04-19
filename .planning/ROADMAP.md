# Roadmap: SCOPE v1.14 SDK Architecture & Intelligent Agents

**Milestone:** v1.14 SDK Architecture & Intelligent Agents
**Requirements:** 17 total (SDK-01–05, POL-01–04, ORCH-01–03, AGENT-01–03, TEST-01–02)
**Phases:** 65–75 (11 phases)

## Phase 65: Project Foundation — package.json & SDK Setup

**Requirements:** SDK-01
**Target files:** `package.json`, `scripts/lib/*`, `scripts/enum/`
**Dependency:** None — foundational for all SDK work
**Status:** Complete (2026-04-19)

### What changes

- **SDK-01**: Root `package.json` with 20 `@aws-sdk/client-*` packages (v3.1032.0). Shared utility library at `scripts/lib/` (retry+pagination, envelope formatter, region iterator, logger). `scripts/enum/` directory ready for enum scripts.

### Success criteria

1. `package.json` exists with all SDK packages. ✓
2. `npm install` succeeds. ✓
3. `scripts/lib/` exports 7 functions (withRetry, paginate, createEnvelope, writeEnvelope, getEnabledRegions, forEachRegion, createLogger). ✓
4. `scripts/enum/` directory exists. ✓

---

## Phase 66: Policy Resolution Script

**Requirements:** POL-01, POL-02, POL-03
**Target files:** `scripts/resolve-permissions.js` (new), `config/aws-managed-policies.json` (new)
**Dependency:** Phase 65 (needs scripts/lib/)

### What changes

- **POL-01**: Create `scripts/resolve-permissions.js` — deterministic policy resolution. Takes a principal's attached policies (from IAM enum output), applies permission boundaries, layers SCPs/RCPs, and computes effective allowed/denied actions.
- **POL-02**: Create `config/aws-managed-policies.json` — reference file mapping common AWS managed policy ARNs to their action lists.
- **POL-03**: Script loads SCPs from `config/scps/*.json` (existing convention) and applies deny logic.

### Success criteria

1. `scripts/resolve-permissions.js` exists, accepts principal policy data on stdin, outputs effective actions JSON.
2. `config/aws-managed-policies.json` exists with at least the top 20 most common AWS managed policies.
3. Script correctly resolves: managed policy allows + SCP denies = effective deny.
4. Script correctly resolves: permission boundary restricts broader policy.
5. Output distinguishes CONFIRMED (fully resolved) from CONDITIONAL (complex logic, unresolvable locally).

---

## Phase 67: SDK Enum Scripts — IAM & STS (with Staleness)

**Requirements:** SDK-02, SDK-04, SDK-05
**Target files:** `scripts/enum/iam.js`, `scripts/enum/sts.js` (new)
**Dependency:** Phase 65

### What changes

- **SDK-02**: Create `scripts/enum/iam.js` and `scripts/enum/sts.js` replicating full enumeration logic of current Haiku agents. Output is identical module envelope JSON. All filtering and classification logic preserved in code.
- **SDK-04**: IAM script includes `RoleLastUsed`, `GetAccessKeyLastUsed`, `GenerateCredentialReport`, `ListServiceLastAccessedDetails`. Findings include `last_activity` fields.
- **SDK-05**: Pagination, throttle retry, regional support.

### Success criteria

1. `scripts/enum/iam.js` produces identical module envelope structure to current enum-iam agent.
2. IAM enum includes staleness: `last_activity` on users and roles.
3. Service-linked roles excluded from identity findings.
4. Trust relationship classification preserved (same-account, cross-account, service, federated, wildcard).
5. Risk labeling preserved (critical/high/medium/low on trust policies).
6. `scripts/enum/sts.js` produces caller identity, org structure, SCPs.
7. Both scripts handle pagination and throttle retry.

---

## Phase 68: SDK Enum Scripts — Data & Secrets Services

**Requirements:** SDK-02, SDK-03, SDK-05
**Target files:** `scripts/enum/s3.js`, `scripts/enum/kms.js`, `scripts/enum/secrets.js`, `scripts/enum/rds.js`, `scripts/enum/dynamodb.js`, `scripts/enum/ssm.js` (new)
**Dependency:** Phase 65

### What changes

- **SDK-02**: S3, KMS, Secrets Manager, RDS scripts replicate existing agent logic (public access detection, encryption status, resource policies, snapshot sharing).
- **SDK-03** (partial): DynamoDB and SSM Parameter Store are new services.
- **SDK-05**: Pagination, throttle retry, regional enumeration.

### Success criteria

1. S3, KMS, Secrets, RDS scripts produce identical output to current agents.
2. DynamoDB script enumerates tables, policies, encryption, streams.
3. SSM script enumerates parameters, resource policies, encryption.
4. All scripts handle regional enumeration and pagination.

---

## Phase 69: SDK Enum Scripts — Compute & Network Services

**Requirements:** SDK-02, SDK-05
**Target files:** `scripts/enum/ec2.js`, `scripts/enum/lambda.js`, `scripts/enum/codebuild.js` (new)
**Dependency:** Phase 65
**Status:** Plan 69-01 complete (2026-04-19)

### What changes

- **SDK-02**: EC2, Lambda, CodeBuild scripts replicate existing agent logic (IMDS detection, security groups, snapshot sharing, execution roles, layers, resource policies).
- **SDK-05**: Pagination, throttle retry, regional enumeration.
- ECS/Fargate deferred to future container-layer milestone (alongside EKS, ECR).

### Success criteria

1. EC2, Lambda, CodeBuild scripts produce identical output to current agents.
2. EC2 preserves IMDS detection, security group analysis, snapshot sharing.
3. Lambda preserves execution role, layer, URL, resource policy enumeration.
4. CodeBuild preserves service role, source config, env var name detection.

---

## Phase 70: SDK Enum Scripts — Messaging, API & Identity Services

**Requirements:** SDK-02, SDK-03, SDK-05
**Target files:** `scripts/enum/sns.js`, `scripts/enum/sqs.js`, `scripts/enum/apigateway.js`, `scripts/enum/bedrock.js`, `scripts/enum/cognito.js` (new)
**Dependency:** Phase 65
**Status:** Plan 70-02 complete (2026-04-19)

### What changes

- **SDK-02**: SNS, SQS, API Gateway scripts replicate existing agent logic.
- **SDK-03** (partial): Bedrock and Cognito are new services.
- **SDK-05**: Pagination, throttle retry, regional enumeration.

### Success criteria

1. SNS, SQS, API Gateway scripts produce identical output to current agents.
2. Bedrock script enumerates model access, custom models, agents, knowledge bases, guardrails, invocation logging.
3. Cognito script enumerates identity pools (unauth access), user pools, auth/unauth role assignments.
4. All scripts handle pagination and regional enumeration.

---

## Phase 71: Migration Testing & Enum Agent Removal

**Requirements:** TEST-01, TEST-02, ORCH-02
**Target files:** `test/`, `agents/subagents/scope-enum-*.md` (removed)
**Dependency:** Phases 67, 68, 69, 70

### What changes

- **TEST-01**: Fixture-based tests for each SDK enum script.
- **TEST-02**: Regression test comparing SDK output structure to Haiku agent output.
- **ORCH-02**: Remove 12 Haiku enum agent files after tests confirm structural compatibility.

### Success criteria

1. Every SDK enum script has at least one fixture-based test.
2. Regression tests confirm structural compatibility with Haiku agent output format.
3. 12 enum agent .md files removed from `agents/subagents/`.
4. All tests pass.

---

## Phase 72: Orchestrator Rewrite

**Requirements:** ORCH-01, ORCH-03
**Target files:** `agents/scope-audit.md`, `bin/extract-graph.js`
**Dependency:** Phase 71

### What changes

- **ORCH-01**: Rewrite scope-audit.md to call SDK scripts directly via Bash tool instead of dispatching subagents. Preserve parallel execution, gate pattern, error handling.
- **ORCH-03**: Update extract-graph.js to consume new service data (Bedrock, ECS, DynamoDB, SSM, Cognito nodes).

### Success criteria

1. scope-audit.md invokes `node scripts/enum/*.js`, not subagent dispatch.
2. Parallel execution preserved.
3. extract-graph.js produces nodes from all 17 services.
4. Gate pattern unchanged.

---

## Phase 73: Policy Resolution Integration

**Requirements:** POL-04
**Target files:** `agents/subagents/scope-attack-paths.md`
**Dependency:** Phase 66 (resolve-permissions.js must exist)

### What changes

- **POL-04**: Wire resolve-permissions.js into attack-paths. After graph construction, attack-paths calls the script to get effective permissions per principal. Uses resolved permissions for confidence labels: CONFIRMED (locally verified) or CONDITIONAL (unresolvable).

### Success criteria

1. Attack-paths invokes resolve-permissions.js for principals in candidate paths.
2. Paths with CONFIRMED permissions are labeled as such in results.json.
3. Paths with unresolvable policy logic are labeled CONDITIONAL.
4. No API calls to SimulatePrincipalPolicy — all resolution is local.

---

## Phase 74: Research Subagent

**Requirements:** AGENT-01, AGENT-03
**Target files:** `agents/subagents/scope-research.md` (new)
**Dependency:** None — independent

### What changes

- **AGENT-01**: Create research subagent that uses WebSearch and available MCP tools to find real-world abuse context. Dispatchable by attack-paths, hunt, and exploit.
- **AGENT-03**: Agent discovers MCP tools at runtime, uses what's available.

### Success criteria

1. `scope-research.md` exists with clear input/output contract.
2. Agent uses WebSearch for threat intel (hackingthe.cloud, HackTricks, CVEs).
3. Agent discovers and uses available MCP tools (OpenCTI, etc.) when present.
4. Output is structured threat context consumable by parent agents.
5. Dispatchable by attack-paths, hunt, and exploit (documented in each parent).

---

## Phase 75: Reporting Agent

**Requirements:** AGENT-02, AGENT-03
**Target files:** `agents/scope-report.md` (new)
**Dependency:** None — independent

### What changes

- **AGENT-02**: Create reporting agent that synthesizes across all phases into unified engagement report.
- **AGENT-03**: Discovers and uses available MCP tools at runtime.

### Success criteria

1. `scope-report.md` exists with input/output contract.
2. Produces cross-phase engagement report (audit + research + exploit + hunt).
3. Separate from scope-defend (which focuses on defensive recommendations only).
4. Discovers and uses MCP tools when available.

---

## Dependency Order

```
Phase 65 (SDK-01: foundation) — COMPLETE
    ├── Phase 66 (POL-01, 02, 03: policy resolution script)
    │       └── Phase 73 (POL-04: attack-paths integration)
    ├── Phase 67 (SDK-02, 04, 05: IAM + STS)  ─┐
    ├── Phase 68 (SDK-02, 03, 05: data services) ├─ Phase 71 (TEST, ORCH-02: testing + removal)
    ├── Phase 69 (SDK-02, 03, 05: compute)       │       └── Phase 72 (ORCH-01, 03: orchestrator)
    └── Phase 70 (SDK-02, 03, 05: messaging)   ─┘
Phase 74 (AGENT-01, 03: research) — independent
Phase 75 (AGENT-02, 03: reporting) — independent
```

---

*Roadmap defined: 2026-04-19*
*Last updated: 2026-04-19 — SIM phases replaced with POL (local policy resolution)*
