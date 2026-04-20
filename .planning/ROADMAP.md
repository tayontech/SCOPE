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

## ~~Phase 66: Policy Resolution Script~~ (CANCELLED)

**Status:** Cancelled — superseded by Phase 72 (D-18 through D-22)
**Reason:** IAM script now captures inline and customer-managed policy documents directly from GAAD. AWS managed policies resolved by name or targeted API call. Static `config/aws-managed-policies.json` dropped. Policy data is available in the IAM envelope for attack-paths to reason about directly — no separate resolution script needed.

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
**Plans:** 5/5 plans complete

### What changes

- **TEST-01**: Fixture-based tests for each SDK enum script.
- **TEST-02**: Regression test comparing SDK output structure to Haiku agent output.
- **ORCH-02**: Remove 12 Haiku enum agent files after tests confirm structural compatibility.

### Plans

- [x] 71-01-PLAN.md — Test infrastructure + refactor/test IAM and STS
- [x] 71-02-PLAN.md — Refactor/test S3, KMS, Secrets, RDS, Lambda
- [x] 71-03-PLAN.md — Refactor/test EC2, SNS, SQS, CodeBuild
- [x] 71-04-PLAN.md — Refactor/test API Gateway, Bedrock, Cognito, DynamoDB, SSM
- [x] 71-05-PLAN.md — Enum agent removal + reference cleanup

### Success criteria

1. Every SDK enum script has at least one fixture-based test.
2. Regression tests confirm structural compatibility with Haiku agent output format.
3. 12 enum agent .md files removed from `agents/subagents/`.
4. All tests pass.

---

## Phase 72: Orchestrator Rewrite

**Requirements:** ORCH-01, ORCH-03
**Target files:** `agents/scope-audit.md`, `bin/extract-graph.js`, `scripts/lib/discover-regions.js`, `scripts/enum/iam.js`, `scripts/enum/*.js`
**Dependency:** Phase 71
**Plans:** 4/4 plans complete

### What changes

- **ORCH-01**: Rewrite scope-audit.md to call SDK scripts directly via Bash tool instead of dispatching subagents. Preserve parallel execution, gate pattern, error handling. Add region discovery script, update all regional scripts for --regions flag support, add OIDC enumeration and policy document capture to IAM script.
- **ORCH-03**: Update extract-graph.js to consume new service data (Bedrock, DynamoDB, SSM, Cognito, Lambda, EC2, CodeBuild, API Gateway, SNS, SQS nodes) with cross-service edges.

### Plans

- [x] 72-01-PLAN.md — Region discovery script + --regions flag update for all regional scripts
- [x] 72-02-PLAN.md — IAM OIDC enumeration + policy document capture
- [x] 72-03-PLAN.md — scope-audit.md orchestrator rewrite
- [x] 72-04-PLAN.md — extract-graph.js 16-service expansion + test fixtures

### Success criteria

1. scope-audit.md invokes `node scripts/enum/*.js`, not subagent dispatch.
2. Parallel execution preserved.
3. extract-graph.js produces nodes from all 16 services with cross-service edges.
4. Gate pattern unchanged.

---

## ~~Phase 73: Policy Resolution Integration~~ (CANCELLED)

**Status:** Cancelled — Phase 66 (resolve-permissions.js) was dropped.
**Reason:** Policy documents are now captured directly in the IAM envelope (Phase 72, D-18/D-19/D-20). Attack-paths can reason about effective permissions from the raw policy documents in iam.json — inline policies have full Statement arrays, customer-managed policies have full documents. No separate resolution script or integration needed. Permission reasoning folded into Phase 76 (reasoning agent modernization) where attack-paths prompts are updated to use the new policy document data.

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

## Phase 76: Reasoning Agent Prompt Modernization

**Requirements:** None (maintenance — no new requirements)
**Target files:** `agents/subagents/scope-attack-paths.md`, `agents/scope-defend.md`, `agents/scope-hunt.md`, `agents/subagents/scope-hunt-*.md`
**Dependency:** Phase 72 (orchestrator rewritten, new data model)
**Plans:** 1/2 plans executed

Plans:
- [x] 76-01-PLAN.md — attack-paths modernization (16 modules, OIDC, policy docs, edge types)
- [ ] 76-02-PLAN.md — defend stale reference cleanup + hunt verification

### What changes

Update attack-paths, defend, and hunt agent prompts for the new SDK data model. Stale reference cleanup and data model alignment — not a rework of agent logic.

- **attack-paths:** Add 4 new module JSONs (16 total), OIDC as first-class attack vector with trust condition analysis, direct reasoning from policy documents in iam.json, awareness of cross-service graph edges.
- **defend:** Remove stale enum agent references, update service awareness to 16. Logic rework is a separate phase.
- **hunt + subagents:** Remove stale enum agent references. Verify hunt-audit handles 16 module JSONs.

### Success criteria

1. attack-paths lists all 16 module JSONs and reasons about OIDC trusts + policy documents.
2. No agent references Haiku enum agents, validate-enum-output.js, or subagent dispatch.
3. All agent prompts tested with `node bin/install.js` to confirm valid frontmatter and installation.

---

## Phase 77: Exploit Agent Rework

**Requirements:** None (rework — no new requirements)
**Target files:** `agents/scope-exploit.md`
**Dependency:** Phase 76 (attack-paths modernized), Phase 74 (research subagent available)

### What changes

Redesign the exploit agent as a red team operator. Rethink permission discovery for scenarios without IAM read access (probing, service-specific enumeration). Integrate research subagent for real-world technique lookup. Update to leverage policy document data from iam.json when audit data exists.

### Success criteria

1. Exploit works as standalone red team operator — doesn't require prior audit run.
2. Permission discovery handles no-IAM-read scenarios (probing, error-based inference).
3. Research subagent dispatched for technique context on discovered permissions.
4. When audit data exists, exploit uses iam.json policy documents instead of re-enumerating.

---

## Phase 78: Defend Agent Rework

**Requirements:** None (rework — no new requirements)
**Target files:** `agents/scope-defend.md` (rewritten), `agents/subagents/scope-defend-*.md` (new subagents)
**Dependency:** Phase 76 (prompts modernized)

### What changes

Redesign defend with subagent architecture producing account-specific, actionable output:

- **scope-defend-guardrails** — Systemic pattern detection across all module JSONs. SCPs/RCPs only when a gap is widespread (e.g., 8/12 EC2 instances have IMDSv1). Not individual finding reactions.
- **scope-defend-splunk** — SPL detections mapped 1:1 to attack paths from results.json. Account-specific, not generic rules.
- **scope-defend-policy** — Scoped-down replacement policies using policy documents + staleness data. Actual replacement JSON, not "consider reducing permissions."
- **scope-defend-remediation** — Prioritized remediation plan with dependency mapping. "Fix #1 eliminates findings #3, #5, #7."
- **scope-defend-validate** — Adversarial review of all generated controls. Catches SCPs that break legitimate operations, noisy SPL queries, over-scoped policy replacements.

### Success criteria

1. Five defend subagents produce independent, parallelizable output.
2. SCPs/RCPs only recommended for systemic patterns (not individual findings).
3. SPL detections tied 1:1 to specific attack paths.
4. Policy tightening uses actual policy documents and staleness data.
5. Validator catches operational impact issues before delivery.

---

## Phase 79: Splunk Integration Research

**Requirements:** None (research — no new requirements)
**Target files:** `agents/scope-hunt.md`, `agents/subagents/scope-defend-splunk.md`, `hunt/context.json`
**Dependency:** Phase 78 (defend-splunk subagent exists)

### What changes

Research and design multi-index Splunk integration for hunt and defend-splunk. Replace hardcoded `index=cloudtrail` with operator-configured data source awareness. Investigations may span multiple indexes (cloudtrail, github, okta, azure_ad, vpc_flow, guardduty).

- Ask operator what indexes/data sources are available at session start
- Route queries to correct index based on investigation type (OIDC trust → github index, federated auth → okta index)
- Session-scoped configuration (not persisted across sessions per memory rules)

### Success criteria

1. No hardcoded `index=cloudtrail` in any agent.
2. Operator asked for available indexes at session start.
3. Hunt and defend-splunk use correct index per query type.
4. Graceful fallback when an index isn't available.

---

## Phase 80: Platform Directory Structure & Install Modernization

**Requirements:** None (infrastructure — no new requirements)
**Target files:** `bin/install.js`, `.claude/`, `.gemini/`, `.codex/`
**Dependency:** Phase 76 (agent prompts finalized before re-installing)

### What changes

Research and update the platform-specific directory structures (`.claude/`, `.gemini/`, `.codex/`) and `bin/install.js` to ensure correct agent installation, hook placement, and settings configuration across all three platforms. Address missing `.gemini/` directory, stale installed agent copies, and validate against current platform documentation.

### Success criteria

1. `bin/install.js` correctly installs all agents to `.claude/agents/`, `.gemini/agents/`, `.codex/agents/`.
2. `.gemini/` directory structure created and populated.
3. All installed agent copies match source files (no stale copies).
4. Hooks installed correctly per platform conventions.
5. Platform directory structures validated against current documentation.

---

## Dependency Order

```
Phase 65 (SDK-01: foundation) — COMPLETE
    ├── ~~Phase 66~~ — CANCELLED
    │       └── ~~Phase 73~~ — CANCELLED
    ├── Phase 67 (IAM + STS)  ─┐
    ├── Phase 68 (data services) ├─ Phase 71 (testing + removal) — COMPLETE
    ├── Phase 69 (compute)       │       └── Phase 72 (orchestrator + policy docs) — COMPLETE
    └── Phase 70 (messaging)   ─┘               └── Phase 76 (attack-paths/hunt/defend cleanup)
                                                        ├── Phase 77 (exploit rework) ← also needs Phase 74
                                                        ├── Phase 78 (defend rework)
                                                        │       └── Phase 79 (Splunk integration research)
                                                        └── Phase 80 (platform directory structure)
Phase 74 (research subagent) — independent, but needed before Phase 77
Phase 75 (reporting agent) — independent, but needs Phase 74's output format
```

---

*Roadmap defined: 2026-04-19*
*Last updated: 2026-04-19 — Added Phase 80 (platform directory structure & install modernization)*
