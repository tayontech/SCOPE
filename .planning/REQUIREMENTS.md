# Requirements: SCOPE v1.14 SDK Architecture & Intelligent Agents

**Defined:** 2026-04-19
**Core Value:** Code does plumbing, LLMs do thinking — deterministic AWS SDK scripts handle enumeration, LLM agents focus on creative reasoning, research, and analysis.

## v1.14 Requirements

### SDK Enumeration (SDK)

- [x] **SDK-01**: Root `package.json` with `@aws-sdk/client-*` dependencies for all 17 enumerated services. Shared utility library at `scripts/lib/` (retry, pagination, envelope, regions, logger).
- [ ] **SDK-02**: SDK enum scripts for existing 12 services (`scripts/enum/iam.js`, `scripts/enum/s3.js`, etc.) that produce identical module envelope JSON to the current Haiku agents. Each script replicates the full enumeration logic: API calls, filtering (e.g., exclude service-linked roles), classification (trust types, risk levels), and output formatting.
- [ ] **SDK-03**: SDK enum scripts for 5 new services: Bedrock, ECS/Fargate, DynamoDB, SSM Parameter Store, Cognito. Output follows the same module envelope schema.
- [ ] **SDK-04**: IAM enum script includes staleness detection: `RoleLastUsed`, `GetAccessKeyLastUsed`, `GenerateCredentialReport`, `ListServiceLastAccessedDetails`. Findings include `last_activity` fields for all principals.
- [ ] **SDK-05**: All SDK enum scripts handle pagination automatically, retry on throttle with exponential backoff, and support regional enumeration (run per-region where applicable).

### Policy Resolution (POL)

- [ ] **POL-01**: `scripts/resolve-permissions.js` — deterministic policy resolution script that computes effective permissions for a principal by layering: attached policies (customer managed documents from IAM enum) + AWS managed policy definitions (from reference config) + SCPs/RCPs (from config) + permission boundaries (from IAM enum).
- [ ] **POL-02**: AWS managed policy definitions stored in `config/aws-managed-policies.json` — maps policy ARN to action list. Covers the most common managed policies (AdministratorAccess, PowerUserAccess, ReadOnlyAccess, service-specific policies encountered in enum).
- [ ] **POL-03**: SCPs/RCPs loaded from `config/scps/*.json` (existing convention) — operator pre-loads from org management account. Policy resolution script applies SCP deny logic against computed allows.
- [ ] **POL-04**: Attack-paths agent uses resolve-permissions output (effective actions per principal) instead of probabilistic reasoning for permission claims. Confidence labels: CONFIRMED (resolved locally) or CONDITIONAL (unresolvable — custom policy logic too complex).

### Orchestrator (ORCH)

- [ ] **ORCH-01**: `scope-audit.md` rewritten to call SDK enum scripts directly (via Bash tool: `node scripts/enum/iam.js --run-dir $RUN_DIR --region $REGION`) instead of dispatching Haiku subagents. Parallel execution preserved.
- [x] **ORCH-02**: 12 Haiku enum agent files (`agents/subagents/scope-enum-*.md`) removed after SDK scripts are verified to produce identical output.
- [ ] **ORCH-03**: `extract-graph.js` updated to consume new service data (Bedrock, ECS, DynamoDB, SSM, Cognito) — produces nodes/edges from expanded enum output.

### Intelligent Agents (AGENT)

- [ ] **AGENT-01**: Research subagent (`agents/subagents/scope-research.md`) — uses WebSearch and available MCP tools to find real-world abuse context for discovered permissions/services. Dispatchable by attack-paths, hunt, and exploit.
- [ ] **AGENT-02**: Reporting agent (`agents/scope-report.md`) — synthesizes across all phases (audit + research + exploit + hunt) into a unified engagement report with business context. Separate from scope-defend (which focuses on defensive recommendations only).
- [ ] **AGENT-03**: All new agents discover and use available MCP tools at runtime. No SCOPE-specific MCP configuration — operators configure MCPs in their platform settings.

### Testing (TEST)

- [ ] **TEST-01**: Fixture-based integration tests for each SDK enum script — known-good API response fixtures, verify output matches expected module envelope JSON.
- [ ] **TEST-02**: Regression test verifying SDK enum output is structurally identical to Haiku agent output for the same input data (validates the migration produces no downstream breakage).

## Future Requirements

### Deeper Layers (DEEP)

- **DEEP-01**: EKS enumeration agent — cluster IAM, OIDC providers, node roles (complex, own agent)
- **DEEP-02**: ECR enumeration — repository policies, image scanning, supply chain analysis
- **DEEP-03**: CloudWatch Logs investigation agent — log source for hunt/investigation alongside Splunk
- **DEEP-04**: Code review agent — Lambda/CodeBuild source analysis from attacker's perspective (needs scoping: prioritization heuristic, which functions to pull)
- **DEEP-05**: Dashboard rewrite — new data layer requires updated visualization

## Out of Scope

| Feature | Reason |
|---------|--------|
| IAM Simulator API calls | Unnecessary — effective permissions resolvable from local policy data + SCPs |
| EKS enumeration | Complex, deserves own milestone |
| ECR enumeration | Deeper container layer, after infrastructure |
| CloudWatch Logs agent | Data/event layer, future milestone |
| Code review agent | Needs scoping discussion (what to pull, prioritization) |
| Dashboard rewrite | Follows after data layer stabilizes |
| SCOPE MCP config file | Platform handles MCP registration natively |
| Hunt memory/learning pipeline | Deferred — needs multi-environment isolation design |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SDK-01 | 65 | Complete |
| SDK-02 | 67, 68, 69, 70 | Pending |
| SDK-03 | 68, 69, 70 | Pending |
| SDK-04 | 67 | Pending |
| SDK-05 | 67, 68, 69, 70 | Pending |
| POL-01 | 66 | Pending |
| POL-02 | 66 | Pending |
| POL-03 | 66 | Pending |
| POL-04 | 73 | Pending |
| ORCH-01 | 72 | Pending |
| ORCH-02 | 71 | Complete |
| ORCH-03 | 72 | Pending |
| AGENT-01 | 74 | Pending |
| AGENT-02 | 75 | Pending |
| AGENT-03 | 74, 75 | Pending |
| TEST-01 | 71 | Pending |
| TEST-02 | 71 | Pending |

**Coverage:**
- v1.14 requirements: 17 total
- Mapped to phases: 17
- Unmapped: 0

---
*Requirements defined: 2026-04-19*
*Last updated: 2026-04-19 — SIM requirements replaced with POL (local policy resolution)*
