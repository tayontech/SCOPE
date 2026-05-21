# Python Enumerator Rewrite Design

**Date:** 2026-05-18
**Status:** Draft for review
**Scope:** Clean-start architecture for replacing the JavaScript enumeration layer with Python while preserving the existing SCOPE audit pipeline contract.

---

## Goal

Move SCOPE's AWS enumeration and supporting script logic from JavaScript to Python in a way that improves correctness, security-tooling fit, testability, and long-term maintainability without breaking the existing dashboard, agents, or JSON contract.

The rewrite is contract-first: Python enumerators must initially produce module envelopes compatible with the current JavaScript outputs. Richer coverage and error fields can then be layered in through the module envelope coverage design.

---

## Repository Layout

```text
enumerators/
  __init__.py
  s3.py
  iam.py
  sts.py
  ...

scope_core/
  __init__.py
  aws.py
  base_enum.py
  contract.py
  coverage.py
  envelope.py
  logger.py
  models.py
  parallel.py
  policy_parser.py
  regions.py
  retry.py

scope_runtime/
  __init__.py
  __main__.py
  audit.py
  extract_graph.py
  generate_report.py
  install.py

tools/
  parity_diff.py
  regen_schemas.py
  smoke_run.py
  regen_fixtures.py

tests/
  enumerators/
  scope_core/
  fixtures/

config/
dashboard/
agents/
docs/
pyproject.toml
uv.lock
```

### Boundary Decisions

- `enumerators/` contains one Python module per AWS service or service domain. It replaces `scripts/enum/*.js`.
- `scope_core/` contains shared runtime libraries. It replaces `scripts/lib/*.js`.
- `scope_runtime/` contains product runtime commands. Pipeline steps such as audit orchestration, graph extraction, report generation, and install belong here rather than in a generic tools directory.
- `tools/` is reserved for maintainer-only utilities such as smoke runners, fixture regeneration, and migration helpers.
- `config/schemas/*.json` remains JSON and continues to be the external contract for hooks, agents, dashboard consumers, and non-Python tooling.
- `config/hooks/*.sh` remains shell. Hooks are lifecycle glue, not enumeration logic.
- `dashboard/` remains React/JavaScript.
- `agents/` remains markdown/prompt assets. Agent updates are required later, but should follow real Python output rather than speculative schema changes.

### Public API

`scope_core/__init__.py` exposes only the stable helpers enumerators and CLI code are expected to import:

- `ClientFactory`
- `CoverageTracker`
- `ModuleEnvelope`
- `CoverageEntry`
- `ErrorRecord`
- `Enumerator`
- `map_bounded`
- `write_envelope`

Enumerators should import through `scope_core` where possible instead of reaching into implementation modules. Internal helpers can still be imported directly inside tests when necessary.

---

## Core Model Layer

`scope_core/models.py` uses Pydantic v2 as the source of truth for core records:

- `CoverageReason`
- `CoverageEntry`
- `ErrorRecord`
- `ModuleEnvelope`
- task result models used by bounded parallel helpers

Pydantic is preferred over dataclasses or `TypedDict` because SCOPE's outputs are runtime contracts, not just developer annotations. The models provide construction-time validation, stable JSON serialization, and JSON Schema generation.

The checked-in schemas under `config/schemas/` remain authoritative for external consumers, but should be generated or checked against the Pydantic models so the Python model layer and hook schemas cannot drift silently.

`ModuleEnvelope` must include the current required module-envelope fields:

- `module`
- `account_id`
- `region`
- `timestamp`
- `status`
- `findings`

It also supports the additive coverage contract:

- `coverage`
- `errors`

`CoverageEntry.status` includes `complete`, `partial`, `skipped`, and `error`. `skipped` is required to represent expected optional-check gaps such as STS Organizations access not being available.

Coverage entry status is derived from recorded events:

- `error`: any module-wide failure event was recorded for this check.
- `partial`: at least one failed resource event was recorded for this check, whether or not any successful resource events were recorded.
- `skipped`: all recorded events for the check were skipped, with no successes or failures.
- `complete`: at least one success was recorded and no failures were recorded. Skipped optional events may also exist.

Module status remains narrower: `complete`, `partial`, or `error`.

### Schema Generation Policy

Pydantic models are the Python source of truth, but checked-in JSON Schemas remain the reviewable contract for non-Python consumers.

Schema drift should be verify-only in CI and tests. A model change must fail the drift test until the corresponding schema file is deliberately regenerated and committed.

Regeneration is a maintainer action:

```bash
python -m tools.regen_schemas
```

Do not auto-overwrite `config/schemas/*.json` during normal test or build runs. Auto-overwrite can hide drift behind a passing build and make schema changes invisible in review.

---

## Coverage Tracking

`scope_core/coverage.py` exposes a method-specific `CoverageTracker`.

Each enumerator creates its tracker with explicit primary and required checks:

```python
tracker = CoverageTracker(
    primary=["list_buckets"],
    required=["bucket_policy", "bucket_acl"],
)
```

The tracker API is intentionally explicit:

```python
tracker.record_ok(check, resource=None)
tracker.record_skipped(check, resource=None, reason="access_denied")
tracker.record_resource_failure(check, resource, operation, err)
tracker.record_module_failure(check, operation, err)
tracker.derive_status()
tracker.to_envelope_fields()
```

This avoids the ambiguity of a flat `record({ status: "failed" })` call. Resource-level failure and module-level failure have different status implications and should be represented by different methods.

Status derivation belongs in `CoverageTracker` or a dedicated status helper, not in `envelope.py`. `envelope.py` validates shape and enum values; it should not need service-specific knowledge about primary, required, or optional checks.

### Status Rules

- `complete`: primary enumeration succeeded. Optional skipped checks are recorded in `coverage[]`.
- `partial`: primary resources were discovered, but required per-resource checks failed for one or more resources.
- `error`: primary enumeration failed, or the script crashed after CLI arguments and run directory were accepted.

Primary failures should still emit coverage when possible. For example, a denied `ListBuckets` call should produce a module-wide coverage entry with `status: "error"` even if no findings exist.

---

## AWS Client Layer

`scope_core/aws.py` provides a `ClientFactory` around boto3:

```python
factory = ClientFactory(region="us-east-1", profile=None)
account_id = factory.account_id
s3 = factory.client("s3")
pages = factory.paginate(s3, "list_buckets")
```

Responsibilities:

- create and cache boto3 low-level clients
- resolve and cache `account_id` with STS
- centralize client config, retries, user agent, and connection pool sizing
- expose paginator helpers
- avoid passing `account_id` through every enumerator manually

Use low-level boto3 clients, not boto3 resources. Boto3 resources are not thread-safe and the resource interface is not where AWS is investing new features.

Recommended default client config:

```python
Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    user_agent_extra="SCOPE/...",
    max_pool_connections=20,
)
```

The connection pool should be at least as large as the largest bounded per-module worker count.

---

## Region Discovery

`scope_core/regions.py` owns AWS region discovery for the audit orchestrator.

Default behavior:

- call `ec2.describe_regions(AllRegions=False)` to return regions enabled for the caller
- cache the discovered list for the run
- sort returned region names for stable output
- if region discovery is denied or unavailable, fall back to a conservative hardcoded commercial-region list and record the fallback in logs/coverage

The audit orchestrator uses this helper when the operator selects all regions or omits an explicit region list. Individual enumerators receive resolved regions from the orchestrator rather than rediscovering regions themselves.

---

## Concurrency Policy

SCOPE should use sync boto3 for the v1 Python rewrite.

Rationale:

- boto3 is official, mature, and aligned with AWS examples.
- the audit orchestrator already runs service enumerators concurrently.
- only a small number of modules, especially IAM, are likely to need heavy intra-module fanout.
- async would color the whole call stack and require async-aware base enum, tests, retries, logging, and client lifecycle handling.
- aioboto3 is viable, but it adds a community-maintained wrapper layer and should be reserved for a measured need.

For hot spots, use bounded threadpool fanout through one shared helper:

```text
scope_core/parallel.py
```

Rules:

- Enumerators are synchronous boto3 code.
- Intra-module fanout happens only through `scope_core.parallel.map_bounded()`.
- Enumerators do not create raw `ThreadPoolExecutor` instances.
- No aioboto3 in v1.

`map_bounded()` should:

- preserve input order or return a stable `index`
- return structured task results instead of throwing by default
- keep AWS-specific coverage handling out of `parallel.py`
- allow modules to convert failures into `CoverageTracker` events

Example shape:

```python
results = map_bounded(users, fetch_user_details, max_workers=10)

for result in results:
    if result.ok:
        findings.append(result.value)
    else:
        tracker.record_resource_failure(
            check="user_detail",
            resource=result.item["Arn"],
            operation="GetUser",
            err=result.error,
        )
```

---

## CLI Runtime

`scope_core/base_enum.py` replaces `scripts/lib/base-enum.js`.

`scope_core/contract.py` defines the enumerator protocol:

```python
class Enumerator(Protocol):
    def __call__(self, factory: ClientFactory, region: str) -> ModuleEnvelope:
        ...
```

Every service enumerator implements this shape. `base_enum.dispatch(module_name, run_fn)` validates that the returned value is a `ModuleEnvelope` before writing it, so new enumerators have one obvious template and contract failures are caught at the boundary.

It handles:

- CLI argument parsing
- run directory validation
- account ID resolution
- logger setup and flushing
- single-region and multi-region execution
- module envelope writing
- fatal runtime error envelopes after CLI arguments and run directory are accepted

`scope_runtime/audit.py` owns orchestration:

- discover regions
- launch service enumerators
- collect module envelopes
- run graph extraction
- run report generation
- hand off to agents or existing audit pipeline steps as needed

`scope_runtime/__main__.py` should expose stable commands suitable for humans and agents:

```bash
python -m scope_runtime audit ...
python -m scope_runtime enum s3 ...
python -m scope_runtime extract-graph ...
python -m scope_runtime generate-report ...
```

Exact command names can be refined during implementation, but the entrypoint should hide internal package layout from callers.

---

## Policy Parsing

`scope_core/policy_parser.py` owns shared IAM-style policy handling:

- parse string or dict policies
- normalize single-object and array `Statement`
- normalize `Action`, `NotAction`, `Resource`, `NotResource`, and `Principal`
- detect wildcard actions and resources
- support IAM, S3, KMS, SNS, SQS, Lambda, Secrets Manager, and SSM resource policy shapes

This avoids repeating the current class of parser bugs where single-object `Statement` values are ignored in some services.

---

## Testing

Use pytest.

Test layers:

- `tests/scope_core/`: model validation, envelope writing, coverage status derivation, retry behavior, bounded parallel helper, policy parser.
- `tests/enumerators/`: one file per service using botocore stubs or equivalent mocks.
- `tests/fixtures/`: mirror the current enum fixtures so JS and Python outputs can be compared module by module during migration.

Fixture migration should be incremental. Do not require every module fixture to include coverage fields before that module has been migrated to coverage-aware output.

Add a schema drift test:

- generate JSON Schema from Pydantic models
- compare to checked-in `config/schemas/module-envelope.schema.json`
- fail when they diverge unexpectedly

Add shadow-read parity tooling:

- `tools/parity_diff.py` compares JS and Python module envelopes produced from the same account/region run.
- It normalizes field ordering, timestamp formats, and intentional integer/string coercions between the AWS SDK for JavaScript and boto3.
- It reports semantic differences that must be reviewed before removing a module's JavaScript implementation.

---

## Agent And Skill Impact

Agents and skills will need updates, but they should not block the Python script rewrite.

The target responsibility split is:

```text
Python = deterministic collection, normalization, validation
Agents = reasoning, synthesis, remediation, narrative
```

The AWS SDK does not create consistency by itself. Consistency comes from the Python model layer, envelope writer, policy parser, coverage tracker, retry/client helpers, and resource indexing. Once those deterministic layers exist, agents should consume facts rather than manufacture normalized facts.

Track these as required follow-up work:

- `agents/scope-audit.md`: update orchestration from Node scripts to Python CLI commands.
- `agents/subagents/scope-attack-*.md`: teach domain agents to consume `coverage[]`, `errors[]`, and `<field>_status`.
- `agents/subagents/scope-enum-*.md`: retire after Python parity. These agents currently perform deterministic AWS CLI calls, jq normalization, ARN construction, temp-file merging, status calculation, and envelope writing. That behavior belongs in Python.
- `agents/subagents/scope-pipeline.md`: migrate normalization and indexing into Python where practical. Agents should not parse markdown fallbacks or rebuild graph payloads when structured JSON artifacts exist.
- Superpowers/GSD docs and plans: update references from `scripts/enum/*.js`, `scripts/lib/*.js`, `bin/*.js`, `package.json`, and `npm test`.

Keep these agent classes, with narrower responsibilities:

- `scope-attack-{identity,compute,data,network}`: keep as attack-path analysts over normalized module envelopes, `graph.json`, and future `resource_index.json`. They should not normalize raw AWS responses or infer whether missing fields mean absent, denied, or errored.
- `scope-attack-synthesizer`: keep for cross-domain path stitching and final audit `results.json` synthesis.
- `scope-defend-*`: keep for remediation strategy, SCP/RCP/SPL generation, guardrails, and validation.
- `scope-synthesizer`: keep for engagement narrative over structured audit and defend output.
- `scope-research`: keep for external technique enrichment.
- `scope-verify`: keep for claim validation, AWS action/event correctness, policy syntax, and satisfiability checks.
- `scope-hunt-*`: keep. Hunt is Splunk/investigation workflow, not AWS enumeration.

The migration order should preserve the JSON contract first, then update agents once real Python envelopes exist. Do not delete enum agents until the Python orchestrator has produced equivalent module envelopes end to end.

### Target Pipeline

```text
Python enumerators
  -> module envelopes

Python graph/resource extraction
  -> graph.json
  -> resource_index.json

Attack-domain agents
  -> attack-{domain}.json

Attack synthesizer
  -> results.json

Defend / synth / report agents
  -> remediation, detections, narrative
```

---

## Migration Strategy

Avoid a big-bang rewrite.

Recommended phases:

1. Add Python project scaffolding: `pyproject.toml`, `uv.lock`, package directories, pytest setup.
2. Implement `scope_core` foundation: models, envelope, coverage, aws, retry, logger, base enum, policy parser, parallel helper.
3. Port one low-risk module first, preferably `sts`, to validate CLI, envelope writing, logging, and account resolution. This phase also handles the existing STS Organizations deprecation: keep `org_accessible`, `org_status`, and `org_error_code` on the identity finding for one release, emit equivalent `coverage[]` entries, and mark the old fields `# DEPRECATED - remove in v1.16`.
4. Port `s3` next to exercise policy parsing, per-resource status fields, required checks, optional checks, and coverage.
5. Add parity tests that compare Python output against current JS fixtures where the contract overlaps.
6. Add shadow-read parity for migrated modules. During the migration window, `scope_runtime/audit.py` supports `--shadow-read=<module>` to run both the JS and Python enumerator for the same account/region and write a diff report generated by `tools/parity_diff.py`. Review diffs before removing that module's JavaScript implementation.
7. Port remaining modules by domain: identity, data, compute, network, AI/app services.
8. Update `scope_runtime/audit.py` to prefer Python enumerators once fixture parity and shadow-read parity are proven for the module.
9. Update agents and skills to reference Python commands and richer coverage output.
10. Remove old JS scripts, tests, and package files in a final cleanup commit only after the Python path is verified end to end.

---

## Preserved JavaScript Behaviors

The Python port must preserve prior contract decisions unless a new spec explicitly changes them:

- Always-on crash envelope after CLI arguments and run directory are accepted. Runtime failures should write a module envelope with `status: "error"`, `findings: []`, and structured `errors[]` when possible.
- Per-finding `<field>_status` fields default to `null` until the related check runs. Do not default to `absent` before a successful API response proves absence.
- Expected not-found responses map to `absent`, not `error`. Examples include S3 `NoSuchBucketPolicy`, missing Lambda resource policy, or equivalent `ResourceNotFoundException` cases where the API successfully proves no resource policy/config exists.
- AccessDenied on optional checks maps to skipped coverage and an `access_denied` field status; it does not imply the field is absent.
- AccessDenied on required per-resource checks maps to partial module status and an `access_denied` field status.
- AccessDenied on primary list operations maps to error module status.
- Multi-region output must preserve stable ordering where possible so fixtures and parity diffs remain reviewable.

---

## Non-Goals

- No aioboto3 in v1.
- No full dashboard rewrite.
- No immediate agent rewrite before Python envelopes exist.
- No removal of JavaScript enumerators until Python parity is verified.
- No per-check script explosion; keep one enumerator per AWS service/domain unless a specific check proves it needs isolation.

---

## Open Questions

1. Exact CLI command names under `scope_runtime`.
2. Which module follows `sts` and `s3` in the migration sequence.
3. Final removal criteria for the JavaScript implementation.
