# Full Python Enumerator Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port every remaining JavaScript AWS enumerator to Python, route audit enumeration through Python, and retire the old deterministic enum-agent prompts after parity is verified.

**Architecture:** Keep the existing module-envelope contract. Each Python module in `enumerators/` owns deterministic AWS collection, normalization, coverage, error records, and envelope-compatible findings. `scope_runtime enum` becomes the only runtime path for module enumeration; JavaScript scripts remain only as parity references until all modules pass fixture, shadow-read, and schema checks.

**Tech Stack:** Python 3.11+, boto3/botocore, Pydantic models in `scope_core`, pytest, existing JS fixtures as parity references, existing JSON schema hook.

---

## Prerequisites

This plan covers migration spec Phases 4-10. It starts after the Python foundation and STS pilot plan has landed. A fresh executor must verify these artifacts before Task 1:

- `pyproject.toml` and `uv.lock` exist and `uv run pytest` works.
- `scope_core/` exists with `ClientFactory`, `CoverageTracker`, `ModuleEnvelope`, public `map_bounded`, `scope_core.parallel.map_bounded`, `regions.discover_regions`, and envelope writing.
- `scope_runtime enum` exists and can run a Python enumerator.
- `tools/parity_diff.py` exists and normalizes module envelopes.
- `enumerators/sts.py` and `tests/enumerators/test_sts.py` exist.
- `uv run pytest tests/enumerators/test_sts.py tests/scope_core -q` passes.

At the time this plan was written, those prerequisites are satisfied by the preceding foundation/STS work on this branch. If a fresh checkout does not have them, stop and execute `docs/superpowers/plans/2026-05-18-python-enumerator-foundation-sts.md` first.

---

## File Structure

Create Python enumerators:
- `enumerators/apigateway.py`
- `enumerators/bedrock.py`
- `enumerators/codebuild.py`
- `enumerators/cognito.py`
- `enumerators/dynamodb.py`
- `enumerators/ec2.py`
- `enumerators/iam.py`
- `enumerators/kms.py`
- `enumerators/aws_lambda.py` — CLI service name remains `lambda`; file name avoids Python's `lambda` keyword without the awkward trailing underscore
- `enumerators/rds.py`
- `enumerators/s3.py`
- `enumerators/secrets.py`
- `enumerators/sns.py`
- `enumerators/sqs.py`
- `enumerators/ssm.py`

Create tests:
- `tests/enumerators/test_apigateway.py`
- `tests/enumerators/test_bedrock.py`
- `tests/enumerators/test_codebuild.py`
- `tests/enumerators/test_cognito.py`
- `tests/enumerators/test_dynamodb.py`
- `tests/enumerators/test_ec2.py`
- `tests/enumerators/test_iam.py`
- `tests/enumerators/test_kms.py`
- `tests/enumerators/test_lambda.py`
- `tests/enumerators/test_rds.py`
- `tests/enumerators/test_s3.py`
- `tests/enumerators/test_secrets.py`
- `tests/enumerators/test_sns.py`
- `tests/enumerators/test_sqs.py`
- `tests/enumerators/test_ssm.py`
- `tests/scope_runtime/test_audit_dispatch.py`

Modify runtime/docs:
- `scope_runtime/__main__.py` — map CLI module name `lambda` to import module `enumerators.aws_lambda`.
- `scope_runtime/audit.py` — new Python audit dispatcher for all modules.
- `agents/scope-audit.md` — replace Node dispatch with `uv run python -m scope_runtime audit ...` or explicit `scope_runtime enum` loop.
- `agents/subagents/scope-enum-*.md` — mark deprecated/transitional or remove from installation once Python audit is live.
- `bin/install.js` — stop installing deprecated enum subagents only after `scope-audit.md` no longer references them.

Do not delete `scripts/enum/*.js` until Task 7 parity gate passes.

---

## Per-Module Port Protocol

Every module port task below follows this protocol. Do not batch multiple modules into one unreviewed implementation step.

For each module:

1. Read `scripts/enum/<module>.js` and `test/fixtures/enum/<module>/expected.json`.
2. Write a failing Python test that constructs fake clients from the JS fixture shape and asserts the normalized Python envelope matches the JS expected envelope where the contract overlaps.
3. Run the focused test and confirm it fails because the Python enumerator is missing or incomplete.
4. Implement the minimal Python `run(factory, region) -> ModuleEnvelope`.
5. Run the focused test and inspect any diff with `tools.parity_diff.normalize_envelope`.
6. Add at least one failure-path test for the primary list/get operation and any required detail operation.
7. Run the module test and the existing STS/core tests.
8. Commit that module before moving to the next module.

The test harness intentionally exposes `factory.paginate(client, op, result_key, **kwargs)`. This matches `scope_core.aws.ClientFactory`; the harness is not trying to model raw boto3 paginator syntax.

The assertion from Step 2 is the pass/fail gate. Step 5 is the refinement loop for understanding and shrinking diffs while the module is being implemented.

Each module worker must report:

- JS fixture file used.
- Python tests added.
- Known intentional differences from JS output, if any.
- Focused test command and result.

For subagent execution, put the report in the worker's final handoff message. For inline execution, put the same report in the controller's task checkpoint summary before the commit.

---

## Task 1: Shared Enumerator Test Harness

**Files:**
- Create: `tests/enumerators/conftest.py`
- Create: `tests/enumerators/fakes.py`

- [ ] **Step 1: Add fake client and factory helpers**

Create helpers that let each test provide operation responses and errors without touching AWS:

```python
from __future__ import annotations

from collections import defaultdict
from typing import Any


class FakeClient:
    def __init__(self, operations: dict[str, Any]):
        self.operations = operations
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.call_counts = defaultdict(int)

    def __getattr__(self, name: str):
        def call(**kwargs: Any):
            self.calls.append((name, kwargs))
            self.call_counts[name] += 1
            value = self.operations.get(name)
            if isinstance(value, list):
                index = min(self.call_counts[name] - 1, len(value) - 1)
                value = value[index]
            if isinstance(value, Exception):
                raise value
            if callable(value):
                return value(**kwargs)
            return value if value is not None else {}

        return call

    def paginate(self, operation_name: str, result_key: str, **kwargs: Any) -> list[Any]:
        value = getattr(self, operation_name)(**kwargs)
        if result_key not in value:
            return []
        return value[result_key]


class FakeFactory:
    account_id = "123456789012"

    def __init__(self, **clients: FakeClient):
        self.clients = clients

    def client(self, service: str) -> FakeClient:
        return self.clients[service]

    def paginate(self, client: FakeClient, operation_name: str, result_key: str, **kwargs: Any) -> list[Any]:
        return client.paginate(operation_name, result_key, **kwargs)
```

- [ ] **Step 2: Run existing tests**

Run:

```bash
uv run pytest tests/enumerators tests/scope_core -q
```

Expected: existing STS tests still pass.

- [ ] **Step 3: Commit harness**

```bash
git add tests/enumerators/conftest.py tests/enumerators/fakes.py
git commit -m "test: add python enumerator fixture harness"
```

---

## Task 2: Small Regional Modules

**Modules:** `sns`, `sqs`, `ssm`, `secrets`, `codebuild`

**Files:**
- Create: `enumerators/sns.py`, `enumerators/sqs.py`, `enumerators/ssm.py`, `enumerators/secrets.py`, `enumerators/codebuild.py`
- Create matching `tests/enumerators/test_*.py`

- [ ] **Step 1: Port `sns` using the per-module protocol**

Use `scripts/enum/sns.js` and `test/fixtures/enum/sns/expected.json`. Commit:

```bash
git add enumerators/sns.py tests/enumerators/test_sns.py
git commit -m "feat: port sns enumerator to python"
```

- [ ] **Step 2: Port `sqs` using the per-module protocol**

Use `scripts/enum/sqs.js` and `test/fixtures/enum/sqs/expected.json`. Commit:

```bash
git add enumerators/sqs.py tests/enumerators/test_sqs.py
git commit -m "feat: port sqs enumerator to python"
```

- [ ] **Step 3: Port `ssm` using the per-module protocol**

Use `scripts/enum/ssm.js` and `test/fixtures/enum/ssm/expected.json`. Commit:

```bash
git add enumerators/ssm.py tests/enumerators/test_ssm.py
git commit -m "feat: port ssm enumerator to python"
```

- [ ] **Step 4: Port `secrets` using the per-module protocol**

Use `scripts/enum/secrets.js` and `test/fixtures/enum/secrets/expected.json`. Commit:

```bash
git add enumerators/secrets.py tests/enumerators/test_secrets.py
git commit -m "feat: port secrets enumerator to python"
```

- [ ] **Step 5: Port `codebuild` using the per-module protocol**

Use `scripts/enum/codebuild.js` and `test/fixtures/enum/codebuild/expected.json`. Commit:

```bash
git add enumerators/codebuild.py tests/enumerators/test_codebuild.py
git commit -m "feat: port codebuild enumerator to python"
```

- [ ] **Step 6: Verify wave**

Run:

```bash
uv run pytest tests/enumerators/test_sns.py tests/enumerators/test_sqs.py tests/enumerators/test_ssm.py tests/enumerators/test_secrets.py tests/enumerators/test_codebuild.py -q
uv run pytest tests/enumerators tests/scope_core -q
```

Expected: all pass.

---

## Task 3: Data, Storage, And KMS Modules

**Modules:** `dynamodb`, `kms`, `rds`, `s3`

**Files:**
- Create: `enumerators/dynamodb.py`, `enumerators/kms.py`, `enumerators/rds.py`, `enumerators/s3.py`
- Create matching tests.

- [ ] **Step 1: Port `dynamodb` using the per-module protocol**

Implement table listing, table detail, resource policy / backups / tags where the JS module currently emits them. Preserve current finding fields and coverage semantics.

```bash
git add enumerators/dynamodb.py tests/enumerators/test_dynamodb.py
git commit -m "feat: port dynamodb enumerator to python"
```

- [ ] **Step 2: Port `kms` using the per-module protocol**

Implement key listing, key metadata, rotation, key policy, grants, and policy-principal extraction. Reuse `scope_core.policy_parser` if present; otherwise port only the deterministic helper needed by KMS/S3/SNS/SQS/Lambda.

```bash
git add enumerators/kms.py tests/enumerators/test_kms.py
git commit -m "feat: port kms enumerator to python"
```

- [ ] **Step 3: Port `rds` using the per-module protocol**

Implement DB instances and manual snapshots. Preserve public snapshot detection fields.

```bash
git add enumerators/rds.py tests/enumerators/test_rds.py
git commit -m "feat: port rds enumerator to python"
```

- [ ] **Step 4: Port `s3` using the per-module protocol**

Implement global bucket listing and per-bucket detail calls: location, policy, public access block, versioning, encryption, logging, ACL. Preserve `<field>_status` fields and access denied handling from the JS module.

```bash
git add enumerators/s3.py tests/enumerators/test_s3.py
git commit -m "feat: port s3 enumerator to python"
```

- [ ] **Step 5: Verify wave**

Run:

```bash
uv run pytest tests/enumerators/test_dynamodb.py tests/enumerators/test_kms.py tests/enumerators/test_rds.py tests/enumerators/test_s3.py -q
uv run pytest tests/enumerators tests/scope_core -q
```

Expected: all pass.

---

## Task 4: Compute, API, And AI Service Modules

**Modules:** `lambda`, `ec2`, `apigateway`, `bedrock`, `cognito`

**Files:**
- Create: `enumerators/aws_lambda.py`, `enumerators/ec2.py`, `enumerators/apigateway.py`, `enumerators/bedrock.py`, `enumerators/cognito.py`
- Create matching tests.
- Modify: `tests/scope_core/test_base_enum.py`

- [ ] **Step 1: Add `lambda` import mapping**

Modify `scope_runtime/__main__.py` so CLI module name `lambda` imports `enumerators.aws_lambda`. Add a focused test that `scope_runtime enum lambda ...` attempts to import `enumerators.aws_lambda`.

```bash
git add scope_runtime/__main__.py tests/scope_core/test_base_enum.py
git commit -m "fix: map lambda enum module import"
```

- [ ] **Step 2: Port `lambda` using the per-module protocol**

Implement function listing, function URL config, resource policy, layers, environment secret pattern metadata, and event source mappings.

```bash
git add enumerators/aws_lambda.py tests/enumerators/test_lambda.py
git commit -m "feat: port lambda enumerator to python"
```

- [ ] **Step 3: Port `ec2` using the per-module protocol**

Implement instances, security groups, VPCs, EBS snapshots, ELBv2/ELB load balancers, and listeners. Preserve multi-resource finding types.

```bash
git add enumerators/ec2.py tests/enumerators/test_ec2.py
git commit -m "feat: port ec2 enumerator to python"
```

- [ ] **Step 4: Port `apigateway` using the per-module protocol**

Implement REST APIs, HTTP APIs, WebSocket APIs, authorizers, stages, resources, integrations, and resource policies.

```bash
git add enumerators/apigateway.py tests/enumerators/test_apigateway.py
git commit -m "feat: port apigateway enumerator to python"
```

- [ ] **Step 5: Port `bedrock` using the per-module protocol**

Implement foundation/custom model and agent discovery according to the JS module output contract.

Before implementation, list Bedrock primary/required checks from `scripts/enum/bedrock.js` in the worker report because this module has not been reviewed in detail yet.

```bash
git add enumerators/bedrock.py tests/enumerators/test_bedrock.py
git commit -m "feat: port bedrock enumerator to python"
```

- [ ] **Step 6: Port `cognito` using the per-module protocol**

Implement identity pools and user pools, clients, domain/MFA/password details, and schema attributes according to the JS output contract.

```bash
git add enumerators/cognito.py tests/enumerators/test_cognito.py
git commit -m "feat: port cognito enumerator to python"
```

- [ ] **Step 7: Verify wave**

Run:

```bash
uv run pytest tests/enumerators/test_lambda.py tests/enumerators/test_ec2.py tests/enumerators/test_apigateway.py tests/enumerators/test_bedrock.py tests/enumerators/test_cognito.py -q
uv run pytest tests/enumerators tests/scope_core -q
```

Expected: all pass.

---

## Task 5: IAM Module

**Files:**
- Create: `enumerators/iam.py`
- Create: `tests/enumerators/test_iam.py`

- [ ] **Step 1: Write IAM fixture parity test**

Read `scripts/enum/iam.js` and `test/fixtures/enum/iam/expected.json`. Add a focused test that builds fake IAM responses from the fixture and asserts normalized Python output matches the JS expected envelope where the contract overlaps.

Run:

```bash
uv run pytest tests/enumerators/test_iam.py -q
```

Expected: fail because `enumerators.iam` does not exist or returns an incomplete envelope.

- [ ] **Step 2: Port account-level IAM inventory**

Implement the base IAM calls from `scripts/enum/iam.js`:
- account authorization details
- account password policy
- account summary / aliases if emitted by the JS module
- users, roles, groups, and customer-managed policies from the authorization details response

Run:

```bash
uv run pytest tests/enumerators/test_iam.py -q
```

Expected: remaining fixture diff is limited to per-resource detail fields not implemented yet.

- [ ] **Step 3: Port user detail collection**

Add tests and implementation for:
- inline user policies
- attached user policies
- access keys
- MFA devices
- console login profile
- access denied / no-such-entity behavior matching the JS fixture contract

Run:

```bash
uv run pytest tests/enumerators/test_iam.py -q
```

Expected: user-related fixture diff is gone.

- [ ] **Step 4: Port role and trust detail collection**

Add tests and implementation for:
- inline role policies
- attached role policies
- assume-role trust principal normalization
- external ID metadata
- service principal trust metadata

Run:

```bash
uv run pytest tests/enumerators/test_iam.py -q
```

Expected: role-related fixture diff is gone.

- [ ] **Step 5: Port group and managed-policy detail collection**

Add tests and implementation for:
- inline group policies
- attached group policies
- managed policy versions
- policy document parsing through `scope_core.policy_parser`

Run:

```bash
uv run pytest tests/enumerators/test_iam.py -q
```

Expected: fixture parity test passes except any explicitly documented intentional diffs.

- [ ] **Step 6: Add bounded fan-out only where measured**

Use `scope_core.parallel.map_bounded` for per-user/per-role/per-group detail fan-out only if the straight synchronous implementation is visibly slow against the fixture or a real IAM-heavy account. Keep boto3 synchronous; do not introduce `aioboto3`.

If `map_bounded` is used, add a test that verifies the configured concurrency bound is passed. If it is not used, record `not used; no measured bottleneck in this module port` in the worker report.

- [ ] **Step 7: Add IAM failure-path coverage**

Add tests for:
- `get_account_authorization_details` module-wide failure
- one denied required detail operation
- one absent optional detail operation that should produce `absent` or `null` status rather than module `error`

- [ ] **Step 8: Verify IAM**

Run:

```bash
uv run pytest tests/enumerators/test_iam.py -q
uv run pytest tests/enumerators tests/scope_core -q
```

Expected: all pass.

- [ ] **Step 9: Commit IAM**

```bash
git add enumerators/iam.py tests/enumerators/test_iam.py
git commit -m "feat: port iam enumerator to python"
```

---

## Task 6: Python Audit Dispatcher

**Files:**
- Create: `scope_runtime/audit.py`
- Modify: `scope_runtime/__main__.py`
- Create: `tests/scope_runtime/test_audit_dispatch.py`

- [ ] **Step 1: Add audit CLI tests**

Test that `scope_runtime audit --all --run-dir <dir>` builds the 16-module service list, discovers regions, dispatches Python modules with global/regional behavior, and maps service name `lambda` to import module `enumerators.aws_lambda`.

- [ ] **Step 2: Implement `scope_runtime audit`**

Implement:
- service routing for `--all`, single service, multiple services
- a module import map containing `lambda -> enumerators.aws_lambda`; all other service names import `enumerators.<service>`
- account ID resolution via `ClientFactory`
- enabled region discovery via `scope_core.regions.discover_regions`
- parallel module execution using subprocess calls to `uv run python -m scope_runtime enum <module>`
- per-module logs under `$RUN_DIR/logs`
- nonzero exit if any module command fails to write a valid envelope

- [ ] **Step 3: Verify audit dispatcher**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py -q
uv run pytest -q
```

Expected: all pass.

- [ ] **Step 4: Commit dispatcher**

```bash
git add scope_runtime/audit.py scope_runtime/__main__.py tests/scope_runtime/test_audit_dispatch.py
git commit -m "feat: add python audit dispatcher"
```

---

## Task 7: Parity And Script Retirement Gate

**Files:**
- Modify: `agents/scope-audit.md`
- Modify: `agents/subagents/README.md`
- Modify: `bin/install.js`
- Delete only after parity passes: `scripts/enum/*.js`, `scripts/lib/*.js`, JS enum tests/fixtures as appropriate, `package.json`, `package-lock.json`

- [ ] **Step 1: Run fixture parity**

Run Python tests for every module and compare normalized output against JS expected fixtures where the contract overlaps.

```bash
uv run pytest tests/enumerators -q
```

Expected: all pass.

- [ ] **Step 2: Run live shadow-read parity for every module**

For every migrated module, run JS and Python against the same account/region and compare with `tools/parity_diff.py`:

```text
apigateway
bedrock
codebuild
cognito
dynamodb
ec2
iam
kms
lambda
rds
s3
secrets
sns
sqs
ssm
sts
```

Expected: reviewed diffs only; no unexplained semantic differences. Any diff not absorbed by `normalize_envelope` must be fixed or recorded as intentional in the worker report. Cosmetic differences already handled by normalization, such as timestamp precision and integer/string coercions, do not count as semantic diffs.

- [ ] **Step 3: Update `agents/scope-audit.md`**

Replace Node dispatch text with Python audit dispatch:

```bash
uv run python -m scope_runtime audit --run-dir "$RUN_DIR" --services "$APPROVED_SERVICES" --regions "$REGIONS_ARG"
```

Remove instructions that agents should call `node scripts/enum/*.js`.

- [ ] **Step 4: Deprecate deterministic enum subagents**

Mark `agents/subagents/scope-enum-*.md` with a deprecation notice and remove them from the install manifest only after `agents/scope-audit.md` and any installer tests no longer reference them. Keep attack, defend, synth, verify, research, and hunt agents.

- [ ] **Step 5: Delete JavaScript enum runtime only after all checks pass**

Delete old deterministic JS enum runtime files only after fixture parity, all-module live shadow-read parity, and Python audit pass:

```bash
git rm scripts/enum/*.js scripts/lib/*.js
```

Do not remove dashboard JavaScript.

- [ ] **Step 6: Full verification**

Run:

```bash
uv run pytest
uv run python -c "from scope_core import ClientFactory, CoverageTracker, ModuleEnvelope, map_bounded, write_envelope; print('imports ok')"
git status --short
```

Expected: Python tests pass and no JS enum runtime remains referenced by agents.

- [ ] **Step 7: Commit retirement**

```bash
git add agents/scope-audit.md agents/subagents/README.md bin/install.js scope_runtime scripts tests
git commit -m "refactor: migrate audit enumeration to python"
```

---

## Out Of Scope

- Rewriting dashboard JavaScript.
- Removing attack/defend/synth/hunt agents.
- Introducing async boto clients.
- Changing the external module-envelope schema except additive fields already modeled in Python.
