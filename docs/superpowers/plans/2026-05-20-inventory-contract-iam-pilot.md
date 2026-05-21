# Inventory Contract IAM Pilot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Python module envelope's `findings` field with factual `resources`, update all Python enumerators to the new envelope field, and convert IAM into the reference facts-only enumerator.

**Architecture:** This is the first implementation slice of `docs/superpowers/specs/2026-05-20-inventory-contract-design.md`. It updates the core envelope/model/schema contract, mechanically moves every Python enumerator to the top-level `resources` envelope field, adds reusable inventory assertions for tests, and ports IAM to the new facts-only resource semantics. Full facts-only cleanup for non-IAM services and graph extraction are intentionally left for follow-up plans after IAM establishes the pattern.

**Tech Stack:** Python 3.12, Pydantic v2, pytest, boto3/botocore, uv.

---

## Scope

This plan implements:

- `ModuleEnvelope.resources`
- schema regeneration for `resources`
- crash envelopes using `resources: []`
- audit dispatcher validation against `resources`
- mechanical top-level `resources` output for every Python enumerator
- IAM reference output with no nested `findings`, `severity`, or `risk`
- IAM service-linked role exclusion
- IAM attached/inline policy behavior agreed in the spec
- IAM OIDC/federated trust condition preservation

This plan does not implement:

- facts-only cleanup for non-IAM service resources
- `scope_core/graph.py`
- `scope_runtime/extract_graph.py`
- agent prompt rewrites
- dashboard changes
- JavaScript retirement

## Files

- Modify: `scope_core/models.py` — rename `ModuleEnvelope.findings` to `resources`.
- Modify: `scope_core/envelope.py` — accept `resources` in `create_envelope`.
- Modify: `scope_core/base_enum.py` — write error envelopes with `resources: []`.
- Modify: `tools/regen_schemas.py` — require `resources` instead of `findings`.
- Modify: `config/schemas/module-envelope.schema.json` — regenerated schema.
- Modify: `scope_runtime/audit.py` — no behavior change expected, but fixtures/tests must emit `resources`.
- Modify: `enumerators/*.py` — all module envelopes must pass `resources=...`.
- Modify: `enumerators/iam.py` — reference IAM inventory implementation.
- Create: `tests/enumerators/inventory_assertions.py` — reusable facts-only test helper.
- Modify: `tests/scope_core/test_models.py`
- Modify: `tests/scope_core/test_envelope.py`
- Modify: `tests/scope_core/test_base_enum.py`
- Modify: `tests/scope_runtime/test_audit_dispatch.py`
- Modify: `tests/enumerators/*.py`
- Modify: `tests/enumerators/test_iam.py`
- Modify: `test/fixtures/enum/*/expected.json`
- Modify: `test/fixtures/enum/iam/expected.json`

---

### Task 1: Core Envelope Contract Uses Resources

**Files:**
- Modify: `scope_core/models.py`
- Modify: `scope_core/envelope.py`
- Modify: `scope_core/base_enum.py`
- Modify: `tools/regen_schemas.py`
- Modify: `config/schemas/module-envelope.schema.json`
- Modify: `tests/scope_core/test_models.py`
- Modify: `tests/scope_core/test_envelope.py`
- Modify: `tests/scope_core/test_base_enum.py`

- [ ] **Step 1: Update model tests to require `resources`**

Edit `tests/scope_core/test_models.py`.

Replace the basic envelope construction test with:

```python
def test_module_envelope_serializes_timestamp_as_zulu():
    envelope = ModuleEnvelope(
        module="sts",
        account_id="123456789012",
        region="global",
        status="complete",
        resources=[{"resource_type": "sts_identity", "resource_id": "caller"}],
    )

    dumped = envelope.model_dump()
    payload = json.loads(envelope.model_dump_json())

    assert dumped["timestamp"].tzinfo is not None
    assert payload["timestamp"].endswith("Z")
    assert payload["resources"] == [{"resource_type": "sts_identity", "resource_id": "caller"}]
    assert "findings" not in payload
```

Replace the old `test_module_envelope_requires_findings` with:

```python
def test_module_envelope_requires_resources():
    with pytest.raises(ValueError):
        ModuleEnvelope(
            module="sts",
            account_id="123456789012",
            region="global",
            status="complete",
        )
```

Update schema assertions in the same file:

```python
def test_module_envelope_schema_requires_resources_not_findings():
    schema = ModuleEnvelope.model_json_schema()

    assert "resources" in schema["required"]
    assert "findings" not in schema["required"]
    assert "resources" in schema["properties"]
    assert "findings" not in schema["properties"]
```

- [ ] **Step 2: Run model test to verify red**

Run:

```bash
uv run pytest tests/scope_core/test_models.py -q
```

Expected: FAIL because `ModuleEnvelope` still requires `findings` and has no `resources` field.

- [ ] **Step 3: Update `ModuleEnvelope`**

In `scope_core/models.py`, change the envelope model field:

```python
class ModuleEnvelope(BaseModel):
    model_config = ConfigDict(extra="allow")

    module: ModuleName
    account_id: str
    region: str
    status: ModuleStatus
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resources: list[dict[str, Any]]
    coverage: list[CoverageEntry] = Field(default_factory=list)
    errors: list[ErrorRecord] = Field(default_factory=list)
```

- [ ] **Step 4: Update envelope helper tests**

Edit `tests/scope_core/test_envelope.py`.

Change construction and assertions from `findings` to `resources`:

```python
def test_write_envelope_writes_module_json(tmp_path):
    envelope = create_envelope(
        module="sts",
        account_id="123456789012",
        region="global",
        status="complete",
        resources=[{"resource_type": "sts_identity"}],
    )

    path = write_envelope(tmp_path, envelope)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert path == tmp_path / "sts.json"
    assert payload["resources"] == [{"resource_type": "sts_identity"}]
    assert "findings" not in payload
```

Rename `test_create_envelope_preserves_findings_coverage_and_errors` to:

```python
def test_create_envelope_preserves_resources_coverage_and_errors():
    envelope = create_envelope(
        module="sts",
        account_id="123456789012",
        region="global",
        status="partial",
        resources=[{"resource_type": "sts_identity", "resource_id": "caller"}],
        coverage=[
            CoverageEntry(
                check="organizations",
                scope="module_wide",
                status="partial",
                succeeded=0,
                failed=1,
                skipped=0,
            )
        ],
        errors=[ErrorRecord(operation="organizations.DescribeOrganization", code="AccessDeniedException")],
    )

    assert envelope.resources == [{"resource_type": "sts_identity", "resource_id": "caller"}]
    assert envelope.coverage[0].check == "organizations"
    assert envelope.errors[0].operation == "organizations.DescribeOrganization"
```

- [ ] **Step 5: Update envelope helper implementation**

Edit `scope_core/envelope.py`:

```python
def create_envelope(
    *,
    module: str,
    account_id: str,
    region: str,
    status: str,
    resources: list[dict[str, Any]] | None = None,
    coverage: list[CoverageEntry] | None = None,
    errors: list[ErrorRecord] | None = None,
) -> ModuleEnvelope:
    return ModuleEnvelope(
        module=module,
        account_id=account_id,
        region=region,
        status=status,
        resources=resources or [],
        coverage=coverage or [],
        errors=errors or [],
    )
```

- [ ] **Step 6: Update crash envelope tests**

Edit `tests/scope_core/test_base_enum.py`.

Every `ModuleEnvelope(...)` in test helpers must use `resources=[...]` instead of `findings=[...]`.

Every payload assertion should check `resources`:

```python
assert payload["resources"] == [{"resource_type": "sts_identity"}]
assert "findings" not in payload
```

For error-envelope assertions, use:

```python
assert payload["resources"] == []
assert payload["errors"][0]["operation"] == "sts.run"
```

- [ ] **Step 7: Update crash envelope implementation**

Edit `scope_core/base_enum.py`.

Change the `create_envelope(...)` call in the exception path:

```python
error_envelope = create_envelope(
    module=module_name,
    account_id=_account_id_or_unknown(factory),
    region=region,
    status="error",
    resources=[],
    coverage=[],
    errors=[
        ErrorRecord(
            operation=f"{module_name}.run",
            resource=None,
            code=err.__class__.__name__,
            message=str(err),
        )
    ],
)
```

- [ ] **Step 8: Update schema generator**

Edit `tools/regen_schemas.py`:

```python
schema["required"] = ["module", "account_id", "region", "timestamp", "status", "resources"]
```

- [ ] **Step 9: Regenerate module schema**

Run:

```bash
uv run python -m tools.regen_schemas --write
```

Expected: `config/schemas/module-envelope.schema.json` is rewritten and contains `resources` but not `findings`.

- [ ] **Step 10: Run focused core tests**

Run:

```bash
uv run pytest tests/scope_core/test_models.py tests/scope_core/test_envelope.py tests/scope_core/test_base_enum.py -q
```

Expected: PASS.

- [ ] **Step 11: Commit core contract**

```bash
git add scope_core/models.py scope_core/envelope.py scope_core/base_enum.py tools/regen_schemas.py config/schemas/module-envelope.schema.json tests/scope_core/test_models.py tests/scope_core/test_envelope.py tests/scope_core/test_base_enum.py
git commit -m "refactor: rename module findings to resources"
```

---

### Task 2: Audit Dispatcher and Test Fixtures Emit Resources

**Files:**
- Modify: `tests/scope_runtime/test_audit_dispatch.py`
- Modify: `scope_runtime/audit.py` only if validation assumptions need adjustment

- [ ] **Step 1: Update audit dispatch test payloads**

Edit `tests/scope_runtime/test_audit_dispatch.py`.

Every fake envelope payload should use:

```python
payload = {
    "module": module,
    "account_id": "123456789012",
    "region": region,
    "status": "complete",
    "resources": [],
    "coverage": [],
    "errors": [],
}
```

Do not include `findings`.

- [ ] **Step 2: Run audit dispatcher tests**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py -q
```

Expected: PASS. If it fails inside `ModuleEnvelope.model_validate`, verify the payload contains `resources`.

- [ ] **Step 3: Commit dispatcher fixture update**

```bash
git add tests/scope_runtime/test_audit_dispatch.py scope_runtime/audit.py
git commit -m "test: update audit dispatcher resources contract"
```

---

### Task 3: Mechanical Resources Rename for Existing Enumerators

**Files:**
- Modify: `enumerators/apigateway.py`
- Modify: `enumerators/aws_lambda.py`
- Modify: `enumerators/bedrock.py`
- Modify: `enumerators/codebuild.py`
- Modify: `enumerators/cognito.py`
- Modify: `enumerators/dynamodb.py`
- Modify: `enumerators/ec2.py`
- Modify: `enumerators/iam.py`
- Modify: `enumerators/kms.py`
- Modify: `enumerators/rds.py`
- Modify: `enumerators/s3.py`
- Modify: `enumerators/secrets.py`
- Modify: `enumerators/sns.py`
- Modify: `enumerators/sqs.py`
- Modify: `enumerators/ssm.py`
- Modify: `enumerators/sts.py`
- Modify: `tests/enumerators/test_*.py`
- Modify: `test/fixtures/enum/*/expected.json`
- Modify: `tools/parity_diff.py`

- [ ] **Step 1: Update enumerator ModuleEnvelope construction**

In every file under `enumerators/`, replace `findings=` with `resources=` only at `ModuleEnvelope(...)` construction sites.

Example before:

```python
return ModuleEnvelope(
    module="s3",
    account_id=factory.account_id,
    region=region,
    status=tracker.derive_status(),
    findings=findings,
    coverage=coverage,
    errors=errors,
)
```

Example after:

```python
return ModuleEnvelope(
    module="s3",
    account_id=factory.account_id,
    region=region,
    status=tracker.derive_status(),
    resources=findings,
    coverage=coverage,
    errors=errors,
)
```

For this task only, local variable names may remain `findings` in non-IAM modules. The emitted envelope field must be `resources`.

- [ ] **Step 2: Update enumerator tests to read envelope.resources**

In every file under `tests/enumerators/`, replace direct envelope access:

```python
envelope.findings
```

with:

```python
envelope.resources
```

Update `_contract(...)` helpers so top-level comparison maps `resources`:

```python
def _contract(envelope) -> dict:
    dumped = envelope.model_dump(mode="json")
    return {
        "resources": dumped["resources"],
        "status": dumped["status"],
        "coverage": dumped["coverage"],
        "errors": dumped["errors"],
    }
```

If a helper returns keys from an expected fixture, leave it as:

```python
return {key: dumped[key] for key in expected}
```

because expected fixtures will be updated to `resources`.

- [ ] **Step 3: Update expected fixture top-level field only**

For every `test/fixtures/enum/*/expected.json`, rename only the top-level `findings` property to `resources`. Do not rename nested resource fields in this task.

Before:

```json
{
  "findings": [
    {
      "resource_type": "example",
      "findings": []
    }
  ],
  "status": "complete",
  "coverage": [],
  "errors": []
}
```

After:

```json
{
  "resources": [
    {
      "resource_type": "example",
      "findings": []
    }
  ],
  "status": "complete",
  "coverage": [],
  "errors": []
}
```

Nested `findings` in non-IAM resources remain until the follow-up facts-only cleanup plan.

- [ ] **Step 4: Update parity normalization**

Edit `tools/parity_diff.py`.

Replace top-level findings sort logic with resources sort logic:

```python
if isinstance(normalized.get("resources"), list):
    normalized["resources"] = sorted(normalized["resources"], key=_finding_sort_key)
```

Keep the helper name `_finding_sort_key` for now if it is used only as a generic resource sort key. Renaming it is optional and not required in this task.

- [ ] **Step 5: Run all non-IAM enumerator tests**

Run:

```bash
uv run pytest tests/enumerators --ignore=tests/enumerators/test_iam.py -q
```

Expected: PASS. If a non-IAM test fails because a top-level expected fixture still uses `findings`, update that fixture's top-level key to `resources`.

- [ ] **Step 6: Commit mechanical resources rename**

```bash
git add enumerators tests/enumerators test/fixtures/enum tools/parity_diff.py
git commit -m "refactor: emit resources from python enumerators"
```

---

### Task 4: Add Facts-Only Inventory Test Helper

**Files:**
- Create: `tests/enumerators/inventory_assertions.py`
- Test: `tests/enumerators/test_iam.py`

- [ ] **Step 1: Create failing IAM facts-only assertion usage**

Edit `tests/enumerators/test_iam.py`.

Add import:

```python
from tests.enumerators.inventory_assertions import assert_facts_only_resources
```

In `test_iam_matches_js_fixture_contract_gaad_path`, after `envelope = ...`, add:

```python
assert_facts_only_resources(envelope.resources)
```

- [ ] **Step 2: Run IAM test to verify red**

Run:

```bash
uv run pytest tests/enumerators/test_iam.py::test_iam_matches_js_fixture_contract_gaad_path -q
```

Expected: FAIL with `ModuleNotFoundError` for `tests.enumerators.inventory_assertions`.

- [ ] **Step 3: Create inventory assertion helper**

Create `tests/enumerators/inventory_assertions.py`:

```python
from __future__ import annotations

from typing import Any


FORBIDDEN_KEYS = {"findings", "severity", "risk", "attack_path"}
FORBIDDEN_TEXT = (
    "credential theft",
    "defense evasion",
    "privilege escalation",
    "attack surface",
    "critical",
    "high",
    "medium",
    "low",
)


def assert_facts_only_resources(resources: list[dict[str, Any]]) -> None:
    for index, resource in enumerate(resources):
        _assert_facts_only(resource, path=f"resources[{index}]")


def _assert_facts_only(value: Any, *, path: str) -> None:
    if isinstance(value, dict):
        forbidden = FORBIDDEN_KEYS.intersection(value)
        assert not forbidden, f"{path} contains forbidden judgment key(s): {sorted(forbidden)}"
        for key, child in value.items():
            _assert_facts_only(child, path=f"{path}.{key}")
        return

    if isinstance(value, list):
        for index, child in enumerate(value):
            _assert_facts_only(child, path=f"{path}[{index}]")
        return

    if isinstance(value, str):
        lowered = value.lower()
        matches = [text for text in FORBIDDEN_TEXT if text in lowered]
        assert not matches, f"{path} contains forbidden judgment text: {matches}"
```

- [ ] **Step 4: Run helper-backed IAM test**

Run:

```bash
uv run pytest tests/enumerators/test_iam.py::test_iam_matches_js_fixture_contract_gaad_path -q
```

Expected: FAIL because IAM still emits nested `findings` and trust `risk`.

- [ ] **Step 5: Commit failing helper is not allowed**

Do not commit yet. Continue to Task 5 and make IAM pass before committing the helper.

---

### Task 5: Convert IAM to Facts-Only Resources

**Files:**
- Modify: `enumerators/iam.py`
- Modify: `tests/enumerators/test_iam.py`
- Modify: `test/fixtures/enum/iam/expected.json`
- Create: `tests/enumerators/inventory_assertions.py`

- [ ] **Step 1: Update IAM test contract helper**

Edit `_contract` in `tests/enumerators/test_iam.py`:

```python
def _contract(envelope, expected: dict) -> dict:
    dumped = envelope.model_dump(mode="json")
    return {key: dumped[key] for key in expected}
```

Ensure expected fixtures use `resources`, not `findings`.

- [ ] **Step 2: Add service-linked role exclusion test**

Add to `tests/enumerators/test_iam.py`:

```python
def test_iam_excludes_service_linked_roles():
    iam = FakeClient(
        {
            "get_account_authorization_details": {
                "UserDetailList": [],
                "RoleDetailList": [
                    {
                        "RoleName": "AWSServiceRoleForAmazonSSM",
                        "Arn": "arn:aws:iam::123456789012:role/aws-service-role/ssm.amazonaws.com/AWSServiceRoleForAmazonSSM",
                        "Path": "/aws-service-role/ssm.amazonaws.com/",
                        "AssumeRolePolicyDocument": '{"Statement":[]}',
                        "AttachedManagedPolicies": [],
                        "RolePolicyList": [],
                    },
                    {
                        "RoleName": "DeployRole",
                        "Arn": "arn:aws:iam::123456789012:role/DeployRole",
                        "Path": "/",
                        "AssumeRolePolicyDocument": '{"Statement":[]}',
                        "AttachedManagedPolicies": [],
                        "RolePolicyList": [],
                    },
                ],
                "GroupDetailList": [],
                "Policies": [],
                "IsTruncated": False,
            },
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {"Content": "user,mfa_active,password_last_used\n<root_account>,true,N/A"},
            "list_open_id_connect_providers": {"OpenIDConnectProviderList": []},
            "generate_service_last_accessed_details": {"JobId": "job-role"},
            "get_service_last_accessed_details": {"JobStatus": "COMPLETED", "ServicesLastAccessed": []},
        }
    )

    envelope = run(FakeFactory(iam=iam), "global")

    role_names = [resource["resource_id"] for resource in envelope.resources if resource["resource_type"] == "iam_role"]
    assert role_names == ["DeployRole"]
```

- [ ] **Step 3: Add OIDC trust conditions test**

Add to `tests/enumerators/test_iam.py`:

```python
def test_iam_preserves_oidc_trust_conditions_without_risk():
    trust_policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
                    "StringLike": {"token.actions.githubusercontent.com:sub": "repo:scope/demo:*"},
                },
            }
        ]
    }
    iam = FakeClient(
        {
            "get_account_authorization_details": {
                "UserDetailList": [],
                "RoleDetailList": [
                    {
                        "RoleName": "GithubDeployRole",
                        "Arn": "arn:aws:iam::123456789012:role/GithubDeployRole",
                        "Path": "/",
                        "AssumeRolePolicyDocument": json.dumps(trust_policy),
                        "AttachedManagedPolicies": [],
                        "RolePolicyList": [],
                    }
                ],
                "GroupDetailList": [],
                "Policies": [],
                "IsTruncated": False,
            },
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {"Content": "user,mfa_active,password_last_used\n<root_account>,true,N/A"},
            "list_open_id_connect_providers": {
                "OpenIDConnectProviderList": [
                    {"Arn": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}
                ]
            },
            "get_open_id_connect_provider": {
                "Url": "token.actions.githubusercontent.com",
                "ClientIDList": ["sts.amazonaws.com"],
                "ThumbprintList": ["abc123"],
            },
            "generate_service_last_accessed_details": {"JobId": "job-role"},
            "get_service_last_accessed_details": {"JobStatus": "COMPLETED", "ServicesLastAccessed": []},
        }
    )

    envelope = run(FakeFactory(iam=iam), "global")

    role = next(resource for resource in envelope.resources if resource["resource_type"] == "iam_role")
    trust = role["trust_relationships"][0]
    assert trust["trust_type"] == "federated"
    assert trust["conditions"] == trust_policy["Statement"][0]["Condition"]
    assert "risk" not in trust

    oidc = next(resource for resource in envelope.resources if resource["resource_type"] == "oidc_provider")
    assert oidc["url"] == "token.actions.githubusercontent.com"
    assert oidc["assumed_role_arns"] == ["arn:aws:iam::123456789012:role/GithubDeployRole"]
```

- [ ] **Step 4: Add attached policy document rules test**

Add to `tests/enumerators/test_iam.py`:

```python
def test_iam_attached_policy_documents_follow_inventory_rules():
    customer_policy_arn = "arn:aws:iam::123456789012:policy/CustomRead"
    aws_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam = FakeClient(
        {
            "get_account_authorization_details": {
                "UserDetailList": [
                    {
                        "UserName": "PolicyUser",
                        "Arn": "arn:aws:iam::123456789012:user/PolicyUser",
                        "GroupList": [],
                        "AttachedManagedPolicies": [
                            {"PolicyName": "CustomRead", "PolicyArn": customer_policy_arn},
                            {"PolicyName": "AdministratorAccess", "PolicyArn": aws_policy_arn},
                        ],
                        "UserPolicyList": [
                            {
                                "PolicyName": "InlineListBuckets",
                                "PolicyDocument": '{"Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}',
                            }
                        ],
                    }
                ],
                "RoleDetailList": [],
                "GroupDetailList": [],
                "Policies": [
                    {
                        "Arn": customer_policy_arn,
                        "DefaultVersionId": "v1",
                    }
                ],
                "IsTruncated": False,
            },
            "get_policy_version": {
                "PolicyVersion": {
                    "Document": '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/*"}]}'
                }
            },
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {"Content": "user,mfa_active,password_last_used\n<root_account>,true,N/A\nPolicyUser,false,N/A"},
            "list_access_keys": {"AccessKeyMetadata": []},
            "list_mfa_devices": {"MFADevices": []},
            "get_login_profile": _no_such_entity(),
            "list_open_id_connect_providers": {"OpenIDConnectProviderList": []},
            "generate_service_last_accessed_details": {"JobId": "job-user"},
            "get_service_last_accessed_details": {"JobStatus": "COMPLETED", "ServicesLastAccessed": []},
        }
    )

    envelope = run(FakeFactory(iam=iam), "global")

    user = next(resource for resource in envelope.resources if resource["resource_type"] == "iam_user")
    attached = {policy["arn"]: policy for policy in user["attached_policies"]}
    assert attached[customer_policy_arn]["name"] == "CustomRead"
    assert attached[customer_policy_arn]["document"]["Statement"][0]["Action"] == "s3:GetObject"
    assert attached[aws_policy_arn]["name"] == "AdministratorAccess"
    assert attached[aws_policy_arn]["document"] is None
    assert user["inline_policies"][0]["document"]["Statement"][0]["Action"] == "s3:ListAllMyBuckets"
```

- [ ] **Step 5: Run IAM tests to verify red**

Run:

```bash
uv run pytest tests/enumerators/test_iam.py -q
```

Expected: FAIL because IAM still returns `findings`, includes service-linked roles, and emits `risk`.

- [ ] **Step 6: Update IAM envelope helper**

Edit `enumerators/iam.py`.

Rename local variables from findings to resources and change `_envelope`:

```python
def _envelope(account_id: str, region: str, resources: list[dict[str, Any]], status: str, errors: list[ErrorRecord]):
    return ModuleEnvelope(
        module="iam",
        account_id=account_id,
        region=region,
        status=status,
        resources=resources,
        coverage=[],
        errors=errors,
    )
```

In `run`, change:

```python
oidc_resources, oidc_errors = _oidc_providers(iam, roles)
...
resources = [*users, *roles, *groups, *oidc_resources]
return _envelope(factory.account_id, region, resources, status, errors)
```

- [ ] **Step 7: Exclude service-linked roles in GAAD path**

In `_enumerate_gaad`, filter roles before conversion:

```python
roles_raw = [role for role in roles_raw if not _is_service_linked_role(role)]
```

Add helper:

```python
def _is_service_linked_role(role: dict[str, Any]) -> bool:
    name = str(role.get("RoleName") or "")
    path = str(role.get("Path") or "")
    arn = str(role.get("Arn") or "")
    return (
        name.startswith("AWSServiceRoleFor")
        or path.startswith("/aws-service-role/")
        or ":role/aws-service-role/" in arn
    )
```

- [ ] **Step 8: Exclude service-linked roles in fallback path**

In `_enumerate_fallback`, change:

```python
roles = [role for role in factory.paginate(iam, "list_roles", "Roles") if not _is_service_linked_role(role)]
```

- [ ] **Step 9: Remove nested findings from IAM resources**

In `_user_from_gaad`, `_role_from_gaad`, `_group_from_gaad`, `_oidc_providers`, and `_fallback_group`, remove:

```python
"findings": [],
```

- [ ] **Step 10: Add policy names to attached policies**

In `_user_from_gaad`, `_role_from_gaad`, and `_group_from_gaad`, attached policy entries should include `name`:

```python
attached_policies = [
    {
        "name": policy.get("PolicyName"),
        "arn": policy.get("PolicyArn"),
        "document": managed_docs.get(policy.get("PolicyArn")),
    }
    for policy in user.get("AttachedManagedPolicies") or []
]
```

Apply the same pattern for roles and groups.

In fallback attached policy construction, use:

```python
attached = [
    {
        "name": policy.get("PolicyName"),
        "arn": policy.get("PolicyArn"),
        "document": _managed_policy_document(iam, policy.get("PolicyArn")),
    }
    for policy in attached_raw
]
```

- [ ] **Step 11: Preserve trust conditions and remove risk**

In `_parse_trust_policy`, replace entry construction with:

```python
entry = {
    **_classify_principal(principal, account_id),
    "has_external_id": has_external_id,
    "has_mfa_condition": has_mfa,
    "conditions": conditions or {},
}
relationships.append(entry)
```

Do not call `_derive_risk`. Leave `_derive_risk` unused for now, then remove `_derive_risk` if no references remain.

- [ ] **Step 12: Update cross-account trust test expectation**

In `test_iam_cross_account_trust_without_external_id_is_high_risk`, rename the test to:

```python
def test_iam_cross_account_trust_preserves_factual_conditions():
```

Update expected trust relationship:

```python
assert role["trust_relationships"] == [
    {
        "principal": "arn:aws:iam::999999999999:root",
        "trust_type": "cross-account",
        "is_wildcard": False,
        "has_external_id": False,
        "has_mfa_condition": False,
        "conditions": {},
    }
]
```

- [ ] **Step 13: Update IAM fixture expected JSON**

Edit `test/fixtures/enum/iam/expected.json`:

- rename top-level `findings` to `resources`
- remove every nested `"findings": []`
- remove every trust `"risk": "..."`
- add `"conditions": {}` to each trust relationship
- add `"name"` to attached policy objects where present

- [ ] **Step 14: Run IAM tests**

Run:

```bash
uv run pytest tests/enumerators/test_iam.py -q
```

Expected: PASS.

- [ ] **Step 15: Commit IAM pilot**

```bash
git add enumerators/iam.py tests/enumerators/test_iam.py tests/enumerators/inventory_assertions.py test/fixtures/enum/iam/expected.json
git commit -m "refactor: convert iam enumerator to resources"
```

---

### Task 6: Verify Contract Drift and IAM Smoke

**Files:**
- No source changes expected.

- [ ] **Step 1: Run schema drift check**

Run:

```bash
uv run python -m tools.regen_schemas
```

Expected:

```text
module-envelope schema is up to date
```

- [ ] **Step 2: Run focused test suite**

Run:

```bash
uv run pytest tests/scope_core/test_models.py tests/scope_core/test_envelope.py tests/scope_core/test_base_enum.py tests/scope_runtime/test_audit_dispatch.py tests/enumerators/test_iam.py -q
```

Expected: PASS.

- [ ] **Step 3: Run full test suite**

Run:

```bash
uv run pytest -q
```

Expected: PASS. Non-IAM enumerators are expected to use top-level `resources` after Task 3, even though their nested resource-level judgment cleanup is deferred.

- [ ] **Step 4: Run real IAM smoke**

Run:

```bash
RUN_DIR=/tmp/scope-iam-resources-$(date +%Y%m%d%H%M%S)
echo "$RUN_DIR"
uv run python -m scope_runtime enum iam --region global --run-dir "$RUN_DIR"
python3 - "$RUN_DIR" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

run_dir = Path(sys.argv[1])
payload = json.loads((run_dir / "iam.json").read_text(encoding="utf-8"))
resources = payload["resources"]
print("status", payload["status"])
print("errors", len(payload["errors"]))
print("resources", len(resources))
print("types", Counter(resource["resource_type"] for resource in resources))
print("has_findings", "findings" in payload)
print("service_linked_roles", [
    resource["resource_id"]
    for resource in resources
    if resource.get("resource_type") == "iam_role"
    and (
        str(resource.get("resource_id", "")).startswith("AWSServiceRoleFor")
        or ":role/aws-service-role/" in str(resource.get("arn", ""))
    )
])
PY
```

Expected:

- command exits 0
- `status complete`
- `errors 0`
- `has_findings False`
- `service_linked_roles []`

- [ ] **Step 5: Confirm no verification-only source changes**

Run:

```bash
git status --short
```

Expected: no tracked file changes. If the smoke run revealed a real source or fixture issue, return to the task that owns that file, add a failing test for the issue, fix it, rerun verification, and commit with the task-specific files only.

---

## Follow-Up Plans

After this plan is complete:

1. Convert remaining enumerators to `resources` and facts-only output.
2. Add `scope_core/graph.py` and `scope_runtime/extract_graph.py`.
3. Update agents to consume `resources + graph + coverage + errors`.
4. Rerun single-region and all-enabled-region AWS verification.
5. Retire JavaScript enumeration paths after parity is verified.

## Self-Review Notes

- Spec coverage: this plan covers the envelope rename, mechanical top-level `resources` conversion for every Python enumerator, facts-only rules for IAM, IAM reference behavior, and verification for the IAM slice. It intentionally defers non-IAM facts-only cleanup, graph extraction, agents, and dashboard.
- Placeholder scan: no `TBD` or open implementation placeholders are present.
- Type consistency: this plan consistently uses `resources` in model, helpers, schema, tests, and IAM.
