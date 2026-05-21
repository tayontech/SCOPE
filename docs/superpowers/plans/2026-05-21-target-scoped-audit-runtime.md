# Target-Scoped Audit Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add target-scoped audit support so `scope_runtime audit --target` and `--target-file` run only the required services/regions, emit scoped resources, and preserve existing `--all` and `--services` behavior.

**Architecture:** Add a focused target parsing/planning module under `scope_runtime`, extend the audit CLI to accept target modes, run the minimum work items for each target, then apply a second-pass target/context filter before aggregation. Existing enumerators keep working unchanged; selector plumbing is added for future native per-resource paths, while v1 supports all current services through runtime post-filtering with explicit `target_filter` coverage.

**Tech Stack:** Python 3.12, argparse, dataclasses, Pydantic models, pytest, existing `scope_runtime` audit/aggregation/post-processing pipeline.

---

## File Structure

- Create: `scope_runtime/targets.py`
  - Owns ARN parsing, newline target-file parsing, target-to-module planning, target matching, context extraction, and envelope filtering.
- Modify: `scope_runtime/audit.py`
  - Adds `--target` and `--target-file`, builds target-mode work items, writes scope metadata, applies target filtering before aggregation, and computes target-aware status.
- Modify: `scope_runtime/__main__.py`
  - Forwards target CLI arguments to `scope_runtime.audit.main`.
- Modify: `scope_runtime/aggregation.py`
  - Accepts optional `scope` metadata and writes it to `summary.json`.
- Modify: `scope_runtime/post_processing.py`
  - Copies `summary["scope"]` into `results.json`.
- Modify: `scope_core/base_enum.py`
  - Adds optional selector loading and backward-compatible invocation for future selector-aware enumerators.
- Modify: `scope_core/contract.py`
  - Updates the enumerator protocol to document optional selector support without forcing all current modules to change in this task.
- Test: `tests/scope_runtime/test_targets.py`
  - Unit tests for target parsing, target-file parsing, planner behavior, matching, and envelope filtering.
- Test: `tests/scope_runtime/test_audit_dispatch.py`
  - CLI/runtime tests for target execution using fake enumerator subprocesses.
- Test: `tests/scope_runtime/test_aggregation.py`
  - Verifies summary scope metadata and resource-row scope metadata survive aggregation.
- Test: `tests/scope_runtime/test_post_processing.py`
  - Verifies `results.json` includes scope metadata.
- Test: `tests/scope_core/test_base_enum.py`
  - Verifies selector-aware dispatch remains backward compatible.

---

## Implementation Notes

Target mode v1 supports every current SCOPE service:

```python
TARGET_SUPPORTED_MODULES = {
    "apigateway",
    "bedrock",
    "codebuild",
    "cognito",
    "dynamodb",
    "ec2",
    "iam",
    "kms",
    "lambda",
    "rds",
    "s3",
    "secrets",
    "sns",
    "sqs",
    "ssm",
    "sts",
}
```

Runtime filtering is a deliberate v1 choice. Native selector-aware enumerators can be added module-by-module later without changing the CLI or output contract.

The target run filter is applied after all module envelopes are copied into `modules/<service>/<region>.json` and before `aggregate_run()`. This makes context selection possible because the filter can inspect target resources first, collect related ARNs, then include matching IAM/KMS/S3/context resources from other envelopes.

Target mode must not call enabled-region discovery. Regional target ARNs provide their own region; no-region global/account resources use service rules.

---

### Task 1: Target Parser And Planner

**Files:**
- Create: `scope_runtime/targets.py`
- Test: `tests/scope_runtime/test_targets.py`

- [ ] **Step 1: Write target parsing tests**

Create `tests/scope_runtime/test_targets.py` with these tests:

```python
from __future__ import annotations

from pathlib import Path

import pytest

from scope_runtime.targets import (
    TargetParseError,
    build_scope_metadata,
    module_for_target,
    parse_target,
    parse_targets,
    read_target_file,
    required_work_items_for_targets,
)


@pytest.mark.parametrize(
    ("arn", "service", "module", "region", "resource_type", "resource_id"),
    [
        ("arn:aws:apigateway:us-east-1::/restapis/api123", "apigateway", "apigateway", "us-east-1", "restapis", "api123"),
        ("arn:aws:bedrock:us-east-1:123456789012:agent/agent123", "bedrock", "bedrock", "us-east-1", "agent", "agent123"),
        ("arn:aws:codebuild:us-east-1:123456789012:project/test-project", "codebuild", "codebuild", "us-east-1", "project", "test-project"),
        ("arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_abc", "cognito-idp", "cognito", "us-east-1", "userpool", "us-east-1_abc"),
        ("arn:aws:dynamodb:us-east-1:123456789012:table/Orders", "dynamodb", "dynamodb", "us-east-1", "table", "Orders"),
        ("arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0", "ec2", "ec2", "us-east-1", "instance", "i-0123456789abcdef0"),
        ("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/abc", "elasticloadbalancing", "ec2", "us-east-1", "loadbalancer", "app/app-lb/abc"),
        ("arn:aws:iam::123456789012:role/Admin", "iam", "iam", None, "role", "Admin"),
        ("arn:aws:kms:us-east-1:123456789012:key/aaaa-bbbb", "kms", "kms", "us-east-1", "key", "aaaa-bbbb"),
        ("arn:aws:lambda:us-east-1:123456789012:function:my-func", "lambda", "lambda", "us-east-1", "function", "my-func"),
        ("arn:aws:rds:us-east-1:123456789012:db:prod", "rds", "rds", "us-east-1", "db", "prod"),
        ("arn:aws:s3:::my-bucket", "s3", "s3", None, "bucket", "my-bucket"),
        ("arn:aws:secretsmanager:us-east-1:123456789012:secret:db-password-AbCdEf", "secretsmanager", "secrets", "us-east-1", "secret", "db-password-AbCdEf"),
        ("arn:aws:sns:us-east-1:123456789012:alerts", "sns", "sns", "us-east-1", "topic", "alerts"),
        ("arn:aws:sqs:us-east-1:123456789012:queue-name", "sqs", "sqs", "us-east-1", "queue", "queue-name"),
        ("arn:aws:ssm:us-east-1:123456789012:parameter/app/db", "ssm", "ssm", "us-east-1", "parameter", "app/db"),
        ("arn:aws:sts::123456789012:assumed-role/Admin/session", "sts", "sts", None, "assumed-role", "Admin/session"),
    ],
)
def test_parse_target_supports_current_scope_services(
    arn: str,
    service: str,
    module: str,
    region: str | None,
    resource_type: str,
    resource_id: str,
):
    target = parse_target(arn)

    assert target.raw == arn
    assert target.arn == arn
    assert target.partition == "aws"
    assert target.service == service
    assert target.region == region
    assert target.account_id in {None, "123456789012"}
    assert target.resource_type == resource_type
    assert target.resource_id == resource_id
    assert module_for_target(target) == module


def test_parse_target_rejects_non_arn_before_aws_calls():
    with pytest.raises(TargetParseError) as exc:
        parse_target("lambda:my-func")

    assert "Expected ARN" in str(exc.value)


def test_parse_target_rejects_unsupported_service():
    with pytest.raises(TargetParseError) as exc:
        parse_target("arn:aws:cloudtrail:us-east-1:123456789012:trail/main")

    assert "Unsupported target service" in str(exc.value)


def test_parse_target_rejects_regional_service_without_region():
    with pytest.raises(TargetParseError) as exc:
        parse_target("arn:aws:lambda::123456789012:function:my-func")

    assert "requires a region" in str(exc.value)


def test_read_target_file_ignores_blank_lines_and_comments(tmp_path: Path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        "\n"
        "# production targets\n"
        "arn:aws:iam::123456789012:role/Admin\n"
        "  \n"
        "arn:aws:s3:::my-bucket\n",
        encoding="utf-8",
    )

    targets = read_target_file(target_file)

    assert [target.arn for target in targets] == [
        "arn:aws:iam::123456789012:role/Admin",
        "arn:aws:s3:::my-bucket",
    ]


def test_read_target_file_rejects_empty_file(tmp_path: Path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text("# no targets\n\n", encoding="utf-8")

    with pytest.raises(TargetParseError) as exc:
        read_target_file(target_file)

    assert "No targets found" in str(exc.value)


def test_required_work_items_for_targets_uses_target_regions_and_context():
    targets = parse_targets(
        [
            "arn:aws:lambda:us-east-1:123456789012:function:my-func",
            "arn:aws:s3:::my-bucket",
            "arn:aws:iam::123456789012:role/Admin",
        ]
    )

    pairs = required_work_items_for_targets(targets)

    assert pairs == [
        ("lambda", "us-east-1"),
        ("s3", "global"),
        ("iam", "global"),
        ("sts", "global"),
    ]


def test_build_scope_metadata_serializes_target_mode():
    targets = parse_targets(["arn:aws:s3:::my-bucket"])

    assert build_scope_metadata(mode="target", targets=targets) == {
        "mode": "target",
        "targets": ["arn:aws:s3:::my-bucket"],
    }
```

- [ ] **Step 2: Run parser tests to verify they fail**

Run:

```bash
uv run pytest tests/scope_runtime/test_targets.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'scope_runtime.targets'`.

- [ ] **Step 3: Implement target parser and planner**

Create `scope_runtime/targets.py`:

```python
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


class TargetParseError(ValueError):
    pass


@dataclass(frozen=True)
class TargetScope:
    raw: str
    arn: str
    partition: str
    service: str
    region: str | None
    account_id: str | None
    resource_type: str
    resource_id: str


@dataclass(frozen=True)
class ResourceSelector:
    mode: Literal["all", "target"]
    targets: tuple[TargetScope, ...] = ()


ARN_PATTERN = re.compile(
    r"^arn:(?P<partition>[^:]+):(?P<service>[^:]*):(?P<region>[^:]*):(?P<account>[^:]*):(?P<resource>.+)$"
)

SERVICE_TO_MODULE = {
    "apigateway": "apigateway",
    "bedrock": "bedrock",
    "codebuild": "codebuild",
    "cognito-idp": "cognito",
    "cognito-identity": "cognito",
    "dynamodb": "dynamodb",
    "ec2": "ec2",
    "elasticloadbalancing": "ec2",
    "iam": "iam",
    "kms": "kms",
    "lambda": "lambda",
    "rds": "rds",
    "s3": "s3",
    "secretsmanager": "secrets",
    "sns": "sns",
    "sqs": "sqs",
    "ssm": "ssm",
    "sts": "sts",
}

NO_REGION_MODULES = {"iam", "s3", "sts"}
CONTEXT_MODULES = {"iam", "sts"}


def parse_target(raw: str) -> TargetScope:
    value = raw.strip()
    match = ARN_PATTERN.fullmatch(value)
    if not match:
        raise TargetParseError(f"Expected ARN target, got: {raw}")

    service = match.group("service")
    module = SERVICE_TO_MODULE.get(service)
    if not module:
        raise TargetParseError(f"Unsupported target service: {service}")

    region = match.group("region") or None
    if region is None and module not in NO_REGION_MODULES:
        raise TargetParseError(f"Target service '{service}' requires a region: {raw}")

    resource_type, resource_id = _split_resource(service, match.group("resource"))
    return TargetScope(
        raw=raw,
        arn=value,
        partition=match.group("partition"),
        service=service,
        region=region,
        account_id=match.group("account") or None,
        resource_type=resource_type,
        resource_id=resource_id,
    )


def parse_targets(values: list[str]) -> tuple[TargetScope, ...]:
    targets = tuple(parse_target(value) for value in values)
    if not targets:
        raise TargetParseError("No targets found")
    return targets


def read_target_file(path: Path) -> tuple[TargetScope, ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as err:
        raise TargetParseError(f"Unable to read target file {path}: {err}") from err
    values = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
    return parse_targets(values)


def module_for_target(target: TargetScope) -> str:
    return SERVICE_TO_MODULE[target.service]


def region_for_target(target: TargetScope) -> str:
    module = module_for_target(target)
    if module in NO_REGION_MODULES:
        return "global"
    if target.region is None:
        raise TargetParseError(f"Target service '{target.service}' requires a region: {target.raw}")
    return target.region


def required_work_items_for_targets(targets: tuple[TargetScope, ...]) -> list[tuple[str, str]]:
    ordered: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for target in targets:
        pair = (module_for_target(target), region_for_target(target))
        if pair not in seen:
            ordered.append(pair)
            seen.add(pair)
    for module in ("iam", "sts"):
        pair = (module, "global")
        if pair not in seen:
            ordered.append(pair)
            seen.add(pair)
    return ordered


def build_scope_metadata(*, mode: Literal["all", "service", "target"], targets: tuple[TargetScope, ...] = ()) -> dict[str, Any]:
    return {"mode": mode, "targets": [target.arn for target in targets]}


def selector_to_json(selector: ResourceSelector) -> str:
    payload = {
        "mode": selector.mode,
        "targets": [target.__dict__ for target in selector.targets],
    }
    return json.dumps(payload, sort_keys=True)


def selector_from_json(value: str) -> ResourceSelector:
    payload = json.loads(value)
    mode = payload.get("mode")
    if mode not in {"all", "target"}:
        raise TargetParseError(f"Invalid selector mode: {mode}")
    targets = tuple(TargetScope(**target) for target in payload.get("targets", []))
    return ResourceSelector(mode=mode, targets=targets)


def _split_resource(service: str, resource: str) -> tuple[str, str]:
    normalized = resource.lstrip("/")
    if service == "s3":
        return "bucket", normalized
    if service == "sns":
        return "topic", normalized.rsplit(":", 1)[-1]
    if service == "sqs":
        return "queue", normalized.rsplit(":", 1)[-1]
    if service == "apigateway" and normalized.startswith("restapis/"):
        parts = normalized.split("/")
        return "restapis", parts[1] if len(parts) > 1 else normalized
    for delimiter in ("/", ":"):
        if delimiter in normalized:
            kind, identifier = normalized.split(delimiter, 1)
            return kind, identifier
    return service, normalized
```

- [ ] **Step 4: Run parser tests to verify they pass**

Run:

```bash
uv run pytest tests/scope_runtime/test_targets.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit parser and planner**

Run:

```bash
git add scope_runtime/targets.py tests/scope_runtime/test_targets.py
git commit -m "feat: add target parser and planner"
```

---

### Task 2: Target Matching And Envelope Filtering

**Files:**
- Modify: `scope_runtime/targets.py`
- Test: `tests/scope_runtime/test_targets.py`

- [ ] **Step 1: Add filtering tests**

Append these tests to `tests/scope_runtime/test_targets.py`:

```python
from scope_runtime.targets import filter_module_envelopes_for_targets


def _envelope(module: str, region: str, resources: list[dict]) -> dict:
    return {
        "module": module,
        "account_id": "123456789012",
        "region": region,
        "status": "complete",
        "resources": resources,
        "coverage": [],
        "errors": [],
    }


def test_filter_module_envelopes_keeps_target_and_direct_context():
    targets = parse_targets(["arn:aws:lambda:us-east-1:123456789012:function:my-func"])
    envelopes = {
        ("lambda", "us-east-1"): _envelope(
            "lambda",
            "us-east-1",
            [
                {
                    "resource_type": "lambda_function",
                    "resource_id": "my-func",
                    "arn": "arn:aws:lambda:us-east-1:123456789012:function:my-func",
                    "role": "arn:aws:iam::123456789012:role/LambdaExecRole",
                    "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
                },
                {
                    "resource_type": "lambda_function",
                    "resource_id": "other-func",
                    "arn": "arn:aws:lambda:us-east-1:123456789012:function:other-func",
                },
            ],
        ),
        ("iam", "global"): _envelope(
            "iam",
            "global",
            [
                {
                    "resource_type": "iam_role",
                    "resource_id": "LambdaExecRole",
                    "arn": "arn:aws:iam::123456789012:role/LambdaExecRole",
                    "attached_policies": [{"name": "CustomerPolicy", "arn": "arn:aws:iam::123456789012:policy/CustomerPolicy"}],
                },
                {
                    "resource_type": "iam_role",
                    "resource_id": "UnrelatedRole",
                    "arn": "arn:aws:iam::123456789012:role/UnrelatedRole",
                },
            ],
        ),
        ("kms", "us-east-1"): _envelope(
            "kms",
            "us-east-1",
            [
                {
                    "resource_type": "kms_key",
                    "resource_id": "key-1",
                    "arn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
                }
            ],
        ),
    }

    filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)

    lambda_resources = filtered[("lambda", "us-east-1")]["resources"]
    iam_resources = filtered[("iam", "global")]["resources"]
    kms_resources = filtered[("kms", "us-east-1")]["resources"]
    assert [resource["resource_id"] for resource in lambda_resources] == ["my-func"]
    assert lambda_resources[0]["scope_match"] == "target"
    assert lambda_resources[0]["scope_source"] == targets[0].arn
    assert [resource["resource_id"] for resource in iam_resources] == ["LambdaExecRole"]
    assert iam_resources[0]["scope_match"] == "context"
    assert [resource["resource_id"] for resource in kms_resources] == ["key-1"]
    assert target_results == [{"target": targets[0].arn, "status": "resolved", "module": "lambda", "region": "us-east-1"}]
    assert filtered[("lambda", "us-east-1")]["coverage"][0]["check"] == "target_filter"


def test_filter_module_envelopes_records_not_found_target():
    targets = parse_targets(["arn:aws:s3:::missing-bucket"])
    envelopes = {
        ("s3", "global"): _envelope(
            "s3",
            "global",
            [{"resource_type": "s3_bucket", "resource_id": "other-bucket", "arn": "arn:aws:s3:::other-bucket"}],
        )
    }

    filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)

    assert filtered[("s3", "global")]["resources"] == []
    assert target_results == [{"target": targets[0].arn, "status": "not_found", "module": "s3", "region": "global"}]
    assert filtered[("s3", "global")]["status"] == "partial"
    assert filtered[("s3", "global")]["errors"][0]["code"] == "not_found"


def test_filter_module_envelopes_all_not_found_can_drive_error_status_later():
    targets = parse_targets(
        [
            "arn:aws:sns:us-east-1:123456789012:alerts",
            "arn:aws:sqs:us-east-1:123456789012:jobs",
        ]
    )
    envelopes = {
        ("sns", "us-east-1"): _envelope("sns", "us-east-1", []),
        ("sqs", "us-east-1"): _envelope("sqs", "us-east-1", []),
    }

    _filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)

    assert [result["status"] for result in target_results] == ["not_found", "not_found"]
```

- [ ] **Step 2: Run filtering tests to verify they fail**

Run:

```bash
uv run pytest tests/scope_runtime/test_targets.py::test_filter_module_envelopes_keeps_target_and_direct_context tests/scope_runtime/test_targets.py::test_filter_module_envelopes_records_not_found_target -q
```

Expected: FAIL with `ImportError` for `filter_module_envelopes_for_targets`.

- [ ] **Step 3: Implement matching, context extraction, and filtering**

Append this implementation to `scope_runtime/targets.py`:

```python
def filter_module_envelopes_for_targets(
    envelopes: dict[tuple[str, str], dict[str, Any]],
    targets: tuple[TargetScope, ...],
) -> tuple[dict[tuple[str, str], dict[str, Any]], list[dict[str, Any]]]:
    target_sources_by_arn: dict[str, str] = {}
    direct_related_arns: set[str] = set()
    target_results: list[dict[str, Any]] = []
    filtered: dict[tuple[str, str], dict[str, Any]] = {}

    for target in targets:
        key = (module_for_target(target), region_for_target(target))
        envelope = envelopes.get(key)
        matches: list[dict[str, Any]] = []
        if envelope:
            for resource in envelope.get("resources", []):
                if resource_matches_target(resource, target):
                    annotated = dict(resource)
                    annotated["scope_match"] = "target"
                    annotated["scope_source"] = target.arn
                    matches.append(annotated)
                    resource_arn = annotated.get("arn")
                    if isinstance(resource_arn, str):
                        target_sources_by_arn[resource_arn] = target.arn
                    direct_related_arns.update(extract_related_arns(annotated))
        existing = filtered.setdefault(key, _clone_envelope(envelope, module_for_target(target), region_for_target(target)))
        _merge_resources(existing, matches)
        if matches:
            target_results.append({"target": target.arn, "status": "resolved", "module": key[0], "region": key[1]})
        else:
            target_results.append({"target": target.arn, "status": "not_found", "module": key[0], "region": key[1]})
            _record_target_not_found(existing, target)

    for key, envelope in envelopes.items():
        existing = filtered.setdefault(key, _clone_envelope(envelope, key[0], key[1]))
        for resource in envelope.get("resources", []):
            resource_arn = resource.get("arn")
            source = _context_source_for_resource(resource, direct_related_arns, target_sources_by_arn, targets)
            if not source:
                continue
            annotated = dict(resource)
            annotated["scope_match"] = "context"
            annotated["scope_source"] = source
            _merge_resources(existing, [annotated])

    for key, envelope in list(filtered.items()):
        _append_target_filter_coverage(envelope, targets)
        if not envelope.get("resources") and any(result["module"] == key[0] and result["region"] == key[1] and result["status"] == "not_found" for result in target_results):
            envelope["status"] = "partial"
    return filtered, target_results


def resource_matches_target(resource: dict[str, Any], target: TargetScope) -> bool:
    candidates = {value for value in _resource_identity_values(resource) if isinstance(value, str)}
    if target.arn in candidates or target.resource_id in candidates:
        return True
    resource_arn = resource.get("arn")
    return isinstance(resource_arn, str) and _arn_without_account(resource_arn) == _arn_without_account(target.arn)


def extract_related_arns(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        if value.startswith("arn:"):
            found.add(value)
        return found
    if isinstance(value, dict):
        for nested in value.values():
            found.update(extract_related_arns(nested))
    elif isinstance(value, list):
        for nested in value:
            found.update(extract_related_arns(nested))
    return found


def _resource_identity_values(resource: dict[str, Any]) -> set[Any]:
    values = {resource.get("arn"), resource.get("resource_id"), resource.get("name")}
    values.update(resource.get(key) for key in ("bucket", "bucket_name", "function_name", "role_name", "topic_arn", "queue_url"))
    return values


def _context_source_for_resource(
    resource: dict[str, Any],
    related_arns: set[str],
    target_sources_by_arn: dict[str, str],
    targets: tuple[TargetScope, ...],
) -> str | None:
    resource_arn = resource.get("arn")
    if isinstance(resource_arn, str):
        if resource_arn in target_sources_by_arn:
            return target_sources_by_arn[resource_arn]
        if resource_arn in related_arns:
            return _nearest_target_source(resource_arn, targets)
    resource_related = extract_related_arns(resource)
    if resource_related & related_arns:
        return _nearest_target_source(next(iter(resource_related & related_arns)), targets)
    return None


def _nearest_target_source(_related_arn: str, targets: tuple[TargetScope, ...]) -> str:
    return targets[0].arn


def _clone_envelope(envelope: dict[str, Any] | None, module: str, region: str) -> dict[str, Any]:
    if envelope is None:
        return {
            "module": module,
            "account_id": "unknown",
            "region": region,
            "status": "error",
            "resources": [],
            "coverage": [],
            "errors": [],
        }
    clone = dict(envelope)
    clone["resources"] = []
    clone["coverage"] = list(envelope.get("coverage", []))
    clone["errors"] = list(envelope.get("errors", []))
    return clone


def _merge_resources(envelope: dict[str, Any], resources: list[dict[str, Any]]) -> None:
    seen = {(resource.get("arn"), resource.get("resource_type"), resource.get("resource_id")) for resource in envelope["resources"]}
    for resource in resources:
        key = (resource.get("arn"), resource.get("resource_type"), resource.get("resource_id"))
        if key not in seen:
            envelope["resources"].append(resource)
            seen.add(key)


def _record_target_not_found(envelope: dict[str, Any], target: TargetScope) -> None:
    envelope.setdefault("errors", []).append(
        {
            "operation": "target_filter",
            "resource": target.arn,
            "code": "not_found",
            "message": "Target was not present in enumerator output",
        }
    )


def _append_target_filter_coverage(envelope: dict[str, Any], targets: tuple[TargetScope, ...]) -> None:
    if any(entry.get("check") == "target_filter" for entry in envelope.get("coverage", [])):
        return
    envelope.setdefault("coverage", []).append(
        {
            "check": "target_filter",
            "scope": "module_wide",
            "status": "complete",
            "succeeded": 1,
            "failed": 0,
            "skipped": 0,
            "reasons": [
                {
                    "code": "post_filter",
                    "count": 1,
                    "sample_resource": targets[0].arn,
                }
            ],
        }
    )


def _arn_without_account(arn: str) -> str:
    parts = arn.split(":", 5)
    if len(parts) != 6:
        return arn
    parts[4] = "*"
    return ":".join(parts)
```

- [ ] **Step 4: Run filtering tests to verify they pass**

Run:

```bash
uv run pytest tests/scope_runtime/test_targets.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit filtering**

Run:

```bash
git add scope_runtime/targets.py tests/scope_runtime/test_targets.py
git commit -m "feat: filter target-scoped module envelopes"
```

---

### Task 3: Audit CLI Target Modes

**Files:**
- Modify: `scope_runtime/audit.py`
- Modify: `scope_runtime/__main__.py`
- Test: `tests/scope_runtime/test_audit_dispatch.py`

- [ ] **Step 1: Add CLI parser and forwarding tests**

Append these tests to `tests/scope_runtime/test_audit_dispatch.py`:

```python
def test_audit_parser_accepts_target_and_target_file():
    target_args = audit._parser().parse_args(["--target", "arn:aws:s3:::my-bucket"])
    file_args = audit._parser().parse_args(["--target-file", "targets.txt"])

    assert target_args.target == "arn:aws:s3:::my-bucket"
    assert file_args.target_file == "targets.txt"


def test_module_cli_forwards_target_arguments(monkeypatch):
    forwarded = []

    def fake_audit_main(argv):
        forwarded.extend(argv)
        return 0

    monkeypatch.setattr(audit, "main", fake_audit_main)

    result = cli.main(
        [
            "audit",
            "--target",
            "arn:aws:lambda:us-east-1:123456789012:function:my-func",
            "--output-dir",
            "/tmp/runs",
            "--concurrency",
            "2",
        ]
    )

    assert result == 0
    assert forwarded == [
        "--target",
        "arn:aws:lambda:us-east-1:123456789012:function:my-func",
        "--output-dir",
        "/tmp/runs",
        "--concurrency",
        "2",
    ]
```

- [ ] **Step 2: Run CLI tests to verify they fail**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_audit_parser_accepts_target_and_target_file tests/scope_runtime/test_audit_dispatch.py::test_module_cli_forwards_target_arguments -q
```

Expected: FAIL because `--target` and `--target-file` are unknown.

- [ ] **Step 3: Extend audit parsers**

In `scope_runtime/audit.py`, update `_parser()`:

```python
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scope_runtime audit")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true")
    group.add_argument("--services")
    group.add_argument("--target")
    group.add_argument("--target-file")
    parser.add_argument("--regions")
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--run-dir")
    output_group.add_argument("--output-dir")
    parser.add_argument("--dashboard-export", action="store_true")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--profile", default=None)
    return parser
```

In `scope_runtime/__main__.py`, update the audit subparser and forwarded args:

```python
    audit_group.add_argument("--target")
    audit_group.add_argument("--target-file")
```

and:

```python
        if args.target:
            forwarded.extend(["--target", args.target])
        if args.target_file:
            forwarded.extend(["--target-file", args.target_file])
```

- [ ] **Step 4: Run CLI tests to verify they pass**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_audit_parser_accepts_target_and_target_file tests/scope_runtime/test_audit_dispatch.py::test_module_cli_forwards_target_arguments -q
```

Expected: PASS.

- [ ] **Step 5: Commit CLI target arguments**

Run:

```bash
git add scope_runtime/audit.py scope_runtime/__main__.py tests/scope_runtime/test_audit_dispatch.py
git commit -m "feat: accept target audit arguments"
```

---

### Task 4: Audit Target Work-Item Planning

**Files:**
- Modify: `scope_runtime/audit.py`
- Test: `tests/scope_runtime/test_audit_dispatch.py`

- [ ] **Step 1: Add target-mode planning tests**

Append these tests to `tests/scope_runtime/test_audit_dispatch.py`:

```python
def test_audit_target_lambda_plans_single_region_and_context(monkeypatch, tmp_path: Path):
    commands = []

    def fake_run_command(command, log_path: Path):
        commands.append(command)
        module = command[command.index("enum") + 1]
        region = command[command.index("--logical-region") + 1]
        run_dir = Path(command[command.index("--run-dir") + 1])
        resources = []
        if module == "lambda":
            resources = [
                {
                    "resource_type": "lambda_function",
                    "resource_id": "my-func",
                    "arn": "arn:aws:lambda:us-east-1:123456789012:function:my-func",
                    "role": "arn:aws:iam::123456789012:role/LambdaExecRole",
                },
                {
                    "resource_type": "lambda_function",
                    "resource_id": "other",
                    "arn": "arn:aws:lambda:us-east-1:123456789012:function:other",
                },
            ]
        elif module == "iam":
            resources = [
                {"resource_type": "iam_role", "resource_id": "LambdaExecRole", "arn": "arn:aws:iam::123456789012:role/LambdaExecRole"},
                {"resource_type": "iam_role", "resource_id": "OtherRole", "arn": "arn:aws:iam::123456789012:role/OtherRole"},
            ]
        payload = {
            "module": module,
            "account_id": "123456789012",
            "region": region,
            "status": "complete",
            "resources": resources,
            "coverage": [],
            "errors": [],
        }
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / f"{module}.json").write_text(json.dumps(payload), encoding="utf-8")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("", encoding="utf-8")
        return 0

    class NoEc2DiscoveryFactory(FakeClientFactory):
        def client(self, service: str):
            raise AssertionError("target mode must not discover regions")

    monkeypatch.setattr(audit, "ClientFactory", NoEc2DiscoveryFactory)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    run_dir = tmp_path / "run"
    result = audit.main(
        [
            "--target",
            "arn:aws:lambda:us-east-1:123456789012:function:my-func",
            "--run-dir",
            str(run_dir),
            "--concurrency",
            "3",
        ]
    )

    assert result == 0
    pairs = [(command[command.index("enum") + 1], command[command.index("--logical-region") + 1]) for command in commands]
    assert pairs == [("lambda", "us-east-1"), ("iam", "global"), ("sts", "global")]
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["scope"] == {
        "mode": "target",
        "targets": ["arn:aws:lambda:us-east-1:123456789012:function:my-func"],
    }
    assert manifest["services_requested"] == ["lambda", "iam", "sts"]
    assert manifest["regions_requested"] == ["us-east-1"]


def test_audit_target_file_combines_targets_in_one_run(monkeypatch, tmp_path: Path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        "arn:aws:s3:::my-bucket\n"
        "arn:aws:sns:us-west-2:123456789012:alerts\n",
        encoding="utf-8",
    )
    commands = []

    def fake_run_command(command, log_path: Path):
        commands.append(command)
        module = command[command.index("enum") + 1]
        region = command[command.index("--logical-region") + 1]
        run_dir = Path(command[command.index("--run-dir") + 1])
        resources = []
        if module == "s3":
            resources = [{"resource_type": "s3_bucket", "resource_id": "my-bucket", "arn": "arn:aws:s3:::my-bucket"}]
        if module == "sns":
            resources = [{"resource_type": "sns_topic", "resource_id": "alerts", "arn": "arn:aws:sns:us-west-2:123456789012:alerts"}]
        payload = {
            "module": module,
            "account_id": "123456789012",
            "region": region,
            "status": "complete",
            "resources": resources,
            "coverage": [],
            "errors": [],
        }
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / f"{module}.json").write_text(json.dumps(payload), encoding="utf-8")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("", encoding="utf-8")
        return 0

    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    run_dir = tmp_path / "run"
    result = audit.main(["--target-file", str(target_file), "--run-dir", str(run_dir)])

    assert result == 0
    pairs = [(command[command.index("enum") + 1], command[command.index("--logical-region") + 1]) for command in commands]
    assert pairs == [("s3", "global"), ("sns", "us-west-2"), ("iam", "global"), ("sts", "global")]
    assert (run_dir / "manifest.json").exists()
    assert (run_dir / "summary.json").exists()
    assert (run_dir / "results.json").exists()
```

- [ ] **Step 2: Run planning tests to verify they fail**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_audit_target_lambda_plans_single_region_and_context tests/scope_runtime/test_audit_dispatch.py::test_audit_target_file_combines_targets_in_one_run -q
```

Expected: FAIL because `audit.main()` still derives modules from `--all`/`--services` only.

- [ ] **Step 3: Add target input resolution in audit runtime**

In `scope_runtime/audit.py`, import target helpers:

```python
from scope_runtime.targets import (
    TargetParseError,
    TargetScope,
    build_scope_metadata,
    module_for_target,
    parse_targets,
    read_target_file,
    required_work_items_for_targets,
)
```

Add helpers:

```python
def _requested_scope(args: argparse.Namespace) -> tuple[str, tuple[TargetScope, ...], list[str], list[str]]:
    if args.target:
        targets = parse_targets([args.target])
        pairs = required_work_items_for_targets(targets)
        modules = _ordered_unique([module for module, _region in pairs])
        regions = _ordered_unique([region for module, region in pairs if module not in GLOBAL_MODULES and module not in ACCOUNT_SCOPED_MODULES])
        return "target", targets, modules, regions
    if args.target_file:
        targets = read_target_file(Path(args.target_file))
        pairs = required_work_items_for_targets(targets)
        modules = _ordered_unique([module for module, _region in pairs])
        regions = _ordered_unique([region for module, region in pairs if module not in GLOBAL_MODULES and module not in ACCOUNT_SCOPED_MODULES])
        return "target", targets, modules, regions
    if args.all:
        modules = ALL_MODULES
        return "all", (), modules, _regions(args, modules)
    modules = _validate_modules(_split_csv(args.services))
    if not modules:
        raise SystemExit("--all, --services, --target, or --target-file is required")
    return "service", (), modules, _regions(args, modules)


def _ordered_unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            ordered.append(value)
            seen.add(value)
    return ordered
```

Update the start of `main()`:

```python
    try:
        scope_mode, target_scopes, modules, regions = _requested_scope(args)
    except TargetParseError as err:
        raise SystemExit(str(err)) from err
```

Replace the old `modules = ...` and `regions = _regions(...)` logic with these values. Add:

```python
    scope = build_scope_metadata(mode=scope_mode, targets=target_scopes)
```

Include `scope` in the manifest.

- [ ] **Step 4: Build target-specific work items**

Modify `_build_work_items()` to accept explicit module/region pairs:

```python
def _build_work_items(
    run_dir: Path,
    modules: list[str],
    regions: list[str],
    explicit_pairs: list[tuple[str, str]] | None = None,
) -> list[WorkItem]:
    items: list[WorkItem] = []
    modules = _validate_modules(modules)
    regions = _validate_regions(regions)
    pairs = explicit_pairs or [
        (module, region)
        for module in modules
        for region in _module_regions(module, regions)
    ]
    for module, region in pairs:
        items.append(
            WorkItem(
                module=module,
                region=region,
                enum_run_dir=run_dir / ".module-runs" / module / region,
                output_path=_module_region_path(run_dir, module, region),
                log_path=run_dir / "logs" / f"{module}-{region}.log",
                execution_region=_execution_region(module, region),
            )
        )
    return items
```

In `main()`, use:

```python
    explicit_pairs = required_work_items_for_targets(target_scopes) if scope_mode == "target" else None
    items = _build_work_items(run_dir=run_dir, modules=modules, regions=regions, explicit_pairs=explicit_pairs)
```

- [ ] **Step 5: Run planning tests to verify they pass**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_audit_target_lambda_plans_single_region_and_context tests/scope_runtime/test_audit_dispatch.py::test_audit_target_file_combines_targets_in_one_run -q
```

Expected: PASS after Task 5 filtering integration is also complete. If this step fails because unrelated resources are not filtered yet, keep the test in place and complete Task 5 before committing.

- [ ] **Step 6: Commit target planning**

Run only after the tests in Step 5 pass:

```bash
git add scope_runtime/audit.py scope_runtime/__main__.py tests/scope_runtime/test_audit_dispatch.py
git commit -m "feat: plan target-scoped audit work"
```

---

### Task 5: Apply Target Filter Before Aggregation

**Files:**
- Modify: `scope_runtime/audit.py`
- Test: `tests/scope_runtime/test_audit_dispatch.py`

- [ ] **Step 1: Add runtime filtering assertions**

Extend `test_audit_target_lambda_plans_single_region_and_context` from Task 4 with these assertions:

```python
    resources = [
        json.loads(line)
        for line in (run_dir / "resources.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [(resource["service"], resource["resource_id"], resource["scope_match"]) for resource in resources] == [
        ("iam", "LambdaExecRole", "context"),
        ("lambda", "my-func", "target"),
    ]
    assert all(resource["scope_source"] == "arn:aws:lambda:us-east-1:123456789012:function:my-func" for resource in resources)
```

Append this target status test:

```python
def test_audit_target_file_partial_when_one_target_not_found(monkeypatch, tmp_path: Path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        "arn:aws:s3:::existing-bucket\n"
        "arn:aws:sns:us-east-1:123456789012:missing-topic\n",
        encoding="utf-8",
    )

    def fake_run_command(command, log_path: Path):
        module = command[command.index("enum") + 1]
        region = command[command.index("--logical-region") + 1]
        run_dir = Path(command[command.index("--run-dir") + 1])
        resources = []
        if module == "s3":
            resources = [{"resource_type": "s3_bucket", "resource_id": "existing-bucket", "arn": "arn:aws:s3:::existing-bucket"}]
        payload = {
            "module": module,
            "account_id": "123456789012",
            "region": region,
            "status": "complete",
            "resources": resources,
            "coverage": [],
            "errors": [],
        }
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / f"{module}.json").write_text(json.dumps(payload), encoding="utf-8")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("", encoding="utf-8")
        return 0

    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    result = audit.main(["--target-file", str(target_file), "--run-dir", str(tmp_path / "run")])

    summary = json.loads((tmp_path / "run" / "summary.json").read_text(encoding="utf-8"))
    assert result == 1
    assert summary["status"] == "partial"
    assert summary["target_results"] == [
        {"target": "arn:aws:s3:::existing-bucket", "status": "resolved", "module": "s3", "region": "global"},
        {"target": "arn:aws:sns:us-east-1:123456789012:missing-topic", "status": "not_found", "module": "sns", "region": "us-east-1"},
    ]


def test_audit_target_error_when_all_targets_not_found(monkeypatch, tmp_path: Path):
    def fake_run_command(command, log_path: Path):
        module = command[command.index("enum") + 1]
        region = command[command.index("--logical-region") + 1]
        run_dir = Path(command[command.index("--run-dir") + 1])
        payload = {
            "module": module,
            "account_id": "123456789012",
            "region": region,
            "status": "complete",
            "resources": [],
            "coverage": [],
            "errors": [],
        }
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / f"{module}.json").write_text(json.dumps(payload), encoding="utf-8")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("", encoding="utf-8")
        return 0

    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    run_dir = tmp_path / "run"
    result = audit.main(["--target", "arn:aws:sns:us-east-1:123456789012:missing-topic", "--run-dir", str(run_dir)])

    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert result == 1
    assert summary["status"] == "error"
    assert summary["target_results"][0]["status"] == "not_found"
```

- [ ] **Step 2: Run runtime filtering tests to verify they fail**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_audit_target_lambda_plans_single_region_and_context tests/scope_runtime/test_audit_dispatch.py::test_audit_target_file_partial_when_one_target_not_found tests/scope_runtime/test_audit_target_error_when_all_targets_not_found -q
```

Expected: FAIL because outputs are not filtered and target-aware status is not computed.

- [ ] **Step 3: Implement target filter application**

In `scope_runtime/audit.py`, import:

```python
from scope_runtime.targets import filter_module_envelopes_for_targets
```

Add:

```python
def _apply_target_filter(run_dir: Path, items: list[WorkItem], targets: tuple[TargetScope, ...]) -> list[dict[str, str]]:
    envelopes: dict[tuple[str, str], dict] = {}
    for item in items:
        if not item.output_path.exists():
            continue
        with item.output_path.open(encoding="utf-8") as handle:
            envelopes[(item.module, item.region)] = json.load(handle)
    filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)
    for (module, region), payload in filtered.items():
        output_path = _module_region_path(run_dir, module, region)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target_results
```

Call this after `_run_work_items()` and before `aggregate_run()`:

```python
    target_results: list[dict[str, str]] = []
    if scope_mode == "target":
        target_results = _apply_target_filter(run_dir, items, target_scopes)
```

Pass `scope` and `target_results` into `aggregate_run()` after Task 6 updates its signature.

- [ ] **Step 4: Add target status override**

Add helper in `scope_runtime/audit.py`:

```python
def _derive_target_run_status(summary_status: str, target_results: list[dict[str, str]]) -> str:
    if not target_results:
        return summary_status
    resolved = sum(1 for result in target_results if result["status"] == "resolved")
    if resolved == len(target_results):
        return "complete" if summary_status == "complete" else summary_status
    if resolved == 0:
        return "error"
    return "partial"
```

After aggregation:

```python
    if scope_mode == "target":
        summary["target_results"] = target_results
        summary["status"] = _derive_target_run_status(summary["status"], target_results)
        (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
```

- [ ] **Step 5: Run runtime filtering tests to verify they pass**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_audit_target_lambda_plans_single_region_and_context tests/scope_runtime/test_audit_dispatch.py::test_audit_target_file_partial_when_one_target_not_found tests/scope_runtime/test_audit_target_error_when_all_targets_not_found -q
```

Expected: PASS.

- [ ] **Step 6: Commit runtime filtering**

Run:

```bash
git add scope_runtime/audit.py tests/scope_runtime/test_audit_dispatch.py
git commit -m "feat: apply target-scoped audit filtering"
```

---

### Task 6: Scope Metadata In Summary And Results

**Files:**
- Modify: `scope_runtime/aggregation.py`
- Modify: `scope_runtime/post_processing.py`
- Modify: `scope_runtime/audit.py`
- Test: `tests/scope_runtime/test_aggregation.py`
- Test: `tests/scope_runtime/test_post_processing.py`
- Test: `tests/scope_runtime/test_audit_dispatch.py`

- [ ] **Step 1: Add aggregation and post-processing tests**

In `tests/scope_runtime/test_aggregation.py`, add:

```python
def test_aggregate_run_writes_scope_metadata(tmp_path: Path):
    modules_dir = tmp_path / "modules" / "s3"
    modules_dir.mkdir(parents=True)
    (modules_dir / "global.json").write_text(
        json.dumps(
            {
                "module": "s3",
                "account_id": "123456789012",
                "region": "global",
                "status": "complete",
                "resources": [
                    {
                        "resource_type": "s3_bucket",
                        "resource_id": "my-bucket",
                        "arn": "arn:aws:s3:::my-bucket",
                        "scope_match": "target",
                        "scope_source": "arn:aws:s3:::my-bucket",
                    }
                ],
                "coverage": [],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )

    summary = aggregate_run(
        tmp_path,
        run_id="run-1",
        account=AccountContext(account_id="123456789012", account_name=None, account_owned=False, account_registry_source=None),
        failed_work_items=[],
        scope={"mode": "target", "targets": ["arn:aws:s3:::my-bucket"]},
    )

    assert summary["scope"] == {"mode": "target", "targets": ["arn:aws:s3:::my-bucket"]}
    row = json.loads((tmp_path / "resources.jsonl").read_text(encoding="utf-8"))
    assert row["scope_match"] == "target"
    assert row["scope_source"] == "arn:aws:s3:::my-bucket"
```

In `tests/scope_runtime/test_post_processing.py`, add:

```python
def test_build_results_includes_scope_metadata(tmp_path: Path):
    account = AccountContext(account_id="123456789012", account_name="dev", account_owned=True, account_registry_source="config/aws_accounts.json")
    results = build_results(
        run_dir=tmp_path,
        run_id="run-1",
        account=account,
        summary={
            "status": "complete",
            "modules": [],
            "scope": {"mode": "target", "targets": ["arn:aws:s3:::my-bucket"]},
        },
        graph={"nodes": [], "edges": []},
        timestamp="2026-05-21T00:00:00Z",
        post_processing_errors=[],
    )

    assert results["scope"] == {"mode": "target", "targets": ["arn:aws:s3:::my-bucket"]}
```

- [ ] **Step 2: Run metadata tests to verify they fail**

Run:

```bash
uv run pytest tests/scope_runtime/test_aggregation.py::test_aggregate_run_writes_scope_metadata tests/scope_runtime/test_post_processing.py::test_build_results_includes_scope_metadata -q
```

Expected: FAIL because `aggregate_run()` does not accept `scope` and `build_results()` does not emit it.

- [ ] **Step 3: Add scope metadata to aggregation**

Modify `scope_runtime/aggregation.py` signature:

```python
def aggregate_run(
    run_dir: Path,
    *,
    run_id: str,
    account: AccountContext,
    failed_work_items: list[dict[str, Any]],
    scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
```

Add to `summary`:

```python
        "scope": scope or {"mode": "service", "targets": []},
```

Update existing `aggregate_run()` call sites to pass `scope=scope`.

- [ ] **Step 4: Add scope metadata to results**

Modify `scope_runtime/post_processing.py` in `build_results()`:

```python
        "scope": summary.get("scope", {"mode": "service", "targets": []}),
```

Place it next to `source`, `run_id`, and account fields.

- [ ] **Step 5: Run metadata tests to verify they pass**

Run:

```bash
uv run pytest tests/scope_runtime/test_aggregation.py::test_aggregate_run_writes_scope_metadata tests/scope_runtime/test_post_processing.py::test_build_results_includes_scope_metadata -q
```

Expected: PASS.

- [ ] **Step 6: Run target runtime tests again**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_audit_target_lambda_plans_single_region_and_context tests/scope_runtime/test_audit_dispatch.py::test_audit_target_file_combines_targets_in_one_run -q
```

Expected: PASS.

- [ ] **Step 7: Commit scope metadata**

Run:

```bash
git add scope_runtime/aggregation.py scope_runtime/post_processing.py scope_runtime/audit.py tests/scope_runtime/test_aggregation.py tests/scope_runtime/test_post_processing.py tests/scope_runtime/test_audit_dispatch.py
git commit -m "feat: include audit scope metadata in outputs"
```

---

### Task 7: Selector Plumbing For Future Native Target Paths

**Files:**
- Modify: `scope_core/base_enum.py`
- Modify: `scope_core/contract.py`
- Modify: `scope_runtime/__main__.py`
- Test: `tests/scope_core/test_base_enum.py`

- [ ] **Step 1: Add backward-compatible selector tests**

Add these tests to `tests/scope_core/test_base_enum.py`:

```python
def test_dispatch_passes_selector_to_selector_aware_run(tmp_path: Path):
    received = {}

    def run(factory, region, selector=None):
        received["selector"] = selector
        return ModuleEnvelope(
            module="sts",
            account_id="123456789012",
            region=region,
            status="complete",
            resources=[],
            coverage=[],
            errors=[],
        )

    selector = {"mode": "target", "targets": [{"arn": "arn:aws:sts::123456789012:assumed-role/Admin/session"}]}
    dispatch(module_name="sts", run_fn=run, run_dir=tmp_path, region="global", factory=object(), selector=selector)

    assert received["selector"] == selector


def test_dispatch_keeps_two_argument_enumerators_working(tmp_path: Path):
    called = {}

    def run(factory, region):
        called["region"] = region
        return ModuleEnvelope(
            module="sts",
            account_id="123456789012",
            region=region,
            status="complete",
            resources=[],
            coverage=[],
            errors=[],
        )

    dispatch(module_name="sts", run_fn=run, run_dir=tmp_path, region="global", factory=object(), selector={"mode": "target"})

    assert called["region"] == "global"
```

- [ ] **Step 2: Run selector tests to verify they fail**

Run:

```bash
uv run pytest tests/scope_core/test_base_enum.py::test_dispatch_passes_selector_to_selector_aware_run tests/scope_core/test_base_enum.py::test_dispatch_keeps_two_argument_enumerators_working -q
```

Expected: FAIL because `dispatch()` has no `selector` parameter.

- [ ] **Step 3: Implement selector-aware dispatch**

In `scope_core/base_enum.py`, import `inspect` and update `dispatch()`:

```python
def dispatch(
    *,
    module_name: str,
    run_fn: Enumerator,
    run_dir: str | Path,
    region: str,
    factory: Any,
    selector: Any | None = None,
) -> Path:
```

Replace the direct call with:

```python
        envelope = _call_run_fn(run_fn, factory, region, selector)
```

Add:

```python
def _call_run_fn(run_fn: Enumerator, factory: Any, region: str, selector: Any | None) -> ModuleEnvelope:
    try:
        signature = inspect.signature(run_fn)
    except (TypeError, ValueError):
        return run_fn(factory, region)
    if "selector" in signature.parameters or len(signature.parameters) >= 3:
        return run_fn(factory, region, selector)
    return run_fn(factory, region)
```

- [ ] **Step 4: Document selector in contract**

In `scope_core/contract.py`, update the protocol call signature to:

```python
    def __call__(self, factory: Any, region: str, selector: Any | None = None) -> ModuleEnvelope:
        ...
```

- [ ] **Step 5: Add enum CLI selector forwarding**

In `scope_runtime/__main__.py`, add an optional enum parser argument:

```python
    enum_parser.add_argument("--selector-json", default=None)
```

Before `dispatch()`, parse it:

```python
        selector = json.loads(args.selector_json) if args.selector_json else None
```

Pass `selector=selector` to `dispatch()`. Import `json` at the top of the file.

- [ ] **Step 6: Run selector tests to verify they pass**

Run:

```bash
uv run pytest tests/scope_core/test_base_enum.py::test_dispatch_passes_selector_to_selector_aware_run tests/scope_core/test_base_enum.py::test_dispatch_keeps_two_argument_enumerators_working -q
```

Expected: PASS.

- [ ] **Step 7: Commit selector plumbing**

Run:

```bash
git add scope_core/base_enum.py scope_core/contract.py scope_runtime/__main__.py tests/scope_core/test_base_enum.py
git commit -m "feat: plumb optional enumerator selectors"
```

---

### Task 8: Full Regression And Real AWS Smoke Test

**Files:**
- No source edits unless verification finds a defect.

- [ ] **Step 1: Run Python runtime regression**

Run:

```bash
uv run pytest tests/scope_runtime tests/scope_core tests/enumerators -q
```

Expected: PASS.

- [ ] **Step 2: Run CLI help smoke**

Run:

```bash
uv run python -m scope_runtime audit --help
```

Expected output includes:

```text
--target TARGET
--target-file TARGET_FILE
```

- [ ] **Step 3: Run local fake target smoke with a temporary run directory**

Run:

```bash
uv run python -m scope_runtime audit --target arn:aws:s3:::this-bucket-should-not-exist-for-local-help-only --run-dir /tmp/scope-target-smoke
```

Expected: If real AWS credentials are present, this may call AWS. If no credentials are present, it should fail cleanly with a run directory and error summary rather than crashing with an argument/parser error. Remove `/tmp/scope-target-smoke` before re-running because the runtime intentionally refuses to overwrite run directories.

- [ ] **Step 4: Run real AWS target smoke with user-approved target ARN**

Use a known existing resource ARN supplied by the operator. Prefer S3 or IAM because they are global and fast. The operator must export `SCOPE_TARGET_ARN` before this step:

```bash
test -n "$SCOPE_TARGET_ARN"
uv run python -m scope_runtime audit --target "$SCOPE_TARGET_ARN" --output-dir runs --concurrency 4
```

Expected:

- Command exits `0` when the target exists and required calls are allowed.
- Printed path points to a new run directory.
- `manifest.json`, `summary.json`, `resources.jsonl`, and `results.json` all contain `"scope": {"mode": "target", ...}`.
- `resources.jsonl` contains the target resource with `scope_match="target"`.
- No unrelated resources from the same service are present.

- [ ] **Step 5: Inspect failed or partial real AWS output if needed**

If Step 4 exits non-zero, inspect:

Set `SCOPE_RUN_DIR` to the printed run directory, then run:

```bash
test -n "$SCOPE_RUN_DIR"
jq '.status, .scope, .target_results, .failed_items' "$SCOPE_RUN_DIR/summary.json"
jq '.post_processing.errors' "$SCOPE_RUN_DIR/results.json"
```

Expected: A denied or missing target is represented as `partial` or `error` in JSON, not as a Python traceback.

- [ ] **Step 6: Commit verification fixes only if needed**

If verification required code changes, commit them:

```bash
git add scope_runtime scope_core tests/scope_runtime tests/scope_core
git commit -m "fix: stabilize target-scoped audit runtime"
```

If no source edits were needed, do not create an empty commit.

---

## Self-Review

Spec coverage:

- `--target` and `--target-file`: Tasks 3 and 4.
- Newline target file with blank/comment handling: Task 1.
- ARN parser for all current SCOPE services: Task 1.
- Resource selector and optional enumerator API: Task 7.
- Minimum service/region planning: Task 4.
- No region discovery in target mode: Task 4.
- Target/context resource metadata: Tasks 2, 5, and 6.
- `manifest.json`, `summary.json`, `results.json` scope metadata: Tasks 4 and 6.
- Status semantics for complete/partial/error: Task 5.
- Backward compatibility for `--all` and `--services`: Task 8 regression suite.
- Real AWS smoke validation: Task 8.

No unsupported placeholders remain in the executable tasks. Native per-resource enumerator optimizations are intentionally not required for the first target-mode implementation because the approved design allows post-filtering where a module does not yet have a native selector path.
