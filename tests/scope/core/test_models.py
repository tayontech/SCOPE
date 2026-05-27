import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from scope.core.models import CoverageEntry, ErrorRecord, ModuleEnvelope, TaskResult


def test_module_envelope_serializes_current_contract():
    envelope = ModuleEnvelope(
        module="sts",
        account_id="123456789012",
        region="global",
        status="complete",
        timestamp=datetime(2026, 5, 18, 12, 0, tzinfo=timezone.utc),
        resources=[{"resource_type": "sts_identity", "resource_id": "caller"}],
        coverage=[],
        errors=[],
    )

    dumped = envelope.model_dump()
    payload = json.loads(envelope.model_dump_json())

    assert payload["module"] == "sts"
    assert payload["account_id"] == "123456789012"
    assert payload["region"] == "global"
    assert payload["status"] == "complete"
    assert payload["resources"] == [{"resource_type": "sts_identity", "resource_id": "caller"}]
    assert "findings" not in payload
    assert payload["coverage"] == []
    assert payload["errors"] == []
    assert dumped["timestamp"] == datetime(2026, 5, 18, 12, 0, tzinfo=timezone.utc)
    assert payload["timestamp"] == "2026-05-18T12:00:00Z"


def test_coverage_status_allows_skipped():
    entry = CoverageEntry(
        check="organizations",
        scope="module_wide",
        status="skipped",
        succeeded=0,
        failed=0,
        skipped=1,
        reasons=[],
    )

    assert entry.status == "skipped"


def test_unknown_account_id_only_allowed_for_error_status():
    ModuleEnvelope(
        module="sts",
        account_id="unknown",
        region="global",
        status="error",
        resources=[],
        coverage=[],
        errors=[ErrorRecord(operation="sts.GetCallerIdentity", resource=None, code="Error", message="boom")],
    )

    with pytest.raises(ValidationError):
        ModuleEnvelope(
            module="sts",
            account_id="unknown",
            region="global",
            status="complete",
            resources=[],
            coverage=[],
            errors=[],
        )


def test_error_record_message_is_optional():
    record = ErrorRecord(operation="x", code="Y")

    assert record.message is None


def test_task_result_preserves_original_exception():
    error = RuntimeError("bad item")
    result = TaskResult(
        index=0,
        item="item",
        ok=False,
        error=ErrorRecord(operation="worker", code="RuntimeError", message="bad item"),
        exception=error,
    )

    assert result.exception is error


def test_module_envelope_requires_resources():
    with pytest.raises(ValidationError):
        ModuleEnvelope(
            module="sts",
            account_id="123456789012",
            region="global",
            status="complete",
            coverage=[],
            errors=[],
        )


def test_module_envelope_does_not_serialize_legacy_findings_extra():
    envelope = ModuleEnvelope(
        module="sts",
        account_id="123456789012",
        region="global",
        status="complete",
        resources=[],
        findings=[],
        coverage=[],
        errors=[],
    )

    payload = json.loads(envelope.model_dump_json())

    assert payload["resources"] == []
    assert "findings" not in payload


def test_module_envelope_preserves_unrelated_extra_metadata():
    envelope = ModuleEnvelope(
        module="sts",
        account_id="123456789012",
        region="global",
        status="complete",
        resources=[],
        inventory_version="2026-05-20",
        coverage=[],
        errors=[],
    )

    payload = json.loads(envelope.model_dump_json())

    assert payload["inventory_version"] == "2026-05-20"
    assert "findings" not in payload


def test_schema_contains_coverage_status_skipped():
    schema = ModuleEnvelope.model_json_schema()
    coverage_status = schema["$defs"]["CoverageEntry"]["properties"]["status"]["enum"]

    assert "skipped" in coverage_status


def test_schema_contains_module_enum_values():
    schema = ModuleEnvelope.model_json_schema()
    module_enum = schema["properties"]["module"]["enum"]

    assert "sts" in module_enum
    assert "bedrock" in module_enum
    assert "cloudfront" in module_enum
    assert "ecs" in module_enum
    assert "route53" in module_enum


def test_schema_regeneration_helpers_render_required_contract():
    from tools.regen_schemas import generate_module_schema, render_schema

    schema = generate_module_schema()
    rendered = json.loads(render_schema())

    assert "oneOf" in schema["properties"]["account_id"]
    assert "timestamp" in schema["required"]
    assert "resources" in schema["required"]
    assert "findings" not in schema["required"]
    assert "resources" in schema["properties"]
    assert "findings" not in schema["properties"]
    assert rendered["required"] == schema["required"]
