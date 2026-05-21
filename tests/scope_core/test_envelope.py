import json
from pathlib import Path

from scope_core.envelope import create_envelope, write_envelope
from scope_core.models import ErrorRecord


def test_write_envelope_creates_module_json(tmp_path: Path):
    envelope = create_envelope(
        module="sts",
        account_id="123456789012",
        region="global",
        status="complete",
        resources=[{"resource_type": "sts_identity"}],
        coverage=[],
        errors=[],
    )

    path = write_envelope(tmp_path, envelope)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert path == tmp_path / "sts.json"
    assert payload["module"] == "sts"
    assert payload["resources"] == [{"resource_type": "sts_identity"}]
    assert "findings" not in payload
    assert payload["coverage"] == []
    assert payload["errors"] == []


def test_create_envelope_preserves_resources_coverage_and_errors():
    error = ErrorRecord(operation="sts.GetCallerIdentity", code="AccessDenied", message="denied")
    envelope = create_envelope(
        module="sts",
        account_id="123456789012",
        region="global",
        status="partial",
        resources=[{"resource_type": "sts_identity", "resource_id": "caller"}],
        coverage=[],
        errors=[error],
    )

    assert envelope.resources == [{"resource_type": "sts_identity", "resource_id": "caller"}]
    assert envelope.coverage == []
    assert envelope.errors == [error]


def test_error_envelope_allows_unknown_account(tmp_path: Path):
    envelope = create_envelope(
        module="sts",
        account_id="unknown",
        region="global",
        status="error",
        resources=[],
        coverage=[],
        errors=[ErrorRecord(operation="sts.GetCallerIdentity", code="AccessDenied", message="denied")],
    )

    path = write_envelope(tmp_path, envelope)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["account_id"] == "unknown"
    assert payload["status"] == "error"
    assert payload["resources"] == []
    assert "findings" not in payload
