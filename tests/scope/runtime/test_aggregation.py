from __future__ import annotations

import json
from pathlib import Path

from scope.runtime.aggregation import aggregate_run, derive_run_status
from scope.runtime.run_context import AccountContext


def _write_envelope(
    path: Path,
    module: str,
    region: str,
    resources: list[dict],
    errors: list[dict] | None = None,
    coverage: list[dict] | None = None,
    status: str = "complete",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "module": module,
                "account_id": "123456789012",
                "region": region,
                "status": status,
                "resources": resources,
                "coverage": coverage or [],
                "errors": errors or [],
            }
        ),
        encoding="utf-8",
    )


def test_derive_run_status_rules() -> None:
    assert derive_run_status(valid_count=2, failed_count=0) == "complete"
    assert derive_run_status(valid_count=2, failed_count=1) == "partial"
    assert derive_run_status(valid_count=0, failed_count=2) == "error"
    assert derive_run_status(valid_count=0, failed_count=0) == "error"


def test_aggregate_run_writes_resources_jsonl_and_summary(tmp_path: Path) -> None:
    _write_envelope(
        tmp_path / "modules" / "ec2" / "us-east-1.json",
        "ec2",
        "us-east-1",
        [
            {
                "resource_type": "ec2_instance",
                "resource_id": "i-123",
                "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-123",
            }
        ],
    )
    _write_envelope(
        tmp_path / "modules" / "iam" / "global.json",
        "iam",
        "global",
        [
            {
                "resource_type": "iam_user",
                "resource_id": "alice",
                "arn": "arn:aws:iam::123456789012:user/alice",
            }
        ],
    )
    context = AccountContext("123456789012", "prod", True, "config/accounts.json")

    summary = aggregate_run(
        tmp_path,
        run_id="prod-123456789012-2026-05-21T003147Z",
        account=context,
        failed_work_items=[],
    )

    resources_path = tmp_path / "resources.jsonl"
    rows = [json.loads(line) for line in resources_path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2
    assert rows[0]["account_id"] == "123456789012"
    assert rows[0]["account_name"] == "prod"
    assert rows[0]["account_owned"] is True
    assert rows[0]["run_id"] == "prod-123456789012-2026-05-21T003147Z"
    assert rows[0]["service"] == "ec2"
    assert rows[0]["region"] == "us-east-1"
    assert rows[0]["source_path"].startswith("modules/")
    assert summary["status"] == "complete"
    assert summary["total_resources"] == 2
    assert summary["services"] == {
        "ec2": {"resources": 1, "errors": 0, "skipped": 0, "regions": 1, "statuses": {"complete": 1}},
        "iam": {"resources": 1, "errors": 0, "skipped": 0, "regions": 1, "statuses": {"complete": 1}},
    }
    assert (tmp_path / "summary.json").exists()


def test_aggregate_run_writes_scope_metadata(tmp_path: Path) -> None:
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
        account=AccountContext(
            account_id="123456789012",
            account_name=None,
            account_owned=False,
            account_registry_source=None,
        ),
        failed_work_items=[],
        scope={"mode": "target", "targets": ["arn:aws:s3:::my-bucket"]},
    )

    assert summary["scope"] == {"mode": "target", "targets": ["arn:aws:s3:::my-bucket"]}
    row = json.loads((tmp_path / "resources.jsonl").read_text(encoding="utf-8"))
    assert row["scope_match"] == "target"
    assert row["scope_source"] == "arn:aws:s3:::my-bucket"


def test_aggregate_run_records_invalid_module_as_failed(tmp_path: Path) -> None:
    bad_path = tmp_path / "modules" / "sns" / "us-east-1.json"
    bad_path.parent.mkdir(parents=True, exist_ok=True)
    bad_path.write_text("{bad json", encoding="utf-8")
    context = AccountContext("123456789012", None, False, None)

    summary = aggregate_run(
        tmp_path,
        run_id="external-123456789012-2026-05-21T003147Z",
        account=context,
        failed_work_items=[],
    )

    assert summary["status"] == "error"
    assert summary["failed_count"] == 1
    assert summary["failed_items"][0]["path"] == "modules/sns/us-east-1.json"


def test_aggregate_run_records_undecodable_module_as_failed(tmp_path: Path) -> None:
    bad_path = tmp_path / "modules" / "sns" / "us-east-1.json"
    bad_path.parent.mkdir(parents=True, exist_ok=True)
    bad_path.write_bytes(b"\xff\xfe\xfa")
    context = AccountContext("123456789012", None, False, None)

    summary = aggregate_run(
        tmp_path,
        run_id="external-123456789012-2026-05-21T003147Z",
        account=context,
        failed_work_items=[],
    )

    resources_path = tmp_path / "resources.jsonl"
    assert summary["status"] == "error"
    assert summary["failed_count"] == 1
    assert summary["failed_items"][0]["path"] == "modules/sns/us-east-1.json"
    assert summary["failed_items"][0]["error"] == "UnicodeDecodeError"
    assert resources_path.exists()
    assert resources_path.read_text(encoding="utf-8") == ""


def test_aggregate_run_with_valid_and_failed_items_is_partial(tmp_path: Path) -> None:
    _write_envelope(
        tmp_path / "modules" / "ec2" / "us-east-1.json",
        "ec2",
        "us-east-1",
        [
            {"resource_type": "ec2_instance", "resource_id": "i-123"},
            {"resource_type": "ec2_instance", "resource_id": "i-456"},
        ],
    )
    bad_path = tmp_path / "modules" / "sns" / "us-east-1.json"
    bad_path.parent.mkdir(parents=True, exist_ok=True)
    bad_path.write_text("{bad json", encoding="utf-8")
    context = AccountContext("123456789012", "prod", True, "config/accounts.json")

    summary = aggregate_run(
        tmp_path,
        run_id="prod-123456789012-2026-05-21T003147Z",
        account=context,
        failed_work_items=[
            {
                "service": "sqs",
                "region": "us-west-2",
                "error": "worker failed",
            }
        ],
    )

    assert summary["status"] == "partial"
    assert summary["failed_count"] == 2
    assert summary["failed_items"] == [
        {"service": "sqs", "region": "us-west-2", "error": "worker failed"},
        {"path": "modules/sns/us-east-1.json", "error": "JSONDecodeError"},
    ]
    assert summary["services"] == {
        "ec2": {"resources": 2, "errors": 0, "skipped": 0, "regions": 1, "statuses": {"complete": 1}}
    }


def test_resource_context_fields_win_and_conflicts_are_preserved(tmp_path: Path) -> None:
    _write_envelope(
        tmp_path / "modules" / "iam" / "global.json",
        "iam",
        "global",
        [
            {
                "resource_type": "iam_policy",
                "resource_id": "policy-1",
                "run_id": "resource-run",
                "account_id": "999988887777",
                "account_name": "resource-account",
                "account_owned": False,
                "service": "resource-service",
                "region": "us-east-1",
                "source_path": "resource/path.json",
            }
        ],
    )
    context = AccountContext("123456789012", "prod", True, "config/accounts.json")

    aggregate_run(
        tmp_path,
        run_id="prod-123456789012-2026-05-21T003147Z",
        account=context,
        failed_work_items=[],
    )

    row = json.loads((tmp_path / "resources.jsonl").read_text(encoding="utf-8"))
    assert row["run_id"] == "prod-123456789012-2026-05-21T003147Z"
    assert row["account_id"] == "123456789012"
    assert row["account_name"] == "prod"
    assert row["account_owned"] is True
    assert row["service"] == "iam"
    assert row["region"] == "global"
    assert row["source_path"] == "modules/iam/global.json"
    assert row["resource_run_id"] == "resource-run"
    assert row["resource_account_id"] == "999988887777"
    assert row["resource_account_name"] == "resource-account"
    assert row["resource_account_owned"] is False
    assert row["resource_service"] == "resource-service"
    assert row["resource_region"] == "us-east-1"
    assert row["resource_source_path"] == "resource/path.json"


def test_resource_context_conflict_uses_second_escape_when_prefixed_key_exists(tmp_path: Path) -> None:
    _write_envelope(
        tmp_path / "modules" / "iam" / "global.json",
        "iam",
        "global",
        [
            {
                "resource_type": "iam_policy",
                "resource_id": "policy-1",
                "account_id": "999988887777",
                "resource_account_id": "existing-resource-account",
                "region": "us-east-1",
                "resource_region": "existing-resource-region",
            }
        ],
    )
    context = AccountContext("123456789012", "prod", True, "config/accounts.json")

    aggregate_run(
        tmp_path,
        run_id="prod-123456789012-2026-05-21T003147Z",
        account=context,
        failed_work_items=[],
    )

    row = json.loads((tmp_path / "resources.jsonl").read_text(encoding="utf-8"))
    assert row["account_id"] == "123456789012"
    assert row["region"] == "global"
    assert row["resource_account_id"] == "existing-resource-account"
    assert row["resource_context_account_id"] == "999988887777"
    assert row["resource_region"] == "existing-resource-region"
    assert row["resource_context_region"] == "us-east-1"


def test_resource_context_conflict_uses_numbered_escape_when_prior_escapes_exist(tmp_path: Path) -> None:
    _write_envelope(
        tmp_path / "modules" / "iam" / "global.json",
        "iam",
        "global",
        [
            {
                "resource_type": "iam_policy",
                "resource_id": "policy-1",
                "account_id": "999988887777",
                "resource_account_id": "existing-resource-account",
                "resource_context_account_id": "existing-context-account",
            }
        ],
    )
    context = AccountContext("123456789012", "prod", True, "config/accounts.json")

    aggregate_run(
        tmp_path,
        run_id="prod-123456789012-2026-05-21T003147Z",
        account=context,
        failed_work_items=[],
    )

    row = json.loads((tmp_path / "resources.jsonl").read_text(encoding="utf-8"))
    assert row["account_id"] == "123456789012"
    assert row["resource_account_id"] == "existing-resource-account"
    assert row["resource_context_account_id"] == "existing-context-account"
    assert row["resource_context_2_account_id"] == "999988887777"


def test_aggregate_run_with_no_outputs_is_error_and_writes_empty_resources(tmp_path: Path) -> None:
    context = AccountContext("123456789012", "prod", True, "config/accounts.json")

    summary = aggregate_run(
        tmp_path,
        run_id="prod-123456789012-2026-05-21T003147Z",
        account=context,
        failed_work_items=[],
    )

    resources_path = tmp_path / "resources.jsonl"
    assert summary["status"] == "error"
    assert summary["valid_count"] == 0
    assert summary["failed_count"] == 0
    assert summary["total_resources"] == 0
    assert resources_path.exists()
    assert resources_path.read_text(encoding="utf-8") == ""


def test_service_totals_roll_up_multiple_regions_for_same_service(tmp_path: Path) -> None:
    _write_envelope(
        tmp_path / "modules" / "ec2" / "us-east-1.json",
        "ec2",
        "us-east-1",
        [
            {"resource_type": "ec2_instance", "resource_id": "i-123"},
            {"resource_type": "ec2_instance", "resource_id": "i-456"},
        ],
        errors=[{"operation": "DescribeInstances", "code": "Throttled"}],
        status="partial",
    )
    _write_envelope(
        tmp_path / "modules" / "ec2" / "us-west-2.json",
        "ec2",
        "us-west-2",
        [{"resource_type": "ec2_instance", "resource_id": "i-789"}],
    )
    context = AccountContext("123456789012", "prod", True, "config/accounts.json")

    summary = aggregate_run(
        tmp_path,
        run_id="prod-123456789012-2026-05-21T003147Z",
        account=context,
        failed_work_items=[],
    )

    assert summary["services"]["ec2"] == {
        "resources": 3,
        "errors": 1,
        "skipped": 0,
        "regions": 2,
        "statuses": {"partial": 1, "complete": 1},
    }


def test_aggregate_run_summarizes_skipped_coverage(tmp_path: Path) -> None:
    _write_envelope(
        tmp_path / "modules" / "ec2" / "us-east-1.json",
        "ec2",
        "us-east-1",
        [{"resource_type": "ec2_instance", "resource_id": "i-123"}],
        coverage=[
            {
                "check": "DescribeInstanceAttribute",
                "scope": "per_resource",
                "status": "skipped",
                "succeeded": 0,
                "failed": 0,
                "skipped": 3,
                "reasons": [],
            }
        ],
    )
    context = AccountContext("123456789012", "prod", True, "config/accounts.json")

    summary = aggregate_run(
        tmp_path,
        run_id="prod-123456789012-2026-05-21T003147Z",
        account=context,
        failed_work_items=[],
    )

    assert summary["total_skipped"] == 3
    assert summary["services"]["ec2"]["skipped"] == 3
    assert summary["modules"] == [
        {
            "module": "ec2",
            "region": "us-east-1",
            "status": "complete",
            "resources": 1,
            "errors": 0,
            "skipped": 3,
            "path": "modules/ec2/us-east-1.json",
        }
    ]
