import json

from tools.parity_diff import diff_envelopes, main, normalize_envelope


def test_normalize_removes_timestamp_and_orders_resources():
    envelope = {
        "module": "sts",
        "timestamp": "2026-05-18T12:00:00Z",
        "resources": [
            {"resource_type": "b", "resource_id": "2", "findings": [{"type": "z"}, {"type": "a"}]},
            {"resource_type": "a", "resource_id": "1", "findings": [{"type": "z"}, {"type": "a"}]},
        ],
    }

    normalized = normalize_envelope(envelope)

    assert "timestamp" not in normalized
    assert normalized["resources"][0]["resource_type"] == "a"
    assert normalized["resources"][0]["findings"] == [{"type": "z"}, {"type": "a"}]


def test_normalize_orders_resources_by_type_id_and_arn():
    envelope = {
        "resources": [
            {"resource_type": "bucket", "resource_id": "z", "arn": "arn:aws:s3:::z"},
            {"resource_type": "bucket", "resource_id": "a", "arn": "arn:aws:s3:::b"},
            {"resource_type": "bucket", "resource_id": "a", "arn": "arn:aws:s3:::a"},
        ],
    }

    normalized = normalize_envelope(envelope)

    assert normalized["resources"] == [
        {"arn": "arn:aws:s3:::a", "resource_id": "a", "resource_type": "bucket"},
        {"arn": "arn:aws:s3:::b", "resource_id": "a", "resource_type": "bucket"},
        {"arn": "arn:aws:s3:::z", "resource_id": "z", "resource_type": "bucket"},
    ]


def test_diff_envelopes_reports_semantic_difference():
    left = {"module": "sts", "status": "complete", "resources": []}
    right = {"module": "sts", "status": "partial", "resources": []}

    diff = diff_envelopes(left, right)

    assert diff["equal"] is False
    assert diff["left"]["status"] == "complete"
    assert diff["right"]["status"] == "partial"


def test_diff_envelopes_ignores_timestamp_and_resource_order():
    left = {
        "module": "sts",
        "timestamp": "2026-05-18T12:00:00Z",
        "resources": [
            {"resource_type": "b", "resource_id": "2"},
            {"resource_type": "a", "resource_id": "1"},
        ],
    }
    right = {
        "module": "sts",
        "timestamp": "2026-05-18T12:05:00Z",
        "resources": [
            {"resource_type": "a", "resource_id": "1"},
            {"resource_type": "b", "resource_id": "2"},
        ],
    }

    diff = diff_envelopes(left, right)

    assert diff["equal"] is True


def test_diff_envelopes_ignores_duplicate_resource_order_with_canonical_tiebreaker():
    left = {
        "resources": [
            {"resource_type": "bucket", "resource_id": "same", "arn": "arn", "name": "b"},
            {"resource_type": "bucket", "resource_id": "same", "arn": "arn", "name": "a"},
        ],
    }
    right = {
        "resources": [
            {"resource_type": "bucket", "resource_id": "same", "arn": "arn", "name": "a"},
            {"resource_type": "bucket", "resource_id": "same", "arn": "arn", "name": "b"},
        ],
    }

    diff = diff_envelopes(left, right)

    assert diff["equal"] is True
    assert [resource["name"] for resource in diff["left"]["resources"]] == ["a", "b"]


def test_diff_envelopes_ignores_coverage_and_error_order():
    left = {
        "coverage": [
            {"check": "b", "scope": "module_wide", "status": "complete", "succeeded": 1, "failed": 0, "skipped": 0},
            {"check": "a", "scope": "module_wide", "status": "complete", "succeeded": 1, "failed": 0, "skipped": 0},
        ],
        "errors": [
            {"operation": "b", "resource": "2", "code": "B", "message": "b"},
            {"operation": "a", "resource": "1", "code": "A", "message": "a"},
        ],
    }
    right = {
        "coverage": [
            {"check": "a", "scope": "module_wide", "status": "complete", "succeeded": 1, "failed": 0, "skipped": 0},
            {"check": "b", "scope": "module_wide", "status": "complete", "succeeded": 1, "failed": 0, "skipped": 0},
        ],
        "errors": [
            {"operation": "a", "resource": "1", "code": "A", "message": "a"},
            {"operation": "b", "resource": "2", "code": "B", "message": "b"},
        ],
    }

    diff = diff_envelopes(left, right)

    assert diff["equal"] is True
    assert [entry["check"] for entry in diff["left"]["coverage"]] == ["a", "b"]
    assert [error["operation"] for error in diff["left"]["errors"]] == ["a", "b"]


def test_main_prints_json_and_returns_exit_code(tmp_path, capsys):
    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    left.write_text(json.dumps({"timestamp": "left", "resources": []}), encoding="utf-8")
    right.write_text(json.dumps({"timestamp": "right", "resources": []}), encoding="utf-8")

    assert main([str(left), str(right)]) == 0
    assert json.loads(capsys.readouterr().out)["equal"] is True

    right.write_text(json.dumps({"status": "partial", "resources": []}), encoding="utf-8")

    assert main([str(left), str(right)]) == 1
    assert json.loads(capsys.readouterr().out)["equal"] is False
