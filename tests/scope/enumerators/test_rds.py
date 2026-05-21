from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from scope.enumerators.rds import run
from tests.scope.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "enum" / "rds"


def _expected_contract() -> dict:
    return json.loads((FIXTURE_DIR / "expected.json").read_text(encoding="utf-8"))


def _contract(envelope, expected: dict) -> dict:
    dumped = envelope.model_dump(mode="json")
    return {key: dumped[key] for key in expected}


def test_rds_matches_js_fixture_contract():
    rds = FakeClient(
        {
            "describe_db_instances": {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "test-db-instance",
                        "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:test-db-instance",
                        "Engine": "mysql",
                        "EngineVersion": "8.0.33",
                        "PubliclyAccessible": False,
                        "StorageEncrypted": True,
                        "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/aaaa-1111-bbbb-2222",
                        "IAMDatabaseAuthenticationEnabled": False,
                        "DeletionProtection": True,
                        "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-12345678", "Status": "active"}],
                        "MultiAZ": True,
                    },
                ],
            },
            "describe_db_snapshots": {
                "DBSnapshots": [
                    {
                        "DBSnapshotIdentifier": "test-snapshot-1",
                        "DBSnapshotArn": "arn:aws:rds:us-east-1:123456789012:snapshot:test-snapshot-1",
                        "Engine": "mysql",
                        "Encrypted": True,
                        "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/aaaa-1111-bbbb-2222",
                        "DBInstanceIdentifier": "test-db-instance",
                    },
                ],
            },
            "describe_db_snapshot_attributes": {
                "DBSnapshotAttributesResult": {
                    "DBSnapshotIdentifier": "test-snapshot-1",
                    "DBSnapshotAttributes": [
                        {
                            "AttributeName": "restore",
                            "AttributeValues": [],
                        },
                    ],
                },
            },
        }
    )
    expected = _expected_contract()

    envelope = run(FakeFactory(rds=rds), "us-east-1")

    assert normalize_envelope(_contract(envelope, expected)) == normalize_envelope(expected)


def test_rds_describe_db_instances_failure_returns_error_envelope():
    rds = FakeClient(
        {
            "describe_db_instances": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "DescribeDBInstances",
            ),
        }
    )

    envelope = run(FakeFactory(rds=rds), "us-east-1")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "rds.DescribeDBInstances"
    assert envelope.errors[0].code == "AccessDeniedException"
    coverage = next(entry for entry in envelope.coverage if entry.check == "describe_db_instances")
    assert coverage.status == "error"
    assert coverage.failed == 1


def test_rds_describe_snapshots_failure_marks_module_partial():
    rds = FakeClient(
        {
            "describe_db_instances": {"DBInstances": []},
            "describe_db_snapshots": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "DescribeDBSnapshots",
            ),
        }
    )

    envelope = run(FakeFactory(rds=rds), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.errors[0].operation == "rds.DescribeDBSnapshots"
    coverage = next(entry for entry in envelope.coverage if entry.check == "describe_db_snapshots")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_rds_snapshot_attributes_failure_marks_snapshot_partial():
    snapshot_arn = "arn:aws:rds:us-east-1:123456789012:snapshot:test-snapshot-1"
    rds = FakeClient(
        {
            "describe_db_instances": {"DBInstances": []},
            "describe_db_snapshots": {
                "DBSnapshots": [
                    {
                        "DBSnapshotIdentifier": "test-snapshot-1",
                        "DBSnapshotArn": snapshot_arn,
                        "Encrypted": True,
                    },
                ],
            },
            "describe_db_snapshot_attributes": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "DescribeDBSnapshotAttributes",
            ),
        }
    )

    envelope = run(FakeFactory(rds=rds), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources[0]["snapshot_attributes_status"] == "access_denied"
    assert envelope.errors[0].operation == "rds.DescribeDBSnapshotAttributes"
    assert envelope.errors[0].resource == snapshot_arn
    coverage = next(entry for entry in envelope.coverage if entry.check == "snapshot_attributes")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_rds_public_snapshot_emits_critical_finding():
    rds = FakeClient(
        {
            "describe_db_instances": {"DBInstances": []},
            "describe_db_snapshots": {
                "DBSnapshots": [
                    {
                        "DBSnapshotIdentifier": "public-snapshot",
                        "DBSnapshotArn": "arn:aws:rds:us-east-1:123456789012:snapshot:public-snapshot",
                        "Encrypted": False,
                    },
                ],
            },
            "describe_db_snapshot_attributes": {
                "DBSnapshotAttributesResult": {
                    "DBSnapshotAttributes": [
                        {
                            "AttributeName": "restore",
                            "AttributeValues": ["all", "111122223333"],
                        },
                    ],
                },
            },
        }
    )

    envelope = run(FakeFactory(rds=rds), "us-east-1")

    snapshot = envelope.resources[0]
    assert snapshot["public"] is True
    assert snapshot["shared_with"] == ["111122223333"]
    assert {finding["type"] for finding in snapshot["findings"]} == {
        "public_snapshot",
        "unencrypted_snapshot",
        "shared_snapshot",
    }
