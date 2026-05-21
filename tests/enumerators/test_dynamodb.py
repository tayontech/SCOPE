from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from enumerators.dynamodb import run
from tests.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "enum" / "dynamodb"


def _expected_contract() -> dict:
    return json.loads((FIXTURE_DIR / "expected.json").read_text(encoding="utf-8"))


def _contract(envelope) -> dict:
    dumped = envelope.model_dump(mode="json")
    return {
        "resources": dumped["resources"],
        "status": dumped["status"],
        "coverage": dumped["coverage"],
        "errors": dumped["errors"],
    }


def test_dynamodb_matches_js_fixture_contract():
    dynamodb = FakeClient(
        {
            "list_tables": {"TableNames": ["TestTable"], "LastEvaluatedTableName": None},
            "describe_table": {
                "Table": {
                    "TableName": "TestTable",
                    "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/TestTable",
                    "TableStatus": "ACTIVE",
                    "SSEDescription": {
                        "SSEType": "KMS",
                        "KMSMasterKeyArn": "arn:aws:kms:us-east-1:123456789012:key/test-key-id",
                    },
                    "StreamSpecification": {
                        "StreamEnabled": True,
                        "StreamViewType": "NEW_AND_OLD_IMAGES",
                    },
                    "DeletionProtectionEnabled": True,
                    "TableClassSummary": {"TableClass": "STANDARD"},
                },
            },
            "describe_continuous_backups": {
                "ContinuousBackupsDescription": {
                    "ContinuousBackupsStatus": "ENABLED",
                    "PointInTimeRecoveryDescription": {
                        "PointInTimeRecoveryStatus": "ENABLED",
                    },
                },
            },
            "list_backups": {
                "BackupSummaries": [
                    {
                        "BackupArn": (
                            "arn:aws:dynamodb:us-east-1:123456789012:table/"
                            "TestTable/backup/01234567890000-abcdef01"
                        ),
                    },
                ],
            },
            "get_resource_policy": {},
        }
    )

    envelope = run(FakeFactory(dynamodb=dynamodb), "us-east-1")

    assert normalize_envelope(_contract(envelope)) == normalize_envelope(_expected_contract())


def test_dynamodb_list_tables_failure_returns_error_envelope():
    dynamodb = FakeClient(
        {
            "list_tables": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListTables",
            ),
        }
    )

    envelope = run(FakeFactory(dynamodb=dynamodb), "us-east-1")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "dynamodb.ListTables"
    assert envelope.errors[0].code == "AccessDeniedException"
    coverage = next(entry for entry in envelope.coverage if entry.check == "list_tables")
    assert coverage.status == "error"
    assert coverage.failed == 1


def test_dynamodb_describe_table_failure_marks_module_partial():
    dynamodb = FakeClient(
        {
            "list_tables": {"TableNames": ["TestTable"], "LastEvaluatedTableName": None},
            "describe_table": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "DescribeTable",
            ),
        }
    )

    envelope = run(FakeFactory(dynamodb=dynamodb), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "dynamodb.DescribeTable"
    assert envelope.errors[0].resource == "TestTable"
    coverage = next(entry for entry in envelope.coverage if entry.check == "describe_table")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_dynamodb_optional_backup_access_denied_is_skipped_not_partial():
    table_arn = "arn:aws:dynamodb:us-east-1:123456789012:table/TestTable"
    dynamodb = FakeClient(
        {
            "list_tables": {"TableNames": ["TestTable"], "LastEvaluatedTableName": None},
            "describe_table": {"Table": {"TableName": "TestTable", "TableArn": table_arn}},
            "describe_continuous_backups": {},
            "list_backups": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListBackups",
            ),
            "get_resource_policy": {},
        }
    )

    envelope = run(FakeFactory(dynamodb=dynamodb), "us-east-1")

    assert envelope.status == "complete"
    assert envelope.errors == []
    assert envelope.resources[0]["backups_status"] == "access_denied"
    coverage = next(entry for entry in envelope.coverage if entry.check == "list_backups")
    assert coverage.status == "skipped"
    assert coverage.skipped == 1
