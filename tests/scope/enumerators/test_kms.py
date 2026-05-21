from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from scope.enumerators.kms import run
from tests.scope.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "enum" / "kms"


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


def test_kms_matches_js_fixture_contract():
    kms = FakeClient(
        {
            "list_keys": {
                "Keys": [
                    {"KeyId": "aaaa-1111-bbbb-2222"},
                    {"KeyId": "cccc-3333-dddd-4444"},
                ],
            },
            "describe_key": [
                {
                    "KeyMetadata": {
                        "KeyId": "aaaa-1111-bbbb-2222",
                        "Arn": "arn:aws:kms:us-east-1:123456789012:key/aaaa-1111-bbbb-2222",
                        "KeyManager": "CUSTOMER",
                        "KeyState": "Enabled",
                        "KeyUsage": "ENCRYPT_DECRYPT",
                        "Origin": "AWS_KMS",
                        "Description": "My test key",
                    },
                },
                {
                    "KeyMetadata": {
                        "KeyId": "cccc-3333-dddd-4444",
                        "Arn": "arn:aws:kms:us-east-1:123456789012:key/cccc-3333-dddd-4444",
                        "KeyManager": "AWS",
                        "KeyState": "Enabled",
                        "KeyUsage": "ENCRYPT_DECRYPT",
                        "Origin": "AWS_KMS",
                        "Description": "AWS managed key",
                    },
                },
            ],
            "get_key_policy": {
                "Policy": (
                    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                    '"Principal":{"AWS":"arn:aws:iam::123456789012:root"},'
                    '"Action":"kms:*","Resource":"*"}]}'
                ),
            },
            "list_grants": {"Grants": []},
            "get_key_rotation_status": {"KeyRotationEnabled": True},
        }
    )

    envelope = run(FakeFactory(kms=kms), "us-east-1")

    assert normalize_envelope(_contract(envelope)) == normalize_envelope(_expected_contract())


def test_kms_list_keys_failure_returns_error_envelope():
    kms = FakeClient(
        {
            "list_keys": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListKeys",
            ),
        }
    )

    envelope = run(FakeFactory(kms=kms), "us-east-1")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "kms.ListKeys"
    assert envelope.errors[0].code == "AccessDeniedException"
    coverage = next(entry for entry in envelope.coverage if entry.check == "list_keys")
    assert coverage.status == "error"
    assert coverage.failed == 1


def test_kms_describe_key_failure_marks_module_partial():
    kms = FakeClient(
        {
            "list_keys": {"Keys": [{"KeyId": "aaaa-1111-bbbb-2222"}]},
            "describe_key": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "DescribeKey",
            ),
        }
    )

    envelope = run(FakeFactory(kms=kms), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "kms.DescribeKey"
    assert envelope.errors[0].resource == "aaaa-1111-bbbb-2222"
    coverage = next(entry for entry in envelope.coverage if entry.check == "describe_key")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_kms_key_policy_failure_marks_key_partial():
    key_arn = "arn:aws:kms:us-east-1:123456789012:key/aaaa-1111-bbbb-2222"
    kms = FakeClient(
        {
            "list_keys": {"Keys": [{"KeyId": "aaaa-1111-bbbb-2222"}]},
            "describe_key": {
                "KeyMetadata": {
                    "KeyId": "aaaa-1111-bbbb-2222",
                    "Arn": key_arn,
                    "KeyManager": "CUSTOMER",
                    "KeyState": "Enabled",
                },
            },
            "get_key_policy": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetKeyPolicy",
            ),
            "list_grants": {"Grants": []},
            "get_key_rotation_status": {"KeyRotationEnabled": True},
        }
    )

    envelope = run(FakeFactory(kms=kms), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources[0]["policy_status"] == "access_denied"
    assert envelope.errors[0].operation == "kms.GetKeyPolicy"
    assert envelope.errors[0].resource == key_arn
    coverage = next(entry for entry in envelope.coverage if entry.check == "key_policy")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_kms_rotation_unsupported_is_optional_skip():
    key_arn = "arn:aws:kms:us-east-1:123456789012:key/aaaa-1111-bbbb-2222"
    kms = FakeClient(
        {
            "list_keys": {"Keys": [{"KeyId": "aaaa-1111-bbbb-2222"}]},
            "describe_key": {
                "KeyMetadata": {
                    "KeyId": "aaaa-1111-bbbb-2222",
                    "Arn": key_arn,
                    "KeyManager": "CUSTOMER",
                    "KeyState": "Enabled",
                },
            },
            "get_key_policy": {"Policy": "{}"},
            "list_grants": {"Grants": []},
            "get_key_rotation_status": ClientError(
                {"Error": {"Code": "UnsupportedOperationException", "Message": "unsupported"}},
                "GetKeyRotationStatus",
            ),
        }
    )

    envelope = run(FakeFactory(kms=kms), "us-east-1")

    assert envelope.status == "complete"
    assert envelope.errors == []
    assert envelope.resources[0]["rotation_enabled"] is None
    assert envelope.resources[0]["rotation_status"] == "unsupported"
    coverage = next(entry for entry in envelope.coverage if entry.check == "rotation_status")
    assert coverage.status == "skipped"
    assert coverage.skipped == 1
