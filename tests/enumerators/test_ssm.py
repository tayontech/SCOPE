from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from enumerators.ssm import run
from tests.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "enum" / "ssm"


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


def test_ssm_matches_js_fixture_contract():
    ssm = FakeClient(
        {
            "describe_parameters": {
                "Parameters": [
                    {
                        "Name": "/app/secret-key",
                        "Type": "SecureString",
                        "KeyId": "arn:aws:kms:us-east-1:123456789012:key/secure-key-id",
                        "LastModifiedDate": "2024-03-15T00:00:00.000Z",
                        "Version": 3,
                        "Tier": "Standard",
                        "DataType": "text",
                    },
                    {
                        "Name": "/app/config/region",
                        "Type": "String",
                        "LastModifiedDate": "2024-01-01T00:00:00.000Z",
                        "Version": 1,
                        "Tier": "Standard",
                        "DataType": "text",
                    },
                ],
            },
            "get_resource_policies": {"Policies": []},
        }
    )

    envelope = run(FakeFactory(ssm=ssm), "us-east-1")

    assert normalize_envelope(_contract(envelope)) == normalize_envelope(_expected_contract())


def test_ssm_describe_parameters_failure_returns_error_envelope():
    ssm = FakeClient(
        {
            "describe_parameters": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "DescribeParameters",
            ),
        }
    )

    envelope = run(FakeFactory(ssm=ssm), "us-east-1")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "ssm.DescribeParameters"
    assert envelope.errors[0].code == "AccessDeniedException"
    coverage = next(entry for entry in envelope.coverage if entry.check == "describe_parameters")
    assert coverage.status == "error"
    assert coverage.failed == 1


def test_ssm_resource_policy_access_denied_is_optional_skip():
    ssm = FakeClient(
        {
            "describe_parameters": {
                "Parameters": [
                    {
                        "Name": "/app/secret-key",
                        "Type": "SecureString",
                        "LastModifiedDate": "2024-03-15T00:00:00.000Z",
                        "Version": 3,
                    },
                ],
            },
            "get_resource_policies": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetResourcePolicies",
            ),
        }
    )

    envelope = run(FakeFactory(ssm=ssm), "us-east-1")

    assert envelope.status == "complete"
    assert envelope.errors == []
    assert envelope.resources[0]["resource_policy_status"] == "access_denied"
    coverage = next(entry for entry in envelope.coverage if entry.check == "resource_policy")
    assert coverage.status == "skipped"
    assert coverage.skipped == 1
    assert coverage.reasons[0].code == "access_denied"
