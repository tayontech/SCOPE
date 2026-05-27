from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from scope.enumerators.secrets import run
from tests.scope.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "enum" / "secrets"


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


def test_secrets_matches_js_fixture_contract():
    secrets = FakeClient(
        {
            "list_secrets": {
                "SecretList": [
                    {
                        "Name": "my-test-secret",
                        "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-test-secret-AbCdEf",
                        "RotationEnabled": False,
                        "LastRotatedDate": None,
                        "LastAccessedDate": None,
                        "KmsKeyId": None,
                    },
                ],
            },
            "get_resource_policy": {"ResourcePolicy": None},
        }
    )

    envelope = run(FakeFactory(secrets=secrets), "us-east-1")

    assert normalize_envelope(_contract(envelope)) == normalize_envelope(_expected_contract())


def test_secrets_list_secrets_failure_returns_error_envelope():
    secrets = FakeClient(
        {
            "list_secrets": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListSecrets",
            ),
        }
    )

    envelope = run(FakeFactory(secrets=secrets), "us-east-1")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "secretsmanager.ListSecrets"
    assert envelope.errors[0].code == "AccessDeniedException"
    coverage = next(entry for entry in envelope.coverage if entry.check == "list_secrets")
    assert coverage.status == "error"
    assert coverage.failed == 1


def test_secrets_resource_policy_access_denied_marks_secret_partial():
    secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-test-secret-AbCdEf"
    secrets = FakeClient(
        {
            "list_secrets": {
                "SecretList": [
                    {
                        "Name": "my-test-secret",
                        "ARN": secret_arn,
                        "RotationEnabled": True,
                    },
                ],
            },
            "get_resource_policy": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetResourcePolicy",
            ),
        }
    )

    envelope = run(FakeFactory(secrets=secrets), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources[0]["resource_policy_status"] == "access_denied"
    assert envelope.errors[0].operation == "secretsmanager.GetResourcePolicy"
    assert envelope.errors[0].resource == secret_arn
    coverage = next(entry for entry in envelope.coverage if entry.check == "resource_policy")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_secrets_resource_not_found_between_list_and_policy_is_not_error():
    secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:deleted-AbCdEf"
    secrets = FakeClient(
        {
            "list_secrets": {"SecretList": [{"Name": "deleted", "ARN": secret_arn}]},
            "get_resource_policy": ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "missing"}},
                "GetResourcePolicy",
            ),
        }
    )

    envelope = run(FakeFactory(secrets=secrets), "us-east-1")

    assert envelope.status == "complete"
    assert envelope.resources == []
    assert envelope.errors == []
    coverage = next(entry for entry in envelope.coverage if entry.check == "resource_policy")
    assert coverage.status == "complete"


def test_secrets_preserves_resource_policy_statements():
    secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CrossAccountRead",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:role/Reader"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": secret_arn,
            }
        ],
    }
    secrets = FakeClient(
        {
            "list_secrets": {
                "SecretList": [
                    {
                        "Name": "shared",
                        "ARN": secret_arn,
                        "RotationEnabled": True,
                    },
                ],
            },
            "get_resource_policy": {"ResourcePolicy": json.dumps(policy)},
        }
    )

    envelope = run(FakeFactory(secrets=secrets), "us-east-1")

    secret = envelope.resources[0]
    assert secret["resource_policy_document"] == policy
    assert secret["resource_policy_principals"] == ["arn:aws:iam::999999999999:role/Reader"]
    assert secret["resource_policy_statements"][0]["normalized_actions"] == ["secretsmanager:GetSecretValue"]
    assert secret["resource_policy_statements"][0]["is_cross_account"] is True
