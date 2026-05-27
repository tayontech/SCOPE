from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from scope.enumerators.s3 import run
from tests.scope.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "enum" / "s3"


def _expected_contract() -> dict:
    return json.loads((FIXTURE_DIR / "expected.json").read_text(encoding="utf-8"))


def _contract(envelope, expected: dict) -> dict:
    dumped = envelope.model_dump(mode="json")
    return {key: dumped[key] for key in expected}


def test_s3_matches_js_fixture_contract():
    s3 = FakeClient(
        {
            "list_buckets": {"Buckets": [{"Name": "my-test-bucket"}]},
            "get_bucket_location": {"LocationConstraint": "us-east-1"},
            "get_bucket_policy": {},
            "get_public_access_block": {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            },
            "get_bucket_versioning": {"Status": "Enabled", "MFADelete": None},
            "get_bucket_encryption": {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256",
                            },
                        },
                    ],
                },
            },
            "get_bucket_logging": {"LoggingEnabled": None},
            "get_bucket_acl": {
                "Grants": [
                    {
                        "Grantee": {
                            "Type": "CanonicalUser",
                            "ID": "abc123",
                            "URI": None,
                        },
                        "Permission": "FULL_CONTROL",
                    },
                ],
            },
        }
    )
    expected = _expected_contract()

    envelope = run(FakeFactory(s3=s3), "us-east-1")

    assert normalize_envelope(_contract(envelope, expected)) == normalize_envelope(expected)


def _minimal_bucket_ops(**overrides):
    operations = {
        "list_buckets": {"Buckets": [{"Name": "my-test-bucket"}]},
        "get_bucket_location": {"LocationConstraint": "us-east-1"},
        "get_bucket_policy": {},
        "get_public_access_block": {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        },
        "get_bucket_versioning": {"Status": "Enabled", "MFADelete": None},
        "get_bucket_encryption": {},
        "get_bucket_logging": {"LoggingEnabled": None},
        "get_bucket_acl": {"Grants": []},
    }
    operations.update(overrides)
    return operations


def test_s3_list_buckets_failure_returns_error_envelope():
    s3 = FakeClient(
        {
            "list_buckets": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListBuckets",
            ),
        }
    )

    envelope = run(FakeFactory(s3=s3), "us-east-1")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "s3.ListBuckets"
    assert envelope.errors[0].code == "AccessDeniedException"
    coverage = next(entry for entry in envelope.coverage if entry.check == "list_buckets")
    assert coverage.status == "error"
    assert coverage.failed == 1


def test_s3_global_region_includes_all_buckets_with_actual_regions():
    s3 = FakeClient(
        _minimal_bucket_ops(
            list_buckets={"Buckets": [{"Name": "east-bucket"}, {"Name": "west-bucket"}]},
            get_bucket_location=[
                {"LocationConstraint": "us-east-1"},
                {"LocationConstraint": "us-west-2"},
            ],
        )
    )

    envelope = run(FakeFactory(s3=s3), "global")

    assert envelope.region == "global"
    assert [
        (resource["resource_id"], resource["region"])
        for resource in envelope.resources
    ] == [
        ("east-bucket", "us-east-1"),
        ("west-bucket", "us-west-2"),
    ]


def test_s3_bucket_policy_access_denied_marks_bucket_partial():
    bucket_arn = "arn:aws:s3:::my-test-bucket"
    s3 = FakeClient(
        _minimal_bucket_ops(
            get_bucket_policy=ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetBucketPolicy",
            )
        )
    )

    envelope = run(FakeFactory(s3=s3), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources[0]["policy_status"] == "access_denied"
    assert envelope.errors[0].operation == "s3.GetBucketPolicy"
    assert envelope.errors[0].resource == bucket_arn
    coverage = next(entry for entry in envelope.coverage if entry.check == "bucket_policy")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_s3_optional_versioning_access_denied_is_skipped():
    s3 = FakeClient(
        _minimal_bucket_ops(
            get_bucket_versioning=ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetBucketVersioning",
            )
        )
    )

    envelope = run(FakeFactory(s3=s3), "us-east-1")

    assert envelope.status == "complete"
    assert envelope.errors == []
    assert envelope.resources[0]["versioning_status"] == "access_denied"
    coverage = next(entry for entry in envelope.coverage if entry.check == "bucket_versioning")
    assert coverage.status == "skipped"
    assert coverage.skipped == 1


def test_s3_public_policy_and_acl_generate_findings():
    s3 = FakeClient(
        _minimal_bucket_ops(
            get_bucket_policy={
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                            }
                        ]
                    }
                )
            },
            get_bucket_acl={
                "Grants": [
                    {
                        "Grantee": {
                            "Type": "Group",
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                        },
                        "Permission": "READ",
                    }
                ]
            },
        )
    )

    envelope = run(FakeFactory(s3=s3), "us-east-1")

    finding_types = {finding["type"] for finding in envelope.resources[0]["findings"]}
    assert "public_policy" in finding_types
    assert "public_acl" in finding_types


def test_s3_preserves_resource_policy_statements_and_conditions():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "VpcEndpointRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::my-test-bucket/*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceArn": "arn:aws:vpce:us-east-1:123456789012:vpce/vpce-abc123"
                    }
                },
            }
        ],
    }
    s3 = FakeClient(
        _minimal_bucket_ops(
            get_bucket_policy={"Policy": json.dumps(policy)},
        )
    )

    envelope = run(FakeFactory(s3=s3), "us-east-1")

    bucket = envelope.resources[0]
    assert bucket["resource_policy_document"] == policy
    assert bucket["resource_policy"] == {"principals": ["*"]}
    assert bucket["resource_policy_statements"][0]["sid"] == "VpcEndpointRead"
    assert bucket["resource_policy_statements"][0]["normalized_actions"] == ["s3:GetObject"]
    assert bucket["resource_policy_statements"][0]["normalized_resources"] == ["arn:aws:s3:::my-test-bucket/*"]
    assert bucket["resource_policy_statements"][0]["source_arns"] == [
        "arn:aws:vpce:us-east-1:123456789012:vpce/vpce-abc123"
    ]


def test_s3_preserves_bucket_notification_configuration():
    notification = {
        "LambdaFunctionConfigurations": [
            {
                "Id": "ProcessUploads",
                "LambdaFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:processor",
                "Events": ["s3:ObjectCreated:*"],
            }
        ],
        "TopicConfigurations": [
            {
                "Id": "PublishUploads",
                "TopicArn": "arn:aws:sns:us-east-1:123456789012:uploads",
                "Events": ["s3:ObjectCreated:Put"],
            }
        ],
        "QueueConfigurations": [
            {
                "Id": "QueueUploads",
                "QueueArn": "arn:aws:sqs:us-east-1:123456789012:uploads",
                "Events": ["s3:ObjectCreated:Put"],
            }
        ],
    }
    s3 = FakeClient(
        _minimal_bucket_ops(
            get_bucket_notification_configuration=notification,
        )
    )

    envelope = run(FakeFactory(s3=s3), "us-east-1")

    bucket = envelope.resources[0]
    assert bucket["notification_configuration"] == notification
    assert bucket["notification_configuration_status"] == "present"
