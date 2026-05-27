from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from scope.enumerators.sns import run
from tests.scope.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "enum" / "sns"


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


def test_sns_matches_js_fixture_contract():
    sns = FakeClient(
        {
            "list_topics": {
                "Topics": [
                    {"TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic"},
                ],
            },
            "get_topic_attributes": {
                "Attributes": {
                    "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
                    "SubscriptionsConfirmed": "2",
                    "KmsMasterKeyId": None,
                },
            },
        }
    )

    envelope = run(FakeFactory(sns=sns), "us-east-1")

    assert normalize_envelope(_contract(envelope)) == normalize_envelope(_expected_contract())


def test_sns_list_topics_failure_returns_error_envelope():
    sns = FakeClient(
        {
            "list_topics": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListTopics",
            ),
        }
    )

    envelope = run(FakeFactory(sns=sns), "us-east-1")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "sns.ListTopics"
    assert envelope.errors[0].code == "AccessDeniedException"
    coverage = next(entry for entry in envelope.coverage if entry.check == "list_topics")
    assert coverage.status == "error"
    assert coverage.failed == 1


def test_sns_topic_attributes_access_denied_marks_topic_partial():
    sns = FakeClient(
        {
            "list_topics": {
                "Topics": [
                    {"TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic"},
                ],
            },
            "get_topic_attributes": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetTopicAttributes",
            ),
        }
    )

    envelope = run(FakeFactory(sns=sns), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources[0]["topic_attributes_status"] == "access_denied"
    assert envelope.errors[0].operation == "sns.GetTopicAttributes"
    assert envelope.errors[0].resource == "arn:aws:sns:us-east-1:123456789012:test-topic"
    coverage = next(entry for entry in envelope.coverage if entry.check == "topic_attributes")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_sns_preserves_resource_policy_statements_and_conditions():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3PublishOnly",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sns:Publish",
                "Resource": "arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns",
                "Condition": {
                    "StringEquals": {
                        "AWS:SourceArn": "arn:aws:s3:::tot-vpc-logs",
                        "AWS:SourceOwner": "123456789012",
                    }
                },
            }
        ],
    }
    sns = FakeClient(
        {
            "list_topics": {
                "Topics": [
                    {"TopicArn": "arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns"},
                ],
            },
            "get_topic_attributes": {
                "Attributes": {
                    "TopicArn": "arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns",
                    "Policy": json.dumps(policy),
                },
            },
        }
    )

    envelope = run(FakeFactory(sns=sns), "us-east-1")

    topic = envelope.resources[0]
    assert topic["resource_policy_document"] == policy
    assert topic["resource_policy"] == {"principals": ["*"]}
    assert topic["resource_policy_statements"][0]["sid"] == "S3PublishOnly"
    assert topic["resource_policy_statements"][0]["normalized_actions"] == ["sns:Publish"]
    assert topic["resource_policy_statements"][0]["condition"] == policy["Statement"][0]["Condition"]
    assert topic["resource_policy_statements"][0]["source_arns"] == ["arn:aws:s3:::tot-vpc-logs"]


def test_sns_collects_topic_subscriptions():
    topic_arn = "arn:aws:sns:us-east-1:123456789012:uploads"
    queue_arn = "arn:aws:sqs:us-east-1:123456789012:uploads-queue"
    function_arn = "arn:aws:lambda:us-east-1:123456789012:function:processor"
    sns = FakeClient(
        {
            "list_topics": {"Topics": [{"TopicArn": topic_arn}]},
            "get_topic_attributes": {
                "Attributes": {
                    "TopicArn": topic_arn,
                    "SubscriptionsConfirmed": "2",
                }
            },
            "list_subscriptions_by_topic": {
                "Subscriptions": [
                    {
                        "SubscriptionArn": "arn:aws:sns:us-east-1:123456789012:uploads:sub-1",
                        "Protocol": "sqs",
                        "Endpoint": queue_arn,
                    },
                    {
                        "SubscriptionArn": "arn:aws:sns:us-east-1:123456789012:uploads:sub-2",
                        "Protocol": "lambda",
                        "Endpoint": function_arn,
                    },
                ]
            },
        }
    )

    envelope = run(FakeFactory(sns=sns), "us-east-1")

    topic = envelope.resources[0]
    assert topic["subscriptions_status"] == "present"
    assert topic["subscriptions"] == [
        {
            "subscription_arn": "arn:aws:sns:us-east-1:123456789012:uploads:sub-1",
            "protocol": "sqs",
            "endpoint": queue_arn,
        },
        {
            "subscription_arn": "arn:aws:sns:us-east-1:123456789012:uploads:sub-2",
            "protocol": "lambda",
            "endpoint": function_arn,
        },
    ]
