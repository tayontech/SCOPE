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
