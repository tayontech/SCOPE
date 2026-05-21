from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from enumerators.sqs import run
from tests.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "enum" / "sqs"


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


def test_sqs_matches_js_fixture_contract():
    sqs = FakeClient(
        {
            "list_queues": {
                "QueueUrls": [
                    "https://sqs.us-east-1.amazonaws.com/123456789012/test-queue",
                ],
            },
            "get_queue_attributes": {
                "Attributes": {
                    "QueueArn": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                    "VisibilityTimeout": "30",
                    "FifoQueue": "false",
                },
            },
        }
    )

    envelope = run(FakeFactory(sqs=sqs), "us-east-1")

    assert normalize_envelope(_contract(envelope)) == normalize_envelope(_expected_contract())


def test_sqs_list_queues_failure_returns_error_envelope():
    sqs = FakeClient(
        {
            "list_queues": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListQueues",
            ),
        }
    )

    envelope = run(FakeFactory(sqs=sqs), "us-east-1")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "sqs.ListQueues"
    assert envelope.errors[0].code == "AccessDeniedException"
    coverage = next(entry for entry in envelope.coverage if entry.check == "list_queues")
    assert coverage.status == "error"
    assert coverage.failed == 1


def test_sqs_missing_queue_urls_key_is_empty_region():
    sqs = FakeClient({"list_queues": {}})
    factory = FakeFactory(sqs=sqs)

    def strict_paginate(client, operation_name, result_key, **kwargs):
        value = getattr(client, operation_name)(**kwargs)
        if result_key not in value:
            raise KeyError(f"Paginator page missing result key: {result_key}")
        return value[result_key]

    factory.paginate = strict_paginate

    envelope = run(factory, "us-west-2")

    assert envelope.status == "complete"
    assert envelope.resources == []
    assert envelope.errors == []
    coverage = next(entry for entry in envelope.coverage if entry.check == "list_queues")
    assert coverage.status == "complete"
    assert coverage.succeeded == 1


def test_sqs_queue_attributes_access_denied_marks_queue_partial():
    queue_url = "https://sqs.us-east-1.amazonaws.com/123456789012/test-queue"
    sqs = FakeClient(
        {
            "list_queues": {"QueueUrls": [queue_url]},
            "get_queue_attributes": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetQueueAttributes",
            ),
        }
    )

    envelope = run(FakeFactory(sqs=sqs), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources[0]["queue_attributes_status"] == "access_denied"
    assert envelope.errors[0].operation == "sqs.GetQueueAttributes"
    assert envelope.errors[0].resource == queue_url
    coverage = next(entry for entry in envelope.coverage if entry.check == "queue_attributes")
    assert coverage.status == "partial"
    assert coverage.failed == 1
