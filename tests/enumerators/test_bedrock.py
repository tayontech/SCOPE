from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from enumerators.bedrock import run
from tests.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "enum" / "bedrock"


def _expected_contract() -> dict:
    expected = json.loads((FIXTURE_DIR / "expected.json").read_text(encoding="utf-8"))
    expected.pop("account_id", None)
    return expected


def _contract(envelope, expected: dict) -> dict:
    dumped = envelope.model_dump(mode="json")
    return {key: dumped[key] for key in expected}


def test_bedrock_matches_js_fixture_contract_except_legacy_unknown_account():
    bedrock = FakeClient(
        {
            "list_foundation_models": {
                "modelSummaries": [
                    {
                        "modelId": "anthropic.claude-3-sonnet-20240229-v1:0",
                        "modelName": "Claude 3 Sonnet",
                        "providerName": "Anthropic",
                        "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0",
                        "inputModalities": ["TEXT"],
                        "outputModalities": ["TEXT"],
                        "customizationsSupported": [],
                        "inferenceTypesSupported": ["ON_DEMAND"],
                    }
                ]
            },
            "list_custom_models": {
                "modelSummaries": [
                    {
                        "modelName": "my-custom-model",
                        "modelArn": "arn:aws:bedrock:us-east-1:123456789012:custom-model/my-custom-model",
                        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-express-v1",
                        "creationTime": "2024-01-15T00:00:00Z",
                    }
                ]
            },
            "list_guardrails": {"guardrails": []},
            "get_model_invocation_logging_configuration": {"loggingConfig": None},
            "list_provisioned_model_throughputs": {"provisionedModelSummaries": []},
        }
    )
    agent = FakeClient(
        {
            "list_agents": {"agentSummaries": [{"agentId": "agent-abc123", "agentName": "TestAgent", "agentStatus": "PREPARED"}]},
            "get_agent": {
                "agent": {
                    "agentId": "agent-abc123",
                    "agentName": "TestAgent",
                    "agentArn": "arn:aws:bedrock:us-east-1:123456789012:agent/agent-abc123",
                    "agentStatus": "PREPARED",
                    "agentResourceRoleArn": "arn:aws:iam::123456789012:role/AmazonBedrockExecutionRoleForAgents_test",
                    "foundationModel": "anthropic.claude-3-sonnet-20240229-v1:0",
                    "description": "Test agent",
                    "createdAt": "2024-01-01T00:00:00Z",
                    "updatedAt": "2024-01-15T00:00:00Z",
                }
            },
            "list_knowledge_bases": {
                "knowledgeBaseSummaries": [
                    {"knowledgeBaseId": "kb-xyz789", "name": "TestKnowledgeBase", "status": "ACTIVE"}
                ]
            },
            "get_knowledge_base": {
                "knowledgeBase": {
                    "knowledgeBaseId": "kb-xyz789",
                    "name": "TestKnowledgeBase",
                    "knowledgeBaseArn": "arn:aws:bedrock:us-east-1:123456789012:knowledge-base/kb-xyz789",
                    "status": "ACTIVE",
                    "roleArn": "arn:aws:iam::123456789012:role/AmazonBedrockExecutionRoleForKnowledgeBase_test",
                    "storageConfiguration": {"type": "OPENSEARCH_SERVERLESS"},
                    "description": "Test knowledge base",
                    "createdAt": "2024-01-01T00:00:00Z",
                    "updatedAt": "2024-01-15T00:00:00Z",
                }
            },
        }
    )
    expected = _expected_contract()

    envelope = run(FakeFactory(bedrock=bedrock, bedrock_agent=agent), "us-east-1")

    assert envelope.account_id == "123456789012"
    assert normalize_envelope(_contract(envelope, expected)) == normalize_envelope(expected)


def test_bedrock_region_not_available_returns_complete_empty():
    bedrock = FakeClient(
        {
            "list_foundation_models": ClientError(
                {"Error": {"Code": "UnknownEndpoint", "Message": "could not resolve endpoint"}},
                "ListFoundationModels",
            ),
        }
    )
    agent = FakeClient({})

    envelope = run(FakeFactory(bedrock=bedrock, bedrock_agent=agent), "us-west-1")

    assert envelope.status == "complete"
    assert envelope.resources == []
    assert envelope.errors == []


def test_bedrock_secondary_failure_marks_partial_with_error_record():
    bedrock = FakeClient(
        {
            "list_foundation_models": {"modelSummaries": []},
            "list_custom_models": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListCustomModels",
            ),
            "list_guardrails": {"guardrails": []},
            "get_model_invocation_logging_configuration": {"loggingConfig": {"textDataDeliveryEnabled": True}},
            "list_provisioned_model_throughputs": {"provisionedModelSummaries": []},
        }
    )
    agent = FakeClient({"list_agents": {"agentSummaries": []}, "list_knowledge_bases": {"knowledgeBaseSummaries": []}})

    envelope = run(FakeFactory(bedrock=bedrock, bedrock_agent=agent), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "bedrock.ListCustomModels"
    assert envelope.errors[0].resource == "custom_models"
    assert envelope.errors[0].code == "AccessDeniedException"


def test_bedrock_unsupported_optional_operation_is_skipped():
    bedrock = FakeClient(
        {
            "list_foundation_models": {"modelSummaries": []},
            "list_custom_models": ClientError(
                {"Error": {"Code": "UnknownOperationException", "Message": "Unknown Operation"}},
                "ListCustomModels",
            ),
            "list_guardrails": {"guardrails": []},
            "get_model_invocation_logging_configuration": {"loggingConfig": {"textDataDeliveryEnabled": True}},
            "list_provisioned_model_throughputs": {"provisionedModelSummaries": []},
        }
    )
    agent = FakeClient({"list_agents": {"agentSummaries": []}, "list_knowledge_bases": {"knowledgeBaseSummaries": []}})

    envelope = run(FakeFactory(bedrock=bedrock, bedrock_agent=agent), "us-west-1")

    assert envelope.status == "complete"
    assert envelope.resources == []
    assert envelope.errors == []


def test_bedrock_logging_enabled_does_not_emit_logging_disabled_finding():
    bedrock = FakeClient(
        {
            "list_foundation_models": {"modelSummaries": []},
            "list_custom_models": {"modelSummaries": []},
            "list_guardrails": {"guardrails": []},
            "get_model_invocation_logging_configuration": {"loggingConfig": {"textDataDeliveryEnabled": True}},
            "list_provisioned_model_throughputs": {"provisionedModelSummaries": []},
        }
    )
    agent = FakeClient({"list_agents": {"agentSummaries": []}, "list_knowledge_bases": {"knowledgeBaseSummaries": []}})

    envelope = run(FakeFactory(bedrock=bedrock, bedrock_agent=agent), "us-east-1")

    assert envelope.status == "complete"
    assert envelope.resources == []
