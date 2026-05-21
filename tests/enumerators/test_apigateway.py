from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from enumerators.apigateway import run
from tests.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "enum" / "apigateway"


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


def test_apigateway_matches_js_fixture_contract():
    rest = FakeClient(
        {
            "get_rest_apis": {"items": [{"id": "abc123def4", "name": "TestRestApi"}]},
            "get_authorizers": {"items": [{"id": "auth1", "name": "CognitoAuthorizer", "type": "COGNITO_USER_POOLS"}]},
            "get_stages": {"item": [{"stageName": "prod"}, {"stageName": "dev"}]},
            "get_resources": {"items": [{"id": "res1", "path": "/", "resourceMethods": {}}]},
        }
    )
    v2 = FakeClient(
        {
            "get_apis": {"Items": [{"ApiId": "zyxwvuts12", "Name": "TestHttpApi", "ProtocolType": "HTTP"}]},
            "get_authorizers": {"Items": []},
            "get_stages": {"Items": [{"StageName": "$default"}]},
            "get_integrations": {
                "Items": [
                    {
                        "IntegrationId": "int1",
                        "IntegrationType": "AWS_PROXY",
                        "IntegrationUri": "arn:aws:lambda:us-east-1:123456789012:function:TestFunction",
                    }
                ]
            },
        }
    )

    envelope = run(FakeFactory(apigateway=rest, apigatewayv2=v2), "us-east-1")

    assert normalize_envelope(_contract(envelope)) == normalize_envelope(_expected_contract())


def test_apigateway_get_rest_apis_failure_returns_error_status():
    rest = FakeClient(
        {
            "get_rest_apis": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetRestApis",
            ),
        }
    )
    v2 = FakeClient({"get_apis": {"Items": []}})

    envelope = run(FakeFactory(apigateway=rest, apigatewayv2=v2), "us-east-1")

    assert envelope.status == "error"
    assert envelope.errors[0].operation == "apigateway.GetRestApis"
    coverage = next(entry for entry in envelope.coverage if entry.check == "get_rest_apis")
    assert coverage.status == "error"


def test_apigateway_v2_integrations_failure_marks_module_partial():
    api_arn = "arn:aws:apigateway:us-east-1::/apis/zyxwvuts12"
    rest = FakeClient({"get_rest_apis": {"items": []}})
    v2 = FakeClient(
        {
            "get_apis": {"Items": [{"ApiId": "zyxwvuts12", "Name": "TestHttpApi", "ProtocolType": "HTTP"}]},
            "get_authorizers": {"Items": []},
            "get_stages": {"Items": []},
            "get_integrations": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetIntegrations",
            ),
        }
    )

    envelope = run(FakeFactory(apigateway=rest, apigatewayv2=v2), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources[0]["lambda_integrations_status"] == "access_denied"
    assert envelope.errors[0].operation == "apigatewayv2.GetIntegrations"
    assert envelope.errors[0].resource == api_arn
    coverage = next(entry for entry in envelope.coverage if entry.check == "v2_integrations")
    assert coverage.status == "partial"


def test_apigateway_extracts_rest_lambda_integrations():
    rest = FakeClient(
        {
            "get_rest_apis": {"items": [{"id": "abc123def4", "name": "TestRestApi"}]},
            "get_authorizers": {"items": []},
            "get_stages": {"item": []},
            "get_resources": {
                "items": [
                    {
                        "resourceMethods": {
                            "GET": {
                                "methodIntegration": {
                                    "uri": (
                                        "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/"
                                        "arn:aws:lambda:us-east-1:123456789012:function:RestFunction/invocations"
                                    )
                                }
                            }
                        }
                    }
                ]
            },
        }
    )
    v2 = FakeClient({"get_apis": {"Items": []}})

    envelope = run(FakeFactory(apigateway=rest, apigatewayv2=v2), "us-east-1")

    assert envelope.resources[0]["lambda_integrations"] == [
        "arn:aws:lambda:us-east-1:123456789012:function:RestFunction"
    ]
