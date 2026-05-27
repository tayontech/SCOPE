from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from scope.enumerators.apigateway import run
from tests.scope.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "enum" / "apigateway"


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


def test_apigateway_marks_regional_rest_api_as_public_endpoint():
    rest = FakeClient(
        {
            "get_rest_apis": {
                "items": [
                    {
                        "id": "abc123def4",
                        "name": "PublicRestApi",
                        "endpointConfiguration": {"types": ["REGIONAL"]},
                    }
                ]
            },
            "get_authorizers": {"items": []},
            "get_stages": {"item": [{"stageName": "prod"}]},
            "get_resources": {"items": []},
        }
    )
    v2 = FakeClient({"get_apis": {"Items": []}})

    envelope = run(FakeFactory(apigateway=rest, apigatewayv2=v2), "us-east-1")

    api = envelope.resources[0]
    assert api["endpoint_configuration"] == {"types": ["REGIONAL"]}
    assert api["public_endpoint"] is True


def test_apigateway_marks_disabled_v2_execute_api_endpoint_not_public():
    rest = FakeClient({"get_rest_apis": {"items": []}})
    v2 = FakeClient(
        {
            "get_apis": {
                "Items": [
                    {
                        "ApiId": "zyxwvuts12",
                        "Name": "PrivateHttpApi",
                        "ProtocolType": "HTTP",
                        "DisableExecuteApiEndpoint": True,
                    }
                ]
            },
            "get_authorizers": {"Items": []},
            "get_stages": {"Items": []},
            "get_integrations": {"Items": []},
        }
    )

    envelope = run(FakeFactory(apigateway=rest, apigatewayv2=v2), "us-east-1")

    api = envelope.resources[0]
    assert api["disable_execute_api_endpoint"] is True
    assert api["public_endpoint"] is False


def test_apigateway_preserves_rest_resource_policy_statements():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "VpceInvoke",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "execute-api:Invoke",
                "Resource": "arn:aws:execute-api:us-east-1:123456789012:abc123def4/*/*/*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceArn": "arn:aws:vpce:us-east-1:123456789012:vpce/vpce-abc123"
                    }
                },
            }
        ],
    }
    rest = FakeClient(
        {
            "get_rest_apis": {
                "items": [
                    {
                        "id": "abc123def4",
                        "name": "PrivateRestApi",
                        "policy": json.dumps(policy),
                    }
                ]
            },
            "get_authorizers": {"items": []},
            "get_stages": {"item": [{"stageName": "prod"}]},
            "get_resources": {"items": []},
        }
    )
    v2 = FakeClient({"get_apis": {"Items": []}})

    envelope = run(FakeFactory(apigateway=rest, apigatewayv2=v2), "us-east-1")

    api = envelope.resources[0]
    assert api["resource_policy_document"] == policy
    assert api["resource_policy_statements"][0]["sid"] == "VpceInvoke"
    assert api["resource_policy_statements"][0]["normalized_principals"] == ["*"]
    assert api["resource_policy_statements"][0]["normalized_actions"] == ["execute-api:Invoke"]
    assert api["resource_policy_statements"][0]["source_arns"] == [
        "arn:aws:vpce:us-east-1:123456789012:vpce/vpce-abc123"
    ]
