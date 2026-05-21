from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from scope.enumerators.cognito import run
from tests.scope.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "enum" / "cognito"


def _expected_contract() -> dict:
    expected = json.loads((FIXTURE_DIR / "expected.json").read_text(encoding="utf-8"))
    expected.pop("account_id", None)
    return expected


def _contract(envelope, expected: dict) -> dict:
    dumped = envelope.model_dump(mode="json")
    return {key: dumped[key] for key in expected}


def test_cognito_matches_js_fixture_contract_except_legacy_unknown_account():
    identity = FakeClient(
        {
            "list_identity_pools": {
                "IdentityPools": [
                    {
                        "IdentityPoolId": "us-east-1:pool-abc123",
                        "IdentityPoolName": "TestIdentityPool",
                    }
                ]
            },
            "describe_identity_pool": {
                "IdentityPoolId": "us-east-1:pool-abc123",
                "IdentityPoolName": "TestIdentityPool",
                "AllowUnauthenticatedIdentities": True,
                "Roles": {
                    "authenticated": "arn:aws:iam::123456789012:role/Cognito_TestIdentityPoolAuth_Role",
                    "unauthenticated": "arn:aws:iam::123456789012:role/Cognito_TestIdentityPoolUnauth_Role",
                },
                "SupportedLoginProviders": {},
                "OpenIdConnectProviderARNs": [],
                "CognitoIdentityProviders": [
                    {
                        "ProviderName": "cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool",
                        "ClientId": "client123",
                        "ServerSideTokenCheck": False,
                    }
                ],
                "SamlProviderARNs": [],
            },
        }
    )
    idp = FakeClient(
        {
            "list_user_pools": {"UserPools": [{"Id": "us-east-1_TestPool", "Name": "TestUserPool"}]},
            "describe_user_pool": {
                "UserPool": {
                    "Id": "us-east-1_TestPool",
                    "Name": "TestUserPool",
                    "Arn": "arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_TestPool",
                    "MfaConfiguration": "OFF",
                    "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": False},
                    "Policies": {
                        "PasswordPolicy": {
                            "MinimumLength": 8,
                            "RequireUppercase": True,
                            "RequireLowercase": True,
                            "RequireNumbers": True,
                            "RequireSymbols": False,
                            "TemporaryPasswordValidityDays": 7,
                        }
                    },
                    "SchemaAttributes": [],
                    "EstimatedNumberOfUsers": 42,
                    "CreationDate": "2024-01-01T00:00:00Z",
                    "LastModifiedDate": "2024-06-01T00:00:00Z",
                }
            },
            "list_user_pool_clients": {
                "UserPoolClients": [
                    {
                        "ClientId": "clientabc123",
                        "ClientName": "TestWebClient",
                        "UserPoolId": "us-east-1_TestPool",
                    }
                ]
            },
            "describe_user_pool_client": {
                "UserPoolClient": {
                    "ClientId": "clientabc123",
                    "ClientName": "TestWebClient",
                    "UserPoolId": "us-east-1_TestPool",
                    "AllowedOAuthFlows": ["code"],
                    "AllowedOAuthFlowsUserPoolClient": True,
                    "AllowedOAuthScopes": ["email", "openid"],
                    "CallbackURLs": ["https://example.com/callback"],
                    "LogoutURLs": ["https://example.com/logout"],
                    "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
                    "AccessTokenValidity": 60,
                    "IdTokenValidity": 60,
                    "RefreshTokenValidity": 30,
                    "PreventUserExistenceErrors": "ENABLED",
                }
            },
        }
    )
    expected = _expected_contract()

    envelope = run(FakeFactory(cognito_identity=identity, cognito_idp=idp), "us-east-1")

    assert envelope.account_id == "123456789012"
    assert normalize_envelope(_contract(envelope, expected)) == normalize_envelope(expected)


def test_cognito_list_identity_pools_failure_marks_module_partial():
    identity = FakeClient(
        {
            "list_identity_pools": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListIdentityPools",
            )
        }
    )
    idp = FakeClient({"list_user_pools": {"UserPools": []}})

    envelope = run(FakeFactory(cognito_identity=identity, cognito_idp=idp), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.errors[0].operation == "cognito-identity.ListIdentityPools"
    coverage = next(entry for entry in envelope.coverage if entry.check == "list_identity_pools")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_cognito_describe_identity_pool_failure_emits_fallback_finding():
    identity_pool_arn = "arn:aws:cognito-identity:us-east-1:unknown:identitypool/us-east-1:pool-abc123"
    identity = FakeClient(
        {
            "list_identity_pools": {
                "IdentityPools": [
                    {
                        "IdentityPoolId": "us-east-1:pool-abc123",
                        "IdentityPoolName": "TestIdentityPool",
                    }
                ]
            },
            "describe_identity_pool": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "DescribeIdentityPool",
            ),
        }
    )
    idp = FakeClient({"list_user_pools": {"UserPools": []}})

    envelope = run(FakeFactory(cognito_identity=identity, cognito_idp=idp), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources[0]["describe_status"] == "access_denied"
    assert envelope.errors[0].operation == "cognito-identity.DescribeIdentityPool"
    assert envelope.errors[0].resource == identity_pool_arn


def test_cognito_implicit_oauth_flow_emits_client_finding():
    identity = FakeClient({"list_identity_pools": {"IdentityPools": []}})
    idp = FakeClient(
        {
            "list_user_pools": {"UserPools": [{"Id": "us-east-1_TestPool", "Name": "TestUserPool"}]},
            "describe_user_pool": {
                "UserPool": {
                    "Id": "us-east-1_TestPool",
                    "Name": "TestUserPool",
                    "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
                    "MfaConfiguration": "ON",
                }
            },
            "list_user_pool_clients": {
                "UserPoolClients": [
                    {
                        "ClientId": "clientabc123",
                        "ClientName": "TestWebClient",
                    }
                ]
            },
            "describe_user_pool_client": {
                "UserPoolClient": {
                    "ClientId": "clientabc123",
                    "ClientName": "TestWebClient",
                    "AllowedOAuthFlows": ["implicit"],
                }
            },
        }
    )

    envelope = run(FakeFactory(cognito_identity=identity, cognito_idp=idp), "us-east-1")

    client = next(finding for finding in envelope.resources if finding["resource_type"] == "cognito_user_pool_client")
    assert client["findings"] == ["Implicit OAuth flow enabled — tokens exposed in URL fragment"]
