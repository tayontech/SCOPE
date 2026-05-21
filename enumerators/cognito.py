from __future__ import annotations

from typing import Any

from scope_core.coverage import CoverageTracker
from scope_core.models import ModuleEnvelope


PRIMARY_CHECKS: list[str] = []
REQUIRED_CHECKS = [
    "list_identity_pools",
    "describe_identity_pool",
    "list_user_pools",
    "describe_user_pool",
    "list_user_pool_clients",
    "describe_user_pool_client",
]


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    identity = factory.client("cognito_identity")
    idp = factory.client("cognito_idp")
    findings = [
        *_identity_pools(identity, region, tracker),
        *_user_pool_findings(idp, region, tracker),
    ]

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="cognito",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )


def _identity_pools(client: Any, region: str, tracker: CoverageTracker) -> list[dict[str, Any]]:
    try:
        pools = _paginate_token(client, "list_identity_pools", "IdentityPools", MaxResults=60)
        tracker.record_ok("list_identity_pools", resource="identity_pools")
    except Exception as err:
        tracker.record_resource_failure("list_identity_pools", None, "cognito-identity.ListIdentityPools", err)
        return []

    findings: list[dict[str, Any]] = []
    for pool in pools:
        pool_id = pool.get("IdentityPoolId")
        pool_arn = f"arn:aws:cognito-identity:{region}:unknown:identitypool/{pool_id}"
        try:
            detail = client.describe_identity_pool(IdentityPoolId=pool_id)
            allow_unauth = detail.get("AllowUnauthenticatedIdentities") is True
            roles = detail.get("Roles") or {}
            findings.append(
                {
                    "resource_type": "cognito_identity_pool",
                    "resource_id": detail.get("IdentityPoolName") or pool_id,
                    "arn": pool_arn,
                    "pool_id": pool_id,
                    "pool_name": detail.get("IdentityPoolName"),
                    "region": region,
                    "allow_unauthenticated": allow_unauth,
                    "authenticated_role_arn": roles.get("authenticated"),
                    "unauthenticated_role_arn": roles.get("unauthenticated"),
                    "supported_login_providers": detail.get("SupportedLoginProviders") or {},
                    "open_id_connect_provider_arns": detail.get("OpenIdConnectProviderARNs") or [],
                    "cognito_identity_providers": [
                        {
                            "provider_name": provider.get("ProviderName"),
                            "client_id": provider.get("ClientId"),
                            "server_side_token_check": provider.get("ServerSideTokenCheck") or False,
                        }
                        for provider in detail.get("CognitoIdentityProviders") or []
                    ],
                    "saml_provider_arns": detail.get("SamlProviderARNs") or [],
                    "describe_status": "present",
                    "findings": [
                        "CRITICAL: AllowUnauthenticatedIdentities is TRUE — anyone can call GetId + GetCredentialsForIdentity and receive temporary AWS credentials without authentication"
                    ]
                    if allow_unauth
                    else [],
                }
            )
            tracker.record_ok("describe_identity_pool", resource=pool_arn)
        except Exception as err:
            findings.append(
                {
                    "resource_type": "cognito_identity_pool",
                    "resource_id": pool_id,
                    "arn": pool_arn,
                    "pool_id": pool_id,
                    "pool_name": pool.get("IdentityPoolName"),
                    "region": region,
                    "allow_unauthenticated": None,
                    "describe_status": _classify_status(_error_code(err)),
                    "findings": [],
                }
            )
            tracker.record_resource_failure("describe_identity_pool", pool_arn, "cognito-identity.DescribeIdentityPool", err)
    return findings


def _user_pool_findings(client: Any, region: str, tracker: CoverageTracker) -> list[dict[str, Any]]:
    try:
        pools = _paginate_token(client, "list_user_pools", "UserPools", MaxResults=60)
        tracker.record_ok("list_user_pools", resource="user_pools")
    except Exception as err:
        tracker.record_resource_failure("list_user_pools", None, "cognito-idp.ListUserPools", err)
        return []

    findings: list[dict[str, Any]] = []
    client_findings: list[dict[str, Any]] = []
    for pool in pools:
        pool_id = pool.get("Id")
        pool_arn = f"arn:aws:cognito-idp:{region}:unknown:userpool/{pool_id}"
        try:
            detail = (client.describe_user_pool(UserPoolId=pool_id).get("UserPool") or {})
            tracker.record_ok("describe_user_pool", resource=pool_arn)
        except Exception as err:
            findings.append(
                {
                    "resource_type": "cognito_user_pool",
                    "resource_id": pool_id,
                    "arn": pool_arn,
                    "pool_id": pool_id,
                    "pool_name": pool.get("Name"),
                    "region": region,
                    "describe_status": _classify_status(_error_code(err)),
                    "clients_status": None,
                    "findings": [],
                }
            )
            tracker.record_resource_failure("describe_user_pool", pool_arn, "cognito-idp.DescribeUserPool", err)
            continue

        try:
            clients = _paginate_token(client, "list_user_pool_clients", "UserPoolClients", UserPoolId=pool_id, MaxResults=60)
            clients_status = "present"
            tracker.record_ok("list_user_pool_clients", resource=pool_arn)
        except Exception as err:
            clients = []
            clients_status = _classify_status(_error_code(err))
            tracker.record_resource_failure("list_user_pool_clients", pool_arn, "cognito-idp.ListUserPoolClients", err)

        findings.append(_user_pool_finding(detail, pool, pool_id, pool_arn, region, clients_status))

        for summary in clients:
            client_findings.append(_user_pool_client_finding(client, summary, pool_id, region, tracker))

    return [*findings, *client_findings]


def _user_pool_finding(
    detail: dict[str, Any],
    pool: dict[str, Any],
    pool_id: str,
    pool_arn: str,
    region: str,
    clients_status: str | None,
) -> dict[str, Any]:
    self_registration = not ((detail.get("AdminCreateUserConfig") or {}).get("AllowAdminCreateUserOnly") is True)
    mfa = detail.get("MfaConfiguration") or "OFF"
    password_policy = ((detail.get("Policies") or {}).get("PasswordPolicy") or {})
    custom_attributes = [
        attribute for attribute in detail.get("SchemaAttributes") or [] if (attribute.get("Name") or "").startswith("custom:")
    ]
    findings = []
    if self_registration:
        findings.append("Self-registration enabled — anyone can create an account")
    if mfa == "OFF":
        findings.append("MFA is OFF — no multi-factor authentication enforced")
    return {
        "resource_type": "cognito_user_pool",
        "resource_id": detail.get("Name") or pool_id,
        "arn": detail.get("Arn") or pool_arn,
        "pool_id": pool_id,
        "pool_name": detail.get("Name") or pool.get("Name"),
        "region": region,
        "self_registration_enabled": self_registration,
        "mfa_configuration": mfa,
        "password_policy": {
            "minimum_length": password_policy.get("MinimumLength"),
            "require_uppercase": password_policy.get("RequireUppercase") or False,
            "require_lowercase": password_policy.get("RequireLowercase") or False,
            "require_numbers": password_policy.get("RequireNumbers") or False,
            "require_symbols": password_policy.get("RequireSymbols") or False,
            "temporary_password_validity_days": password_policy.get("TemporaryPasswordValidityDays"),
        },
        "custom_attributes_count": len(custom_attributes),
        "estimated_users": detail.get("EstimatedNumberOfUsers") or 0,
        "creation_date": detail.get("CreationDate"),
        "last_modified_date": detail.get("LastModifiedDate"),
        "describe_status": "present",
        "clients_status": clients_status,
        "findings": findings,
    }


def _user_pool_client_finding(client: Any, summary: dict[str, Any], pool_id: str, region: str, tracker: CoverageTracker) -> dict[str, Any]:
    client_id = summary.get("ClientId")
    client_arn = f"arn:aws:cognito-idp:{region}:unknown:userpool/{pool_id}/client/{client_id}"
    try:
        detail = (
            client.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id).get("UserPoolClient") or {}
        )
        flows = detail.get("AllowedOAuthFlows") or []
        tracker.record_ok("describe_user_pool_client", resource=client_arn)
        return {
            "resource_type": "cognito_user_pool_client",
            "resource_id": detail.get("ClientName") or client_id,
            "arn": client_arn,
            "client_id": client_id,
            "client_name": detail.get("ClientName"),
            "user_pool_id": pool_id,
            "region": region,
            "allowed_oauth_flows": flows,
            "allowed_oauth_flows_user_pool_client": detail.get("AllowedOAuthFlowsUserPoolClient") or False,
            "allowed_oauth_scopes": detail.get("AllowedOAuthScopes") or [],
            "callback_urls": detail.get("CallbackURLs") or [],
            "logout_urls": detail.get("LogoutURLs") or [],
            "explicit_auth_flows": detail.get("ExplicitAuthFlows") or [],
            "token_validity": {
                "access_token": detail.get("AccessTokenValidity"),
                "id_token": detail.get("IdTokenValidity"),
                "refresh_token": detail.get("RefreshTokenValidity"),
            },
            "prevent_user_existence_errors": detail.get("PreventUserExistenceErrors"),
            "describe_status": "present",
            "findings": ["Implicit OAuth flow enabled — tokens exposed in URL fragment"] if "implicit" in flows else [],
        }
    except Exception as err:
        tracker.record_resource_failure(
            "describe_user_pool_client",
            client_arn,
            "cognito-idp.DescribeUserPoolClient",
            err,
        )
        return {
            "resource_type": "cognito_user_pool_client",
            "resource_id": client_id,
            "arn": client_arn,
            "client_id": client_id,
            "user_pool_id": pool_id,
            "region": region,
            "describe_status": _classify_status(_error_code(err)),
            "findings": [],
        }


def _paginate_token(client: Any, operation_name: str, result_key: str, **kwargs: Any) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    next_token = None
    while True:
        params = dict(kwargs)
        if next_token:
            params["NextToken"] = next_token
        response = getattr(client, operation_name)(**params)
        results.extend(response.get(result_key) or [])
        next_token = response.get("NextToken")
        if not next_token:
            return results


def _classify_status(code: str) -> str:
    return "access_denied" if code in {"AccessDenied", "AccessDeniedException"} else "error"


def _error_code(err: Exception) -> str:
    response = getattr(err, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict) and error.get("Code"):
            return str(error["Code"])
    code = getattr(err, "Code", None)
    if code:
        return str(code)
    return err.__class__.__name__ or "Error"
