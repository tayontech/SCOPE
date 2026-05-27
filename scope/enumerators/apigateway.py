from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import unquote

from scope.core.coverage import CoverageTracker
from scope.core.models import ModuleEnvelope
from scope.enumerators.resource_policy import normalize_resource_policy


PRIMARY_CHECKS = ["get_rest_apis", "get_apis"]
REQUIRED_CHECKS = [
    "rest_authorizers",
    "rest_stages",
    "rest_resources",
    "v2_authorizers",
    "v2_stages",
    "v2_integrations",
]
LAMBDA_ARN_PATTERN = re.compile(r"arn:aws:lambda:[^:]+:\d+:function:[^/]+")


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    rest = factory.client("apigateway")
    v2 = factory.client("apigatewayv2")
    findings = [
        *_enumerate_rest(factory, rest, region, tracker),
        *_enumerate_v2(factory, v2, region, tracker),
    ]

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="apigateway",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )


def _enumerate_rest(factory: Any, rest: Any, region: str, tracker: CoverageTracker) -> list[dict[str, Any]]:
    try:
        apis = factory.paginate(rest, "get_rest_apis", "items")
        tracker.record_ok("get_rest_apis", resource="rest_apis")
    except Exception as err:
        tracker.record_module_failure("get_rest_apis", "apigateway.GetRestApis", err)
        return []

    findings: list[dict[str, Any]] = []
    for api in apis:
        api_id = api.get("id")
        api_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}"
        resource_policy = _parse_resource_policy(api.get("policy"))
        endpoint_configuration = api.get("endpointConfiguration")
        finding = {
            "resource_type": "apigateway_rest_api",
            "resource_id": api_id,
            "arn": api_arn,
            "region": region,
            "name": api.get("name"),
            "api_type": "REST",
            "endpoint_configuration": endpoint_configuration if isinstance(endpoint_configuration, dict) else None,
            "public_endpoint": _rest_public_endpoint(endpoint_configuration),
            "authorizers": [],
            "authorizers_status": None,
            "stages": [],
            "stages_status": None,
            "lambda_integrations": [],
            "lambda_integrations_status": None,
            "resource_policy": resource_policy,
            "findings": [],
        }
        normalized_policy = normalize_resource_policy(resource_policy, account_id=factory.account_id)
        if normalized_policy:
            finding["resource_policy_document"] = normalized_policy["document"]
            finding["resource_policy_statements"] = normalized_policy["statements"]

        try:
            response = rest.get_authorizers(restApiId=api_id)
            finding["authorizers"] = [
                {"type": authorizer.get("type"), "name": authorizer.get("name")}
                for authorizer in response.get("items") or []
            ]
            finding["authorizers_status"] = "present"
            tracker.record_ok("rest_authorizers", resource=api_arn)
        except Exception as err:
            finding["authorizers_status"] = _classify_status(_error_code(err))
            tracker.record_resource_failure("rest_authorizers", api_arn, "apigateway.GetAuthorizers", err)

        try:
            response = rest.get_stages(restApiId=api_id)
            finding["stages"] = [stage.get("stageName") for stage in response.get("item") or []]
            finding["stages_status"] = "present"
            tracker.record_ok("rest_stages", resource=api_arn)
        except Exception as err:
            finding["stages_status"] = _classify_status(_error_code(err))
            tracker.record_resource_failure("rest_stages", api_arn, "apigateway.GetStages", err)

        try:
            resources = factory.paginate(rest, "get_resources", "items", restApiId=api_id, embed=["methods"])
            finding["lambda_integrations"] = _extract_rest_lambda_integrations(resources)
            finding["lambda_integrations_status"] = "present"
            tracker.record_ok("rest_resources", resource=api_arn)
        except Exception as err:
            finding["lambda_integrations_status"] = _classify_status(_error_code(err))
            tracker.record_resource_failure("rest_resources", api_arn, "apigateway.GetResources", err)

        findings.append(finding)
    return findings


def _enumerate_v2(factory: Any, v2: Any, region: str, tracker: CoverageTracker) -> list[dict[str, Any]]:
    try:
        apis = factory.paginate(v2, "get_apis", "Items")
        tracker.record_ok("get_apis", resource="apis")
    except Exception as err:
        tracker.record_module_failure("get_apis", "apigatewayv2.GetApis", err)
        return []

    findings: list[dict[str, Any]] = []
    for api in apis:
        api_id = api.get("ApiId")
        protocol_type = api.get("ProtocolType")
        api_arn = f"arn:aws:apigateway:{region}::/apis/{api_id}"
        disable_execute_api_endpoint = api.get("DisableExecuteApiEndpoint")
        finding = {
            "resource_type": "apigateway_websocket_api" if protocol_type == "WEBSOCKET" else "apigateway_http_api",
            "resource_id": api_id,
            "arn": api_arn,
            "region": region,
            "name": api.get("Name"),
            "api_type": protocol_type,
            "disable_execute_api_endpoint": disable_execute_api_endpoint,
            "public_endpoint": _v2_public_endpoint(disable_execute_api_endpoint),
            "authorizers": [],
            "authorizers_status": None,
            "stages": [],
            "stages_status": None,
            "lambda_integrations": [],
            "lambda_integrations_status": None,
            "resource_policy": None,
            "findings": [],
        }

        try:
            response = v2.get_authorizers(ApiId=api_id)
            finding["authorizers"] = [
                {"type": authorizer.get("AuthorizerType"), "name": authorizer.get("Name")}
                for authorizer in response.get("Items") or []
            ]
            finding["authorizers_status"] = "present"
            tracker.record_ok("v2_authorizers", resource=api_arn)
        except Exception as err:
            finding["authorizers_status"] = _classify_status(_error_code(err))
            tracker.record_resource_failure("v2_authorizers", api_arn, "apigatewayv2.GetAuthorizers", err)

        try:
            response = v2.get_stages(ApiId=api_id)
            finding["stages"] = [stage.get("StageName") for stage in response.get("Items") or []]
            finding["stages_status"] = "present"
            tracker.record_ok("v2_stages", resource=api_arn)
        except Exception as err:
            finding["stages_status"] = _classify_status(_error_code(err))
            tracker.record_resource_failure("v2_stages", api_arn, "apigatewayv2.GetStages", err)

        try:
            response = v2.get_integrations(ApiId=api_id)
            finding["lambda_integrations"] = _extract_lambda_integrations(response.get("Items") or [])
            finding["lambda_integrations_status"] = "present"
            tracker.record_ok("v2_integrations", resource=api_arn)
        except Exception as err:
            finding["lambda_integrations_status"] = _classify_status(_error_code(err))
            tracker.record_resource_failure("v2_integrations", api_arn, "apigatewayv2.GetIntegrations", err)

        findings.append(finding)
    return findings


def _extract_lambda_integrations(integrations: list[dict[str, Any]]) -> list[str]:
    arns: set[str] = set()
    for integration in integrations:
        uri = integration.get("IntegrationUri") or integration.get("uri") or ""
        match = LAMBDA_ARN_PATTERN.search(uri)
        if match:
            arns.add(match.group(0))
    return sorted(arns)


def _extract_rest_lambda_integrations(resources: list[dict[str, Any]]) -> list[str]:
    integrations: list[dict[str, Any]] = []
    for resource in resources:
        for method in (resource.get("resourceMethods") or {}).values():
            integration = method.get("methodIntegration") if isinstance(method, dict) else None
            if integration:
                integrations.append(integration)
    return _extract_lambda_integrations(integrations)


def _parse_resource_policy(policy: str | None) -> str | None:
    if not policy:
        return None
    for candidate in (unquote(policy), policy):
        try:
            json.loads(candidate)
            return candidate
        except json.JSONDecodeError:
            continue
    return None


def _rest_public_endpoint(endpoint_configuration: Any) -> bool | None:
    if not isinstance(endpoint_configuration, dict):
        return None
    types = endpoint_configuration.get("types")
    if not isinstance(types, list):
        return None
    normalized = {str(endpoint_type).upper() for endpoint_type in types}
    if normalized.intersection({"EDGE", "REGIONAL"}):
        return True
    if normalized == {"PRIVATE"}:
        return False
    return None


def _v2_public_endpoint(disable_execute_api_endpoint: Any) -> bool | None:
    if isinstance(disable_execute_api_endpoint, bool):
        return not disable_execute_api_endpoint
    return None


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
