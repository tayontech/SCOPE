from __future__ import annotations

import json
import re
from typing import Any, Callable

from scope.core.coverage import CoverageTracker
from scope.core.models import ModuleEnvelope
from scope.enumerators.resource_policy import normalize_resource_policy


PRIMARY_CHECKS = ["list_functions"]
REQUIRED_CHECKS = ["function_url", "resource_policy", "event_source_mappings"]
SECRET_PATTERNS = re.compile(r"password|secret|token|key|credential|api.?key|auth", re.IGNORECASE)


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    lambda_client = factory.client("lambda")
    findings: list[dict[str, Any]] = []

    try:
        functions = factory.paginate(lambda_client, "list_functions", "Functions")
        tracker.record_ok("list_functions", resource="functions")
    except Exception as err:
        tracker.record_module_failure("list_functions", operation="lambda.ListFunctions", err=err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="lambda",
            account_id=factory.account_id,
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    for function in functions:
        function_arn = function.get("FunctionArn")
        function_url = None
        function_url_config = None
        function_url_status = None
        resource_policy_principals: list[str] = []
        resource_policy_document = None
        resource_policy_statements = None
        resource_policy_status = None
        event_source_mappings: list[dict[str, Any]] = []
        event_source_mappings_status = None

        try:
            response = _safe_get(lambda: lambda_client.get_function_url_config(FunctionName=function.get("FunctionName")))
            if response and response.get("FunctionUrl"):
                function_url = response.get("FunctionUrl")
                function_url_config = {
                    "auth_type": response.get("AuthType"),
                    "invoke_mode": response.get("InvokeMode"),
                    "cors": response.get("Cors"),
                    "creation_time": response.get("CreationTime"),
                    "last_modified_time": response.get("LastModifiedTime"),
                }
                function_url_status = "present"
            else:
                function_url_status = "absent"
            tracker.record_ok("function_url", resource=function_arn)
        except Exception as err:
            code = _error_code(err)
            function_url_status = _classify_status(code)
            tracker.record_resource_failure(
                "function_url",
                resource=function_arn,
                operation="lambda.GetFunctionUrlConfig",
                err=err,
            )

        try:
            response = _safe_get(lambda: lambda_client.get_policy(FunctionName=function.get("FunctionName")))
            if response and response.get("Policy"):
                resource_policy_principals = _extract_policy_principals(response.get("Policy"))
                normalized_policy = normalize_resource_policy(response.get("Policy"), account_id=factory.account_id)
                if normalized_policy is not None:
                    resource_policy_document = normalized_policy["document"]
                    resource_policy_statements = normalized_policy["statements"]
                resource_policy_status = "present"
            else:
                resource_policy_status = "absent"
            tracker.record_ok("resource_policy", resource=function_arn)
        except Exception as err:
            code = _error_code(err)
            resource_policy_status = _classify_status(code)
            tracker.record_resource_failure(
                "resource_policy",
                resource=function_arn,
                operation="lambda.GetPolicy",
                err=err,
            )

        try:
            mappings = factory.paginate(
                lambda_client,
                "list_event_source_mappings",
                "EventSourceMappings",
                FunctionName=function.get("FunctionName"),
            )
            event_source_mappings = [
                {
                    "uuid": mapping.get("UUID"),
                    "event_source_arn": mapping.get("EventSourceArn"),
                    "function_arn": mapping.get("FunctionArn"),
                    "state": mapping.get("State"),
                    "batch_size": mapping.get("BatchSize"),
                }
                for mapping in mappings
                if isinstance(mapping, dict)
            ]
            event_source_mappings_status = "present"
            tracker.record_ok("event_source_mappings", resource=function_arn)
        except Exception as err:
            code = _error_code(err)
            event_source_mappings_status = _classify_status(code)
            tracker.record_resource_failure(
                "event_source_mappings",
                resource=function_arn,
                operation="lambda.ListEventSourceMappings",
                err=err,
            )

        env_var_names = list(((function.get("Environment") or {}).get("Variables") or {}).keys())
        secret_pattern_names = [name for name in env_var_names if SECRET_PATTERNS.search(name)]
        finding = {
            "resource_type": "lambda_function",
            "resource_id": function.get("FunctionName"),
            "arn": function_arn,
            "runtime": function.get("Runtime"),
            "role": function.get("Role"),
            "handler": function.get("Handler"),
            "code_size": function.get("CodeSize"),
            "timeout": function.get("Timeout"),
            "memory_size": function.get("MemorySize"),
            "last_modified": function.get("LastModified"),
            "layers": [
                {
                    "arn": layer.get("Arn"),
                    "code_size": layer.get("CodeSize"),
                }
                for layer in function.get("Layers") or []
            ],
            "function_url": function_url,
            "function_url_status": function_url_status,
            "resource_policy_principals": resource_policy_principals,
            "resource_policy_status": resource_policy_status,
            "event_source_mappings": event_source_mappings,
            "event_source_mappings_status": event_source_mappings_status,
            "env_var_names": env_var_names,
            "secret_pattern_names": secret_pattern_names,
            "findings": [],
        }
        if function_url_config is not None:
            finding["function_url_config"] = function_url_config
        if resource_policy_document is not None:
            finding["resource_policy_document"] = resource_policy_document
            finding["resource_policy_statements"] = resource_policy_statements or []

        if secret_pattern_names:
            finding["findings"].append(
                {
                    "type": "secret_env_vars",
                    "severity": "high",
                    "detail": (
                        f"Function has {len(secret_pattern_names)} env var(s) matching secret patterns: "
                        f"{', '.join(secret_pattern_names)}"
                    ),
                }
            )
        if function_url:
            finding["findings"].append(
                {
                    "type": "function_url_enabled",
                    "severity": "info",
                    "detail": f"Function URL enabled: {function_url}",
                }
            )
        if "*" in resource_policy_principals:
            finding["findings"].append(
                {
                    "type": "wildcard_resource_policy",
                    "severity": "high",
                    "detail": "Resource policy allows wildcard (*) principal",
                }
            )

        findings.append(finding)

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="lambda",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )


def _safe_get(call: Callable[[], dict[str, Any]]) -> dict[str, Any] | None:
    try:
        return call()
    except Exception as err:
        if _error_code(err) == "ResourceNotFoundException":
            return None
        raise


def _extract_policy_principals(policy: str | dict[str, Any] | None) -> list[str]:
    if not policy:
        return []
    try:
        document = json.loads(policy) if isinstance(policy, str) else policy
    except json.JSONDecodeError:
        return []
    statements = document.get("Statement", []) if isinstance(document, dict) else []
    if isinstance(statements, dict):
        statements = [statements]

    principals: set[str] = set()
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if isinstance(principal, str):
            principals.add(principal)
        elif isinstance(principal, dict):
            for key in ("AWS", "Service", "Federated"):
                value = principal.get(key)
                if isinstance(value, str):
                    principals.add(value)
                elif isinstance(value, list):
                    principals.update(str(item) for item in value)
    return sorted(principals)


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
