from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from scope.core.coverage import CoverageTracker
from scope.core.models import ModuleEnvelope


PRIMARY_CHECKS = ["describe_parameters"]
REQUIRED_CHECKS: list[str] = []
ABSENT_RESOURCE_POLICY_CODES = {
    "ResourceNotFoundException",
    "PolicyNotFoundException",
    "ParameterNotFoundException",
    "InvalidResourceId",
}


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    ssm = factory.client("ssm")
    findings: list[dict[str, Any]] = []

    try:
        parameters = factory.paginate(ssm, "describe_parameters", "Parameters")
        tracker.record_ok("describe_parameters", resource="parameters")
    except Exception as err:
        tracker.record_module_failure("describe_parameters", operation="ssm.DescribeParameters", err=err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="ssm",
            account_id=factory.account_id,
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    for parameter in parameters:
        name = parameter.get("Name")
        parameter_arn = _parameter_arn(region, factory.account_id, name)
        finding = {
            "resource_type": "ssm_parameter",
            "resource_id": name,
            "arn": parameter_arn,
            "region": region,
            "type": parameter.get("Type"),
            "tier": parameter.get("Tier") or "Standard",
            "kms_key_id": _kms_key_id(parameter),
            "data_type": parameter.get("DataType"),
            "last_modified": _format_timestamp(parameter.get("LastModifiedDate")),
            "version": parameter.get("Version"),
            "has_resource_policy": False,
            "resource_policy": None,
            "resource_policy_status": None,
            "findings": [],
        }

        try:
            response = ssm.get_resource_policies(ResourceArn=parameter_arn)
            entry = (response.get("Policies") or [None])[0]
            policy = entry.get("Policy") if isinstance(entry, dict) else None
            if policy:
                finding["resource_policy"] = _parse_policy(policy)
                finding["has_resource_policy"] = True
                finding["resource_policy_status"] = "present"
            else:
                finding["resource_policy_status"] = "absent"
            tracker.record_ok("resource_policy", resource=parameter_arn)
        except Exception as err:
            code = _error_code(err)
            if code in ABSENT_RESOURCE_POLICY_CODES:
                finding["resource_policy_status"] = "absent"
                tracker.record_ok("resource_policy", resource=parameter_arn)
            else:
                finding["resource_policy_status"] = _classify_status(code)
                tracker.record_skipped("resource_policy", resource=parameter_arn, reason=finding["resource_policy_status"])

        findings.append(finding)

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="ssm",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )


def _parameter_arn(region: str, account_id: str, name: str | None) -> str:
    normalized = name or ""
    separator = "" if normalized.startswith("/") else "/"
    return f"arn:aws:ssm:{region}:{account_id}:parameter{separator}{normalized}"


def _kms_key_id(parameter: dict[str, Any]) -> str | None:
    if parameter.get("Type") != "SecureString":
        return None
    return parameter.get("KeyId") or "alias/aws/ssm"


def _format_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        normalized = value.astimezone(timezone.utc)
        return normalized.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return str(value)


def _parse_policy(policy: str) -> Any:
    try:
        return json.loads(policy)
    except json.JSONDecodeError:
        return policy


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
