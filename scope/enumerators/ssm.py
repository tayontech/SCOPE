from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from scope.core.coverage import CoverageTracker
from scope.core.models import ModuleEnvelope
from scope.enumerators.resource_policy import normalize_resource_policy


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
            policy_entries = _normalize_policy_entries(response.get("Policies") or [], account_id=factory.account_id)
            if policy_entries:
                finding["resource_policies"] = policy_entries
                finding["resource_policy"] = policy_entries[0]["document"]
                finding["resource_policy_document"] = policy_entries[0]["document"]
                finding["resource_policy_statements"] = [
                    statement
                    for policy_entry in policy_entries
                    for statement in policy_entry["statements"]
                ]
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


def _normalize_policy_entries(policies: list[Any], *, account_id: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for index, entry in enumerate(policies):
        if not isinstance(entry, dict):
            continue
        normalized_policy = normalize_resource_policy(entry.get("Policy"), account_id=account_id)
        if not normalized_policy:
            continue
        entries.append(
            {
                "policy_id": entry.get("PolicyId") or entry.get("PolicyHash") or f"policy-{index + 1}",
                "policy_hash": entry.get("PolicyHash"),
                "document": normalized_policy["document"],
                "principals": normalized_policy["principals"],
                "statements": normalized_policy["statements"],
            }
        )
    return entries


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
