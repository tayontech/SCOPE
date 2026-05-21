from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from scope_core.coverage import CoverageTracker
from scope_core.models import ModuleEnvelope


PRIMARY_CHECKS = ["list_secrets"]
REQUIRED_CHECKS = ["resource_policy"]


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    secrets = factory.client("secrets")
    findings: list[dict[str, Any]] = []

    try:
        secret_list = factory.paginate(secrets, "list_secrets", "SecretList")
        tracker.record_ok("list_secrets", resource="secrets")
    except Exception as err:
        tracker.record_module_failure("list_secrets", operation="secretsmanager.ListSecrets", err=err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="secrets",
            account_id=factory.account_id,
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    for secret in secret_list:
        secret_name = secret.get("Name")
        secret_arn = secret.get("ARN")
        finding = {
            "resource_type": "secrets_secret",
            "resource_id": secret_name,
            "arn": secret_arn,
            "region": region,
            "rotation_enabled": secret.get("RotationEnabled") or False,
            "last_rotated_date": _format_timestamp(secret.get("LastRotatedDate")),
            "last_accessed_date": _format_timestamp(secret.get("LastAccessedDate")),
            "kms_key_id": secret.get("KmsKeyId"),
            "resource_policy_principals": [],
            "resource_policy_status": None,
            "findings": [],
        }

        try:
            response = secrets.get_resource_policy(SecretId=secret_arn)
            policy = response.get("ResourcePolicy")
            if policy:
                finding["resource_policy_principals"] = _extract_policy_principals(policy)
                finding["resource_policy_status"] = "present"
            else:
                finding["resource_policy_status"] = "absent"
            tracker.record_ok("resource_policy", resource=secret_arn)
        except Exception as err:
            code = _error_code(err)
            if code == "ResourceNotFoundException":
                tracker.record_ok("resource_policy", resource=secret_arn)
                continue
            finding["resource_policy_status"] = _classify_status(code)
            tracker.record_resource_failure(
                "resource_policy",
                resource=secret_arn,
                operation="secretsmanager.GetResourcePolicy",
                err=err,
            )

        finding["findings"] = _generate_findings(finding)
        findings.append(finding)

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="secrets",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )


def _generate_findings(secret: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not secret["rotation_enabled"]:
        findings.append(
            {
                "type": "no_rotation",
                "severity": "medium",
                "detail": "Secret rotation is not enabled",
            }
        )

    if "*" in secret.get("resource_policy_principals", []):
        findings.append(
            {
                "type": "wildcard_principal",
                "severity": "high",
                "detail": "Secret resource policy allows wildcard principal",
            }
        )

    last_accessed = secret.get("last_accessed_date")
    if last_accessed:
        days_since_access = (datetime.now(timezone.utc) - _parse_timestamp(last_accessed)).days
        if days_since_access >= 90:
            findings.append(
                {
                    "type": "stale_secret",
                    "severity": "low",
                    "detail": f"Secret not accessed in {days_since_access} days",
                }
            )

    return findings


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


def _format_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        normalized = value.astimezone(timezone.utc)
        return normalized.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return str(value)


def _parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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
