from __future__ import annotations

import json
from typing import Any

from scope.core.coverage import CoverageTracker
from scope.core.models import ModuleEnvelope


PRIMARY_CHECKS = ["list_keys"]
REQUIRED_CHECKS = ["describe_key", "key_policy", "grants"]


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    kms = factory.client("kms")
    findings: list[dict[str, Any]] = []

    try:
        keys = factory.paginate(kms, "list_keys", "Keys")
        tracker.record_ok("list_keys", resource="keys")
    except Exception as err:
        tracker.record_module_failure("list_keys", operation="kms.ListKeys", err=err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="kms",
            account_id=factory.account_id,
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    for key_entry in keys:
        key_id = key_entry.get("KeyId")
        try:
            metadata = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
            tracker.record_ok("describe_key", resource=key_id)
        except Exception as err:
            tracker.record_resource_failure(
                "describe_key",
                resource=key_id,
                operation="kms.DescribeKey",
                err=err,
            )
            continue

        if metadata.get("KeyManager") != "CUSTOMER":
            continue

        key_arn = metadata.get("Arn")
        finding = {
            "resource_type": "kms_key",
            "resource_id": key_id,
            "arn": key_arn,
            "region": region,
            "key_state": metadata.get("KeyState"),
            "usage": metadata.get("KeyUsage"),
            "origin": metadata.get("Origin"),
            "description": metadata.get("Description") or "",
            "rotation_enabled": False,
            "rotation_status": None,
            "policy_principals": [],
            "policy_status": None,
            "grants": [],
            "grants_status": None,
            "findings": [],
        }

        try:
            response = kms.get_key_policy(KeyId=key_id, PolicyName="default")
            finding["policy_principals"] = _extract_policy_principals(response.get("Policy"))
            finding["policy_status"] = "present"
            tracker.record_ok("key_policy", resource=key_arn)
        except Exception as err:
            code = _error_code(err)
            finding["policy_status"] = _classify_status(code)
            tracker.record_resource_failure("key_policy", resource=key_arn, operation="kms.GetKeyPolicy", err=err)

        try:
            grants = factory.paginate(kms, "list_grants", "Grants", KeyId=key_id)
            finding["grants"] = [
                {
                    "grant_id": grant.get("GrantId"),
                    "grantee_principal": grant.get("GranteePrincipal"),
                    "operations": grant.get("Operations") or [],
                    "retiring_principal": grant.get("RetiringPrincipal"),
                }
                for grant in grants
            ]
            finding["grants_status"] = "present"
            tracker.record_ok("grants", resource=key_arn)
        except Exception as err:
            code = _error_code(err)
            finding["grants_status"] = _classify_status(code)
            tracker.record_resource_failure("grants", resource=key_arn, operation="kms.ListGrants", err=err)

        try:
            response = kms.get_key_rotation_status(KeyId=key_id)
            finding["rotation_enabled"] = response.get("KeyRotationEnabled") or False
            finding["rotation_status"] = "present"
            tracker.record_ok("rotation_status", resource=key_arn)
        except Exception as err:
            code = _error_code(err)
            if code == "UnsupportedOperationException":
                finding["rotation_enabled"] = None
                finding["rotation_status"] = "unsupported"
                tracker.record_skipped("rotation_status", resource=key_arn, reason="unsupported")
            else:
                finding["rotation_status"] = _classify_status(code)
                reason = "access_denied" if finding["rotation_status"] == "access_denied" else code
                tracker.record_skipped("rotation_status", resource=key_arn, reason=reason)

        finding["findings"] = _generate_findings(finding)
        findings.append(finding)

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="kms",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )


def _generate_findings(key: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not key["rotation_enabled"]:
        findings.append(
            {
                "type": "no_rotation",
                "severity": "medium",
                "detail": "Key rotation is not enabled",
            }
        )
    if key["key_state"] == "PendingDeletion":
        findings.append(
            {
                "type": "pending_deletion",
                "severity": "low",
                "detail": "Key is pending deletion",
            }
        )
    if "*" in key.get("policy_principals", []):
        findings.append(
            {
                "type": "wildcard_principal",
                "severity": "high",
                "detail": "Key policy allows wildcard principal",
            }
        )
    grants = key.get("grants") or []
    if grants:
        findings.append(
            {
                "type": "has_grants",
                "severity": "low",
                "detail": f"Key has {len(grants)} grant(s)",
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
