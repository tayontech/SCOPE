from __future__ import annotations

import json
from typing import Any, Callable

from scope.core.coverage import CoverageTracker
from scope.core.models import ModuleEnvelope
from scope.enumerators.resource_policy import normalize_resource_policy


PRIMARY_CHECKS = ["list_buckets"]
REQUIRED_CHECKS = ["bucket_policy", "bucket_acl", "bucket_public_access_block"]


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    s3 = factory.client("s3")
    findings: list[dict[str, Any]] = []

    try:
        buckets = (s3.list_buckets().get("Buckets") or [])
        tracker.record_ok("list_buckets", resource="buckets")
    except Exception as err:
        tracker.record_module_failure("list_buckets", operation="s3.ListBuckets", err=err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="s3",
            account_id=factory.account_id,
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    for bucket in buckets:
        bucket_name = bucket.get("Name")
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        try:
            location = s3.get_bucket_location(Bucket=bucket_name)
            bucket_region = _normalize_bucket_region(location.get("LocationConstraint"))
        except Exception as err:
            tracker.record_skipped("bucket_location", resource=bucket_arn, reason=_error_code(err))
            continue

        if region != "global" and bucket_region != region:
            continue

        finding = {
            "resource_type": "s3_bucket",
            "resource_id": bucket_name,
            "arn": bucket_arn,
            "region": bucket_region,
            "policy": None,
            "policy_status": "absent",
            "public_access_block": None,
            "public_access_block_status": "absent",
            "versioning": None,
            "versioning_status": "absent",
            "encryption": None,
            "encryption_status": "absent",
            "logging": None,
            "logging_status": "absent",
            "acl_grants": None,
            "acl_status": "absent",
            "findings": [],
        }

        try:
            response = _safe_get(lambda: s3.get_bucket_policy(Bucket=bucket_name), {"NoSuchBucketPolicy"})
            if response:
                finding["policy"] = response.get("Policy")
                normalized_policy = normalize_resource_policy(response.get("Policy"), account_id=factory.account_id)
                if normalized_policy:
                    finding["resource_policy"] = {"principals": normalized_policy["principals"]}
                    finding["resource_policy_document"] = normalized_policy["document"]
                    finding["resource_policy_statements"] = normalized_policy["statements"]
                finding["policy_status"] = "present"
            else:
                finding["policy_status"] = "absent"
            tracker.record_ok("bucket_policy", resource=bucket_arn)
        except Exception as err:
            code = _error_code(err)
            finding["policy_status"] = _classify_status(code)
            tracker.record_resource_failure("bucket_policy", resource=bucket_arn, operation="s3.GetBucketPolicy", err=err)

        try:
            response = _safe_get(
                lambda: s3.get_public_access_block(Bucket=bucket_name),
                {"NoSuchPublicAccessBlockConfiguration"},
            )
            if response:
                finding["public_access_block"] = response.get("PublicAccessBlockConfiguration")
                finding["public_access_block_status"] = "present"
            else:
                finding["public_access_block_status"] = "absent"
            tracker.record_ok("bucket_public_access_block", resource=bucket_arn)
        except Exception as err:
            code = _error_code(err)
            finding["public_access_block_status"] = _classify_status(code)
            tracker.record_resource_failure(
                "bucket_public_access_block",
                resource=bucket_arn,
                operation="s3.GetPublicAccessBlock",
                err=err,
            )

        try:
            response = s3.get_bucket_versioning(Bucket=bucket_name)
            finding["versioning"] = {
                "Status": response.get("Status"),
                "MFADelete": response.get("MFADelete"),
            }
            finding["versioning_status"] = "present" if response.get("Status") else "absent"
            tracker.record_ok("bucket_versioning", resource=bucket_arn)
        except Exception as err:
            code = _error_code(err)
            finding["versioning_status"] = _classify_status(code)
            tracker.record_skipped("bucket_versioning", resource=bucket_arn, reason=_skip_reason(code))

        try:
            response = _safe_get(
                lambda: s3.get_bucket_encryption(Bucket=bucket_name),
                {"ServerSideEncryptionConfigurationNotFoundError"},
            )
            if response:
                finding["encryption"] = response.get("ServerSideEncryptionConfiguration")
                finding["encryption_status"] = "present"
            else:
                finding["encryption_status"] = "absent"
            tracker.record_ok("bucket_encryption", resource=bucket_arn)
        except Exception as err:
            code = _error_code(err)
            finding["encryption_status"] = _classify_status(code)
            tracker.record_skipped("bucket_encryption", resource=bucket_arn, reason=_skip_reason(code))

        try:
            response = s3.get_bucket_logging(Bucket=bucket_name)
            finding["logging"] = response.get("LoggingEnabled")
            finding["logging_status"] = "present" if response.get("LoggingEnabled") else "absent"
            tracker.record_ok("bucket_logging", resource=bucket_arn)
        except Exception as err:
            code = _error_code(err)
            finding["logging_status"] = _classify_status(code)
            tracker.record_skipped("bucket_logging", resource=bucket_arn, reason=_skip_reason(code))

        try:
            response = s3.get_bucket_notification_configuration(Bucket=bucket_name)
            notification = _notification_configuration(response)
            if notification:
                finding["notification_configuration"] = notification
                finding["notification_configuration_status"] = "present"
            else:
                finding["notification_configuration_status"] = "absent"
            tracker.record_ok("bucket_notification_configuration", resource=bucket_arn)
        except Exception as err:
            code = _error_code(err)
            finding["notification_configuration_status"] = _classify_status(code)
            tracker.record_skipped("bucket_notification_configuration", resource=bucket_arn, reason=_skip_reason(code))

        try:
            response = s3.get_bucket_acl(Bucket=bucket_name)
            finding["acl_grants"] = [
                {
                    "grantee_type": (grant.get("Grantee") or {}).get("Type"),
                    "grantee_id": (grant.get("Grantee") or {}).get("ID"),
                    "grantee_uri": (grant.get("Grantee") or {}).get("URI"),
                    "permission": grant.get("Permission"),
                }
                for grant in response.get("Grants") or []
            ]
            finding["acl_status"] = "present"
            tracker.record_ok("bucket_acl", resource=bucket_arn)
        except Exception as err:
            code = _error_code(err)
            finding["acl_status"] = _classify_status(code)
            tracker.record_resource_failure("bucket_acl", resource=bucket_arn, operation="s3.GetBucketAcl", err=err)

        finding["findings"] = _generate_findings(finding)
        findings.append(finding)

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="s3",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )


def _normalize_bucket_region(location_constraint: str | None) -> str:
    if not location_constraint:
        return "us-east-1"
    if location_constraint == "EU":
        return "eu-west-1"
    return location_constraint


def _safe_get(call: Callable[[], dict[str, Any]], not_found_codes: set[str]) -> dict[str, Any] | None:
    try:
        return call()
    except Exception as err:
        if _error_code(err) in not_found_codes:
            return None
        raise


def _generate_findings(bucket: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    public_grants = [
        grant
        for grant in bucket.get("acl_grants") or []
        if grant.get("grantee_uri")
        and ("AllUsers" in grant["grantee_uri"] or "AuthenticatedUsers" in grant["grantee_uri"])
    ]
    if public_grants:
        findings.append(
            {
                "type": "public_acl",
                "severity": "high",
                "detail": f"Bucket has {len(public_grants)} public ACL grant(s)",
            }
        )

    pab = bucket.get("public_access_block")
    if not pab:
        findings.append(
            {
                "type": "no_public_access_block",
                "severity": "medium",
                "detail": "No public access block configuration set",
            }
        )
    elif not (
        pab.get("BlockPublicAcls")
        and pab.get("IgnorePublicAcls")
        and pab.get("BlockPublicPolicy")
        and pab.get("RestrictPublicBuckets")
    ):
        findings.append(
            {
                "type": "partial_public_access_block",
                "severity": "medium",
                "detail": "Public access block is not fully restrictive",
            }
        )

    if not bucket.get("encryption"):
        findings.append({"type": "no_encryption", "severity": "medium", "detail": "No default server-side encryption configured"})

    versioning = bucket.get("versioning")
    if not versioning or versioning.get("Status") != "Enabled":
        findings.append({"type": "no_versioning", "severity": "low", "detail": "Bucket versioning is not enabled"})

    if _has_public_policy(bucket.get("policy")):
        findings.append(
            {
                "type": "public_policy",
                "severity": "high",
                "detail": "Bucket policy allows wildcard principal",
            }
        )

    return findings


def _has_public_policy(policy: str | None) -> bool:
    if not policy:
        return False
    try:
        document = json.loads(policy)
    except json.JSONDecodeError:
        return False
    statements = document.get("Statement", []) if isinstance(document, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict) and principal.get("AWS") == "*":
            return True
    return False


def _notification_configuration(response: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "LambdaFunctionConfigurations",
        "TopicConfigurations",
        "QueueConfigurations",
        "EventBridgeConfiguration",
    )
    return {key: response[key] for key in keys if response.get(key)}


def _classify_status(code: str) -> str:
    return "access_denied" if code in {"AccessDenied", "AccessDeniedException"} else "error"


def _skip_reason(code: str) -> str:
    return "access_denied" if code in {"AccessDenied", "AccessDeniedException"} else code


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
