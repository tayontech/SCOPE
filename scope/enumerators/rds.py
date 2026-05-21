from __future__ import annotations

from typing import Any

from scope.core.coverage import CoverageTracker
from scope.core.models import ModuleEnvelope


PRIMARY_CHECKS = ["describe_db_instances"]
REQUIRED_CHECKS = ["describe_db_snapshots", "snapshot_attributes"]


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    rds = factory.client("rds")
    findings: list[dict[str, Any]] = []

    try:
        instances = factory.paginate(rds, "describe_db_instances", "DBInstances")
        tracker.record_ok("describe_db_instances", resource="db_instances")
    except Exception as err:
        tracker.record_module_failure("describe_db_instances", operation="rds.DescribeDBInstances", err=err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="rds",
            account_id=factory.account_id,
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    for instance in instances:
        finding = _instance_finding(instance, region)
        finding["findings"] = _generate_instance_findings(finding)
        findings.append(finding)

    snapshots: list[dict[str, Any]] = []
    try:
        snapshots = factory.paginate(rds, "describe_db_snapshots", "DBSnapshots", SnapshotType="manual")
        tracker.record_ok("describe_db_snapshots", resource="manual_snapshots")
    except Exception as err:
        tracker.record_resource_failure(
            "describe_db_snapshots",
            resource=None,
            operation="rds.DescribeDBSnapshots",
            err=err,
        )

    for snapshot in snapshots:
        snapshot_arn = snapshot.get("DBSnapshotArn")
        finding = {
            "resource_type": "rds_snapshot",
            "resource_id": snapshot.get("DBSnapshotIdentifier"),
            "arn": snapshot_arn,
            "region": region,
            "engine": snapshot.get("Engine"),
            "encrypted": snapshot.get("Encrypted") or False,
            "kms_key_id": snapshot.get("KmsKeyId"),
            "db_instance_identifier": snapshot.get("DBInstanceIdentifier"),
            "public": False,
            "shared_with": [],
            "snapshot_attributes_status": None,
            "findings": [],
        }

        try:
            response = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshot.get("DBSnapshotIdentifier"))
            result = response.get("DBSnapshotAttributesResult") or {}
            for attribute in result.get("DBSnapshotAttributes") or []:
                if attribute.get("AttributeName") == "restore":
                    values = attribute.get("AttributeValues") or []
                    finding["public"] = "all" in values
                    finding["shared_with"] = [value for value in values if value != "all"]
            finding["snapshot_attributes_status"] = "present"
            tracker.record_ok("snapshot_attributes", resource=snapshot_arn)
        except Exception as err:
            code = _error_code(err)
            finding["snapshot_attributes_status"] = _classify_status(code)
            tracker.record_resource_failure(
                "snapshot_attributes",
                resource=snapshot_arn,
                operation="rds.DescribeDBSnapshotAttributes",
                err=err,
            )

        finding["findings"] = _generate_snapshot_findings(finding)
        findings.append(finding)

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="rds",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )


def _instance_finding(instance: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "resource_type": "rds_instance",
        "resource_id": instance.get("DBInstanceIdentifier"),
        "arn": instance.get("DBInstanceArn"),
        "region": region,
        "engine": instance.get("Engine"),
        "engine_version": instance.get("EngineVersion"),
        "publicly_accessible": instance.get("PubliclyAccessible") or False,
        "storage_encrypted": instance.get("StorageEncrypted") or False,
        "kms_key_id": instance.get("KmsKeyId"),
        "iam_auth_enabled": instance.get("IAMDatabaseAuthenticationEnabled") or False,
        "deletion_protection": instance.get("DeletionProtection") or False,
        "security_groups": [
            {
                "id": security_group.get("VpcSecurityGroupId"),
                "status": security_group.get("Status"),
            }
            for security_group in instance.get("VpcSecurityGroups") or []
        ],
        "multi_az": instance.get("MultiAZ") or False,
        "findings": [],
    }


def _generate_instance_findings(instance: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if instance["publicly_accessible"]:
        findings.append(
            {"type": "publicly_accessible", "severity": "high", "detail": "DB instance is publicly accessible"}
        )
    if not instance["storage_encrypted"]:
        findings.append({"type": "no_encryption", "severity": "high", "detail": "DB instance storage is not encrypted"})
    if not instance["iam_auth_enabled"]:
        findings.append({"type": "no_iam_auth", "severity": "low", "detail": "IAM authentication is not enabled"})
    if not instance["deletion_protection"]:
        findings.append(
            {"type": "no_deletion_protection", "severity": "low", "detail": "Deletion protection is not enabled"}
        )
    return findings


def _generate_snapshot_findings(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if snapshot["public"]:
        findings.append(
            {
                "type": "public_snapshot",
                "severity": "critical",
                "detail": "DB snapshot is publicly accessible (shared with all)",
            }
        )
    if not snapshot["encrypted"]:
        findings.append({"type": "unencrypted_snapshot", "severity": "high", "detail": "DB snapshot is not encrypted"})
    if snapshot["shared_with"]:
        findings.append(
            {
                "type": "shared_snapshot",
                "severity": "medium",
                "detail": f"Snapshot shared with {len(snapshot['shared_with'])} account(s)",
            }
        )
    return findings


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
