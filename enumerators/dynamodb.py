from __future__ import annotations

import json
from typing import Any

from scope_core.coverage import CoverageTracker
from scope_core.models import ModuleEnvelope


PRIMARY_CHECKS = ["list_tables"]
REQUIRED_CHECKS = ["describe_table"]
ABSENT_RESOURCE_POLICY_CODES = {
    "ResourceNotFoundException",
    "PolicyNotFoundException",
    "UnknownOperationException",
}


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    dynamodb = factory.client("dynamodb")
    findings: list[dict[str, Any]] = []

    try:
        table_names = _list_all_tables(dynamodb)
        tracker.record_ok("list_tables", resource="tables")
    except Exception as err:
        tracker.record_module_failure("list_tables", operation="dynamodb.ListTables", err=err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="dynamodb",
            account_id=factory.account_id,
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    for table_name in table_names:
        try:
            table = dynamodb.describe_table(TableName=table_name).get("Table", {})
            tracker.record_ok("describe_table", resource=table_name)
        except Exception as err:
            tracker.record_resource_failure(
                "describe_table",
                resource=table_name,
                operation="dynamodb.DescribeTable",
                err=err,
            )
            continue

        table_arn = table.get("TableArn")
        finding = _base_table_finding(table, table_name, table_arn, region)

        try:
            response = dynamodb.describe_continuous_backups(TableName=table_name)
            description = response.get("ContinuousBackupsDescription") or {}
            pitr = description.get("PointInTimeRecoveryDescription") or {}
            finding["continuous_backups_status_value"] = description.get("ContinuousBackupsStatus")
            finding["point_in_time_recovery"] = pitr.get("PointInTimeRecoveryStatus") == "ENABLED"
            finding["continuous_backups_status"] = "present"
            tracker.record_ok("continuous_backups", resource=table_arn)
        except Exception as err:
            finding["continuous_backups_status"] = _classify_status(_error_code(err))
            tracker.record_skipped(
                "continuous_backups",
                resource=table_arn,
                reason=finding["continuous_backups_status"],
            )

        try:
            response = dynamodb.list_backups(TableName=table_name)
            finding["backup_count"] = len(response.get("BackupSummaries") or [])
            finding["backups_status"] = "present"
            tracker.record_ok("list_backups", resource=table_arn)
        except Exception as err:
            finding["backups_status"] = _classify_status(_error_code(err))
            tracker.record_skipped("list_backups", resource=table_arn, reason=finding["backups_status"])

        try:
            response = dynamodb.get_resource_policy(ResourceArn=table_arn)
            policy = response.get("Policy")
            if policy:
                finding["resource_policy"] = _parse_policy(policy)
                finding["resource_policy_status"] = "present"
            else:
                finding["resource_policy_status"] = "absent"
            tracker.record_ok("resource_policy", resource=table_arn)
        except Exception as err:
            code = _error_code(err)
            if code in ABSENT_RESOURCE_POLICY_CODES:
                finding["resource_policy_status"] = "absent"
                tracker.record_ok("resource_policy", resource=table_arn)
            else:
                finding["resource_policy_status"] = _classify_status(code)
                tracker.record_skipped("resource_policy", resource=table_arn, reason=finding["resource_policy_status"])

        findings.append(finding)

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="dynamodb",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )


def _list_all_tables(dynamodb: Any) -> list[str]:
    table_names: list[str] = []
    exclusive_start: str | None = None
    while True:
        kwargs = {"ExclusiveStartTableName": exclusive_start} if exclusive_start else {}
        response = dynamodb.list_tables(**kwargs)
        table_names.extend(response.get("TableNames") or [])
        exclusive_start = response.get("LastEvaluatedTableName")
        if not exclusive_start:
            return table_names


def _base_table_finding(table: dict[str, Any], table_name: str, table_arn: str | None, region: str) -> dict[str, Any]:
    sse = table.get("SSEDescription") or {}
    stream = table.get("StreamSpecification") or {}
    replicas = [
        {"region": replica.get("RegionName"), "status": replica.get("ReplicaStatus")}
        for replica in table.get("Replicas") or []
    ]
    table_class = (table.get("TableClassSummary") or {}).get("TableClass") or "STANDARD"

    return {
        "resource_type": "dynamodb_table",
        "resource_id": table_name,
        "arn": table_arn,
        "region": region,
        "encryption_type": sse.get("SSEType") or "AES256",
        "kms_key_id": sse.get("KMSMasterKeyArn"),
        "stream_enabled": stream.get("StreamEnabled") or False,
        "stream_view_type": stream.get("StreamViewType"),
        "is_global_table": bool(table.get("GlobalTableVersion") or replicas),
        "replicas": replicas,
        "deletion_protection": table.get("DeletionProtectionEnabled") or False,
        "table_class": table_class,
        "point_in_time_recovery": None,
        "continuous_backups_status_value": None,
        "continuous_backups_status": None,
        "backup_count": 0,
        "backups_status": None,
        "resource_policy": None,
        "resource_policy_status": None,
        "findings": [],
    }


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
