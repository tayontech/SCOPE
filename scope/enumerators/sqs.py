from __future__ import annotations

import json
from typing import Any

from scope.core.coverage import CoverageTracker
from scope.core.models import ModuleEnvelope
from scope.enumerators.resource_policy import normalize_resource_policy


PRIMARY_CHECKS = ["list_queues"]
REQUIRED_CHECKS = ["queue_attributes"]


def _queue_name_from_url(url: str | None) -> str | None:
    if not url:
        return None
    return url.rstrip("/").split("/")[-1]


def _extract_dlq_arn(redrive_policy: str | None) -> str | None:
    if not redrive_policy:
        return None
    try:
        parsed = json.loads(redrive_policy)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict):
        return parsed.get("deadLetterTargetArn")
    return None


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


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    sqs = factory.client("sqs")
    findings: list[dict[str, Any]] = []

    try:
        queue_urls = factory.paginate(sqs, "list_queues", "QueueUrls")
        tracker.record_ok("list_queues", resource="queues")
    except KeyError as err:
        if "QueueUrls" in str(err):
            queue_urls = []
            tracker.record_ok("list_queues", resource="queues")
        else:
            tracker.record_module_failure("list_queues", operation="sqs.ListQueues", err=err)
            coverage, errors = tracker.to_envelope_fields()
            return ModuleEnvelope(
                module="sqs",
                account_id=factory.account_id,
                region=region,
                status=tracker.derive_status(),
                resources=[],
                coverage=coverage,
                errors=errors,
            )
    except Exception as err:
        tracker.record_module_failure("list_queues", operation="sqs.ListQueues", err=err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="sqs",
            account_id=factory.account_id,
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    for queue_url in queue_urls:
        queue_finding = {
            "resource_type": "sqs_queue",
            "resource_id": _queue_name_from_url(queue_url),
            "arn": None,
            "region": region,
            "queue_url": queue_url,
            "resource_policy": None,
            "fifo": False,
            "dlq_arn": None,
            "kms_key_id": None,
            "visibility_timeout": 30,
            "queue_attributes_status": None,
            "findings": [],
        }

        try:
            response = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])
            attributes = response.get("Attributes", {})
            queue_arn = attributes.get("QueueArn")
            principals = _extract_policy_principals(attributes.get("Policy"))

            queue_finding["arn"] = queue_arn
            queue_finding["resource_policy"] = {"principals": principals} if principals else None
            normalized_policy = normalize_resource_policy(attributes.get("Policy"), account_id=factory.account_id)
            if normalized_policy is not None:
                queue_finding["resource_policy_document"] = normalized_policy["document"]
                queue_finding["resource_policy_statements"] = normalized_policy["statements"]
            queue_finding["fifo"] = attributes.get("FifoQueue") == "true"
            queue_finding["dlq_arn"] = _extract_dlq_arn(attributes.get("RedrivePolicy"))
            queue_finding["kms_key_id"] = attributes.get("KmsMasterKeyId")
            queue_finding["visibility_timeout"] = int(attributes.get("VisibilityTimeout") or 30)
            queue_finding["queue_attributes_status"] = "present"
            tracker.record_ok("queue_attributes", resource=queue_arn or queue_url)
        except Exception as err:
            code = _error_code(err)
            queue_finding["queue_attributes_status"] = (
                "access_denied" if code in {"AccessDenied", "AccessDeniedException"} else "error"
            )
            tracker.record_resource_failure(
                "queue_attributes",
                resource=queue_url,
                operation="sqs.GetQueueAttributes",
                err=err,
            )

        findings.append(queue_finding)

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="sqs",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )


def _error_code(err: Exception) -> str:
    response = getattr(err, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict) and error.get("Code"):
            return str(error["Code"])
    return err.__class__.__name__ or "Error"
