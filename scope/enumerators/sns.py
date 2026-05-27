from __future__ import annotations

import json
from typing import Any

from scope.core.coverage import CoverageTracker
from scope.core.models import ModuleEnvelope
from scope.enumerators.resource_policy import normalize_resource_policy


PRIMARY_CHECKS = ["list_topics"]
REQUIRED_CHECKS = ["topic_attributes", "topic_subscriptions"]


def _topic_name_from_arn(arn: str | None) -> str | None:
    if not arn:
        return None
    return arn.split(":")[-1]


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
    sns = factory.client("sns")
    findings: list[dict[str, Any]] = []

    try:
        topics = factory.paginate(sns, "list_topics", "Topics")
        tracker.record_ok("list_topics", resource="topics")
    except Exception as err:
        tracker.record_module_failure("list_topics", operation="sns.ListTopics", err=err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="sns",
            account_id=factory.account_id,
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    for topic in topics:
        topic_arn = topic.get("TopicArn")
        topic_finding = {
            "resource_type": "sns_topic",
            "resource_id": _topic_name_from_arn(topic_arn),
            "arn": topic_arn,
            "region": region,
            "resource_policy": None,
            "kms_key_id": None,
            "subscriptions_confirmed": 0,
            "subscriptions": [],
            "subscriptions_status": None,
            "topic_attributes_status": None,
            "findings": [],
        }

        try:
            response = sns.get_topic_attributes(TopicArn=topic_arn)
            attributes = response.get("Attributes", {})
            principals = _extract_policy_principals(attributes.get("Policy"))
            topic_finding["resource_policy"] = {"principals": principals} if principals else None
            normalized_policy = normalize_resource_policy(attributes.get("Policy"), account_id=factory.account_id)
            if normalized_policy is not None:
                topic_finding["resource_policy_document"] = normalized_policy["document"]
                topic_finding["resource_policy_statements"] = normalized_policy["statements"]
            topic_finding["kms_key_id"] = attributes.get("KmsMasterKeyId")
            topic_finding["subscriptions_confirmed"] = int(attributes.get("SubscriptionsConfirmed") or 0)
            topic_finding["topic_attributes_status"] = "present"
            tracker.record_ok("topic_attributes", resource=topic_arn)
        except Exception as err:
            code = _error_code(err)
            topic_finding["topic_attributes_status"] = (
                "access_denied" if code in {"AccessDenied", "AccessDeniedException"} else "error"
            )
            tracker.record_resource_failure(
                "topic_attributes",
                resource=topic_arn,
                operation="sns.GetTopicAttributes",
                err=err,
            )

        try:
            subscriptions = factory.paginate(
                sns,
                "list_subscriptions_by_topic",
                "Subscriptions",
                TopicArn=topic_arn,
            )
            topic_finding["subscriptions"] = [
                {
                    "subscription_arn": subscription.get("SubscriptionArn"),
                    "protocol": subscription.get("Protocol"),
                    "endpoint": subscription.get("Endpoint"),
                }
                for subscription in subscriptions
                if isinstance(subscription, dict)
            ]
            topic_finding["subscriptions_status"] = "present"
            tracker.record_ok("topic_subscriptions", resource=topic_arn)
        except Exception as err:
            code = _error_code(err)
            topic_finding["subscriptions_status"] = (
                "access_denied" if code in {"AccessDenied", "AccessDeniedException"} else "error"
            )
            tracker.record_resource_failure(
                "topic_subscriptions",
                resource=topic_arn,
                operation="sns.ListSubscriptionsByTopic",
                err=err,
            )

        findings.append(topic_finding)

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="sns",
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
