from __future__ import annotations

import json
import re
from typing import Any


ACCOUNT_ID_PATTERN = re.compile(r"^arn:[^:]*:iam::(?P<account_id>[0-9]{12}):")
SOURCE_ARN_KEYS = {"aws:sourcearn", "aws:sourceownerarn"}
SOURCE_ACCOUNT_KEYS = {"aws:sourceaccount", "aws:sourceowner"}
SOURCE_ORG_KEYS = {"aws:principalorgid", "aws:sourceorgid"}


def normalize_resource_policy(
    policy: str | dict[str, Any] | None,
    *,
    account_id: str | None = None,
) -> dict[str, Any] | None:
    document = parse_policy_document(policy)
    if document is None:
        return None

    statements = [_normalize_statement(statement, account_id=account_id) for statement in _statements(document)]
    principals = sorted(
        {
            principal
            for statement in statements
            if statement["effect"] == "Allow"
            for principal in statement["normalized_principals"]
        }
    )
    return {
        "document": document,
        "principals": principals,
        "statements": statements,
    }


def parse_policy_document(policy: str | dict[str, Any] | None) -> dict[str, Any] | None:
    if not policy:
        return None
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return None
    if not isinstance(policy, dict):
        return None
    return policy


def _statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [statement for statement in statements if isinstance(statement, dict)]


def _normalize_statement(statement: dict[str, Any], *, account_id: str | None) -> dict[str, Any]:
    principals = sorted(_principal_values(statement.get("Principal")))
    actions = _string_list(statement.get("Action"))
    resources = _string_list(statement.get("Resource"))
    conditions = statement.get("Condition") if isinstance(statement.get("Condition"), dict) else None
    service_principals = sorted(principal for principal in principals if principal.endswith(".amazonaws.com"))
    return {
        "sid": statement.get("Sid"),
        "effect": statement.get("Effect"),
        "principal": statement.get("Principal"),
        "not_principal": statement.get("NotPrincipal"),
        "action": actions,
        "not_action": _string_list(statement.get("NotAction")),
        "resource": resources,
        "not_resource": _string_list(statement.get("NotResource")),
        "condition": conditions,
        "normalized_principals": principals,
        "normalized_actions": actions,
        "normalized_resources": resources,
        "source_arns": _condition_values(conditions, SOURCE_ARN_KEYS),
        "source_accounts": _condition_values(conditions, SOURCE_ACCOUNT_KEYS),
        "source_org_ids": _condition_values(conditions, SOURCE_ORG_KEYS),
        "service_principals": service_principals,
        "is_public": "*" in principals,
        "is_cross_account": _is_cross_account(principals, account_id),
    }


def _principal_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value}
    if not isinstance(value, dict):
        return set()

    principals: set[str] = set()
    for key in ("AWS", "Service", "Federated", "CanonicalUser"):
        item = value.get(key)
        if isinstance(item, str):
            principals.add(item)
        elif isinstance(item, list):
            principals.update(str(part) for part in item)
    return principals


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _condition_values(condition: dict[str, Any] | None, target_keys: set[str]) -> list[str]:
    if not condition:
        return []

    values: set[str] = set()
    for operator_value in condition.values():
        if not isinstance(operator_value, dict):
            continue
        for key, raw_value in operator_value.items():
            if key.lower() not in target_keys:
                continue
            values.update(_string_list(raw_value))
    return sorted(values)


def _is_cross_account(principals: list[str], account_id: str | None) -> bool:
    if not account_id:
        return False
    for principal in principals:
        match = ACCOUNT_ID_PATTERN.match(principal)
        if match and match.group("account_id") != account_id:
            return True
    return False
