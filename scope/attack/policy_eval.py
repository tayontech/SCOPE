from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any, Literal

PolicyDecisionValue = Literal[
    "allowed", "conditional", "explicit_deny", "implicit_deny", "unknown"
]


@dataclass(frozen=True)
class PolicyDecision:
    decision: PolicyDecisionValue
    matched_allow: list[dict[str, Any]] = field(default_factory=list)
    matched_deny: list[dict[str, Any]] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)


def evaluate_policy_documents(
    policy_documents: list[dict[str, Any]], *, action: str, resource: str
) -> PolicyDecision:
    matched_allow: list[dict[str, Any]] = []
    matched_deny: list[dict[str, Any]] = []
    unconditional_allow: list[dict[str, Any]] = []
    unconditional_deny: list[dict[str, Any]] = []
    conditional_deny: list[dict[str, Any]] = []
    malformed_caveats: list[str] = []
    caveats: list[str] = []

    for policy_document in policy_documents:
        if not isinstance(policy_document, dict):
            caveat = f"Malformed policy document: {type(policy_document).__name__}"
            malformed_caveats.append(caveat)
            caveats.append(caveat)
            continue

        statements, statement_caveats = _statements(policy_document)
        malformed_caveats.extend(statement_caveats)
        caveats.extend(statement_caveats)

        for statement in statements:
            shape_caveats = _statement_shape_caveats(statement)
            malformed_caveats.extend(shape_caveats)
            caveats.extend(shape_caveats)
            if not _statement_action_matches(statement, action):
                continue
            if not _statement_resource_matches(statement, resource):
                continue

            effect = str(statement.get("Effect", "")).lower()
            if effect == "deny":
                matched_deny.append(statement)
                if "Condition" in statement:
                    conditional_deny.append(statement)
                    caveats.append(
                        f"Condition present on matching Deny statement: {statement['Condition']}"
                    )
                else:
                    unconditional_deny.append(statement)
            elif effect == "allow":
                matched_allow.append(statement)
                if "Condition" in statement:
                    caveats.append(
                        f"Condition present on matching Allow statement: {statement['Condition']}"
                    )
                else:
                    unconditional_allow.append(statement)

    if unconditional_deny:
        return PolicyDecision(
            "explicit_deny",
            matched_allow=matched_allow,
            matched_deny=matched_deny,
            caveats=caveats,
        )
    if conditional_deny:
        return PolicyDecision(
            "conditional",
            matched_allow=matched_allow,
            matched_deny=matched_deny,
            caveats=caveats,
        )
    if unconditional_allow and not malformed_caveats:
        return PolicyDecision("allowed", matched_allow=matched_allow)
    if matched_allow:
        return PolicyDecision(
            "conditional", matched_allow=matched_allow, caveats=caveats
        )
    if caveats:
        return PolicyDecision("unknown", caveats=caveats)
    return PolicyDecision("implicit_deny")


def _statements(policy_document: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        return [statements], []
    if isinstance(statements, list):
        valid_statements = [
            statement for statement in statements if isinstance(statement, dict)
        ]
        malformed_count = len(statements) - len(valid_statements)
        if malformed_count:
            return valid_statements, [
                f"Malformed Statement entries ignored: {malformed_count}"
            ]
        return valid_statements, []
    return [], [f"Malformed Statement shape: {type(statements).__name__}"]


def _statement_action_matches(statement: dict[str, Any], action: str) -> bool:
    if "Action" in statement and _action_matches(statement.get("Action"), action):
        return True
    if "NotAction" in statement:
        return not _action_matches(statement.get("NotAction"), action)
    return False


def _statement_resource_matches(statement: dict[str, Any], resource: str) -> bool:
    if "Resource" in statement and _resource_matches(
        statement.get("Resource"), resource
    ):
        return True
    if "NotResource" in statement:
        return not _resource_matches(statement.get("NotResource"), resource)
    return False


def _statement_shape_caveats(statement: dict[str, Any]) -> list[str]:
    caveats: list[str] = []
    effect = statement.get("Effect")
    if not isinstance(effect, str) or effect.lower() not in {"allow", "deny"}:
        caveats.append("Malformed Effect on Statement")
    if "Action" not in statement and "NotAction" not in statement:
        caveats.append("Malformed Statement missing action selector")
    if "Resource" not in statement and "NotResource" not in statement:
        caveats.append("Malformed Statement missing resource selector")
    for field_name in ("Action", "NotAction", "Resource", "NotResource"):
        if field_name in statement and not _valid_pattern_shape(statement[field_name]):
            caveats.append(f"Malformed {field_name} shape on Statement")
    return caveats


def _valid_pattern_shape(patterns: Any) -> bool:
    if isinstance(patterns, str):
        return True
    if isinstance(patterns, list):
        return all(isinstance(pattern, str) for pattern in patterns)
    return False


def _action_matches(patterns: Any, action: str) -> bool:
    return _matches(patterns, action, case_sensitive=False)


def _resource_matches(patterns: Any, resource: str) -> bool:
    return _matches(patterns, resource, case_sensitive=True)


def _matches(patterns: Any, value: str, *, case_sensitive: bool) -> bool:
    if isinstance(patterns, str):
        normalized_patterns = [patterns]
    elif isinstance(patterns, list):
        normalized_patterns = patterns
    else:
        return False

    comparable_value = value if case_sensitive else value.lower()
    for pattern in normalized_patterns:
        if not isinstance(pattern, str):
            continue
        comparable_pattern = pattern if case_sensitive else pattern.lower()
        if fnmatch.fnmatchcase(comparable_value, comparable_pattern):
            return True
    return False
