from __future__ import annotations

import re
from typing import Any


FORBIDDEN_KEYS = {"findings", "severity", "risk", "attack_path"}
FORBIDDEN_TEXT = (
    "credential theft",
    "defense evasion",
    "privilege escalation",
    "attack surface",
    "critical",
    "high",
    "medium",
    "low",
)


def assert_facts_only_resources(resources: list[dict[str, Any]]) -> None:
    for index, resource in enumerate(resources):
        _assert_facts_only(resource, path=f"resources[{index}]")


def _assert_facts_only(value: Any, *, path: str) -> None:
    if _is_policy_document_path(path):
        return

    if isinstance(value, dict):
        forbidden = FORBIDDEN_KEYS.intersection(value)
        assert not forbidden, f"{path} contains forbidden judgment key(s): {sorted(forbidden)}"
        for key, child in value.items():
            _assert_facts_only(child, path=f"{path}.{key}")
        return

    if isinstance(value, list):
        for index, child in enumerate(value):
            _assert_facts_only(child, path=f"{path}[{index}]")
        return

    if isinstance(value, str):
        lowered = value.lower()
        matches = [
            text
            for text in FORBIDDEN_TEXT
            if re.search(rf"(?<!\w){re.escape(text)}(?!\w)", lowered)
        ]
        assert not matches, f"{path} contains forbidden judgment text: {matches}"


def _is_policy_document_path(path: str) -> bool:
    return "document" in path.split(".")
