from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def assert_note_file(path: str, required_phrases: list[str]) -> None:
    text = read(path)
    words = text.split()

    assert len(words) <= 1800, f"{path} should stay curated and small"
    assert "not a checklist" in text.lower()
    assert "current environment evidence" in text.lower()
    for phrase in required_phrases:
        assert phrase in text


def test_exploit_reasoning_notes_are_curated_expert_context() -> None:
    assert_note_file(
        "config/exploit-reasoning-notes.md",
        [
            "## PassRole Requires Execution Control",
            "## Data Events Change Post-Exploitation Confidence",
            "## Cross-Account Access Requires Three Agreements",
            "## Bedrock Abuse Depends On Runtime And Data Boundaries",
        ],
    )


def test_hunt_reasoning_notes_are_curated_expert_context() -> None:
    assert_note_file(
        "config/hunt-reasoning-notes.md",
        [
            "## Resolve The Actual Actor Before Query Expansion",
            "## Absence Of Data Events Does Not Refute Activity",
            "## IAM Changes Need Delayed-Use Windows",
            "## Prefer Dashboard Monitoring For High-Volume Ambiguity",
        ],
    )


def test_static_aws_knowledge_catalogues_do_not_exist() -> None:
    assert not (ROOT / "config/techniques.json").exists()
    assert not (ROOT / "config/hunt-techniques.json").exists()
    assert not (ROOT / "config/hunt-reference-patterns.json").exists()
    assert not (ROOT / "config/cloudtrail-classes.json").exists()


def test_remaining_config_json_files_are_valid() -> None:
    removed = {
        "techniques.json",
        "hunt-techniques.json",
        "hunt-reference-patterns.json",
        "cloudtrail-classes.json",
    }
    for path in (ROOT / "config").glob("*.json"):
        assert path.name not in removed
        json.loads(path.read_text(encoding="utf-8"))
