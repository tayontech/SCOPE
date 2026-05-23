from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text()


def assert_frontmatter(body: str, name: str) -> None:
    assert re.match(r"^---\n[\s\S]*?\n---\n", body), f"{name} must start with frontmatter"
    assert re.search(rf"^name: {re.escape(name)}$", body, re.MULTILINE)
    assert re.search(r"^description: Use ", body, re.MULTILINE)


def test_knowledge_skills_define_load_and_update_contracts() -> None:
    load = read("skills/scope-knowledge-load/SKILL.md")
    update = read("skills/scope-knowledge-update/SKILL.md")

    assert_frontmatter(load, "scope-knowledge-load")
    assert_frontmatter(update, "scope-knowledge-update")

    for text in [
        "KNOWLEDGE_CONTEXT",
        "knowledge/environment.md",
        "knowledge/observables.jsonl",
        "knowledge/baselines.json",
        "knowledge/coverage-gaps.md",
        "config/observations.md",
        "Treat knowledge as context, not ground truth.",
        "Cite which knowledge entries influenced decisions.",
        "Do not use a knowledge entry as the only evidence",
    ]:
        assert text in load

    for text in [
        "KNOWLEDGE_UPDATE",
        "Subagents may propose `knowledge_updates[]`",
        "only the top-level orchestrator applies updates",
        "config/observations.md",
        "knowledge/observables.jsonl",
        "knowledge/baselines.json",
        "knowledge/coverage-gaps.md",
        "knowledge/investigations/INV-*.md",
        "knowledge/research/R-*.md",
        "Do not write secrets",
        "Every update must cite evidence",
    ]:
        assert text in update

    for status in [
        "confirmed",
        "likely_normal",
        "suspicious",
        "false_positive",
        "coverage_gap",
        "needs_review",
    ]:
        assert status in load
        assert status in update


def test_knowledge_skills_do_not_persist_resource_identifiers() -> None:
    load = read("skills/scope-knowledge-load/SKILL.md")
    update = read("skills/scope-knowledge-update/SKILL.md")

    assert "Do not write ARNs, account IDs, bucket names, role names, key IDs, or access key IDs" in update
    for forbidden in [
        "If an update contains an account ID",
        "principals, roles, user agents, source IPs, AWS actions",
        "Known-normal AssumeRole chains",
        "external_account",
        "bucket|secret",
    ]:
        assert forbidden not in update

    assert "Resource identifiers are session-scoped" in load
    assert "type: principal|role|ip|user_agent|event_name|bucket|secret|external_account" not in load


def test_knowledge_directory_templates_exist() -> None:
    expected_files = [
        "knowledge/README.md",
        "knowledge/environment.md",
        "knowledge/observables.example.jsonl",
        "knowledge/baselines.json",
        "knowledge/coverage-gaps.md",
        "knowledge/investigations/README.md",
        "knowledge/research/README.md",
    ]
    for path in expected_files:
        assert (ROOT / path).exists(), f"{path} should exist"

    json.loads(read("knowledge/baselines.json"))

    readme = read("knowledge/README.md")
    assert "context, not ground truth" in readme
    assert "Top-level agents read knowledge through `skills/scope-knowledge-load/SKILL.md`" in readme
    assert "Top-level agents update knowledge through `skills/scope-knowledge-update/SKILL.md`" in readme


def test_top_level_agents_use_knowledge_skills() -> None:
    top_level_agents = [
        "agents/scope-audit.md",
        "agents/scope-controls.md",
        "agents/scope-exploit.md",
        "agents/scope-investigate.md",
    ]
    stale_fragments = [
        "Load environment observations",
        "Update environment observations",
        "append up to 5 concise observations",
        "append notable observations",
        "hunt/context.json",
    ]

    for path in top_level_agents:
        body = read(path)
        assert "skills/scope-knowledge-load/SKILL.md" in body, f"{path} should load knowledge"
        assert "skills/scope-knowledge-update/SKILL.md" in body, f"{path} should update knowledge"
        assert "Do not treat knowledge as ground truth" in body, f"{path} should demote stored knowledge"
        for fragment in stale_fragments:
            assert fragment not in body, f"{path} contains stale fragment {fragment!r}"

    investigate = read("agents/scope-investigate.md")
    assert "AGENT=scope-investigate" in investigate
    assert "skills/scope-investigation-report/SKILL.md" in investigate
    assert "Only run this step if the analyst chose to save artifacts" in investigate
    assert "status=skipped" in investigate


def test_investigate_subagents_do_not_write_durable_knowledge() -> None:
    for path in [
        "agents/subagents/scope-investigate-run.md",
        "agents/subagents/scope-investigate-alert.md",
        "agents/subagents/scope-investigate-intel.md",
    ]:
        body = read(path)
        assert "Write durable knowledge or memory files" in body
        assert "context.json" not in body


def test_architecture_uses_knowledge_contract_instead_of_hunt_context_json() -> None:
    body = read("ARCHITECTURE.md")
    assert "skills/scope-knowledge-load/SKILL.md" in body
    assert "skills/scope-knowledge-update/SKILL.md" in body
    assert "scope-knowledge-update" in body
    assert "hunt/context.json" not in body
    assert "context.json" not in body
