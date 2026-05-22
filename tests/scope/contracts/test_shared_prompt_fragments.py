from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text()


def test_stale_shared_evidence_and_verification_fragments_are_removed() -> None:
    assert not (ROOT / "agents/shared/agent-preamble.md").exists()
    assert not (ROOT / "agents/shared/evidence-logging.md").exists()
    assert not (ROOT / "agents/shared/verification-protocol.md").exists()

    for path in [
        "agents/scope-audit.md",
        "agents/scope-hunt.md",
        "agents/scope-exploit.md",
    ]:
        body = read(path)
        assert "@include agents/shared/agent-preamble.md" not in body
        assert "@include agents/shared/evidence-logging.md" not in body
        assert "@include agents/shared/verification-protocol.md" not in body


def test_agent_policy_lives_in_installed_project_doc_source() -> None:
    body = read("config/project-docs/PROJECT.md")
    assert "deploy or mutate AWS resources" in body
    assert "Session Isolation" in body
    assert "Gates are mandatory pauses" in body
    assert "external:*" in body
    assert "`critical`, `high`, `medium`, `low`" in body
    assert "confidence_pct" not in body
    assert "confidence tier" not in body
