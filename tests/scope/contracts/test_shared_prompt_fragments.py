from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text()


def test_stale_shared_evidence_and_verification_fragments_are_removed() -> None:
    assert not (ROOT / "agents/shared/evidence-logging.md").exists()
    assert not (ROOT / "agents/shared/verification-protocol.md").exists()

    for path in [
        "agents/scope-audit.md",
        "agents/scope-hunt.md",
        "agents/scope-exploit.md",
    ]:
        body = read(path)
        assert "@include agents/shared/evidence-logging.md" not in body
        assert "@include agents/shared/verification-protocol.md" not in body


def test_agent_preamble_remains_policy_not_skill() -> None:
    body = read("agents/shared/agent-preamble.md")
    assert "No auto-deployment" in body
    assert "Session Isolation" in body
    assert "Operator Gates" in body
    assert "confidence_pct" not in body
    assert "confidence tier" not in body
