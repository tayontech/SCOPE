from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text()


def assert_frontmatter(body: str, name: str) -> None:
    assert re.match(r"^---\n[\s\S]*?\n---\n", body), f"{name} must start with frontmatter"
    assert re.search(rf"^name: {re.escape(name)}$", body, re.MULTILINE)
    assert re.search(r"^description: Use when ", body, re.MULTILINE)


def test_repo_attack_pipeline_skills_contract() -> None:
    attack = read("skills/scope-attack-path-analysis/SKILL.md")
    evidence = read("skills/scope-evidence-logging/SKILL.md")

    assert_frontmatter(attack, "scope-attack-path-analysis")
    assert_frontmatter(evidence, "scope-evidence-logging")

    for text in [
        "candidate_attack_paths[]",
        "entry point -> new execution context -> new permission set -> impact",
        "role chaining",
        "lateral movement",
        "hops[]",
        "security_observations[]",
        "runtime_assumption",
        "coverage_caveat",
        "Do not call AWS APIs.",
    ]:
        assert text in attack

    for line in attack.splitlines():
        if re.search(r"(^|[^A-Za-z_])attack_paths\[\]", line):
            assert re.search(r"(Do not|does not|scope-attack-validate owns promotion)", line, re.IGNORECASE), line
    assert re.search(r"Do not (write|create|generate|promote)[\s\S]{0,120}(final\s+)?`?attack_paths\[\]`?", attack, re.IGNORECASE)
    assert re.search(
        r"Each hop must change (position|principal context|capability|reachable resource|permission set|execution context|impact)(, (position|principal context|capability|reachable resource|permission set|execution context|impact))*?, or (position|principal context|capability|reachable resource|permission set|execution context|impact)\.",
        attack,
    )

    for pattern in [
        r"public endpoint[\s\S]{0,120}compute role",
        r"assume-role[\s\S]{0,120}stronger action",
        r"pass-role[\s\S]{0,120}compute",
        r"resource policy[\s\S]{0,120}external access[\s\S]{0,120}impact",
        r"single posture facts",
        r"permission lists without context change",
        r"missing required hop",
        r"data claims without target resource/action",
    ]:
        assert re.search(pattern, attack, re.IGNORECASE), pattern

    allowed = {
        "graph_edge",
        "module_resource",
        "policy_document",
        "runtime_assumption",
        "coverage_caveat",
    }
    for text in [
        "valid evidence types",
        "graph edge IDs from `$RUN_DIR/graph.json`",
        "module files/resources under `$RUN_DIR/modules/**`",
        "ARNs through the `arn` field",
        "Every evidence object needs at least one of `id`, `source_path`, or `arn`.",
        "No placeholders.",
        "No nonexistent file paths.",
        "module status",
        "coverage check",
        "field status",
        "scope.attack.schema",
    ]:
        assert text in evidence
    for evidence_type in allowed:
        assert evidence_type in evidence

    line = re.search(r"valid evidence types:\s*([^\n]+)", evidence, re.IGNORECASE)
    assert line
    listed = {value.strip("`") for value in re.findall(r"`([^`]+)`", line.group(1))}
    assert listed == allowed
    assert "arn" not in listed
