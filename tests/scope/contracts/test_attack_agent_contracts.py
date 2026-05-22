from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text()


def assert_matches(text: str, pattern: str, message: str = "") -> None:
    assert re.search(pattern, text, re.MULTILINE | re.DOTALL | re.IGNORECASE), message or pattern


def assert_not_matches(text: str, pattern: str, message: str = "") -> None:
    assert not re.search(pattern, text, re.MULTILINE | re.DOTALL | re.IGNORECASE), message or pattern


def section(text: str, name: str) -> str:
    match = re.search(rf"<{name}>[\s\S]*?</{name}>", text)
    assert match, f"missing <{name}> section"
    return match.group(0)


def test_attack_analyze_agent_contract() -> None:
    prompt = read("agents/subagents/scope-attack-analyze.md")

    assert_matches(prompt, r"^name: scope-attack-analyze$", "frontmatter name missing")
    assert "candidate_attack_paths[]" in prompt
    assert "security_observations[]" in prompt
    assert_matches(
        prompt,
        r"scope-attack-validate[\s\S]{0,180}(owns|promotes|promotion)[\s\S]{0,180}attack_paths\[\]",
        "scope-attack-validate must own final path promotion",
    )
    assert_matches(
        prompt,
        r"(does not|must not|Do not)[\s\S]{0,120}(write|own|create|generate)[\s\S]{0,120}(final\s+)?`?attack_paths\[\]`?",
        "analyze must not own final attack_paths",
    )
    assert_matches(
        prompt,
        r"(keep|preserve)[\s\S]{0,120}`?attack_paths\[\]`?[\s\S]{0,120}(empty|unchanged)",
        "attack_paths must stay empty or unchanged",
    )
    assert_not_matches(
        prompt,
        r"Update only attack-owned fields[\s\S]{0,220}- `attack_paths`",
        "attack_paths must not be analyze-owned",
    )

    assert "skills/scope-attack-path-analysis/SKILL.md" in prompt
    assert "skills/scope-evidence-logging/SKILL.md" in prompt
    assert "uv run python -m scope.attack.lint --run-dir \"$RUN_DIR\" --stage candidates" in prompt

    for field in [
        '"id"',
        '"name"',
        '"category"',
        '"severity"',
        '"starting_position"',
        '"initial_context"',
        '"hops"',
        '"impact"',
        '"affected_resources"',
        '"detection_opportunities"',
        '"mitre_techniques"',
        '"remediation"',
    ]:
        assert field in prompt, f"candidate contract missing {field}"
    for field in [
        '"transition"',
        '"from_context"',
        '"action"',
        '"target"',
        '"resulting_context"',
        '"capability_gained"',
        '"required"',
        '"validation_type"',
        '"evidence"',
        '"assumptions"',
    ]:
        assert field in prompt, f"hop contract missing {field}"
    assert_matches(prompt, r'"hops": \[\s*\{\s*"id"[\s\S]{0,120}"transition"')

    allowed = {
        "graph_edge",
        "module_resource",
        "policy_document",
        "runtime_assumption",
        "coverage_caveat",
    }
    evidence_examples = re.findall(r'"evidence": \[\s*\{\s*"type": "([^"]+)"', prompt)
    assert len(evidence_examples) >= 2
    for example in evidence_examples:
        assert set(example.split("|")) == allowed

    assert 'validation_type: "coverage_caveat"' in prompt
    assert 'evidence[].type: "coverage_caveat"' in prompt
    assert_matches(prompt, r"trivial standalone posture issues[\s\S]{0,180}security_observations\[\]")

    observation_match = re.search(
        r"`security_observations\[\]` entries[\s\S]*?```json\n([\s\S]*?)\n```",
        prompt,
    )
    assert observation_match, "missing security_observations JSON contract"
    observation_block = observation_match.group(1)
    for field in ['"id"', '"severity"', '"description"', '"affected_resources"', '"evidence"', '"reason_not_path"']:
        assert field in observation_block
    assert_not_matches(observation_block, r'"(title|category|remediation)"\s*:')

    assert "Do not call AWS APIs." in prompt
    assert "AWS IAM Policy Simulator" not in prompt
    assert 'METRICS: {"candidates": 0, "observations": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}' in prompt
    assert "ERRORS: []" in prompt


def test_attack_validate_agent_contract() -> None:
    prompt = read("agents/subagents/scope-attack-validate.md")

    assert_matches(prompt, r"^name: scope-attack-validate$", "frontmatter name missing")
    for text in ["candidate_attack_paths[]", "attack_validation[]", "attack_paths[]"]:
        assert text in prompt

    candidate_lint = prompt.index('uv run python -m scope.attack.lint --run-dir "$RUN_DIR" --stage candidates')
    validation_lint = prompt.index('uv run python -m scope.attack.lint --run-dir "$RUN_DIR" --stage validation')
    assert candidate_lint < validation_lint

    for text in [
        "from scope.attack.validate_paths import validate_candidates",
        "validate_candidates(",
        "principal_policies=load_principal_policies()",
        "inline_policies",
        "attached_policies",
        "Do not generate new paths.",
        "Do not call AWS APIs.",
        "Do not run AWS IAM Policy Simulator by default.",
        "Never promote rejected candidates.",
        "Rejected candidates must remain represented in `attack_validation[]`",
        "Rejected candidates must never appear in `attack_paths[]`",
        "Update only attack-owned fields",
        'for field in ("attack_validation", "attack_paths"):',
        'if key.startswith("attack_"):',
        "Do not perform a second manual validation pass.",
    ]:
        assert text in prompt
    assert_matches(prompt, r"modules.+iam.+global\.json")
    assert_matches(prompt, r"resource_type.*iam_user")
    assert_matches(prompt, r"resource_type.*iam_role")
    assert_matches(prompt, r"resource_type.*iam_group")
    assert "needed to evaluate each candidate hop" not in prompt
    assert_matches(
        prompt,
        r"Preserve unchanged:[\s\S]*candidate_attack_paths[\s\S]*security_observations[\s\S]*runtime inventory fields[\s\S]*graph[\s\S]*modules[\s\S]*resources",
    )
    assert 'METRICS: {"candidates": 0, "promoted": 0, "validated": 0, "conditional": 0, "rejected": 0}' in prompt


def test_audit_orchestrates_attack_pipeline() -> None:
    prompt = read("agents/scope-audit.md")

    analyze = prompt.index("Dispatch `scope-attack-analyze` with:")
    candidate_lint = prompt.index('uv run python -m scope.attack.lint --run-dir "$RUN_DIR" --stage candidates')
    validate = prompt.index("Dispatch `scope-attack-validate` with:")
    validation_lint = prompt.index('uv run python -m scope.attack.lint --run-dir "$RUN_DIR" --stage validation')
    gate4 = prompt.index("<gate_4_results_approval>")
    assert analyze < candidate_lint < validate < validation_lint < gate4

    assert_matches(prompt, r"Dispatch `scope-attack-analyze` with:[\s\S]*- `RUN_DIR`[\s\S]*- `ACCOUNT_ID`[\s\S]*- `OWNED_ACCOUNTS`")
    assert_matches(prompt, r"Expected analyze output:[\s\S]*`candidate_attack_paths\[\]`[\s\S]*`security_observations\[\]`[\s\S]*`\$RUN_DIR/results\.json`")
    assert_matches(prompt, r"If candidate lint fails,[\s\S]{0,120}stop before validation[\s\S]{0,120}linter errors")
    assert "Attack analyze failure | Log, stop before candidate lint and surface the error." in prompt
    assert_matches(prompt, r"Dispatch `scope-attack-validate` with:[\s\S]*- `RUN_DIR`[\s\S]*- `ACCOUNT_ID`")
    assert_matches(prompt, r"Expected validate output:[\s\S]*`attack_validation\[\]`[\s\S]*promoted `attack_paths\[\]`[\s\S]*`\$RUN_DIR/results\.json`")
    assert_matches(prompt, r"If validation lint fails,[\s\S]{0,120}stop before Gate 4[\s\S]{0,120}linter errors")
    assert "Attack validation failure | Log, stop before validation lint and surface the error." in prompt

    attack_section = section(prompt, "attack_paths_dispatch")
    assert attack_section.index("scope-attack-analyze") < attack_section.index("stage candidates")
    assert attack_section.index("stage candidates") < attack_section.index("scope-attack-validate")
    assert attack_section.index("scope-attack-validate") < attack_section.index("stage validation")

    verification = section(prompt, "verification")
    assert_matches(verification, r"after attack validation")
    assert_not_matches(verification, r"after attack path synthesis completes")

    gate4_section = section(prompt, "gate_4_results_approval")
    for text in [
        "candidates generated",
        "validated paths",
        "conditional paths",
        "rejected paths",
        "final attack path count by severity",
        "top 3 validated/conditional paths",
    ]:
        assert text in gate4_section
    assert_not_matches(gate4_section, r"confidence|confidence tier|confidence tiers")

    assert_matches(prompt, r"Gate 4 skip exception:[\s\S]{0,180}\$RUN_DIR/results\.json[\s\S]{0,80}remain required")
    assert_not_matches(prompt, r"skips results\.json|results\.json[\s\S]{0,80}skipped")
    assert_matches(prompt, r"engagement-report\.md[\s\S]{0,140}required only when synthesizer runs and succeeds")
    assert "Do not require `engagement-report.md` when Gate 4 was skipped, defend failed, or synthesizer failed." in prompt
    assert_matches(prompt, r"Defend failure is non-blocking[\s\S]{0,140}Do not dispatch synthesizer without defend output\.")
    assert "After defend completes successfully, dispatch the synthesizer subagent automatically." in prompt
    assert_matches(prompt, r"Synthesizer failure is non-blocking[\s\S]{0,120}does not make `engagement-report\.md` mandatory\.")
    assert_matches(prompt, r"Synthesizer handled[\s\S]{0,180}when synthesizer succeeds[\s\S]{0,120}failure is non-blocking")
    assert_matches(prompt, r"Defend handled[\s\S]{0,180}When defend succeeds[\s\S]{0,160}Defend failure is logged and remains non-blocking\.")
    assert_not_matches(prompt, r"Defend creates its run directory[\s\S]{0,80}returns DEFEND_RUN_DIR")
    assert_not_matches(prompt, r"After defend completes \(or fails\), dispatch the synthesizer")
    assert_not_matches(prompt, r"continue to synthesizer/pipeline")
    assert_not_matches(prompt, r"enriches final attack paths|enriches `?attack_paths\[\]`?")
    assert_not_matches(prompt, r"METRICS \(attack_paths and severity counts\)")
    assert_not_matches(prompt, r"single fresh-context subagent")


def test_downstream_prompts_use_validation_status_contract() -> None:
    prompts = {
        path: read(path)
        for path in [
            "agents/scope-defend.md",
            "agents/subagents/scope-defend-splunk.md",
            "agents/subagents/scope-defend-remediation.md",
            "agents/subagents/scope-defend-guardrails.md",
            "agents/subagents/scope-defend-validate.md",
            "agents/subagents/scope-synthesizer.md",
            "agents/subagents/scope-hunt-audit.md",
            "agents/scope-exploit.md",
        ]
    }

    for path, body in prompts.items():
        assert_not_matches(body, r"\bconfidence_tier\b", f"{path} still uses confidence_tier")
        assert_not_matches(body, r"\bconfidence_pct\b", f"{path} still uses confidence_pct")
        if path == "agents/scope-exploit.md":
            assert_not_matches(body, r"confidence percentages(?!, no stealth-ordering headers, no OPSEC sections)")
        else:
            assert_not_matches(body, r"confidence percentages")
        assert_not_matches(body, r"conditional (?:paths? )?(?:is|are) low priority|low priority conditional")

    for path in [
        "agents/scope-defend.md",
        "agents/subagents/scope-defend-splunk.md",
        "agents/subagents/scope-defend-remediation.md",
        "agents/subagents/scope-defend-guardrails.md",
        "agents/subagents/scope-defend-validate.md",
    ]:
        body = prompts[path]
        assert_matches(body, r"attack_paths\[\][\s\S]{0,180}validation_status[\s\S]{0,120}validated[\s\S]{0,80}conditional")
        assert_matches(body, r"runtime_assumptions\[\][\s\S]{0,220}coverage_caveats\[\]|coverage_caveats\[\][\s\S]{0,220}runtime_assumptions\[\]")
        assert "Do not treat conditional as low priority" in body

    splunk = prompts["agents/subagents/scope-defend-splunk.md"]
    assert_matches(splunk, r"attack_paths\[\][\s\S]{0,500}validation_status[\s\S]{0,500}runtime_assumptions[\s\S]{0,500}coverage_caveats")
    assert_matches(splunk, r"Validation Status:[\s\S]{0,300}Runtime Assumptions:[\s\S]{0,300}Coverage Caveats:")

    for path in ["agents/subagents/scope-defend-remediation.md", "agents/subagents/scope-defend-guardrails.md"]:
        assert "validation_status" in prompts[path]
        assert_matches(prompts[path], r"runtime_assumptions[\s\S]{0,180}coverage_caveats|coverage_caveats[\s\S]{0,180}runtime_assumptions")

    hunt = prompts["agents/subagents/scope-hunt-audit.md"]
    assert "validation_status=validated" in hunt
    assert "validation_status=conditional" in hunt
    assert_matches(hunt, r"For AUDIT runs, extract:[\s\S]{0,260}validation_status[\s\S]{0,120}runtime_assumptions\[\][\s\S]{0,120}coverage_caveats\[\]")
    assert_matches(hunt, r"HUNT_RUN_TYPE=AUDIT[\s\S]{0,260}validation_status[\s\S]{0,120}runtime_assumptions\[\][\s\S]{0,120}coverage_caveats\[\]")
    assert not re.search(r"GUARANTEED|CONDITIONAL", hunt), "hunt audit must not use old uppercase confidence tier values"
    assert_not_matches(hunt, r"severity/confidence|Confidence:")
    assert_matches(hunt, r"steps\[\]\.action` as exploit command/action text")
    assert_matches(hunt, r"steps\[\]\.visibility` as MGT/DATA/NONE")
    assert_matches(hunt, r"Derive CloudTrail event candidates from the AWS CLI command or API operation")
    assert "derived eventName candidate" in hunt
    assert_not_matches(hunt, r"steps\[\]\.action`? (?:—|-)\s*these are CloudTrail eventNames|eventName: \[step\.action\]")

    synth = prompts["agents/subagents/scope-synthesizer.md"]
    assert_matches(synth, r"validation_status[\s\S]{0,220}coverage_caveats|coverage_caveats[\s\S]{0,220}validation_status")
    assert "runtime_assumptions" in synth

    exploit = prompts["agents/scope-exploit.md"]
    assert '"attack_paths": [' in exploit
    assert '"paths": [' not in exploit
    assert '"validation_status": "validated"' in exploit
    assert '"runtime_assumptions": []' in exploit
    assert '"coverage_caveats": []' in exploit
    assert "Exploit results must expose final paths in `attack_paths[]`, not `paths[]`" in exploit

    defend = prompts["agents/scope-defend.md"]
    assert_matches(defend, r"ATTACK_PATH_CONTEXT=\$\(jq '\[\.attack_paths\[\]\? \| \{[\s\S]{0,180}validation_status[\s\S]{0,180}runtime_assumptions[\s\S]{0,180}coverage_caveats")
    assert "source_attack_paths: $source_attack_paths" in defend
    assert "source_attack_path_context: $source_attack_path_context" in defend
    assert "source_attack_paths: []" not in defend
