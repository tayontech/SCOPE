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
    assert_matches(
        prompt,
        r"Dispatch `scope-research`[\s\S]{0,700}`?CALLER=attack-paths`?[\s\S]{0,700}`?SERVICE=[^`\n]+`?[\s\S]{0,700}`?PERMISSION_CONTEXT=[^`\n]+`?[\s\S]{0,700}`?ACCOUNT_CONTEXT=[^`\n]+`?[\s\S]{0,700}(enriches|enrich)[\s\S]{0,160}(never gates|does not gate)",
        "scope-research dispatch must include supported attack-paths caller handoff fields and stay non-gating",
    )
    assert_matches(prompt, r"Use the Agent tool[\s\S]{0,120}subagent_type=\"scope-research\"")

    assert "skills/scope-attack-path-analysis/SKILL.md" in prompt
    assert "skills/scope-evidence-logging/SKILL.md" in prompt
    assert "uv run python -m scope.attack.lint --run-dir \"$RUN_DIR\" --stage candidates" in prompt
    assert "public_entrypoints[]" in prompt
    assert "attack_path_seed" in prompt
    assert "do not invent public entrypoints from generic public flags" in prompt
    assert_matches(
        prompt,
        r"<public_entrypoint_handoff>[\s\S]*Only `public_entrypoints\[\]` records with `attack_path_seed: true` can start public-endpoint candidate paths",
    )
    assert_matches(
        prompt,
        r"starting_position\.type` to `public_endpoint`[\s\S]{0,160}`starting_position\.id` to the exact `public_entrypoints\[\]\.id`",
    )
    assert_matches(
        prompt,
        r"The candidate still needs a downstream permission or impact transition after the public access transition",
    )

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


def test_attack_verify_and_exploit_contract_regressions() -> None:
    analyze = read("agents/subagents/scope-attack-analyze.md")
    verify = read("agents/subagents/scope-verify.md")
    exploit = read("agents/scope-exploit.md")

    assert_matches(
        analyze,
        r"if `attack_paths\[\]` is non-empty[\s\S]{0,180}STATUS: error",
        "analyze must not let stale final paths survive into candidate lint",
    )

    assert_matches(verify, r"^tools: Read, Grep, Glob, WebSearch, WebFetch$", "scope-verify should be read-only plus docs lookup")
    assert "Do not call AWS APIs." in verify
    assert_not_matches(verify, r"\b(Edit|Bash)\b", "scope-verify must not edit files or run shell commands")
    assert_not_matches(verify, r"\bGuaranteed\b|\bSpeculative\b", "scope-verify must not use stale confidence taxonomy")
    assert_matches(verify, r"validation_status[\s\S]{0,120}validated[\s\S]{0,120}conditional")
    assert_matches(verify, r"unsupported[\s\S]{0,120}(strip|reject)")

    assert "$AUDIT_RUN_DIR/modules/iam/global.json" in exploit
    assert "$AUDIT_RUN_DIR/modules/<service>/<region>.json" in exploit
    assert "iam.json" not in exploit
    assert "$AUDIT_RUN_DIR/iam.json" not in exploit
    assert_not_matches(exploit, r'for module_file in "\$AUDIT_RUN_DIR"/\*\.json')
    assert_matches(exploit, r'find "\$AUDIT_RUN_DIR/modules"[\s\S]{0,220}cat "\$module_file"')
    assert "Persistence and post-exploitation sections require explicit operator approval" in exploit
    assert "PERSISTENCE_POST_EXPLOITATION_APPROVED" in exploit
    for text in [
        "aws iam get-policy-version",
        "aws iam get-user-policy",
        "aws iam get-role-policy",
    ]:
        assert text in exploit


def test_scope_exploit_uses_curated_reasoning_notes_without_static_cloudtrail_catalogue() -> None:
    exploit = read("agents/scope-exploit.md")

    assert "config/exploit-reasoning-notes.md" in exploit
    assert_matches(
        exploit,
        r"exploit-reasoning-notes\.md[\s\S]{0,260}(optional|warn and continue|continue)",
        "exploit notes must be optional expert context",
    )
    assert_matches(
        exploit,
        r"(expert context|reasoning notes)[\s\S]{0,260}(not a checklist|not exhaustive|not authoritative)",
        "exploit notes must not become a checklist",
    )
    assert_not_matches(exploit, r"config/techniques\.json", "scope-exploit must stop loading techniques.json")
    assert_not_matches(exploit, r"\bTECHNIQUES\b", "scope-exploit must not keep stale TECHNIQUES variable")
    assert_not_matches(exploit, r"config/cloudtrail-classes\.json", "scope-exploit must stop loading cloudtrail-classes.json")
    assert_not_matches(exploit, r"\bCT_CLASSES\b", "scope-exploit must not keep stale CT_CLASSES variable")
    assert_not_matches(exploit, r"\[MGT\]|\[DATA\]|\[NONE\]", "scope-exploit must not tag playbook steps with static CloudTrail classes")
    assert_not_matches(exploit, r"CloudTrail visibility class tags", "scope-exploit must remove static visibility tag exception")
    assert_matches(
        exploit,
        r"Detection[\s\S]{0,100}visibility[\s\S]{0,180}(scope-controls|scope-investigate)",
        "exploit prompt must keep detection and visibility analysis out of exploit output",
    )


def test_scope_investigate_uses_curated_hunt_notes() -> None:
    investigate = read("agents/scope-investigate.md")

    assert "config/hunt-reasoning-notes.md" in investigate
    assert_matches(
        investigate,
        r"hunt-reasoning-notes\.md[\s\S]{0,260}(optional|warn and continue|continue)",
        "hunt notes must be optional expert context",
    )
    assert_matches(
        investigate,
        r"(expert context|reasoning notes)[\s\S]{0,260}(not a checklist|not exhaustive|not authoritative)",
        "hunt notes must not become a checklist",
    )
    assert "config/hunt-techniques.json" in investigate
    assert_not_matches(
        investigate,
        r"config/hunt-reference-patterns\.json",
        "scope-investigate must stop loading hunt-reference-patterns.json",
    )
    assert_not_matches(
        investigate,
        r"Cannot load reference patterns",
        "missing hunt reference patterns must not halt investigations",
    )


def test_attack_analyze_prioritizes_red_team_chain_quality() -> None:
    prompt = read("agents/subagents/scope-attack-analyze.md")

    for text in [
        "entry point -> new execution context -> new permission set -> impact",
        "single-hop candidate",
        "Do not create a candidate from a lone permission, lone trust relationship, lone public flag, or lone sensitive resource.",
        "public API Gateway or function URL",
        "Lambda function or compute resource",
        "execution role",
        "s3:GetObject",
        "secretsmanager:GetSecretValue",
        "kms:Decrypt",
        "RoleA can assume RoleB",
        "RoleB can assume RoleC",
        "new reachable account, principal tier, permission set, service control point bypass, or impact action",
    ]:
        assert text in prompt

    assert_matches(
        prompt,
        r"Candidate decision test:[\s\S]{0,500}initial attacker control[\s\S]{0,500}transition[\s\S]{0,500}new capability[\s\S]{0,500}impact",
    )
    assert_matches(
        prompt,
        r"Minimum chain bar:[\s\S]{0,220}two attacker progress transitions[\s\S]{0,220}impact hop",
    )
    assert_matches(
        prompt,
        r"resource_policy_access[\s\S]{0,180}execute_as[\s\S]{0,180}data_access",
    )
    assert_matches(
        prompt,
        r"assume_role[\s\S]{0,220}assume_role[\s\S]{0,220}data_access",
    )
    assert_matches(
        prompt,
        r"evidence[\s\S]{0,220}graph_edge[\s\S]{0,220}policy_document",
    )
    assert_matches(
        prompt,
        r"security_observations\[\][\s\S]{0,240}single broad policy",
    )
    assert_matches(
        prompt,
        r"attack_path_seed: false[\s\S]{0,220}security_observations\[\]",
    )
    assert_matches(
        prompt,
        r"only concrete action is `execute-api:Invoke`, `lambda:InvokeFunctionUrl`, a TCP connection, or DNS resolution",
    )


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
        "chain quality gate",
        "single-hop candidate does not prove complete attacker progression",
        "candidate hops do not change attacker context or capability",
        "candidate does not end in a concrete impact transition",
        "Public endpoint candidates must reference a `public_entrypoints[]` record with `attack_path_seed: true`",
        "Public reachability alone is not a validated attack path.",
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

    exposure = prompt.index("Dispatch `scope-public-exposure-analysis` with:")
    analyze = prompt.index("Dispatch `scope-attack-analyze` with:")
    candidate_lint = prompt.index('uv run python -m scope.attack.lint --run-dir "$RUN_DIR" --stage candidates')
    validate = prompt.index("Dispatch `scope-attack-validate` with:")
    validation_lint = prompt.index('uv run python -m scope.attack.lint --run-dir "$RUN_DIR" --stage validation')
    gate4 = prompt.index("<gate_4_results_approval>")
    assert exposure < analyze < candidate_lint < validate < validation_lint < gate4

    assert_matches(prompt, r"Dispatch `scope-public-exposure-analysis` with:[\s\S]*- `RUN_DIR`[\s\S]*- `ACCOUNT_ID`[\s\S]*- `OWNED_ACCOUNTS`")
    assert_matches(prompt, r"Expected output:[\s\S]*`public_entrypoints\[\]`[\s\S]*`\$RUN_DIR/results\.json`")
    assert_matches(prompt, r"Public exposure alone is not an attack path")
    assert_matches(prompt, r"attack_path_seed: true[\s\S]{0,160}execution context[\s\S]{0,160}sensitive resource reachability")
    assert_matches(prompt, r"public_entrypoints\[\][\s\S]{0,160}preferred external starting positions")
    assert_matches(prompt, r"Dispatch `scope-attack-analyze` with:[\s\S]*- `RUN_DIR`[\s\S]*- `ACCOUNT_ID`[\s\S]*- `OWNED_ACCOUNTS`")
    assert_matches(prompt, r"Expected analyze output:[\s\S]*`candidate_attack_paths\[\]`[\s\S]*`security_observations\[\]`[\s\S]*`\$RUN_DIR/results\.json`")
    assert_matches(prompt, r"If candidate lint fails,[\s\S]{0,120}stop before validation[\s\S]{0,120}linter errors")
    assert "Attack analyze failure | Log, stop before candidate lint and surface the error." in prompt
    assert_matches(prompt, r"Dispatch `scope-attack-validate` with:[\s\S]*- `RUN_DIR`[\s\S]*- `ACCOUNT_ID`")
    assert_matches(prompt, r"Expected validate output:[\s\S]*`attack_validation\[\]`[\s\S]*promoted `attack_paths\[\]`[\s\S]*`\$RUN_DIR/results\.json`")
    assert_matches(prompt, r"If validation lint fails,[\s\S]{0,120}stop before Gate 4[\s\S]{0,120}linter errors")
    assert "Attack validation failure | Log, stop before validation lint and surface the error." in prompt

    attack_section = section(prompt, "attack_paths_dispatch")
    exposure_section = section(prompt, "public_exposure_analysis")
    assert exposure_section.index("scope-public-exposure-analysis") < attack_section.index("scope-attack-analyze")
    assert "Public exposure analysis must run first." in attack_section
    assert "public_entrypoints[]" in attack_section
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
        "On skip, still write `$RUN_DIR/findings.md`",
        "Do not dispatch scope-controls.",
    ]:
        assert text in gate4_section
    assert_not_matches(gate4_section, r"confidence|confidence tier|confidence tiers")

    assert_matches(prompt, r"Gate 4 skip exception:[\s\S]{0,180}\$RUN_DIR/results\.json[\s\S]{0,120}findings\.md[\s\S]{0,120}remain required")
    assert_not_matches(prompt, r"skips results\.json|results\.json[\s\S]{0,80}skipped")
    assert_not_matches(prompt, r"Gate 4 skip exception:[\s\S]{0,220}Dashboard export, dashboard index")
    assert_not_matches(prompt, r"scope-synthesizer|synthesizer|engagement-report\.md|Engagement Synthesis")
    assert_not_matches(prompt, r"Do not require `engagement-report\.md`")
    assert_not_matches(prompt, r"After controls completes successfully, dispatch the synthesizer subagent automatically\.")
    assert_not_matches(prompt, r"Synthesizer failure is non-blocking")
    assert_not_matches(prompt, r"Synthesizer handled")
    assert_matches(prompt, r"Controls handled[\s\S]{0,180}When controls succeeds[\s\S]{0,160}Controls failure is logged and remains non-blocking\.")
    assert_not_matches(prompt, r"Controls creates its run directory[\s\S]{0,80}returns CONTROLS_RUN_DIR")
    assert_not_matches(prompt, r"After controls completes \(or fails\), dispatch the synthesizer")
    assert_not_matches(prompt, r"continue to synthesizer/pipeline")
    assert_not_matches(prompt, r"enriches final attack paths|enriches `?attack_paths\[\]`?")
    assert_not_matches(prompt, r"METRICS \(attack_paths and severity counts\)")
    assert_not_matches(prompt, r"single fresh-context subagent")


def test_scope_audit_boundary_contract() -> None:
    prompt = read("agents/scope-audit.md")

    assert_matches(prompt, r"^name: scope-audit$", "frontmatter name missing")
    assert "tools: Read, Write, Bash, Grep, Glob, WebSearch, WebFetch" in prompt
    assert "WebSearch and WebFetch are available only for inline `scope-verify` documentation checks" in prompt
    assert "Do not use web tools for audit research" in prompt
    assert "Do not dispatch `scope-research`" in prompt

    gate1 = section(prompt, "gate_1_credentials")
    assert "Region discovery will run during runtime dispatch." in gate1
    assert "If explicit regions were supplied, display those requested regions." in gate1
    assert "enabled regions count" not in gate1
    assert "note if fallback" not in gate1

    gate3 = section(prompt, "gate_3_enumeration_summary")
    assert "`skip`" in gate3
    assert "raw-inventory `findings.md`" in gate3
    assert "skip public exposure, attack analysis, attack validation, Gate 4, controls, and dashboard HTML generation" in gate3
    assert "Preserve `$RUN_DIR/results.json`" in gate3
    assert "Do not delete runtime dashboard export files" in gate3

    results_export = section(prompt, "results_export")
    assert "neither Gate 3 nor Gate 4 was skipped" in results_export
    assert "Gate 3 skip exception" in results_export

    controls = section(prompt, "controls_auto_chain")
    assert "Gate 3 skip exception" in controls
    assert "do not dispatch controls" in controls

    mandatory = section(prompt, "mandatory_outputs")
    assert "Gate 3 skip exception" in mandatory
    assert "$RUN_DIR/results.json" in mandatory
    assert "$RUN_DIR/findings.md" in mandatory
    assert "$RUN_DIR/agent-log.jsonl" in mandatory
    assert "Dashboard export files are expected when runtime export succeeds" in mandatory
    assert "missing and no runtime warning exists" in mandatory

    assert_not_matches(prompt, r"(?<!Do not )Dispatch `?scope-research`?")
    assert_not_matches(prompt, r"(?<!Do not )dispatch scope-research")

    error_handling = section(prompt, "error_handling")
    assert "{service}.json not written" not in error_handling
    assert "[MISSING] {service}.json not written" not in error_handling
    assert "modules/<service>/<region>.json missing" in error_handling
    assert "Subagent STATUS: error" not in error_handling
    assert "Subagent STATUS: partial" not in error_handling
    assert "Controls subagent STATUS: error" in error_handling
    assert "Controls subagent STATUS: partial" in error_handling


def test_scope_research_agent_contract() -> None:
    prompt = read("agents/subagents/scope-research.md")

    assert_matches(prompt, r"^name: scope-research$", "frontmatter name missing")
    assert "RESEARCH_RESULT" in prompt
    assert "`CALLER`: which parent agent dispatched you - `attack-paths` or `exploit`" in prompt
    assert "Dispatched by attack-paths and exploit." in prompt

    assert_not_matches(prompt, r"CALLER=investigate")
    assert_not_matches(prompt, r"attack-paths \| exploit \| investigate")
    assert_not_matches(prompt, r"attack-paths`, `exploit`, or `investigate")
    assert_not_matches(prompt, r"detection perspective")
    assert_not_matches(prompt, r"CloudTrail events it generates")
    assert_not_matches(prompt, r"patterns to hunt for")
    assert_not_matches(prompt, r"Defensive indicators")

    for text in [
        "Write files to disk",
        "Write to MEMORY.md or any memory file",
        "Execute AWS CLI commands or interact with AWS APIs",
        "Run investigations, Splunk queries, or CloudTrail analysis",
        "Perform detection engineering or remediation design",
        "Make decisions about attack paths or exploit strategies",
    ]:
        assert text in prompt

    output_contract = section(prompt, "output_contract")
    assert "### When CALLER=attack-paths" in output_contract
    assert "### When CALLER=exploit" in output_contract
    assert "### When CALLER=investigate" not in output_contract
    assert_matches(output_contract, r"When CALLER=attack-paths[\s\S]*`cli_examples`: null")
    assert_matches(output_contract, r"When CALLER=attack-paths[\s\S]*Do not include CLI commands")
    assert_matches(output_contract, r"When CALLER=attack-paths[\s\S]*Do not include detection guidance")
    assert_matches(output_contract, r"When CALLER=attack-paths[\s\S]*Do not include remediation recommendations")
    assert_matches(output_contract, r"When CALLER=exploit[\s\S]*source-backed AWS CLI commands")

    error_handling = section(prompt, "error_handling")
    for text in [
        "Research failure must not block parent workflows.",
        "If WebSearch fails",
        "sources_found: 0",
        "If WebFetch fails",
        "If an MCP tool call fails",
        "retry once",
    ]:
        assert text in error_handling

    handoff = section(prompt, "handoff_return")
    assert "caller:             [CALLER value - attack-paths | exploit]" in handoff
    assert "When CALLER=attack-paths: null" in handoff
    assert "When CALLER=exploit: list of source-backed AWS CLI commands or []" in handoff


def test_scope_research_docs_do_not_claim_investigation_or_synthesis_support() -> None:
    readme = read("README.md")
    architecture = read("ARCHITECTURE.md")
    installer = read("bin/install.js")

    assert "scope-research` - shared external technique research for attack analysis and exploit playbooks" in readme
    assert "dispatches `scope-attack-analyze`, optionally enriches candidates through `scope-research`, then chains controls" in readme

    assert "| **scope-research** | Dispatched by attack-paths and exploit |" in architecture
    assert "scope-research may enrich attack candidates with bounded external technique context" in architecture
    assert "2. Dispatch scope-research" in architecture

    for text in [readme, architecture, installer]:
        assert "research, synthesis" not in text
        assert "research, and synthesis" not in text
        assert "scope-research` - real-world technique research integration" not in text
        assert "Dispatched by attack-paths, exploit, and investigate" not in text


def test_public_exposure_analysis_agent_contract() -> None:
    prompt = read("agents/subagents/scope-public-exposure-analysis.md")

    assert_matches(prompt, r"^name: scope-public-exposure-analysis$", "frontmatter name missing")
    for text in [
        "public_entrypoints[]",
        "attack_path_seed",
        "Public exposure alone is not an attack path.",
        "Do not call AWS APIs.",
        "API Gateway",
        "Lambda Function URLs",
        "internet-facing listeners",
        "S3 public buckets",
        "Cognito",
        "SNS/SQS resource policies",
        "Set `attack_path_seed: false` when the exposure is real but lacks an observed internal transition or impact.",
        '"starting_position"',
        '"external_unauthenticated|external_authenticated|external_cross_account|external_unknown"',
        '"invokes"',
        '"execution_roles"',
        '"reachable_resources"',
        '"seed_reason"',
        'METRICS: {"public_entrypoints": 0, "attack_path_seeds": 0, "observations": 0}',
    ]:
        assert text in prompt

    assert_matches(
        prompt,
        r"attack_path_seed: true[\s\S]{0,220}execution context[\s\S]{0,220}identity/resource-policy context[\s\S]{0,220}sensitive resource",
    )
    assert "You do not write `candidate_attack_paths[]`, `attack_paths[]`, controls, detections, or remediation plans." in prompt
    assert_not_matches(prompt, r"update only:[\s\S]{0,120}candidate_attack_paths")


def test_downstream_prompts_use_validation_status_contract() -> None:
    prompts = {
        path: read(path)
        for path in [
            "agents/scope-audit.md",
            "agents/scope-controls.md",
            "agents/subagents/scope-controls-detections.md",
            "agents/subagents/scope-controls-remediation.md",
            "agents/subagents/scope-controls-guardrails.md",
            "agents/subagents/scope-controls-policy.md",
            "agents/subagents/scope-controls-validate.md",
            "agents/subagents/scope-investigate-run.md",
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

    audit = prompts["agents/scope-audit.md"]
    success_criteria = section(audit, "success_criteria")
    assert "validation_status" in success_criteria
    assert_matches(success_criteria, r"validation_status[\s\S]{0,120}validated[\s\S]{0,80}conditional")
    assert_matches(success_criteria, r"rejected candidates[\s\S]{0,120}(stay out|must not appear)[\s\S]{0,120}attack_paths\[\]")
    assert_not_matches(success_criteria, r"Guaranteed and Conditional claims")

    for path in [
        "agents/scope-controls.md",
        "agents/subagents/scope-controls-detections.md",
        "agents/subagents/scope-controls-remediation.md",
        "agents/subagents/scope-controls-guardrails.md",
        "agents/subagents/scope-controls-policy.md",
        "agents/subagents/scope-controls-validate.md",
    ]:
        body = prompts[path]
        assert_matches(body, r"attack_paths\[\][\s\S]{0,180}validation_status[\s\S]{0,120}validated[\s\S]{0,80}conditional")
        assert_matches(body, r"runtime_assumptions\[\][\s\S]{0,220}coverage_caveats\[\]|coverage_caveats\[\][\s\S]{0,220}runtime_assumptions\[\]")
        assert "Do not treat conditional as low priority" in body
        assert "Use final `attack_paths[]` as the only attack-path source of truth." in body
        for forbidden_source in [
            "candidate_attack_paths[]",
            "rejected `attack_validation[]` entries",
            "security_observations[]",
            "public_entrypoints[]",
        ]:
            assert forbidden_source in body

    detections = prompts["agents/subagents/scope-controls-detections.md"]
    assert_matches(detections, r"attack_paths\[\][\s\S]{0,500}validation_status[\s\S]{0,500}runtime_assumptions[\s\S]{0,500}coverage_caveats")
    assert_matches(detections, r"Validation Status:[\s\S]{0,300}Runtime Assumptions:[\s\S]{0,300}Coverage Caveats:")

    for path in ["agents/subagents/scope-controls-remediation.md", "agents/subagents/scope-controls-guardrails.md"]:
        assert "validation_status" in prompts[path]
        assert_matches(prompts[path], r"runtime_assumptions[\s\S]{0,180}coverage_caveats|coverage_caveats[\s\S]{0,180}runtime_assumptions")

    policy = prompts["agents/subagents/scope-controls-policy.md"]
    assert_matches(
        policy,
        r"extract `attack_paths\[\]` entries where `validation_status` is `validated` or `conditional`",
    )
    assert "Roles with overprivileged findings but no final attack path involvement are lower priority." in policy

    validate_controls = prompts["agents/subagents/scope-controls-validate.md"]
    assert_matches(
        validate_controls,
        r"source_attack_paths[\s\S]{0,180}candidate[\s\S]{0,180}public entrypoint[\s\S]{0,180}final `attack_paths\[\]` name",
    )

    investigate_run = prompts["agents/subagents/scope-investigate-run.md"]
    assert "validation_status=validated" in investigate_run
    assert "validation_status=conditional" in investigate_run
    assert "Use final `attack_paths[]` as the only attack-path source of truth for audit and exploit run-guided mode." in investigate_run
    assert_matches(
        investigate_run,
        r"Do not generate hypotheses from `candidate_attack_paths\[\]`, rejected `attack_validation\[\]` entries, `security_observations\[\]`, or `public_entrypoints\[\]`",
    )
    assert_matches(
        investigate_run,
        r"Branch: SOURCE_RUN_TYPE=AUDIT[\s\S]{0,500}Filter to `validation_status=validated` paths first[\s\S]{0,180}`validation_status=conditional`",
    )
    assert_matches(investigate_run, r"For AUDIT runs, extract:[\s\S]{0,260}validation_status[\s\S]{0,120}runtime_assumptions\[\][\s\S]{0,120}coverage_caveats\[\]")
    assert_matches(investigate_run, r"SOURCE_RUN_TYPE=AUDIT[\s\S]{0,260}validation_status[\s\S]{0,120}runtime_assumptions\[\][\s\S]{0,120}coverage_caveats\[\]")
    assert not re.search(r"GUARANTEED|CONDITIONAL", investigate_run), "investigation run intake must not use old uppercase confidence tier values"
    assert_not_matches(investigate_run, r"severity/confidence|Confidence:")
    assert_matches(investigate_run, r"steps\[\]\.action` as exploit command/action text")
    assert_matches(investigate_run, r"steps\[\]\.visibility` as MGT/DATA/NONE")
    assert_matches(investigate_run, r"Derive CloudTrail event candidates from the AWS CLI command or API operation")
    assert "derived eventName candidate" in investigate_run
    assert_not_matches(investigate_run, r"steps\[\]\.action`? (?:—|-)\s*these are CloudTrail eventNames|eventName: \[step\.action\]")

    exploit = prompts["agents/scope-exploit.md"]
    assert '"attack_paths": [' in exploit
    assert '"paths": [' not in exploit
    assert '"validation_status": "validated"' in exploit
    assert '"runtime_assumptions": []' in exploit
    assert '"coverage_caveats": []' in exploit
    assert "Exploit results must expose final paths in `attack_paths[]`, not `paths[]`" in exploit
    assert "Exploit results must not expose `candidate_attack_paths[]`, `attack_validation[]`, `security_observations[]`, or `public_entrypoints[]`." in exploit
    assert "Downstream investigation and reporting agents treat `attack_paths[]` as the only attack-path source of truth." in exploit
    assert "skills/scope-exploit-playbook/SKILL.md" in exploit
    assert "The top-level agent owns reasoning, gates, artifact writes, `results.json`, dashboard export, and knowledge updates." in exploit

    controls = prompts["agents/scope-controls.md"]
    assert controls.count("## Wave 2: Validate-Fix Loop") == 1
    assert "subagent-owned structured JSON artifacts" in controls
    assert "guardrails.json" in controls
    assert "detections.json" in controls
    assert "policy-replacements.json" in controls
    assert "Do not infer guardrail mappings" in controls
    assert "The orchestrator does not parse markdown to invent results fields." in controls
    assert "ATTACK_PATH_CONTEXT=" not in controls
    assert "source_attack_paths: $source_attack_paths" not in controls
    assert "source_attack_path_context" not in controls
    assert "source_attack_paths: []" not in controls


def test_controls_validation_and_artifact_contracts() -> None:
    controls = read("agents/scope-controls.md")
    detections = read("agents/subagents/scope-controls-detections.md")
    validate = read("agents/subagents/scope-controls-validate.md")

    assert_matches(
        controls,
        r"Round 1 return:[\s\S]{0,220}STATUS: fail[\s\S]{0,180}STOP[\s\S]{0,120}Do not proceed to Results Assembly",
    )
    assert_matches(
        controls,
        r"Round 2 return:[\s\S]{0,260}BLOCKS > 0[\s\S]{0,180}STOP[\s\S]{0,180}STATUS: partial",
    )
    assert_not_matches(controls, r"BLOCKS > 0 \(STATUS: partial\): proceed to Results Assembly anyway")
    assert_matches(
        controls,
        r"STATUS: complete\|partial[\s\S]{0,220}complete[\s\S]{0,220}partial",
    )
    assert "STRUCTURED_FILE: {controls_run_dir}/detections.json" in controls

    assert_matches(
        detections,
        r"If results\.json has no `attack_paths` array or it is empty[\s\S]{0,260}detections\.md[\s\S]{0,260}detections\.json[\s\S]{0,120}\[\]",
    )
    assert_matches(
        detections,
        r"If `attack_paths` is empty[\s\S]{0,220}detections\.md[\s\S]{0,220}detections\.json[\s\S]{0,120}\[\]",
    )
    assert "STRUCTURED_FILE: {controls_run_dir}/detections.json" in detections
    assert_not_matches(detections, r"jq -r '\.audit_runs_analyzed\[0\]")
    assert_matches(detections, r"\.run_id[\s\S]{0,120}basename \"\$AUDIT_RUN_DIR\"")

    assert_not_matches(validate, r"Do NOT re-evaluate permissiveness")
    assert_matches(
        validate,
        r"replacement policy[\s\S]{0,220}(more permissive|broader)[\s\S]{0,220}BLOCK",
    )


def test_controls_workers_own_structured_output_for_assembly() -> None:
    controls = read("agents/scope-controls.md")
    guardrails = read("agents/subagents/scope-controls-guardrails.md")
    policy = read("agents/subagents/scope-controls-policy.md")
    validate = read("agents/subagents/scope-controls-validate.md")

    assert_matches(
        controls,
        r"scope-controls-guardrails[\s\S]{0,120}`guardrails\.json`[\s\S]{0,120}`guardrails\[\]`",
    )
    assert_matches(
        controls,
        r"scope-controls-policy[\s\S]{0,120}`policy-replacements\.json`[\s\S]{0,120}`policy_replacements\[\]`",
    )
    assert_matches(controls, r"jq -e 'type == \"array\"' \"\$CONTROLS_RUN_DIR/guardrails\.json\"")
    assert_matches(controls, r"jq -e 'type == \"array\"' \"\$CONTROLS_RUN_DIR/policy-replacements\.json\"")
    assert_not_matches(controls, r"Build guardrails array from policy JSON files")
    assert_not_matches(controls, r"Build policy_replacements array from")
    assert_not_matches(controls, r"original_policy_arn: \"unknown\"")
    assert_not_matches(controls, r"See policy-replacements\.md for detailed reasoning")

    for text in [
        "Write guardrails.json",
        "`source_attack_paths` must include only the attack paths this guardrail addresses",
        "`impact_analysis` must contain the actual reasoning",
        "STRUCTURED_FILE: {controls_run_dir}/guardrails.json",
    ]:
        assert text in guardrails

    for text in [
        "policy-replacements.json",
        "`source_attack_paths` must include only attack paths involving this role or policy",
        "`staleness_reasoning` and `boundary_considerations` must contain the actual reasoning",
        "STRUCTURED_FILE: {controls_run_dir}/policy-replacements.json",
    ]:
        assert text in policy

    assert "guardrails.md guardrails.json detections.md detections.json policy-replacements.md policy-replacements.json remediation-plan.md" in validate
    assert "source_attack_paths` maps every guardrail to every attack path without evidence" in validate
    assert "source_attack_paths` maps every replacement to every attack path without role/resource evidence" in validate


def test_controls_detections_use_production_detection_bar() -> None:
    prompt = read("agents/subagents/scope-controls-detections.md")
    validate = read("agents/subagents/scope-controls-validate.md")
    schema = read("config/schemas/controls.schema.json")

    for text in [
        "attacker progress, not raw AWS event usage",
        "Do not start with SPL syntax.",
        "promotion_decision",
        "fidelity_rationale",
        "noise_controls",
        "expected_volume",
        "validation_status",
        "`expected_volume: unknown` or `high` cannot be promoted to `alert`",
        "Do not emit generic single-event alerts",
        "AssumeRole",
        "GetObject",
        "List*",
        "Describe*",
        "ConsoleLogin",
        "CreateAccessKey",
        "hunt_query",
        "coverage_gap",
    ]:
        assert text in prompt

    assert_matches(
        prompt,
        r"Atomic[\s\S]{0,240}one event plus meaningful context filters[\s\S]{0,260}privileged/sensitive target context",
    )
    assert_matches(
        prompt,
        r"Composite[\s\S]{0,260}ordered or bounded correlation[\s\S]{0,260}common events into attacker-progress signal",
    )
    assert_matches(
        prompt,
        r"promotion_decision[\s\S]{0,220}alert[\s\S]{0,220}hunt_query[\s\S]{0,220}coverage_gap[\s\S]{0,220}reject",
    )

    for field in [
        '"type"',
        '"objective"',
        '"promotion_decision"',
        '"fidelity_rationale"',
        '"noise_controls"',
        '"expected_volume"',
        '"validation_status"',
        '"coverage_caveats"',
        '"tuning_guidance"',
    ]:
        assert field in schema

    assert "promotion_decision` is `alert` and `expected_volume` is `unknown` or `high`" in validate
    assert "Atomic alerts require concrete context filters" in validate
    assert "future `scope-controls-detection-validate` subagent" in validate
