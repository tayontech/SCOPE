# Curated Reasoning Notes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove generic AWS knowledge catalogues from config and replace useful LLM context with small Markdown expert notes.

**Architecture:** Keep config for runtime contracts, local settings, operator templates, and project-specific guidance. Delete static catalogues that duplicate agent knowledge: `techniques.json`, `hunt-reference-patterns.json`, and `cloudtrail-classes.json`. Load curated Markdown notes as optional reasoning aids for exploit and investigation, while keeping CloudTrail visibility and detection work inside controls and investigate.

**Tech Stack:** Markdown agent prompts, pytest contract tests, jq for remaining JSON validation, Bash for file removal.

---

## File Structure

- Create `knowledge/exploit-reasoning-notes.md`: curated expert notes for complex exploit reasoning.
- Create `knowledge/hunt-reasoning-notes.md`: curated expert notes for complex hunt reasoning.
- Delete `config/techniques.json`: generic exploit catalogue.
- Delete `config/hunt-reference-patterns.json`: generic alert reference catalogue.
- Delete `config/cloudtrail-classes.json`: static AWS action-to-CloudTrail catalogue.
- Modify `agents/scope-exploit.md`: load exploit notes, remove `techniques.json`, remove CloudTrail step tagging, and keep detection/visibility analysis out of exploit output.
- Modify `agents/scope-investigate.md`: load hunt notes, remove hard requirement for `hunt-reference-patterns.json`, and keep `hunt-techniques.json` as the structured RUN-mode hypothesis catalogue.
- Modify `config/README.md`: document the new files and removed static catalogues.
- Modify `README.md` if it advertises exploit CloudTrail visibility tagging.
- Modify `tests/scope/contracts/test_attack_agent_contracts.py`: add prompt contract tests for new notes and stale-reference removal.
- Add `tests/scope/contracts/test_reasoning_notes_config.py`: validate note files stay small and static catalogues do not exist.

## Task 1: Add Failing Prompt Contract Tests

**Files:**
- Modify: `tests/scope/contracts/test_attack_agent_contracts.py`

- [ ] **Step 1: Add exploit prompt test**

Append this test after `test_attack_verify_and_exploit_contract_regressions`:

```python
def test_scope_exploit_uses_curated_reasoning_notes_without_static_cloudtrail_catalogue() -> None:
    exploit = read("agents/scope-exploit.md")

    assert "knowledge/exploit-reasoning-notes.md" in exploit
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
```

- [ ] **Step 2: Add hunt prompt test**

Append this test after the exploit test from Step 1:

```python
def test_scope_investigate_uses_curated_hunt_notes() -> None:
    investigate = read("agents/scope-investigate.md")

    assert "knowledge/hunt-reasoning-notes.md" in investigate
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
```

- [ ] **Step 3: Run prompt contract tests and verify failure**

Run:

```bash
pytest tests/scope/contracts/test_attack_agent_contracts.py -q
```

Expected: FAIL because `scope-exploit` still loads `config/techniques.json` and `config/cloudtrail-classes.json`, and `scope-investigate` still loads `config/hunt-reference-patterns.json`.

- [ ] **Step 4: Commit failing prompt tests**

```bash
git add tests/scope/contracts/test_attack_agent_contracts.py
git commit -m "test: require curated reasoning notes"
```

## Task 2: Add Config Contract Tests

**Files:**
- Create: `tests/scope/contracts/test_reasoning_notes_config.py`

- [ ] **Step 1: Create failing config tests**

Create `tests/scope/contracts/test_reasoning_notes_config.py`:

```python
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
        "knowledge/exploit-reasoning-notes.md",
        [
            "## PassRole Requires Execution Control",
            "## Data Events Change Post-Exploitation Confidence",
            "## Cross-Account Access Requires Three Agreements",
            "## Bedrock Abuse Depends On Runtime And Data Boundaries",
        ],
    )


def test_hunt_reasoning_notes_are_curated_expert_context() -> None:
    assert_note_file(
        "knowledge/hunt-reasoning-notes.md",
        [
            "## Resolve The Actual Actor Before Query Expansion",
            "## Absence Of Data Events Does Not Refute Activity",
            "## IAM Changes Need Delayed-Use Windows",
            "## Prefer Dashboard Monitoring For High-Volume Ambiguity",
        ],
    )


def test_static_aws_knowledge_catalogues_do_not_exist() -> None:
    assert not (ROOT / "config/techniques.json").exists()
    assert not (ROOT / "config/hunt-reference-patterns.json").exists()
    assert not (ROOT / "config/cloudtrail-classes.json").exists()


def test_remaining_config_json_files_are_valid() -> None:
    removed = {
        "techniques.json",
        "hunt-reference-patterns.json",
        "cloudtrail-classes.json",
    }
    for path in (ROOT / "config").glob("*.json"):
        assert path.name not in removed
        json.loads(path.read_text(encoding="utf-8"))
```

- [ ] **Step 2: Run new tests and verify failure**

Run:

```bash
pytest tests/scope/contracts/test_reasoning_notes_config.py -q
```

Expected: FAIL because the new Markdown note files do not exist and the removed JSON catalogues still exist.

- [ ] **Step 3: Commit failing config tests**

```bash
git add tests/scope/contracts/test_reasoning_notes_config.py
git commit -m "test: cover reasoning note config"
```

## Task 3: Create Curated Markdown Notes And Remove Static Catalogues

**Files:**
- Create: `knowledge/exploit-reasoning-notes.md`
- Create: `knowledge/hunt-reasoning-notes.md`
- Delete: `config/techniques.json`
- Delete: `config/hunt-reference-patterns.json`
- Delete: `config/cloudtrail-classes.json`

- [ ] **Step 1: Create exploit reasoning notes**

Create `knowledge/exploit-reasoning-notes.md`:

```md
# Exploit Reasoning Notes

Purpose: curated expert context for `scope-exploit`. These notes are not a checklist, not exhaustive, and not authoritative over current environment evidence, AWS documentation, or validated audit data.

## PassRole Requires Execution Control

Applies to: `iam:PassRole`, `lambda:CreateFunction`, `ecs:RunTask`, `ec2:RunInstances`, `codebuild:StartBuild`

Why it matters:
`iam:PassRole` does not create escalation by itself. The attacker needs a trusted service path and a way to cause that service to execute attacker-controlled code, configuration, instance profile attachment, or build instructions.

Reasoning prompts:
- Does the target role trust the service the principal can use?
- Do `iam:PassedToService`, resource ARNs, tags, or permissions boundaries constrain the pass?
- Can the principal create, update, or trigger a resource that runs with the passed role?

Validation pivots:
- Inspect role trust policy and identity policy conditions.
- Confirm the service action that attaches or uses the role.
- Confirm a trigger path that changes attacker capability.

Avoid:
- Calling broad `iam:PassRole` exploitable without proving execution control.

## Data Events Change Post-Exploitation Confidence

Applies to: `s3:GetObject`, `lambda:InvokeFunction`, `dynamodb:GetItem`, `sqs:ReceiveMessage`, `sns:Publish`, `bedrock:InvokeModel`

Why it matters:
Many impact actions appear only in CloudTrail data events, and most environments do not ingest those by default. Missing Splunk evidence may mean missing telemetry rather than no attacker activity.

Reasoning prompts:
- Is this action management-plane, data-plane, or service-specific runtime telemetry?
- Does the environment ingest data events for this resource type?
- Should the result be a detection, a dashboard, or a coverage gap handled by controls or investigate?

Validation pivots:
- Check CloudTrail event selectors or SIEM source coverage when the workflow reaches investigation or controls.
- Compare management events that precede the data action.
- Mark confidence as conditional when telemetry cannot observe the impact action.

Avoid:
- Treating lack of data-event evidence as proof that exfiltration or invocation did not happen.

## Cross-Account Access Requires Three Agreements

Applies to: `sts:AssumeRole`, resource policies, KMS grants, S3 bucket policies, SNS/SQS policies

Why it matters:
Cross-account access needs identity-side permission, resource-side permission or trust, and conditions that match the caller context. One permissive side rarely proves the path.

Reasoning prompts:
- Does the caller identity allow the action?
- Does the target trust or resource policy allow that caller?
- Do org ID, external ID, principal ARN, source account, or source ARN conditions match?

Validation pivots:
- Pair identity policy evidence with target trust or resource policy evidence.
- Trace condition keys through the actual calling service.
- Treat missing target-side policy as conditional, not validated.

Avoid:
- Promoting a cross-account path from identity permission alone.

## Bedrock Abuse Depends On Runtime And Data Boundaries

Applies to: Bedrock agents, knowledge bases, guardrails, model invocation, prompt management

Why it matters:
Bedrock findings can involve model runtime access, prompt or agent configuration changes, knowledge-base data exposure, or guardrail weakening. Each has different evidence and telemetry coverage.

Reasoning prompts:
- Does the principal control configuration, runtime invocation, data sources, or guardrails?
- Can the action expose sensitive prompts, retrieve knowledge-base content, or weaken safety controls?
- Does the environment have telemetry for runtime actions, or only management-plane changes?

Validation pivots:
- Separate management-plane configuration changes from runtime invocation.
- Check attached data source permissions and model invocation permissions.
- Record telemetry uncertainty as a caveat instead of adding static playbook tags.

Avoid:
- Treating all Bedrock permissions as equal-impact or equally observable.
```

- [ ] **Step 2: Create hunt reasoning notes**

Create `knowledge/hunt-reasoning-notes.md`:

```md
# Hunt Reasoning Notes

Purpose: curated expert context for `scope-investigate`. These notes are not a checklist, not exhaustive, and not authoritative over current environment evidence, Splunk results, or analyst-provided context.

## Resolve The Actual Actor Before Query Expansion

Applies to: assumed roles, access keys, federated users, service principals, IAM Identity Center

Why it matters:
CloudTrail often shows the session identity, not the human or workload that initiated the chain. Expanding queries from the wrong identity creates false timelines.

Reasoning prompts:
- Is `userIdentity.arn` an assumed-role session, long-term IAM principal, AWS service, or federated identity?
- Does `userIdentity.sessionContext.sessionIssuer.arn` point to the stable role?
- Does the access key ID connect the event to a different principal or session?

Validation pivots:
- Build one timeline by session ARN and one by session issuer ARN.
- Pivot through `accessKeyId`, `sourceIPAddress`, `userAgent`, and `principalId`.
- Separate service-initiated actions from direct principal actions.

Avoid:
- Treating an assumed-role session name as a stable human identity.

## Absence Of Data Events Does Not Refute Activity

Applies to: S3 object access, Lambda invoke, DynamoDB item access, SQS message reads, Bedrock runtime

Why it matters:
Many high-impact actions require CloudTrail data events or service-specific telemetry. Most environments do not ingest those sources broadly.

Reasoning prompts:
- Does the hypothesis depend on a data-plane action?
- Does the SIEM contain that data-event source for the resource?
- Are there management-plane precursors that still support or weaken the hypothesis?

Validation pivots:
- Query for event selector changes and known data-event source indexes.
- Look for precursor actions such as permission changes, role assumptions, function updates, or bucket policy changes.
- Record telemetry gaps separately from refuting evidence.

Avoid:
- Closing a hypothesis because the SIEM lacks the data source needed to observe it.

## IAM Changes Need Delayed-Use Windows

Applies to: `CreateAccessKey`, `Attach*Policy`, `Put*Policy`, `CreatePolicyVersion`, `UpdateAssumeRolePolicy`

Why it matters:
Attackers may create access or change policy and wait before using it. A narrow two-hour window can miss delayed exploitation.

Reasoning prompts:
- Does the change create durable access or only immediate execution?
- What later activity would prove the new access got used?
- Does a business workflow explain the delay?

Validation pivots:
- Search immediate, 24-hour, and 7-day windows when retention allows.
- Pivot by target principal, actor principal, access key, and changed role.
- Compare post-change services against the target's historical baseline.

Avoid:
- Marking policy changes benign only because no immediate follow-on action exists.

## Prefer Dashboard Monitoring For High-Volume Ambiguity

Applies to: enumeration bursts, common CI/CD role activity, repeated denied API calls, broad read-only access

Why it matters:
Some patterns deserve visibility but make poor alerts without environment baselines. Dashboards can show drift and concentration without creating noisy detections.

Reasoning prompts:
- Would this fire often for normal automation?
- Does the signal need threshold tuning or owner context before alerting?
- Would a dashboard reveal trend, outlier, or coverage gaps better than a detection?

Validation pivots:
- Aggregate by actor, account, service, event, and user agent.
- Compare recent activity to prior periods.
- Recommend dashboard monitoring when alert promotion lacks stable precision.

Avoid:
- Forcing every useful hunt insight into a detection rule.
```

- [ ] **Step 3: Delete stale JSON catalogues**

Run:

```bash
rm config/techniques.json config/hunt-reference-patterns.json config/cloudtrail-classes.json
```

- [ ] **Step 4: Run config tests**

Run:

```bash
pytest tests/scope/contracts/test_reasoning_notes_config.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit note files and JSON removals**

```bash
git add knowledge/exploit-reasoning-notes.md knowledge/hunt-reasoning-notes.md config/techniques.json config/hunt-reference-patterns.json config/cloudtrail-classes.json
git commit -m "refactor: replace static catalogues with reasoning notes"
```

## Task 4: Update Exploit Prompt

**Files:**
- Modify: `agents/scope-exploit.md`

- [ ] **Step 1: Remove CloudTrail classification section**

Delete the entire `<cloudtrail_classification>...</cloudtrail_classification>` section from `agents/scope-exploit.md`.

- [ ] **Step 2: Remove the static tag exception**

Delete this exception block near the top of `agents/scope-exploit.md`:

```md
EXCEPTION: CloudTrail visibility class tags ([MGT], [DATA], [NONE]) are permitted on playbook steps. These are operational metadata from the static classification table, not detection analysis. The prohibition on detection likelihood, OPSEC recommendations, GuardDuty findings, SOC guidance, and narrative detection discussion remains fully in effect.
```

Keep the hard prohibition on CloudTrail event names, GuardDuty finding types, detection likelihood, OPSEC notes, and SOC recommendations.

- [ ] **Step 3: Add exploit reasoning note loading**

After Gate 2 operator approval and before escalation analysis begins, add:

````md
### Curated Exploit Reasoning Notes

Load optional expert context after permission discovery:

```bash
if [ -f knowledge/exploit-reasoning-notes.md ]; then
  EXPLOIT_REASONING_NOTES=$(cat knowledge/exploit-reasoning-notes.md)
  echo "Exploit reasoning notes loaded: knowledge/exploit-reasoning-notes.md"
else
  EXPLOIT_REASONING_NOTES=""
  echo "knowledge/exploit-reasoning-notes.md not found - continuing without curated expert notes"
fi
```

Use these notes as expert context for complex exploit reasoning, validation pivots, false assumptions, and telemetry caveats. They are not a checklist, not exhaustive, and not authoritative over current environment evidence, AWS documentation, research results, or validated audit data.
````

- [ ] **Step 4: Remove stale exploit references**

Replace:

```md
After permission discovery, load techniques.json (seed knowledge) and cloudtrail-classes.json. Then reason about escalation paths through unified creative reasoning — all paths emerge from analysis of discovered permissions, informed by seed knowledge and research context.
```

with:

```md
After permission discovery, load `knowledge/exploit-reasoning-notes.md` as optional expert context. Then reason about escalation paths through unified creative reasoning. All paths emerge from discovered permissions, environment evidence, optional expert notes, and research context.
```

Replace:

```md
- Load `TECHNIQUES` (from techniques.json if available) as seed knowledge — reference material, not a rigid checklist
```

with:

```md
- Use `EXPLOIT_REASONING_NOTES` as optional expert context, not as a checklist
```

Replace:

```md
Focus on permission baselines for this principal type, novel escalation paths not in techniques.json, and persistence mechanisms discovered.
```

with:

```md
Focus on permission baselines for this principal type, novel escalation paths, stale assumptions in reasoning notes, and persistence mechanisms discovered.
```

Delete the `**techniques.json missing:**` and `**cloudtrail-classes.json missing:**` error-handling blocks.

- [ ] **Step 5: Remove playbook tag requirement**

Replace:

```md
- Tags every step with `[MGT]`, `[DATA]`, or `[NONE]`.
```

with:

```md
- Does not tag steps with static CloudTrail visibility classes. Detection and visibility analysis belongs to `scope-controls` and `scope-investigate`.
```

- [ ] **Step 6: Run focused exploit prompt test**

Run:

```bash
pytest tests/scope/contracts/test_attack_agent_contracts.py::test_scope_exploit_uses_curated_reasoning_notes_without_static_cloudtrail_catalogue -q
```

Expected: PASS.

- [ ] **Step 7: Commit exploit prompt update**

```bash
git add agents/scope-exploit.md
git commit -m "refactor: remove exploit cloudtrail catalogue"
```

## Task 5: Update Investigation Prompt To Use Hunt Notes

**Files:**
- Modify: `agents/scope-investigate.md`

- [ ] **Step 1: Add optional hunt note loading after active hypothesis setup**

In `agents/scope-investigate.md`, after the active hypothesis session state section, add:

````md
### Curated Hunt Reasoning Notes

Load optional expert context before selecting investigation steps:

```bash
if [ -f knowledge/hunt-reasoning-notes.md ]; then
  HUNT_REASONING_NOTES=$(cat knowledge/hunt-reasoning-notes.md)
  echo "Hunt reasoning notes loaded: knowledge/hunt-reasoning-notes.md"
else
  HUNT_REASONING_NOTES=""
  echo "knowledge/hunt-reasoning-notes.md not found - continuing without curated expert notes"
fi
```

Use these notes as expert context for complex hunts, false-positive reasoning, visibility caveats, and dashboard-worthy monitoring ideas. They are not a checklist, not exhaustive, and not authoritative over current environment evidence or Splunk results.
````

- [ ] **Step 2: Remove reference pattern loading section**

Delete the section titled `### Reference Pattern Loading` that loads `config/hunt-reference-patterns.json` and halts when it is missing.

- [ ] **Step 3: Update reasoning framework wording**

Replace:

```md
5. **Reference pattern** — No environmental signal applies. Fall back to the reference pattern steps for this alert type (see Reference Patterns below).
```

with:

```md
5. **Curated reasoning notes** — No environmental signal applies. Use `HUNT_REASONING_NOTES` for expert caveats, false-positive traps, and visibility gaps that can shape the next query or dashboard recommendation.
```

Replace:

```md
Use `$REF_PATTERN` to read `investigation_angles` and `spl_templates` for the matched alert type. Adapt SPL template field values from `investigation_context`. Apply the priority hierarchy — reference patterns are a floor, not a ceiling.
```

with:

```md
Use `$HUNT_REASONING_NOTES` only to sharpen reasoning. Build SPL from the active hypothesis, current evidence, `hunt-techniques.json` when applicable, and Splunk field context.
```

- [ ] **Step 4: Run focused hunt prompt test**

Run:

```bash
pytest tests/scope/contracts/test_attack_agent_contracts.py::test_scope_investigate_uses_curated_hunt_notes -q
```

Expected: PASS.

- [ ] **Step 5: Commit investigation prompt update**

```bash
git add agents/scope-investigate.md
git commit -m "refactor: load curated hunt reasoning notes"
```

## Task 6: Update Docs And Stale References

**Files:**
- Modify: `config/README.md`
- Modify: `README.md` if it references CloudTrail visibility tagging.
- Modify: `ARCHITECTURE.md` if it references removed files.
- Modify: `config/project-docs/LLM-CONTEXT.md` if it references removed files.
- Modify: any active test or hook file that references removed files.

- [ ] **Step 1: Update config README active file list**

In `config/README.md`, replace:

```md
- `cloudtrail-classes.json`: exploit step visibility classification.
- `techniques.json`: exploit seed technique knowledge.
- `hunt-techniques.json`: investigation technique catalogue.
- `hunt-reference-patterns.json`: investigation reference pattern catalogue.
```

with:

```md
- `exploit-reasoning-notes.md`: curated expert notes for complex exploit reasoning.
- `hunt-techniques.json`: structured RUN-mode investigation hypothesis catalogue.
- `hunt-reasoning-notes.md`: curated expert notes for complex hunt reasoning.
```

- [ ] **Step 2: Remove README visibility tagging claim**

If `README.md` contains:

```md
- **Visibility tagging** — CloudTrail classification tags each step as management event, data event, or not logged without turning the playbook into detection guidance
```

delete that bullet or replace it with:

```md
- **Focused exploit output** — exploit playbooks avoid detection and CloudTrail visibility guidance; controls and investigate own detection engineering, dashboards, and telemetry caveats
```

- [ ] **Step 3: Search for stale references**

Run:

```bash
rg -n "cloudtrail-classes\\.json|techniques\\.json|hunt-reference-patterns\\.json|CT_CLASSES|TECHNIQUES\\b|REF_PATTERN|\\[MGT\\]|\\[DATA\\]|\\[NONE\\]|Visibility tagging" agents config/README.md config/hooks config/settings config/project-docs/LLM-CONTEXT.md README.md ARCHITECTURE.md
```

Expected: no matches in active files.

- [ ] **Step 4: Update active docs that still reference removed files**

For active docs, use these replacements:

```md
`config/techniques.json`
```

becomes:

```md
`knowledge/exploit-reasoning-notes.md`
```

and:

```md
`config/hunt-reference-patterns.json`
```

becomes:

```md
`knowledge/hunt-reasoning-notes.md`
```

Delete references to `config/cloudtrail-classes.json`; do not replace them with another static catalogue.

- [ ] **Step 5: Run stale reference search again**

Run:

```bash
rg -n "cloudtrail-classes\\.json|techniques\\.json|hunt-reference-patterns\\.json|CT_CLASSES|TECHNIQUES\\b|REF_PATTERN|\\[MGT\\]|\\[DATA\\]|\\[NONE\\]|Visibility tagging" agents config/README.md config/hooks config/settings config/project-docs/LLM-CONTEXT.md README.md ARCHITECTURE.md
```

Expected: no matches in active files.

- [ ] **Step 6: Commit docs cleanup**

```bash
git add config/README.md README.md ARCHITECTURE.md config/project-docs/LLM-CONTEXT.md
git commit -m "docs: document curated reasoning notes"
```

If only `config/README.md` and `README.md` changed, stage and commit only those files.

## Task 7: Run Full Verification

**Files:**
- Test only.

- [ ] **Step 1: Validate remaining JSON files**

Run:

```bash
find config -name '*.json' -print0 | xargs -0 jq empty
```

Expected: no output and exit code 0.

- [ ] **Step 2: Run focused contract tests**

Run:

```bash
pytest tests/scope/contracts/test_attack_agent_contracts.py tests/scope/contracts/test_reasoning_notes_config.py -q
```

Expected: PASS.

- [ ] **Step 3: Run full contract tests**

Run:

```bash
pytest tests/scope/contracts -q
```

Expected: PASS.

- [ ] **Step 4: Run full test suite**

Run:

```bash
pytest -q
```

Expected: PASS.

- [ ] **Step 5: Check whitespace and staged diff**

Run:

```bash
git diff --check
git status --short
```

Expected: `git diff --check` exits 0. `git status --short` may show unrelated pre-existing review edits; verify the reasoning-note task changes are committed.

- [ ] **Step 6: Record verification in final implementation summary**

Include:

```md
Verification:
- `find config -name '*.json' -print0 | xargs -0 jq empty`
- `pytest tests/scope/contracts/test_attack_agent_contracts.py tests/scope/contracts/test_reasoning_notes_config.py -q`
- `pytest tests/scope/contracts -q`
- `pytest -q`
- `git diff --check`
```

Do not claim completion unless these commands pass or you state the exact failing command and reason.
