# Scope Research Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align `scope-research` with the approved shared subagent design: supported only by attack-path analysis and exploit, with no stale investigation or synthesis contracts.

**Architecture:** Keep one `scope-research` subagent. Tighten its prompt caller contract, add Python contract tests, and update architecture, README, and installer wording. No runtime, schema, dashboard, or artifact behavior changes.

**Tech Stack:** Markdown agent prompts, Python `pytest` contract tests, Node installer syntax checks.

---

## File Structure

- Modify `agents/subagents/scope-research.md`: remove `investigate` caller support, tighten caller-specific output, remove detection/remediation-oriented research, add explicit error handling.
- Modify `tests/scope/contracts/test_attack_agent_contracts.py`: add contract tests for `scope-research` and stale docs/installer claims.
- Modify `README.md`: describe research as shared by attack analysis and exploit only.
- Modify `ARCHITECTURE.md`: update attack and exploit communication wording for research.
- Modify `bin/install.js`: remove stale `synthesis` text from installer help.

## Task 1: Add Scope Research Contract Tests

**Files:**
- Modify: `tests/scope/contracts/test_attack_agent_contracts.py`

- [ ] **Step 1: Add failing research prompt contract test**

Append this test after `test_audit_orchestrates_attack_pipeline` in `tests/scope/contracts/test_attack_agent_contracts.py`:

```python
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
```

- [ ] **Step 2: Add failing stale architecture/docs contract test**

Append this test after `test_scope_research_agent_contract`:

```python
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
```

- [ ] **Step 3: Run tests and verify they fail**

Run:

```bash
pytest tests/scope/contracts/test_attack_agent_contracts.py -q
```

Expected: FAIL because `scope-research` still mentions `investigate`, detection-oriented research, and stale docs/install text.

## Task 2: Tighten Scope Research Prompt

**Files:**
- Modify: `agents/subagents/scope-research.md`

- [ ] **Step 1: Replace frontmatter description**

Replace the existing description line with:

```yaml
description: Research subagent - uses WebSearch and available MCP tools to find real-world abuse context for AWS permissions and services. Dispatched by attack-paths and exploit. Returns structured RESEARCH_RESULT handoff block to parent.
```

- [ ] **Step 2: Replace the caller input bullet**

Replace:

```markdown
- `CALLER`: which parent agent dispatched you - `attack-paths`, `exploit`, or `investigate`
```

With:

```markdown
- `CALLER`: which parent agent dispatched you - `attack-paths` or `exploit`
```

- [ ] **Step 3: Tighten prohibitions**

In the `You do NOT:` list, replace:

```markdown
- Run investigations, Splunk queries, or CloudTrail analysis
- Make decisions about attack paths or exploit strategies - you provide research context, the parent reasons about it
```

With:

```markdown
- Run investigations, Splunk queries, or CloudTrail analysis
- Perform detection engineering or remediation design
- Make decisions about attack paths or exploit strategies - you provide research context, the parent reasons about it
```

- [ ] **Step 4: Remove defensive indicator extraction**

In `### WebFetch for Detail`, replace:

```markdown
- Defensive indicators (what CloudTrail events the technique generates)
```

With:

```markdown
- Source-backed constraints, prerequisites, and caveats
```

- [ ] **Step 5: Replace output contract section**

Replace the entire `<output_contract>` section with:

```markdown
<output_contract>
## Output Contract - Caller-Aware Depth

Read the CALLER field from the dispatch message to determine output depth. Supported callers are `attack-paths` and `exploit`.

If CALLER has any other value, return a `RESEARCH_RESULT` with `sources_found: 0`, `source_urls: []`, `cli_examples: null`, and an `abuse_narrative` that states the caller is unsupported. Do not perform research for unsupported callers.

### When CALLER=attack-paths

Bounded technique context without execution, detection, remediation, or validation claims. Include:
- `technique_summary`: 1-3 sentence summary
- `abuse_narrative`: Technique description, prerequisites, and real-world context. Explain how the permission has been abused, what conditions enable it, and what the attack surface looks like.
- `cli_examples`: null
- `source_urls`: Tagged source list
- `sources_found`: Count
- `mcp_tools_used`: List

Do not include CLI commands. Do not include detection guidance. Do not include remediation recommendations. Do not claim the path works in the audited environment.

### When CALLER=exploit

Full depth output. Include:
- `technique_summary`: 1-3 sentence summary of the most relevant abuse technique
- `abuse_narrative`: Detailed narrative of how this permission/service has been or could be abused. Include procedural detail where sources support it.
- `cli_examples`: Source-backed AWS CLI commands, code snippets, or step-by-step technique execution procedures extracted from sources. These feed directly into the exploit playbook.
- `source_urls`: Every URL or MCP source that contributed, tagged with source type
- `sources_found`: Count of distinct sources
- `mcp_tools_used`: List of MCP tools used
</output_contract>
```

- [ ] **Step 6: Add error handling section before handoff return**

Add this section between `</synthesis>` and `<handoff_return>`:

```markdown
<error_handling>
## Error Handling

Research failure must not block parent workflows.

- If WebSearch fails, return a `RESEARCH_RESULT` with `sources_found: 0`, `source_urls: []`, no CLI examples, and a concise failure note inside `abuse_narrative`.
- If WebFetch fails for one source, skip that URL and continue with remaining sources.
- If an MCP tool call fails, retry once. If the retry fails, continue with WebSearch results only.
- If no exact public technique exists, synthesize from related techniques or AWS service behavior and label the gap.
</error_handling>
```

- [ ] **Step 7: Replace handoff caller and CLI text**

In the handoff block, replace:

```markdown
  caller:             [CALLER value - attack-paths | exploit | investigate]
```

With:

```markdown
  caller:             [CALLER value - attack-paths | exploit]
```

Replace:

```markdown
  cli_examples:       [When CALLER=exploit: list of AWS CLI commands / code snippets demonstrating
                        the technique, extracted from sources. Each example includes the source URL.
                        When CALLER=attack-paths or CALLER=investigate: null]
```

With:

```markdown
  cli_examples:       [When CALLER=exploit: list of source-backed AWS CLI commands or []
                        when no source provides commands. Each example includes the source URL.
                        When CALLER=attack-paths: null]
```

- [ ] **Step 8: Run focused contract test**

Run:

```bash
pytest tests/scope/contracts/test_attack_agent_contracts.py::test_scope_research_agent_contract -q
```

Expected: PASS.

- [ ] **Step 9: Commit prompt and test**

Run:

```bash
git add agents/subagents/scope-research.md tests/scope/contracts/test_attack_agent_contracts.py
git commit -m "fix: tighten scope research caller contract"
```

## Task 3: Update Docs and Installer Wording

**Files:**
- Modify: `README.md`
- Modify: `ARCHITECTURE.md`
- Modify: `bin/install.js`

- [ ] **Step 1: Update README subagent list**

In `README.md`, replace:

```markdown
- `scope-research` - real-world technique research integration
```

With:

```markdown
- `scope-research` - shared external technique research for attack analysis and exploit playbooks
```

- [ ] **Step 2: Update README audit flow**

In `README.md`, replace:

```markdown
When you run `/scope:audit --all`, the orchestrator runs on your session model, calls `scope audit` for deterministic Python enumeration and post-processing, dispatches `scope-attack-analyze`, then chains controls on a reasoning model. Scope-investigate dispatches intake subagents on a reasoning model, then runs Splunk execution on your session model. Exploit always uses whatever model your session is running.
```

With:

```markdown
When you run `/scope:audit --all`, the orchestrator runs on your session model, calls `scope audit` for deterministic Python enumeration and post-processing, dispatches `scope-attack-analyze`, optionally enriches candidates through `scope-research`, then chains controls on a reasoning model. Scope-investigate dispatches intake subagents on a reasoning model, then runs Splunk execution on your session model. Exploit always uses whatever model your session is running.
```

- [ ] **Step 3: Update README model routing row**

In `README.md`, replace:

```markdown
| Reasoning (attack analysis, controls + subagents, investigation intake, research) | claude-sonnet-4-6 | gemini-3.1-pro-preview | gpt-5.4 |
```

With:

```markdown
| Reasoning (attack analysis, controls + subagents, investigation intake, research subagent) | claude-sonnet-4-6 | gemini-3.1-pro-preview | gpt-5.4 |
```

- [ ] **Step 4: Update ARCHITECTURE attack section**

Under `**Attack path analysis**`, replace:

```markdown
- `scope-attack-analyze` - cross-service attack path analysis over `results.json`, `resources.jsonl`, `graph.json`, and module envelopes
```

With:

```markdown
- `scope-attack-analyze` - cross-service attack path analysis over `results.json`, `resources.jsonl`, `graph.json`, and module envelopes
- `scope-research` - optional bounded external technique context for candidate framing
```

- [ ] **Step 5: Update ARCHITECTURE communication matrix**

Replace:

```markdown
| **scope-research** | Dispatched by exploit and attack-paths | WebSearch, external technique references | Research findings (in-memory, consumed by caller) | - |
```

With:

```markdown
| **scope-research** | Dispatched by attack-paths and exploit | WebSearch, external technique references | Research findings (in-memory, consumed by caller) | - |
```

- [ ] **Step 6: Update ARCHITECTURE system flow wording**

In the `/scope:audit` flow, replace:

```text
  |  | scope-attack-analyze         |    |
  |  | (cross-service paths)        |    |
```

With:

```text
  |  | scope-attack-analyze         |    |
  |  | (cross-service paths;        |    |
  |  | optional scope-research)     |    |
```

- [ ] **Step 7: Add ARCHITECTURE sentence**

After the runtime post-processing paragraph that starts with `` `scope audit` performs deterministic post-processing``, add:

```markdown
`scope-research` may enrich attack candidates with bounded external technique context and exploit playbooks with source-backed procedure examples. It does not write artifacts, run investigations, design detections, or persist knowledge.
```

- [ ] **Step 8: Update installer help**

In `bin/install.js`, replace:

```javascript
  Subagents   Orchestrator-dispatched workers (attack analysis, controls, investigation, research, synthesis)
```

With:

```javascript
  Subagents   Orchestrator-dispatched workers (attack analysis, controls, investigation, research)
```

- [ ] **Step 9: Run docs contract test**

Run:

```bash
pytest tests/scope/contracts/test_attack_agent_contracts.py::test_scope_research_docs_do_not_claim_investigation_or_synthesis_support -q
```

Expected: PASS.

- [ ] **Step 10: Check installer syntax**

Run:

```bash
node --check bin/install.js
```

Expected: no output and exit code 0.

- [ ] **Step 11: Commit docs and installer**

Run:

```bash
git add README.md ARCHITECTURE.md bin/install.js tests/scope/contracts/test_attack_agent_contracts.py
git commit -m "docs: align research subagent architecture"
```

## Task 4: Final Verification

**Files:**
- Verify only; no file changes expected.

- [ ] **Step 1: Run contract tests**

Run:

```bash
pytest tests/scope/contracts -q
```

Expected: PASS.

- [ ] **Step 2: Run installer syntax check**

Run:

```bash
node --check bin/install.js
```

Expected: no output and exit code 0.

- [ ] **Step 3: Check markdown and whitespace diff**

Run:

```bash
git diff --check
```

Expected: no output and exit code 0.

- [ ] **Step 4: Confirm only handoff remains untracked**

Run:

```bash
git status --short
```

Expected:

```text
?? .continue-here.md
```

- [ ] **Step 5: Record completion**

Report:

```text
Implemented scope-research boundary cleanup.
Verification:
- pytest tests/scope/contracts -q
- node --check bin/install.js
- git diff --check
Remaining untracked: .continue-here.md
```

## Self-Review

- Spec coverage: The plan implements supported caller modes, prompt boundaries, source-backed exploit detail, attack-path boundedness, stale docs cleanup, installer wording cleanup, and Python contract coverage from `config/project-docs/SCOPE-RESEARCH-DESIGN.md`.
- Placeholder scan: No incomplete markers or vague implementation steps remain.
- Type consistency: Caller values use exactly `attack-paths` and `exploit`. Handoff field names match the existing `RESEARCH_RESULT` block.
