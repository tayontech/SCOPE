# SCOPE Research Agent Design

## Purpose

`scope-research` gives SCOPE agents bounded external technique context. It performs live source discovery, evaluates relevance, synthesizes real-world AWS abuse patterns, and returns an in-memory handoff to the caller.

The research agent should remain a subagent because it uses external search, source judgment, and synthesis. It should not become a skill until the workflow becomes a reusable prompt fragment with no independent research task.

## Decision

Keep one shared `scope-research` subagent with explicit caller modes.

Supported callers:

- `attack-paths`
- `exploit`

Remove `investigate` as a supported caller unless a future design adds a direct investigation research dispatch. `scope-investigate` already owns threat intel intake through `scope-investigate-intel`; keeping an unused research mode creates stale contracts.

## Agent Boundary

`scope-research` owns:

- Live web research over AWS services, permissions, and abuse techniques.
- Source quality ranking and fallback search expansion.
- Optional MCP enrichment when relevant tools exist.
- Source-tagged synthesis.
- A final `RESEARCH_RESULT` handoff block.

`scope-research` does not own:

- Attack path generation.
- Attack path validation.
- Exploit path selection.
- Investigation execution.
- Detection engineering.
- Remediation design.
- Artifact writes.
- Persistent knowledge updates.
- AWS API calls.

All output remains in memory. The parent decides whether research affects a candidate, playbook, finding, or saved artifact.

## Caller Contracts

### `CALLER=attack-paths`

`scope-attack-analyze` may dispatch `scope-research` at most once per analysis run when external context would improve candidate framing.

Input:

- `SERVICE`: primary AWS service or service family.
- `PERMISSION_CONTEXT`: top permission combinations, trust pattern, resource policy pattern, or service pivot.
- `ACCOUNT_CONTEXT`: optional bounded context, with identifiers treated as session-scoped.

Output:

- `technique_summary`: one to three sentences.
- `abuse_narrative`: technique context, prerequisites, and real-world source support.
- `source_urls`: source-tagged references.
- `cli_examples`: `null`.
- `sources_found`: integer.
- `mcp_tools_used`: list.

Attack-path research must exclude:

- CLI execution procedures.
- Detection guidance.
- Remediation recommendations.
- Final validation language.
- Claims that a path works in this environment.

The attack analyzer may use research to name, prioritize, and explain candidates. Runtime artifacts and validators decide whether a candidate exists and whether it promotes to a final path.

### `CALLER=exploit`

`scope-exploit` dispatches `scope-research` for operator-approved playbook paths after permission discovery and path selection.

Input:

- `SERVICE`: primary service in the path.
- `PERMISSION_CONTEXT`: actual discovered permissions and conditions.
- `ACCOUNT_CONTEXT`: target ARN, account ID, and relevant discovered resources.

Output:

- `technique_summary`: one to three sentences.
- `abuse_narrative`: source-backed technique context and conditions.
- `source_urls`: source-tagged references.
- `cli_examples`: source-backed AWS CLI examples or `[]` when sources do not provide examples.
- `sources_found`: integer.
- `mcp_tools_used`: list.

Exploit research may include procedural details because the exploit parent already gates playbook writing and execution remains outside SCOPE. The parent adapts generic commands to actual discovered resource identifiers and keeps the playbook aligned with exploit-specific prohibitions.

## Source Policy

`scope-research` uses preferred AWS security sources first, then expands to broader search when preferred sources do not answer the request.

Preferred sources should include technique encyclopedias, cloud security research teams, incident reports, official AWS security bulletins, and vulnerability advisories. The prompt should keep source classes rather than overfitting to one vendor list. The agent can name known high-quality sources as examples.

Every claim in `abuse_narrative` needs a source tag or clear general-knowledge framing. `sources_found: 0` means the synthesis came from service behavior and general knowledge, not a documented technique.

## Error Handling

Research failure must not block parent workflows.

- If WebSearch fails, return a `RESEARCH_RESULT` with `sources_found: 0`, a concise failure note inside `abuse_narrative`, and no CLI examples.
- If a WebFetch result fails, skip that URL and continue with remaining sources.
- If an MCP call fails, retry once, then continue with web results.
- If no exact technique exists, synthesize from related techniques or service behavior and label the gap.

## Architecture Updates

Docs and installer text should describe `scope-research` as a shared research subagent used by attack analysis and exploit.

Remove stale claims that it supports investigation. Remove stale installer wording that mentions synthesis subagents, since `scope-synthesizer` no longer exists.

## Test Strategy

Use Python contract tests.

Coverage:

- `agents/subagents/scope-research.md` supports only `CALLER=attack-paths` and `CALLER=exploit`.
- The prompt forbids disk writes, memory writes, AWS API calls, investigations, detection engineering, remediation design, and attack path decisions.
- `CALLER=attack-paths` sets `cli_examples` to `null` and excludes detection/remediation content.
- `CALLER=exploit` allows source-backed CLI examples.
- `README.md`, `ARCHITECTURE.md`, and `bin/install.js` do not claim investigation research support or synthesis subagents.

Verification should run:

```bash
pytest tests/scope/contracts -q
node --check bin/install.js
git diff --check
```

## Non-Goals

- No split into `scope-attack-research` and `scope-exploit-research`.
- No new reusable research skill.
- No persistent `knowledge/research` writes from the research subagent.
- No dashboard or schema changes.
- No new mandatory report artifacts.
