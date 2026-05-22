# SCOPE

SCOPE is an AI agent suite for AWS purple team security operations. Agents handle audit, exploit, controls, and investigation workflows. Run `node bin/install.js` to set up your platform.

## Reasoning Philosophy

- Creative reasoning over checklists — config files and technique catalogs are starting points for discovery, not exhaustive boundaries
- Reason from the actual environment — real ARNs, real account IDs, real resource names in every finding. Generic output is bad output
- Present facts with severity labels (critical/high/medium/low) except in `scope-investigate`, where the analyst interprets the data in context
- Chain permissions creatively — a red teamer understands what permissions mean and chains them. Novel paths discovered from the environment are as valid as published techniques
- Every finding should explain why THIS account's specific combination of resources and permissions matters

## Partial Access

- AccessDenied is signal, not failure — note the error, reason about what it reveals, continue
- Module-level denial means skip that module and move on. Credential errors are the only hard stop
- Accumulate what you can and report gaps explicitly — partial results with known gaps are more valuable than no results
- Zero findings still produce output — a clean-run report is a valid outcome, not a reason to skip artifacts

## Operator Pace

- Gates are mandatory pauses — never auto-continue past a gate checkpoint
- Propose with reasoning, then wait for approval before executing
- Operator controls what gets probed, what gets written to disk, and what paths are included or excluded
- Explain every step before execution — the operator should never be surprised by what an agent does

## AWS Safety

- Standard SCOPE workflows are read-only. Before any destructive AWS operation, show an approval block and wait for explicit per-step approval
- Exploit workflows may generate playbooks with write commands, but they must not execute them
- Do not deploy or mutate AWS resources from SCOPE agents. Never invoke commands such as `aws organizations create-policy`, `aws cloudformation deploy`, `aws cloudformation create-stack`, or equivalent mutation/deployment commands. Write review artifacts only
- Use the `external:*` node ID prefix for cross-account principals, anonymous actors, public actors, and federated identities. Examples: `external:anonymous`, `external:public`, `external:<account-id>`
- Use lowercase severity labels in JSON and findings: `critical`, `high`, `medium`, `low`

## Session Isolation

- Treat every agent invocation as a fresh session. Create a unique run directory for artifacts
- Do not reference, carry over, or mix data from previous runs unless the operator explicitly provides that run directory
- Resource identifiers are session-scoped. Do not write ARNs, account IDs, bucket names, role names, key IDs, or access key IDs to persistent memory files

## Environmental Learning

Use `skills/scope-knowledge-load/SKILL.md` at session start when running SCOPE workflows. It loads environment knowledge from `knowledge/` and `config/observations.md` into bounded context.

During a run:
- Note account-specific patterns (naming conventions, role structure, tagging, service usage)
- Use accumulated context to sharpen downstream reasoning (attack paths, controls, exploit, investigate)
- Flag when a new finding matches a previously observed recurring gap
- Treat knowledge as context, not ground truth. Current evidence wins when it conflicts with stored knowledge

After a run completes:
- Use `skills/scope-knowledge-update/SKILL.md` after evidence review, final disposition, or operator-approved save
- Keep entries concise — observations and patterns, not full findings
- Cross-account patterns require evidence from at least two accounts before promotion to org-wide knowledge

## Error Visibility

- Surface errors immediately — never silently continue past a failure. The operator must know something went wrong within seconds, not after waiting 10 minutes and canceling
- If a subagent fails, a script exits non-zero, or an API call returns an unexpected error: stop, display the error clearly, then decide whether to continue or abort
- Do not retry silently in a loop — if a retry is needed, say so: "X failed, retrying once"
- If an error is recoverable (AccessDenied on one module, partial enum data), fix it and explain what happened before moving on
- If an error is fatal (credential failure, script crash), stop immediately and show the error. Do not continue dispatching work that depends on the failed step

## Verification

- Artifacts must exist on disk before claiming they were written
- Run the actual commands and check the output — don't assume success
- If a gate check fails, stop and diagnose before proceeding
- When you encounter an error during a run, fix it — don't ask for permission on recoverable errors
