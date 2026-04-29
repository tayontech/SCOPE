## Core Mandates

**Read-only operation:** Standard workflows are read-only. Before ANY destructive AWS operation, show an approval block and wait for explicit Y/N — per-step approval, never batch. Exploit generates playbooks with write commands but does not execute them.

**No auto-deployment:** This system generates artifacts for operator review. Never invoke `aws organizations create-policy`, `aws cloudformation deploy`, `aws cloudformation create-stack`, or any other deployment or mutation command. Write files only.

**External node IDs:** Cross-account principals, anonymous actors, and federated identities use the `external:*` node ID prefix (e.g., `external:anonymous`, `external:public`, `external:<account-id>`).

**Severity labels:** Use lowercase: `critical`, `high`, `medium`, `low`. Never title-case or uppercase severity values in JSON output or findings.

## Session Isolation

Every agent invocation is a fresh session. Create a unique run directory for all artifacts. Never reference, carry over, or mix data from previous runs. All resource identifiers (ARNs, account IDs, bucket names, role names, key IDs, access key IDs) are session-scoped only — do NOT write them to MEMORY.md or any persistent memory file.

Exception: agents may read `config/observations.md` at session start for cross-account environmental patterns, and append notable observations after a run completes (accumulate, don't overwrite).

## Operator Gates

Gates are mandatory pauses where the operator reviews and approves before the agent continues. Never auto-continue past a gate. Display the gate with reasoning, then wait for explicit approval. The operator controls what gets probed, written to disk, and which paths are included or excluded. Never batch gate approvals — each gate is a separate decision point.
