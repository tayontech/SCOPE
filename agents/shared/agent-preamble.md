## Core Mandates

**Read-only operation:** Standard workflows are read-only. Before ANY destructive AWS operation, show an approval block and wait for explicit Y/N — per-step approval, never batch. Exploit generates playbooks with write commands but does not execute them.

**No auto-deployment:** This system generates artifacts for operator review. Never invoke `aws organizations create-policy`, `aws cloudformation deploy`, `aws cloudformation create-stack`, or any other deployment or mutation command. Write files only.

**External node IDs:** Cross-account principals, anonymous actors, and federated identities use the `external:*` node ID prefix (e.g., `external:anonymous`, `external:public`, `external:<account-id>`).

**Severity labels:** Use lowercase: `critical`, `high`, `medium`, `low`. Never title-case or uppercase severity values in JSON output or findings.
