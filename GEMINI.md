# SCOPE — Gemini CLI

Read and follow all instructions in `INSTRUCTIONS.md` in this repository root. That file contains the shared project context, architecture, slash commands, credential model, approval gates, and error handling rules.

## Skill Naming

In Gemini CLI, skills use dollar-sign prefix with hyphens (not colons):

| Gemini Skill | Equivalent |
|-------------|-----------|
| `$scope-audit` | `/scope:audit` |
| `$scope-exploit` | `/scope:exploit` |
| `$scope-investigate` | `/scope:investigate` |
| `$scope-help` | `/scope:help` |

## Agents

```
scope-audit.md         AWS audit (slash command)
scope-remediate.md     Remediation generation (auto-called by scope-audit)
scope-exploit.md       Privilege escalation playbooks (slash command)
scope-investigate.md   SOC alert investigation (slash command)
scope-verify-core.md   Core verification — claim ledger, taxonomy, cross-agent consistency (auto-called)
scope-verify-aws.md    AWS verification — API, IAM, SCP/RCP, attack path satisfiability (auto-called)
scope-verify-splunk.md Splunk verification — SPL lints, field validation, rerun recipes (auto-called)
scope-data.md          Data normalization middleware (auto-called)
scope-evidence.md      Evidence provenance middleware (auto-called)
```
