# SCOPE

**AI-powered purple team toolkit for AWS — runs inside Claude Code, Gemini CLI, and Codex.**

SCOPE runs the full security operations loop: enumerate your AWS account, map attack paths, generate defensive controls, and investigate alerts. The AI reasons about what it finds — it doesn't just run scripts.

![Attack Graph](docs/images/dashboard-attack-graph.png)

![Defensive Controls](docs/images/dashboard-defend-policies.png)

![Attack Paths](docs/images/dashboard-attack-paths.png)

## Prerequisites

- Node.js
- AWS credentials configured in your environment
- One of: [Claude Code](https://claude.ai/code), [Gemini CLI](https://github.com/google-gemini/gemini-cli), or [Codex](https://github.com/openai/codex)

## Installation

```bash
git clone https://github.com/tayontech/SCOPE.git
cd SCOPE
node bin/install.js --claude   # install for Claude Code
node bin/install.js --gemini   # install for Gemini CLI
node bin/install.js --codex    # install for Codex
node bin/install.js --all      # install for all platforms
```

## AWS Credentials

SCOPE inherits credentials from your shell environment — no custom credential loading. Use a **read-only IAM role** for audit, defend, and investigate.

```bash
export AWS_PROFILE=my-security-readonly-profile
# then launch your editor
/scope:audit --all
```

## Configuration (Optional)

- **`config/accounts.json`** — Owned AWS account IDs. Helps distinguish internal vs external cross-account trusts. Copy `config/accounts.example.json` and fill in your account IDs.
- **`config/scps/*.json`** — Pre-loaded SCPs for when the caller lacks Organizations API access.

## Commands

| Command | What it does |
|---------|-------------|
| `/scope:audit <target>` | Enumerate AWS resources (IAM, STS, S3, KMS, EC2, Lambda, Secrets, and more). Maps attack paths across 9 categories and auto-chains defensive controls. |
| `/scope:exploit <arn>` | Generate red team playbooks — escalation paths, persistence techniques, exfiltration vectors with ready-to-execute CLI commands. |
| `/scope:defend` | Generate SCPs/RCPs, Splunk detections, and security controls based on audit findings. |
| `/scope:investigate` | SOC alert investigation via Splunk — guided queries, timeline building, IOC correlation. |

> **Codex users:** Use dollar-sign prefix with hyphens: `$scope-audit`, `$scope-exploit`, etc.

## Safety

SCOPE is **read-only by default**. Lifecycle hooks block destructive AWS operations at the tool level. Before any write operation, SCOPE shows an approval block with the action, target resources, and risk level — then waits for your explicit Y/N. Approvals are per-step, never batched. Exploit generates playbooks but does not execute them.

## License

MIT
