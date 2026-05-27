# SCOPE: Security Cloud Ops Purple Engagement

[![GitHub stars](https://img.shields.io/github/stars/tayontech/SCOPE?style=social)](https://github.com/tayontech/SCOPE/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/tayontech/SCOPE?style=social)](https://github.com/tayontech/SCOPE/network/members)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/tayontech/SCOPE/blob/main/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/tayontech/SCOPE)](https://github.com/tayontech/SCOPE/commits/main)

SCOPE runs AWS purple-team workflows with deterministic Python inventory and bounded AI agents. It audits AWS resources, validates attack paths, generates review-only exploit playbooks, produces controls, and guides Splunk investigations.

## How It Works

Run SCOPE from Claude Code, Antigravity CLI, Gemini CLI, or Codex CLI:

```text
/scope:audit --all
```

| Phase | Output |
|-------|--------|
| Audit | Python enumerators inventory IAM, STS, S3, KMS, Secrets Manager, Lambda, EC2, ECS, RDS, API Gateway, SNS, SQS, CodeBuild, Bedrock, CloudFront, Cognito, DynamoDB, Route 53, and SSM |
| Attack paths | Candidate generation, validation, grouped reporting, and review-only AWS CLI replay artifacts |
| Controls | Org-wide issues, SPL detections, monitoring dashboard ideas, policy replacements, remediation, and validation |
| Exploit | Principal-scoped playbooks with approved replay command artifacts |
| Investigate | Alert, run-guided, and intel-driven Splunk investigation workflows |

## Quick Start

```bash
git clone https://github.com/tayontech/SCOPE.git
cd SCOPE
uv run python -m scope.install

export AWS_PROFILE=your-profile

/scope:audit --all
/scope:audit iam s3 lambda
/scope:exploit arn:aws:iam::123456789012:role/target-role
/scope:exploit
/scope:investigate
```

Requirements: Python 3.11+, `uv`, AWS CLI with read-only credentials, and one supported runtime. Node.js supports dashboard generation and Splunk MCP `mcp-remote` transport.

Scripted installs:

```bash
uv run python -m scope.install --claude --local --no-splunk-mcp
uv run python -m scope.install --antigravity --local --no-splunk-mcp
uv run python -m scope.install --gemini --local --no-splunk-mcp
uv run python -m scope.install --codex --local --no-splunk-mcp
uv run python -m scope.install --all --local --with-splunk-mcp
```

Interactive install asks whether to configure bundled Splunk MCP defaults. Scripted installs skip MCP server settings unless you pass `--with-splunk-mcp`. Use `--no-splunk-mcp` when automation should show the choice in logs. SCOPE remains SPL-first until the project adds query-language profiles. See `config/mcp-setup.md`.

## Safety

SCOPE agents run read-only AWS activity by default. `config/hooks/scope-safety-guard.sh` blocks destructive AWS shell operations before execution. Audit and exploit may write AWS CLI replay command artifacts for human review; agents do not execute those write commands.

| Hook | Purpose |
|------|---------|
| Safety Guard | Blocks destructive AWS shell operations |
| SPL Lint | Rejects SPL anti-patterns and side-effect commands |
| Schema Validate | Validates results and module envelopes |
| Artifact Check | Checks required run outputs before completion |

## Dashboard

Generate one self-contained report for a run:

```bash
cd dashboard && npm run dashboard
open dashboard/reports/<run-id>-dashboard.html
```

An explicit audit run directory basename becomes the dashboard run ID. `dashboard/public/index.json` stores `reports[]`; each report points to one audit JSON export and optional controls JSON export. Controls attach to the audit report, so one audit workflow creates one selectable dashboard report.

The dashboard shows attack graphs, path details, public exposure findings, controls, SPL detections, dashboard ideas, policy replacements, and remediation.

## Platforms

| Platform | Status | Hook Config | Install Surface |
|----------|--------|-------------|-----------------|
| Claude Code | Supported | `.claude/settings.json` | `.claude/skills/`, `.claude/agents/` |
| Antigravity CLI | Preferred Google target | `.agents/hooks.json` | `.agents/skills/`, `.agents/mcp_config.json`, `.agents/plugins/scope/agents/` |
| Gemini CLI | Legacy Google target | `.gemini/settings.json` | `.agents/skills/`, `.gemini/agents/` |
| Codex CLI | Supported | `.codex/hooks.json` | `.agents/skills/`, `.codex/agents/` |

Google announced on May 19, 2026 that Gemini CLI and Gemini Code Assist IDE extensions stop serving requests for Google AI Pro, Ultra, and free individual users on June 18, 2026. Use Antigravity CLI for new Google installs. SCOPE keeps `--gemini` for enterprise/API-key users and migration.

## Agents And Models

Top-level agents inherit the runtime session model:

- `scope-audit` orchestrates audit gates, Python runtime execution, attack analysis, replay artifacts, and controls chaining.
- `scope-controls` orchestrates org-wide issues, detections, dashboard ideas, policy replacements, remediation, and validation.
- `scope-exploit` generates principal-scoped red-team playbooks.
- `scope-investigate` runs alert, run-guided, and intel investigation modes.

Subagents run bounded reasoning tasks:

- `scope-attack-analyze`, `scope-attack-validate`, `scope-public-exposure-analysis`, and `scope-awscli-replay` support attack-path analysis and replay artifacts.
- `scope-controls-org-wide`, `scope-controls-detections`, `scope-controls-dashboards`, `scope-controls-policy`, `scope-controls-remediation`, and `scope-controls-validate` support controls.
- `scope-investigate-alert`, `scope-investigate-intel`, and `scope-investigate-run` prepare investigation context.
- `scope-research` - shared external technique research for attack analysis and exploit playbooks.

When you run `/scope:audit --all`, the orchestrator runs on your session model, calls `scope audit` for deterministic Python enumeration and post-processing, seeds IAM and public/service-connected candidates with `scope.attack.candidates`, dispatches `scope-attack-analyze`, optionally enriches candidates through `scope-research`, then can generate review-only AWS CLI replay artifacts for validated paths before chaining controls on a reasoning model.

| Runtime | Reasoning Subagent Tier |
|---------|-------------------------|
| Claude Code | `opus[1m]` alias |
| Antigravity CLI | Model selected in Antigravity |
| Gemini CLI | `pro` alias |
| Codex CLI | `gpt-5.5` with high reasoning effort |

Claude subagents use the `opus[1m]` alias for larger context during artifact-heavy analysis and validation. Enumeration uses deterministic Python, not an AI model.

## Documentation

| Document | Purpose |
|----------|---------|
| [ARCHITECTURE.md](https://github.com/tayontech/SCOPE/blob/main/ARCHITECTURE.md) | Component ownership, pipeline flow, runtime contracts, graphs, and hooks |
| [RELEASE-NOTES.md](https://github.com/tayontech/SCOPE/blob/main/RELEASE-NOTES.md) | Current release changes |
| [config/mcp-setup.md](https://github.com/tayontech/SCOPE/blob/main/config/mcp-setup.md) | Splunk MCP and manual SPL mode |
| [config/README.md](https://github.com/tayontech/SCOPE/blob/main/config/README.md) | Config ownership |
| [knowledge/README.md](https://github.com/tayontech/SCOPE/blob/main/knowledge/README.md) | Durable knowledge rules and redaction |
| [config/project-docs/PROJECT.md](https://github.com/tayontech/SCOPE/blob/main/config/project-docs/PROJECT.md) | Source for generated runtime instruction files |
| [docs/LLM-CONTEXT.md](https://github.com/tayontech/SCOPE/blob/main/docs/LLM-CONTEXT.md) | Reviewer and implementation-agent context |
| [dashboard](https://github.com/tayontech/SCOPE/tree/main/dashboard) | React and D3 report generator |
| [config/hooks](https://github.com/tayontech/SCOPE/tree/main/config/hooks) | Safety and validation hooks |
| [config/schemas](https://github.com/tayontech/SCOPE/tree/main/config/schemas) | JSON Schema contracts |

## Community

- [Issues](https://github.com/tayontech/SCOPE/issues)
- [Pull Requests](https://github.com/tayontech/SCOPE/pulls)

Created by **Tayvion Payton**
