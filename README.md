# SCOPE: Security Cloud Ops Purple Engagement

[![GitHub stars](https://img.shields.io/github/stars/tayontech/SCOPE?style=social)](https://github.com/tayontech/SCOPE/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/tayontech/SCOPE?style=social)](https://github.com/tayontech/SCOPE/network/members)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/tayontech/SCOPE/blob/main/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/tayontech/SCOPE)](https://github.com/tayontech/SCOPE/commits/main)

*One framework. Full purple team loop. From enumeration to defense.*

Most AWS security assessments are manual, fragmented, and slow. Enumeration scripts dump raw output that someone has to stitch together. Findings live in spreadsheets. Attack paths exist only in the assessor's head. Defensive recommendations are generic and disconnected from what was actually found.

**SCOPE changes that.** It's an agentic AI framework that runs the full purple team loop: enumerate AWS resources, reason about attack paths, generate exploit playbooks, produce targeted defensive controls, and investigate threats.

## How It Works

SCOPE runs as a set of AI agents inside [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [Gemini CLI](https://github.com/google-gemini/gemini-cli), or [Codex CLI](https://github.com/openai/codex). One command kicks off the full pipeline:

```
/scope:audit --all
```

The orchestrator runs the Python AWS SDK runtime across 16 AWS services, feeds factual resource inventory into an attack path reasoning engine, auto-chains defensive control generation, and renders everything into an interactive dashboard. No manual handoffs.

| Phase | What Happens |
|-------|-------------|
| **Audit** | Python enumerators inventory IAM, STS, S3, KMS, Secrets Manager, Lambda, EC2, RDS, API Gateway, SNS, SQS, CodeBuild, Bedrock, Cognito, DynamoDB, SSM |
| **Attack Paths** | AI reasons over combined findings to identify privilege escalation chains, lateral movement, and trust abuse |
| **Controls** | Generates SCPs, resource control policies, SPL detections (atomic + composite), and prioritized remediation |
| **Exploit** | Produces narrative red team playbooks with creative reasoning for novel abuse paths beyond standard catalogues |
| **Investigate** | SOC alert investigation, run-guided threat hunting, and threat intel parsing — three modes: investigation, run-guided, and intel |

## Quick Start

```bash
# Clone and install
git clone https://github.com/tayontech/SCOPE.git
cd SCOPE
node bin/install.js

# Configure AWS credentials (any standard method)
export AWS_PROFILE=your-profile

# Run a full audit
/scope:audit --all

# Or target specific services
/scope:audit iam s3 lambda

# Generate exploit playbooks for a principal
/scope:exploit arn:aws:iam::123456789012:role/target-role

# Self-target mode (discovers caller identity automatically)
/scope:exploit

# Investigate a SOC alert
/scope:investigate
```

The installer presents an interactive selector — pick your runtime (Claude Code, Gemini, Codex, or all) and install scope (local project or global).

> **Requirements:** AWS CLI configured with read-only credentials. Node.js for tooling. Claude Code, Gemini CLI, or Codex CLI as the runtime.

## Architecture

```
agents/               Core agents: audit orchestrator, controls, exploit, investigate
agents/subagents/     Attack analysis, controls subagents, investigation intake, research, verification
scope/enumerators/    Python boto3 resource inventory modules
scope/core/           Shared Python runtime: AWS clients, envelope, coverage, retry, models
scope/runtime/        Audit orchestration, target selection, aggregation, post-processing
dashboard/            React + D3 interactive dashboard (self-contained HTML output)
config/               Runtime reference data, lifecycle hooks, schemas, settings templates
bin/                  Tooling: installer, report generator, graph extractor
```

### Exploit Intelligence

The exploit agent uses creative reasoning to discover abuse paths — not just a static checklist. It analyzes a principal's actual permissions and reasons about what attack chains are possible, using known escalation families as a floor, not a ceiling.

- **Permission auto-discovery** — self-target mode discovers caller identity, reads own policies, falls back to targeted probes
- **Visibility tagging** — CloudTrail classification tags each step as management event, data event, or not logged without turning the playbook into detection guidance
- **Creative reasoning** — LLM reasons about unconventional service chain abuse beyond the standard catalogue
- **PassRole attack surface** — maps composable role-passing chains across 10+ AWS services

### Safety by Default

SCOPE agents are **read-only**. A lifecycle hook blocks every destructive AWS API call before it executes. Exploit generates playbooks with write commands but never runs them. Execution requires explicit human approval per-step.

| Hook | Purpose |
|------|---------|
| Safety Guard | Blocks destructive AWS operations at the shell level |
| SPL Lint | Hard-fails on Splunk query anti-patterns |
| Schema Validate | Enforces structured output on all results |
| Artifact Check | Verifies mandatory outputs before agent completion |

### SIEM Integration

SCOPE connects to your SIEM via MCP for live query execution during investigations. The default configuration targets Splunk Cloud (Splunkbase app 7931), but you can use any SIEM that exposes an MCP server. Replace the `mcpServers` block in your platform's config with your SIEM's MCP server definition and credentials. The investigation agent probes for available search tools at startup and adapts accordingly. See `config/mcp-setup.md` for details.

## Dashboard

Agents produce structured JSON that feeds into an interactive React + D3 dashboard. One command generates a self-contained HTML file. No server required.

```bash
cd dashboard && npm run dashboard
open dashboard/<run-id>-dashboard.html
```

The dashboard visualizes:
- Trust relationships with internal/external classification based on owned account IDs
- Attack paths with severity, MITRE ATT&CK mappings, and exploitability ratings
- Privilege escalation chains and lateral movement graphs
- Defensive controls: SCPs, RCPs, and SPL detections with atomic/composite badges
- KPI cards: critical priv esc count, wildcard trusts, cross-account trusts

## Multi-Platform

SCOPE runs on three AI coding platforms with the same agent definitions:

| Platform | Status | Hooks Config | Notes |
|----------|--------|-------------|-------|
| **Claude Code** | Full support | `.claude/settings.json` | Lifecycle hooks, model routing, memory |
| **Gemini CLI** | Full support | `.gemini/settings.json` | Lifecycle hooks, model routing |
| **Codex CLI** | Full support | `.codex/hooks.json` | Lifecycle hooks, model routing |

### Agent Architecture

SCOPE has two types of agents:

**Skills** — run in your session, inherit your model:
- `scope-audit` — orchestrator, dispatches subagents
- `scope-controls` — defensive controls orchestrator, dispatches 5 subagents
- `scope-exploit` — standalone red team playbook generator
- `scope-investigate` — standalone SOC investigation assistant

**Subagents** — dispatched with their own pinned model:
- `scope-attack-analyze` — attack path analysis over Python runtime inventory, graph, and IAM policy context
- `scope-controls-guardrails`, `scope-controls-detections`, `scope-controls-policy`, `scope-controls-remediation`, `scope-controls-validate` — controls subagents
- `scope-investigate-alert`, `scope-investigate-intel`, `scope-investigate-run` — investigation intake and hypothesis generation
- `scope-research` - shared external technique research for attack analysis and exploit playbooks

When you run `/scope:audit --all`, the orchestrator runs on your session model, calls `scope audit` for deterministic Python enumeration and post-processing, dispatches `scope-attack-analyze`, optionally enriches candidates through `scope-research`, then chains controls on a reasoning model. Scope-investigate dispatches intake subagents on a reasoning model, then runs Splunk execution on your session model. Exploit always uses whatever model your session is running.

### Model Routing

`install.js` assigns platform-specific models to subagents during install:

| Agent Type | Claude Code | Gemini CLI | Codex |
|------------|-------------|------------|-------|
| Reasoning (attack analysis, controls + subagents, investigation intake, research subagent) | claude-sonnet-4-6 | gemini-3.1-pro-preview | gpt-5.4 |

Enumeration is deterministic Python via `python -m scope` and `scope/enumerators/` — no AI model. Skills (audit, exploit, investigate) inherit your session model.

## Documentation

| | |
|---|---|
| [PROJECT.md](https://github.com/tayontech/SCOPE/blob/main/config/project-docs/PROJECT.md) | Behavioral guidance: reasoning philosophy, operator pace, environmental learning |
| [LLM-CONTEXT.md](https://github.com/tayontech/SCOPE/blob/main/config/project-docs/LLM-CONTEXT.md) | Reviewer and implementation-agent context for SCOPE contracts, boundaries, and verification |
| [Dashboard](https://github.com/tayontech/SCOPE/tree/main/dashboard) | Visualization setup and customization |
| [Hooks](https://github.com/tayontech/SCOPE/tree/main/config/hooks) | Safety and validation hook reference |
| [Schemas](https://github.com/tayontech/SCOPE/tree/main/config/schemas) | JSON Schema definitions for audit, controls, exploit output |

## Community

- [Issues](https://github.com/tayontech/SCOPE/issues) Bugs and feature requests
- [Pull Requests](https://github.com/tayontech/SCOPE/pulls) Contributions welcome

---

Created by **Tayvion Payton**

*Enumerate. Reason. Controls. One command, full loop.*
