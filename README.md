# SCOPE: Security Cloud Ops Purple Engagement

[![GitHub stars](https://img.shields.io/github/stars/tayontech/SCOPE?style=social)](https://github.com/tayontech/SCOPE/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/tayontech/SCOPE?style=social)](https://github.com/tayontech/SCOPE/network/members)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/tayontech/SCOPE/blob/main/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/tayontech/SCOPE)](https://github.com/tayontech/SCOPE/commits/main)

*One framework. Full purple team loop. From enumeration to defense.*

Most AWS security assessments are manual, fragmented, and slow. Enumeration scripts dump raw output that someone has to stitch together. Findings live in spreadsheets. Attack paths exist only in the assessor's head. Defensive recommendations are generic and disconnected from what was actually found.

**SCOPE changes that.** It's an agentic AI framework that runs the full purple team loop: enumerate AWS resources, reason about attack paths, generate exploit playbooks, produce targeted defensive controls, and investigate alerts.

## How It Works

SCOPE runs as a set of AI agents inside [Claude Code](https://docs.anthropic.com/en/docs/claude-code), [Gemini CLI](https://github.com/google-gemini/gemini-cli), or [Codex CLI](https://github.com/openai/codex). One command kicks off the full pipeline:

```
/scope:audit --all
```

The orchestrator dispatches parallel enumeration agents across AWS services, feeds findings into an attack path reasoning engine, auto-chains defensive control generation, and renders everything into an interactive dashboard. No manual handoffs.

| Phase | What Happens |
|-------|-------------|
| **Audit** | 12 parallel agents enumerate IAM, S3, Lambda, EC2, KMS, Secrets Manager, STS, RDS, API Gateway, SNS, SQS, CodeBuild |
| **Attack Paths** | AI reasons over combined findings to identify privilege escalation chains, lateral movement, and trust abuse |
| **Defend** | Generates SCPs, resource control policies, SPL detections, and prioritized remediation, mapped to what was found |
| **Exploit** | Produces ready-to-execute playbooks for specific principals (red team use) |
| **Investigate** | Guides SOC analysts through CloudTrail-based alert triage in Splunk |

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

# Investigate a SOC alert
/scope:investigate
```

> **Requirements:** AWS CLI configured with read-only credentials. Node.js for tooling. Claude Code, Gemini CLI, or Codex CLI as the runtime.

## Architecture

```
agents/               Core agents: audit orchestrator, defend, exploit, investigate
agents/subagents/     12 enumeration agents, attack path reasoning, verification, data pipeline
dashboard/            React + D3 interactive dashboard (self-contained HTML output)
.scope/hooks/         Lifecycle hooks: safety guard, SPL lint, schema validation
.scope/schemas/       JSON Schema definitions for structured output
bin/                  Tooling: installer, report generator
config/               Optional account config and pre-loaded SCPs
```

### Safety by Default

SCOPE agents are **read-only**. A lifecycle hook blocks every destructive AWS API call before it executes. Exploit generates playbooks with write commands but never runs them. Execution requires explicit human approval per-step.

| Hook | Purpose |
|------|---------|
| Safety Guard | Blocks destructive AWS operations at the shell level |
| SPL Lint | Hard-fails on Splunk query anti-patterns |
| Schema Validate | Enforces structured output on all results |
| Artifact Check | Verifies mandatory outputs before agent completion |

## Dashboard

Agents produce structured JSON that feeds into an interactive React + D3 dashboard. One command generates a self-contained HTML file. No server required.

The dashboard visualizes trust relationships, attack paths, privilege escalation chains, and defensive control mappings across your entire AWS account.

## Multi-Platform

SCOPE runs on three AI coding platforms with the same agent definitions:

| Platform | Status | Notes |
|----------|--------|-------|
| **Claude Code** | Full support | Lifecycle hooks, model routing, memory |
| **Gemini CLI** | Full support | Hooks via settings templates |
| **Codex CLI** | Supported | Safety enforced via AGENTS.md (no hook support) |

## Documentation

| | |
|---|---|
| [CLAUDE.md](https://github.com/tayontech/SCOPE/blob/main/CLAUDE.md) | Full technical reference: agents, hooks, data layer, error handling |
| [Dashboard](https://github.com/tayontech/SCOPE/tree/main/dashboard) | Visualization setup and customization |
| [Hooks](https://github.com/tayontech/SCOPE/tree/main/.scope/hooks) | Safety and validation hook reference |
| [Schemas](https://github.com/tayontech/SCOPE/tree/main/.scope/schemas) | JSON Schema definitions for audit, defend, exploit output |

## Community

- [Issues](https://github.com/tayontech/SCOPE/issues) Bugs and feature requests
- [Pull Requests](https://github.com/tayontech/SCOPE/pulls) Contributions welcome

---

Created by **Tayvion Payton**

*Enumerate. Reason. Defend. One command, full loop.*
