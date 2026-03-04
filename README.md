# SCOPE

**AI agent set for cloud security purple teaming — runs inside Claude Code, Gemini CLI, and Codex**

## What It Does

SCOPE (Security Cloud Ops Purple Engagement) is an AI-powered purple team toolkit for AWS. Four agents cover the full security operations loop:

- **Audit** — Enumerates IAM, STS, Lambda, S3, KMS, Secrets Manager, and EC2 (including VPC, EBS, ELB, SSM, and VPN). Maps effective permissions, discovers attack paths across 9 categories (privilege escalation, trust misconfigurations, data exposure, credential risks, excessive permissions, network exposure, persistence, post-exploitation, lateral movement), filters service-linked roles, and produces interactive attack graphs with per-principal details.
- **Exploit** — Takes a principal ARN and generates a red team playbook: escalation paths with ready-to-execute CLI commands, control circumvention analysis, lateral movement with full attack chain tracing, persistence techniques (41 methods across 8 services), and exfiltration vectors with scope estimates.
- **Defend** — Reads audit findings and generates enterprise-scale SCPs/RCPs, security control recommendations, and Splunk SPL detection rules built against CloudTrail telemetry.
- **Investigate** — Guides SOC analysts through CloudTrail-based alert investigation in Splunk with step-by-step queries, timeline building, and IOC correlation.

The AI reasons about attack paths — it doesn't just run scripts. It decides what to enumerate, interprets results, pivots to interesting findings, and builds correlated detections. Every factual claim is traced to evidence (API output, policy evaluation) through a three-part verification system that classifies output as Guaranteed, Conditional, or Speculative. Audit, exploit, and defend runs produce structured artifacts viewable in the SCOPE dashboard at `http://localhost:3000`. Investigate produces self-contained markdown.

## Architecture

```
User-facing agents (slash commands):
  scope-audit         Enumerate AWS resources (IAM, STS, Lambda, S3, KMS, Secrets Manager, EC2), map permissions, discover attack paths
  scope-exploit       Privilege escalation playbooks, persistence analysis, exfiltration mapping
  scope-investigate   SOC alert investigation via Splunk (standalone, no cross-agent data)

Auto-called agents (not user-invocable):
  scope-defend        Generate defensive controls (SCPs, detections, security controls) — auto-called by audit

Verification agents (auto-called during execution):
  scope-verify-core     Claim ledger, output taxonomy, cross-agent consistency
  scope-verify-aws      API validation, IAM policy syntax, SCP/RCP safety, attack path satisfiability
  scope-verify-splunk   SPL semantic lints, CloudTrail field validation, rerun recipes

Middleware agents (auto-called post-processing pipeline):
  scope-data          Normalize raw artifacts → structured JSON in ./data/
  scope-evidence      Validate evidence provenance → envelopes in ./evidence/
```

## Prerequisites

- Node.js (for installation only)
- AWS credentials configured in your environment (AWS_PROFILE, AWS_ACCESS_KEY_ID, or ~/.aws/credentials)
- One of:
  - [Claude Code](https://claude.ai/code)
  - [Gemini CLI](https://github.com/google-gemini/gemini-cli)
  - [Codex](https://github.com/openai/codex)

## Installation

```bash
git clone https://github.com/tayontech/SCOPE.git
cd SCOPE
node bin/install.js --claude   # install for Claude Code
node bin/install.js --gemini   # install for Gemini CLI
node bin/install.js --codex    # install for Codex
node bin/install.js --all      # install for all editors
```

## AWS Credentials

SCOPE inherits AWS credentials from your environment — set AWS_PROFILE or AWS_ACCESS_KEY_ID before launching your editor. No custom credential loading; it uses whatever boto3/AWS CLI picks up.

**Use a read-only IAM role for audit, defend, and investigate.** These agents read configurations, policies, and metadata — they do not need write, modify, or delete permissions. Attach a role with `ReadOnlyAccess` (or scoped read-only policies for the services you're auditing) to prevent any accidental or unintended modifications to your environment. The exploit agent (`/scope:exploit`) is also read-only by default — it enumerates permissions and generates playbooks but does not execute destructive operations. If you choose to run exploit-generated commands manually, use a separate session with appropriately scoped write credentials.

```bash
export AWS_PROFILE=my-security-readonly-profile
# then launch Claude Code, Gemini CLI, or Codex
```

## Configuration (Optional)

Pre-load environment data in `config/` for situations where live enumeration is limited:

- **`config/accounts.json`** — List of owned AWS account IDs. Helps the audit distinguish internal cross-account trusts from external ones. Without it, only the caller's account is considered "owned." Copy `config/accounts.example.json` to `config/accounts.json` and fill in your real account IDs.
- **`config/scps/*.json`** — Pre-loaded Service Control Policies (one file per SCP). Provides SCP data when the caller lacks Organizations API access. Without them, attack path confidence drops to "SCP status unknown." See `config/scps/README.md` for file format, sourcing instructions, and merge behavior. Files prefixed with `_` are templates and skipped by the loader.

## Usage

Once installed, use slash commands from inside your editor:

| Command | Description |
|---------|-------------|
| `/scope:audit <target> [<target> ...]` | Enumerate AWS resources — accepts ARN, service name (`iam`, `s3`, `kms`, `secrets`, `sts`, `lambda`, `ec2`), `--all`, `@targets.csv`, or multiple services inline (e.g., `iam s3 kms`). The `ec2` service includes VPC, EBS, ELB/ELBv2, SSM, and VPN enumeration. Auto-chains to defensive controls generation. |
| `/scope:exploit <arn> [--fresh]` | Privilege escalation playbooks, persistence analysis, and exfiltration mapping for a specific principal |
| `/scope:investigate` | SOC alert investigation via Splunk — timeline building, IOC correlation |
| `/scope:help` | List available commands, show usage examples, and link to documentation (built-in — reads `commands/help.md` directly, no agent installation needed) |

> **Gemini CLI users:** Skills appear as `$scope-audit` (dollar-sign prefix, hyphen instead of colon)
>
> **Codex users:** Skills appear as `$scope-audit` (dollar-sign prefix, hyphen instead of colon)

### Audit Examples

```
/scope:audit --all                                    # Full account audit
/scope:audit iam                                      # Enumerate all IAM
/scope:audit arn:aws:iam::123456789012:user/alice     # Specific principal
/scope:audit @targets.csv                             # Bulk targets from CSV
/scope:audit iam s3 kms                               # Multiple services inline
```

Audit produces three-layer output: risk summary, permission details, and categorized attack path narratives (privilege escalation, trust misconfigurations, data exposure, credential risks, excessive permissions, network exposure, persistence, post-exploitation, lateral movement). Results include per-principal details and trust relationship analysis.

### Output

Each run creates a timestamped directory with artifacts:

```
./audit/audit-20260301-143022-all/
  findings.md          # Three-layer findings report
  results.json         # Structured data for SCOPE dashboard
  evidence.jsonl       # Structured evidence log

./exploit/exploit-20260301-143022-user-alice/
  playbook.md          # Red team playbook (escalation, persistence, exfiltration)
  results.json         # Structured data for SCOPE dashboard
  evidence.jsonl       # Structured evidence log
```

The post-processing pipeline runs automatically after audit, exploit, and defend runs:
1. **scope-data** — normalizes output into structured JSON in `./data/`
2. **scope-evidence** — validates and indexes evidence provenance in `./evidence/`

If any middleware step fails, the raw artifacts are still available. Visualization is handled by the SCOPE dashboard at `http://localhost:3000`, which reads `results.json` from audit, exploit, and defend runs. Investigate does not export to the dashboard — it produces a markdown determination only.

### Dashboard

All visualization is handled by the SCOPE dashboard at `http://localhost:3000`. Start it with:

```
cd dashboard && npm run dev
```

The dashboard reads `dashboard/public/index.json` to find available runs, then loads `dashboard/public/$RUN_ID.json` per source phase. If `index.json` itself fails to load, the dashboard falls back to `/results.json`. Individual run file failures are silently skipped (no per-file fallback). Results are displayed as audit findings, attack graphs, and defend status in a unified React + D3 interface. Investigate does not export to the dashboard — it produces a markdown determination only. Interactive features include severity filtering, category filtering (9 attack path categories), search, sort (severity/steps/name), clickable stat cards with slide-out detail panels (users, roles, trust relationships, wildcard trusts, critical paths, all paths), attack path edge highlighting on the graph, copy-to-clipboard for detections and defensive control text, a node detail panel with connected edges and associated paths, and run history navigation.

### Verification

All agents apply a three-part verification protocol during execution:
- **Core** — claim ledger, confidence classification, cross-agent consistency
- **AWS** — API call validation, IAM policy syntax, SCP/RCP safety, attack path satisfiability
- **Splunk** — SPL semantic lints, CloudTrail field validation, no macros (raw `index=cloudtrail` only)

Output is classified as Guaranteed, Conditional (with listed gating conditions), or Speculative (stripped). You receive only high-confidence, reproducible results.

## Safety Model

Before any destructive AWS operation, SCOPE displays an `APPROVAL REQUIRED` block listing the action, target resources, and risk level, then waits for your Y/N. Approvals are per-step, never batched. On N: the step is skipped and execution continues.

Investigation mode (`/scope:investigate`) operates in two modes:
- **CONNECTED** — Splunk MCP available, queries execute directly after analyst approval
- **MANUAL** — No MCP, displays SPL for analyst to paste into Splunk and return results
