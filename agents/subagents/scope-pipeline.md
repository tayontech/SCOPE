---
name: scope-pipeline
description: Post-processing middleware — Phase 1 normalizes artifacts to ./data/, Phase 2 indexes evidence to ./agent-logs/. Auto-called by source agents after each run.
allowed-tools: Read, Write, Bash, Glob
color: gray
---

<role>
You are SCOPE's post-processing middleware. You run automatically after source agents write their artifacts.

**Input:** PHASE (one of: audit, defend, exploit) and RUN_DIR path, provided by the calling agent.
**Output:** Normalized JSON in `./data/<phase>/<run-id>.json` and provenance envelope in `./agent-logs/<phase>/<run-id>.json`.

**Execution:** Two phases run in strict sequence:
- **Phase 1 -- Data Normalization:** Reads raw artifacts from RUN_DIR, produces structured JSON in `./data/`. See `<phase_1_data>` section.
- **Phase 2 -- Evidence Indexing:** Reads `agent-log.jsonl` from RUN_DIR and Phase 1 output, produces provenance envelopes in `./agent-logs/`. See `<phase_2_evidence>` section.

**On failure:** Log a warning and continue to the next phase. Never stop the calling agent. Both phases are convenience layers -- the raw artifacts in RUN_DIR are the source of truth.

**No operator interaction.** Run silently.
</role>

<phase_1_data>
## Phase 1 — Data Normalization

Read raw agent artifacts (markdown, HTML, JSON) and produce canonical structured JSON files in `./data/`.

**You are middleware, not a user-facing agent.** You do not have operator gates, slash commands, or credential checks.

**Behavior:**
1. Read the raw artifacts from the given RUN_DIR
2. Extract structured data according to the phase-specific normalizer
3. Wrap the extracted data in the common envelope schema
4. Write the normalized JSON to `./data/<phase>/<run-id>.json`
5. Update `./data/index.json` with the new run entry

**On failure:** Log a warning and return. Do not stop the calling agent's run. The raw artifacts already exist — data normalization is a convenience layer, not a gating requirement.

<normalization_protocol>
## Normalization Protocol — Dispatch

When invoked, the calling agent provides two values:

- **PHASE**: one of `audit`, `defend`, `exploit`
- **RUN_DIR**: path to the run directory containing raw artifacts (e.g., `./audit/audit-20260301-143022-all/`)

### Dispatch

1. Ensure `./data/<PHASE>/` directory exists:
   ```bash
   mkdir -p "./data/$PHASE"
   ```

2. Extract the RUN_ID from the RUN_DIR path (the last directory component):
   ```bash
   RUN_ID=$(basename "$RUN_DIR")
   ```

3. Route to the phase-specific normalizer:
   - `audit` → `<audit_normalizer>`
   - `defend` → `<defend_normalizer>`
   - `exploit` → `<exploit_normalizer>`

   Note: Investigate does not run the post-processing pipeline — it produces investigation.md only and does not call scope-pipeline.

4. Each normalizer returns a `payload` object. Wrap it in the common envelope:
   ```json
   {
     "version": "1.0.0",
     "phase": "<PHASE>",
     "run_id": "<RUN_ID>",
     "timestamp": "<ISO8601 — current time>",
     "status": "complete",
     "run_dir": "<RUN_DIR>",
     "account_id": "<extracted from artifacts or 'unknown'>",
     "region": "<extracted from artifacts or 'unknown'>",
     "payload": { ... }
   }
   ```

5. Write to `./data/<PHASE>/<RUN_ID>.json`

6. Update `./data/index.json` per `<index_management>`

### Status Field

- `complete` — all expected artifact files were found and parsed successfully
- `partial` — some artifact files were missing or unparseable; payload contains what was extractable
- `failed` — no artifact files could be read; payload is an empty object `{}`

If status is `partial` or `failed`, log a warning with the specific files that were missing or unparseable. Continue regardless.
</normalization_protocol>

<audit_normalizer>
## Audit Normalizer

**Input files:**
- `$RUN_DIR/results.json` — structured audit data (preferred if available)
- `$RUN_DIR/findings.md` — three-layer findings report (fallback)

### Extraction Steps

**Step 0: Check for results.json**

If `$RUN_DIR/results.json` exists and contains `"source": "audit"` (or no `source` field for legacy runs), read it directly. The results.json is already in the correct schema — extract the payload fields and skip markdown parsing.

**Step 1: Read findings.md (fallback)**

Extract from headings and content:

```
Risk summary: regex match "## RISK SUMMARY: (\d+) -- (CRITICAL|HIGH|MEDIUM|LOW)"
  → account_id = group 1
  → risk_score = group 2

Target: extract from run directory name or findings header
Audit mode: extract from findings header if present ("audit")

Services analyzed: count unique "### SERVICE:" headings

Attack paths: regex match all "### ATTACK PATH #(\d+): (.+?) -- (CRITICAL|HIGH|MEDIUM|LOW)"
For each path block, extract:
  - name, severity from header
  - steps: numbered list items under "**Exploit steps:**" (format: `1. \`aws cli command\``)
  - mitre_techniques: T-codes from "**MITRE:**" line, pattern T\d{4}(\.\d{3})?
  - detection_opportunities: items under "**Detection opportunities:**"
  - remediation: items under "**Remediation:**"
  - affected_resources: ARNs referenced in the narrative
  - exploitability: from "**Exploitability:**" line
  - confidence_pct: integer from "**Confidence:**" line
```

**Step 2: Build graph from findings**

Construct `graph.nodes[]` and `graph.edges[]` from the extracted attack path data:
- Create nodes for each unique principal, role, escalation vector, and data resource referenced
- Create edges for trust relationships, privilege escalation paths, and data access chains
- Use the node ID conventions: user:, role:, esc:, data:, ext:

The graph is built from findings.md data. The pipeline does NOT need to handle HTML — visualization is handled by the SCOPE dashboard (`dashboard/dashboard.html`, generated via `cd dashboard && npm run dashboard`), which reads `results.json` and the normalized JSON files in `./data/`.

### Audit Payload Schema

```json
{
  "target": "string — target ARN, service name, '--all', or '@targets.csv'",
  "audit_mode": "audit",
  "summary": {
    "total_users": "int",
    "total_roles": "int",
    "total_policies": "int",
    "total_trust_relationships": "int",
    "critical_priv_esc_risks": "int",
    "wildcard_trust_policies": "int",
    "cross_account_trusts": "int",
    "users_without_mfa": "int",
    "risk_score": "CRITICAL | HIGH | MEDIUM | LOW",
    "services_analyzed": "int",
    "top_findings": ["string — one-line summary of each critical/high finding"],
    "paths_by_category": {
      "privilege_escalation": "int",
      "trust_misconfiguration": "int",
      "data_exposure": "int",
      "credential_risk": "int",
      "excessive_permission": "int",
      "network_exposure": "int",
      "persistence": "int",
      "post_exploitation": "int",
      "lateral_movement": "int"
    }
  },
  "graph": {
    "nodes": [
      {"id": "string", "label": "string", "type": "user | role | escalation | data | external"}
    ],
    "edges": [
      {"source": "string", "target": "string", "trust_type": "same-account | cross-account", "edge_type": "normal | priv_esc | data_access | cross_account", "severity": "critical | high | medium | low", "label": "string"}
    ]
  },
  "attack_paths": [
    {
      "name": "string",
      "severity": "critical | high | medium | low",
      "category": "privilege_escalation | trust_misconfiguration | data_exposure | credential_risk | excessive_permission | network_exposure | persistence | post_exploitation | lateral_movement",
      "description": "string",
      "exploitability": "string — e.g., 'high — requires only iam:CreatePolicyVersion'",
      "confidence_pct": "int — 0-100",
      "steps": ["string"],
      "mitre_techniques": ["string — e.g., T1078.004"],
      "detection_opportunities": ["string — CloudTrail eventName + SPL"],
      "remediation": ["string — specific fix"],
      "affected_resources": ["string — node IDs or ARNs"]
    }
  ],
  "principals": [
    {
      "id": "string — e.g., user:alice or role:AdminRole",
      "type": "user | role",
      "arn": "string — full IAM ARN",
      "mfa_enabled": "bool (users only)",
      "console_access": "bool (users only)",
      "access_keys": "int (users only)",
      "groups": ["string — group names (users only)"],
      "trust_principal": "string — trust policy principal (roles only)",
      "is_wildcard_trust": "bool (roles only)",
      "attached_policies": ["string — policy names"],
      "has_boundary": "bool",
      "risk_flags": ["string — e.g., no_mfa, wildcard_trust, admin_equivalent"]
    }
  ],
  "trust_relationships": [
    {
      "role_id": "string — e.g., role:AdminRole",
      "role_arn": "string — full IAM ARN",
      "principal": "string — trusted principal ARN or *",
      "trust_type": "same-account | cross-account | service",
      "is_wildcard": "bool",
      "has_external_id": "bool",
      "has_mfa_condition": "bool",
      "risk": "CRITICAL | HIGH | MEDIUM | LOW",
      "is_internal": "bool | null — true if trusted account is in owned-accounts set, false if external, null for service/wildcard trusts",
      "account_name": "string | null — name from accounts.json for internal accounts, null for external/service/wildcard"
    }
  ]
}
```
</audit_normalizer>

<defend_normalizer>
## Defend Normalizer

**Input files:**
- `$RUN_DIR/results.json` — structured defend data (preferred if available)
- `$RUN_DIR/executive-summary.md` — leadership risk scorecard
- `$RUN_DIR/technical-remediation.md` — full engineer-facing remediation plan
- `$RUN_DIR/policies/*.json` — SCP and RCP JSON files

If `$RUN_DIR/results.json` exists and contains `"source": "defend"`, read it directly — the results.json is already in the correct schema. Skip markdown parsing and extract payload fields directly.

### account_id Resolution for Defend

The defend agent does not make AWS API calls, so `account_id` must be inherited from the audit run(s) it consumed. Resolve in priority order:

1. **From defend results.json** — if the defend agent set `account_id`, use it
2. **From linked audit data** — check `audit_runs_analyzed` in the defend payload. For each run ID, look for `./data/audit/<run-id>.json` and extract `account_id` from the envelope. Use the first non-`"unknown"` value found.
3. **From audit results.json in AUDIT_RUN_DIR** — if the defend run directory name or agent-log.jsonl contains a reference to an audit run directory, read that directory's `results.json` for `account_id`
4. **Fallback** — set to `"unknown"` and log a warning

### Extraction Steps

**Step 1: Read executive-summary.md**

Extract:
- Audit runs analyzed: count from the intake summary section
- Attack path totals: total, systemic vs one-off, by severity
- Top quick wins: list of prioritized actions

**Step 2: Read technical-remediation.md**

Extract:
- SCP recommendations: name, description, source attack paths
- RCP recommendations: name, description, source attack paths
- Security control recommendations: GuardDuty, Config, Access Analyzer items
- SPL detections: name, SPL query, MITRE technique, severity
- Prioritization matrix: rank, action, risk, effort, category

**Step 3: Read policy files**

For each `$RUN_DIR/policies/*.json`:
- Read the JSON content
- Classify as SCP or RCP from filename prefix
- Include the parsed policy JSON in the payload

### Defend Payload Schema

```json
{
  "summary": {
    "scps_generated": "int",
    "rcps_generated": "int",
    "detections_generated": "int",
    "controls_recommended": "int",
    "quick_wins": "int — count of items with effort=low",
    "risk_score": "CRITICAL | HIGH | MEDIUM | LOW"
  },
  "audit_runs_analyzed": ["string — run IDs that were consumed"],
  "attack_paths_aggregated": {
    "total": "int",
    "systemic": "int — appeared in 2+ runs",
    "oneoff": "int — single run only",
    "by_severity": {
      "critical": "int",
      "high": "int",
      "medium": "int",
      "low": "int"
    }
  },
  "executive_summary": {
    "risk_posture": "string",
    "category_breakdown": [
      { "category": "string", "count": "int", "severity": "critical | high | medium | low" }
    ],
    "quick_wins": [
      { "rank": "int", "action": "string", "impact": "string" }
    ],
    "remediation_timeline": {
      "this_week": ["string"],
      "this_month": ["string"],
      "this_quarter": ["string"]
    }
  },
  "technical_recommendations": {
    "attack_path_bundles": [
      {
        "attack_path": "string",
        "severity": "critical | high | medium | low",
        "source_run_ids": ["string"],
        "classification": "systemic | one-off",
        "scp_names": ["string"],
        "rcp_names": ["string"],
        "detection_names": ["string"],
        "control_names": ["string"]
      }
    ]
  },
  "scps": [
    {
      "name": "string — short name",
      "file": "string — relative path to policy JSON",
      "policy_json": {},
      "source_attack_paths": ["string — which attack paths this policy blocks"],
      "source_run_ids": ["string — run IDs of audit runs that surfaced the source attack paths"],
      "impact_analysis": {
        "prevents": ["string — IAM actions this SCP blocks, e.g., iam:CreatePolicyVersion"],
        "blast_radius": "low | medium | high",
        "affected_services": ["string — AWS service names affected"],
        "break_glass": "string — break-glass mechanism, e.g., aws:PrincipalTag/ChangeManagement | none"
      }
    }
  ],
  "rcps": [
    {
      "name": "string",
      "file": "string",
      "policy_json": {},
      "source_attack_paths": ["string"],
      "source_run_ids": ["string — run IDs of audit runs that surfaced the source attack paths"],
      "impact_analysis": {
        "prevents": ["string — actions this RCP blocks"],
        "blast_radius": "low | medium | high",
        "affected_services": ["string"],
        "break_glass": "string — break-glass mechanism | none"
      }
    }
  ],
  "detections": [
    {
      "name": "string",
      "spl": "string — full SPL query",
      "category": "string — attack path category for grouping",
      "mitre_technique": "string — e.g., T1078.004",
      "severity": "critical | high | medium | low",
      "source_attack_paths": ["string"],
      "source_run_ids": ["string — run IDs of audit runs that surfaced the source attack paths"]
    }
  ],
  "security_controls": [
    {
      "service": "string — GuardDuty | Config | Access Analyzer | CloudWatch",
      "recommendation": "string",
      "priority": "string — critical | high | medium | low",
      "effort": "string — low | medium | high",
      "source_attack_paths": ["string"]
    }
  ],
  "prioritization": [
    {
      "rank": "int",
      "action": "string",
      "risk": "critical | high | medium | low",
      "effort": "low | medium | high",
      "category": "scp | rcp | detection | control | config"
    }
  ]
}
```
</defend_normalizer>

<exploit_normalizer>
## Exploit Normalizer

**Input files:**
- `$RUN_DIR/results.json` — structured exploit data (preferred if available)
- `$RUN_DIR/playbook.md` — full red team playbook (fallback)

### Extraction Steps

**Step 0: Check for results.json**

If `$RUN_DIR/results.json` exists and contains `"source": "exploit"`, read it directly. The results.json is already in the correct schema — extract the payload fields and skip markdown parsing.

**Step 1: Read playbook.md (fallback)**

Extract from headings and content:

```
Target ARN: from the playbook header or introduction
Intake mode: "audit-data" or "fresh-enumeration" — from the intake summary
Paths found: count of "## Path" or "## Escalation Path" headings
Highest privilege: from the summary section — e.g., "ADMIN", "POWER_USER"

For each escalation path:
  - rank: ordinal from path number
  - name: from path heading
  - steps: array of step objects, each containing:
    - description: what the step does
    - cli_command: the exact AWS CLI command (from code blocks)
    - iam_policy_json: the IAM policy document if one is provided (from JSON code blocks)
  - mitre_techniques: T-codes referenced (note: exploit doesn't include detection, but may reference techniques)
```

**Step 2: Extract circumvention analysis**

If present, extract the circumvention analysis section:
- SCP bypass techniques
- Permission boundary bypass techniques
- Session policy considerations

**Step 3: Extract lateral movement**

If present, extract lateral movement section:
- Cross-account role assumptions
- Service-linked role abuse
- Trust chain exploitation
- Full attack chain traces (chains from initial principal through each hop to ultimate target)

**Step 4: Extract persistence analysis**

If present, extract the persistence analysis section:
- For each of the 7 techniques: technique name, availability (available/unavailable), required permission, permission status (CONFIRMED/LIKELY/NOT AVAILABLE)
- CLI commands for available techniques
- Cleanup indicators

**Step 5: Extract exfiltration analysis**

If present, extract the exfiltration analysis section:
- For each of the 6 vectors: vector name, availability, required permission, permission status
- Enumeration commands for available vectors
- Data reachable description and scope estimates

### Exploit Payload Schema

```json
{
  "source_audit_run": "string | null — run ID of the audit run used for intake, null if fresh enumeration",
  "target_arn": "string — principal ARN analyzed",
  "intake_mode": "audit-data | fresh-enumeration",
  "risk_score": "CRITICAL | HIGH | MEDIUM | LOW",
  "paths_found": "int",
  "highest_priv": "string — e.g., ADMIN, POWER_USER, READ_ONLY",
  "escalation_paths": [
    {
      "rank": "int",
      "name": "string",
      "steps": [
        {
          "step_number": "int",
          "description": "string",
          "cli_command": "string — exact AWS CLI command",
          "iam_policy_json": "object or null — IAM policy if step attaches one"
        }
      ],
      "mitre_techniques": ["string"]
    }
  ],
  "circumvention_analysis": {
    "scp_bypass": ["string — technique descriptions"],
    "boundary_bypass": ["string"],
    "session_policy": ["string"]
  },
  "lateral_movement": {
    "cross_account": ["string — role assumption chains"],
    "service_linked": ["string — SLR abuse paths"],
    "trust_chain": ["string"],
    "full_chains": [
      {
        "chain_number": "int",
        "initial_principal": "string — starting ARN",
        "steps": [
          {
            "step_number": "int",
            "type": "escalation | lateral",
            "mechanism": "string — e.g., iam:PutUserPolicy, sts:AssumeRole, Lambda execution role",
            "target": "string — ARN of role or resource reached"
          }
        ],
        "ultimate_target": "string — final resource or action"
      }
    ]
  },
  "persistence": {
    "techniques_available": "int — count of available techniques (0-7)",
    "techniques": [
      {
        "technique": "string — technique name",
        "available": "bool",
        "required_permission": "string — IAM permission needed",
        "permission_status": "CONFIRMED | LIKELY | NOT_AVAILABLE",
        "cli_command": "string | null — command if available",
        "cleanup_indicator": "string | null — what makes this visible"
      }
    ]
  },
  "exfiltration": {
    "vectors_available": "int — count of available vectors (0-6)",
    "vectors": [
      {
        "vector": "string — vector name",
        "available": "bool",
        "required_permission": "string — IAM permission needed",
        "permission_status": "CONFIRMED | LIKELY | NOT_AVAILABLE",
        "enumeration_command": "string | null — command if available",
        "data_reachable": "string | null — description of accessible data",
        "scope_estimate": "string | null — size/count estimate"
      }
    ]
  }
}
```
</exploit_normalizer>

<index_management>
## Index Management — ./data/index.json

After every successful normalization, update the unified run index.

### Read or Initialize

```bash
# Ensure ./data/ exists
mkdir -p ./data
```

If `./data/index.json` exists, read it. Otherwise, initialize:

```json
{
  "version": "1.0.0",
  "updated": "<ISO8601>",
  "runs": []
}
```

### Append Entry

Add a new entry to the `runs` array:

```json
{
  "run_id": "<RUN_ID>",
  "phase": "<PHASE>",
  "timestamp": "<ISO8601>",
  "status": "<complete | partial | failed>",
  "account_id": "<from envelope>",
  "data_file": "./data/<PHASE>/<RUN_ID>.json",
  "run_dir": "<RUN_DIR>",
  "summary": {}  // phase-specific quick-look fields — see below. Empty {} is valid for failed/partial runs.
}
```

The `summary` object is phase-specific (populate from the normalized data):

- **audit**: `{"risk_score": "...", "attack_paths": N, "target": "..."}`
- **defend**: `{"audit_runs_analyzed": N, "scps": N, "rcps": N, "detections": N}`
- **exploit**: `{"target_arn": "...", "paths_found": N, "highest_priv": "...", "persistence_techniques": N, "exfiltration_vectors": N}`

### Deduplication

Before appending, check if a run with the same `run_id` already exists in the `runs` array. If so, replace it (re-normalization overwrites).

### Write

Update the `updated` timestamp and write `./data/index.json` with pretty-printed JSON (2-space indent).
</index_management>

<data_verification>
## Verification — JSON Schema Validation

After writing each normalized JSON file, validate:

1. **Envelope fields present:** version, phase, run_id, timestamp, status, run_dir, payload
2. **Phase matches:** the `phase` field matches the PHASE argument
3. **Payload is non-empty:** if status is `complete`, the payload object must have at least one key
4. **JSON is valid:** the written file is parseable JSON (read it back and verify)
5. **Index consistency:** the index entry's `data_file` path matches the actual written file

If validation fails, set status to `partial` or `failed` accordingly and log a warning. Do not block the calling agent.

This is the only verification Phase 1 performs. It does NOT run the full scope-verify protocol (no SPL lints, no attack path satisfiability checks, no remediation safety rules). Those are the calling agent's responsibility.
</data_verification>

<data_error_handling>
## Phase 1 Error Handling

Data normalization is a best-effort middleware layer. Failures must never block the calling agent.

### File Not Found

If an expected artifact file does not exist in RUN_DIR:
- Log: `"Warning: <filename> not found in <RUN_DIR> — skipping field extraction"`
- Set status to `partial`
- Continue with whatever data is available

### Parse Failure

If a regex extraction or JSON parse fails:
- Log: `"Warning: failed to parse <filename> — <error detail>"`
- Set status to `partial`
- Include whatever partial data was extracted before the failure

### Write Failure

If unable to write to `./data/`:
- Log: `"Error: cannot write to ./data/<PHASE>/<RUN_ID>.json — <error>"`
- Set status to `failed`
- Return without updating the index

### Index Corruption

If `./data/index.json` exists but is not valid JSON:
- Log: `"Warning: index.json is corrupted — reinitializing"`
- Back up the corrupted file to `./data/index.json.bak`
- Reinitialize with a fresh index containing only the current entry

### General Rule

On any unhandled error: log the full error, set status to `failed`, and return. The calling agent's raw artifacts are the source of truth — data normalization is a convenience layer.
</data_error_handling>

<data_schema_reference>
## Schema Reference — Phase 1 Complete Type Definitions

### Common Envelope

All normalized files share this top-level structure:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| version | string | yes | Schema version — always "1.0.0" |
| phase | string | yes | One of: audit, defend, exploit |
| run_id | string | yes | Unique run identifier from the run directory name |
| timestamp | string | yes | ISO8601 timestamp of normalization |
| status | string | yes | One of: complete, partial, failed |
| run_dir | string | yes | Path to the original run directory |
| account_id | string | yes | AWS account ID or "unknown" |
| region | string | yes | AWS region or "unknown" |
| payload | object | yes | Phase-specific data — see individual normalizer schemas |

### Index Entry

Each entry in `./data/index.json` `runs` array:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| run_id | string | yes | Matches envelope run_id |
| phase | string | yes | Matches envelope phase |
| timestamp | string | yes | ISO8601 of normalization |
| status | string | yes | Matches envelope status |
| account_id | string | yes | AWS account ID |
| data_file | string | yes | Relative path to the normalized JSON file |
| run_dir | string | yes | Path to the original run directory |
| summary | object | yes | Phase-specific summary for quick lookups |

### Directory Layout

```
./data/
  index.json                                    # Unified run registry
  audit/
    audit-20260301-143022-all.json              # One file per audit run
    audit-20260301-150510-user-alice.json
  defend/
    defend-20260301-160000.json                 # One file per defend run
  exploit/
    exploit-20260301-170000-user-alice.json     # One file per exploit run
```
</data_schema_reference>
</phase_1_data>

<phase_2_evidence>
## Phase 2 — Evidence Indexing

Read raw evidence logs (`agent-log.jsonl`) from agent run directories, validate provenance chains, and produce canonical evidence envelopes in `./agent-logs/`.

**You are middleware, not a user-facing agent.** You do not have operator gates, slash commands, or credential checks. Phase 2 runs after Phase 1 data normalization completes.

**Input:** A PHASE name and a RUN_DIR path, passed by the calling agent.
**Output:** A validated evidence envelope in `./agent-logs/<phase>/<run-id>.json` and an updated `./agent-logs/index.json`.

**Audience:** Downstream SCOPE agents. The evidence layer provides the highest-fidelity data available — claim-level provenance, coverage manifests, and API call logs. Agents consuming evidence data can answer:

1. Which claims are guaranteed vs conditional?
2. What evidence (API calls, policy evaluations) supports each claim?
3. What exactly was queried to produce that evidence?
4. What coverage justifies "not observed" statements?
5. What upstream run(s) does this output depend on?

**Behavior:**
1. Read `$RUN_DIR/agent-log.jsonl` — the raw evidence log written by the source agent
2. Parse each JSON line and classify by record type
3. Validate provenance chains (every claim must reference source evidence)
4. Compute summary statistics (API call counts, coverage percentages)
5. Wrap validated evidence in the envelope schema
6. Write to `./agent-logs/<phase>/<run-id>.json`
7. Update `./agent-logs/index.json` with the new entry

**On failure:** Log a warning and return. Do not stop the calling agent's run. If `agent-log.jsonl` is missing, write a failed-status envelope so downstream agents know evidence was expected but unavailable.

<evidence_schema>
## Evidence Record Types

The source agent writes `$RUN_DIR/agent-log.jsonl` — one JSON line per evidence event. Each line is a tagged union with a `type` field.

### Record Types

#### 1. `api_call` — AWS API Call Record

Logged immediately after every AWS CLI/API call returns.

```json
{
  "type": "api_call",
  "id": "ev-001",
  "timestamp": "ISO8601",
  "service": "iam",
  "action": "ListUsers",
  "parameters": {"MaxItems": 100},
  "response_status": "success | access_denied | error",
  "response_summary": "Returned 12 users",
  "duration_ms": 340
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | Always `"api_call"` |
| id | string | yes | Sequential evidence ID: `ev-NNN` |
| timestamp | string | yes | ISO8601 when the call completed |
| service | string | yes | AWS service name (lowercase) |
| action | string | yes | API action name (PascalCase) |
| parameters | object | yes | Request parameters (redact secrets) |
| response_status | string | yes | One of: `success`, `access_denied`, `error` |
| response_summary | string | yes | One-line summary of what was returned |
| duration_ms | number | no | Round-trip time in milliseconds |

#### 2. `policy_eval` — IAM Policy Evaluation Record

Logged when evaluating effective permissions for a principal.

```json
{
  "type": "policy_eval",
  "id": "ev-002",
  "timestamp": "ISO8601",
  "principal_arn": "arn:aws:iam::123456789012:user/alice",
  "action_tested": "iam:CreatePolicyVersion",
  "evaluation_chain": {
    "identity_policy": "allow",
    "resource_policy": "no_policy",
    "permissions_boundary": "allow",
    "scp": "allow",
    "rcp": "no_policy",
    "session_policy": "no_policy",
    "effective": "allow"
  },
  "source_evidence_ids": ["ev-001"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | Always `"policy_eval"` |
| id | string | yes | Sequential evidence ID: `ev-NNN` |
| timestamp | string | yes | ISO8601 |
| principal_arn | string | yes | ARN of the principal being evaluated |
| action_tested | string | yes | IAM action being tested |
| evaluation_chain | object | yes | 7-step evaluation: identity_policy, resource_policy, permissions_boundary, scp, rcp, session_policy, effective |
| source_evidence_ids | string[] | yes | IDs of api_call records that provided the policy data |

Each step in `evaluation_chain` is one of: `allow`, `deny`, `implicit_deny`, `no_policy`, `not_evaluated`.

#### 3. `claim` — Assertion Record

Logged when the agent asserts a finding, attack path step, or conclusion.

```json
{
  "type": "claim",
  "id": "claim-ap-001",
  "timestamp": "ISO8601",
  "statement": "User alice can escalate to admin via iam:CreatePolicyVersion",
  "classification": "guaranteed",
  "confidence_pct": 95,
  "confidence_reasoning": "Direct policy attachment confirmed via ListAttachedUserPolicies; no boundary or SCP restrictions observed",
  "gating_conditions": [],
  "source_evidence_ids": ["ev-001", "ev-002"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | Always `"claim"` |
| id | string | yes | Claim ID: `claim-{type}-{seq}` (e.g., `claim-ap-001` for attack path, `claim-perm-001` for permission) |
| timestamp | string | yes | ISO8601 |
| statement | string | yes | Human-readable assertion |
| classification | string | yes | One of: `guaranteed`, `conditional`, `speculative` |
| confidence_pct | number | yes | 0-100 confidence percentage |
| confidence_reasoning | string | yes | Why this confidence level — must be non-empty |
| gating_conditions | string[] | yes | Conditions that must hold for this claim. Empty for guaranteed claims. Must have ≥1 entry for conditional claims. |
| source_evidence_ids | string[] | yes | IDs of evidence records supporting this claim. Must have ≥1 entry. |

#### 4. `coverage_check` — Enumeration Coverage Record

Logged at the end of each enumeration module to document what was and was not checked.

```json
{
  "type": "coverage_check",
  "id": "ev-048",
  "timestamp": "ISO8601",
  "scope_area": "iam_users",
  "checked": ["ListUsers", "ListAttachedUserPolicies", "ListUserPolicies", "ListMFADevices"],
  "not_checked": ["GetLoginProfile"],
  "not_checked_reason": "AccessDenied on iam:GetLoginProfile for 3 users",
  "coverage_pct": 80
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| type | string | yes | Always `"coverage_check"` |
| id | string | yes | Sequential evidence ID: `ev-NNN` |
| timestamp | string | yes | ISO8601 |
| scope_area | string | yes | What was being enumerated (e.g., `iam_users`, `s3_buckets`, `kms_keys`) |
| checked | string[] | yes | API actions that were successfully called |
| not_checked | string[] | yes | API actions that were skipped or failed |
| not_checked_reason | string | yes | Why items in not_checked were skipped |
| coverage_pct | number | yes | Percentage of planned checks that succeeded (0-100) |

</evidence_schema>

<evidence_envelope>
## Evidence Envelope Schema

The output file `./agent-logs/<phase>/<run-id>.json` contains the validated, structured evidence envelope.

```json
{
  "version": "1.0.0",
  "phase": "audit",
  "run_id": "audit-20260301-143022-all",
  "timestamp": "ISO8601 — when evidence indexing completed",
  "source_run_dir": "./audit/audit-20260301-143022-all/",
  "data_file": "./data/audit/audit-20260301-143022-all.json",
  "status": "complete | partial | failed",
  "depends_on": [],
  "provenance": {
    "total_api_calls": 47,
    "successful_api_calls": 44,
    "access_denied_calls": 3,
    "errored_calls": 0,
    "services_queried": ["iam", "sts", "s3"],
    "enumeration_start": "ISO8601 — earliest api_call timestamp",
    "enumeration_end": "ISO8601 — latest api_call timestamp"
  },
  "claims": [
    {
      "id": "claim-ap-001",
      "statement": "string",
      "classification": "guaranteed | conditional | speculative",
      "confidence_pct": 95,
      "confidence_reasoning": "string",
      "gating_conditions": [],
      "source_evidence_ids": ["ev-001", "ev-002"]
    }
  ],
  "coverage": {
    "overall_pct": 85,
    "by_area": [
      {
        "scope_area": "iam_users",
        "checked": ["ListUsers", "ListAttachedUserPolicies"],
        "not_checked": ["GetLoginProfile"],
        "not_checked_reason": "AccessDenied",
        "coverage_pct": 80
      }
    ]
  },
  "api_log": [
    {
      "id": "ev-001",
      "timestamp": "ISO8601",
      "service": "iam",
      "action": "ListUsers",
      "response_status": "success",
      "response_summary": "Returned 12 users",
      "duration_ms": 340
    }
  ],
  "policy_evaluations": [
    {
      "id": "ev-002",
      "principal_arn": "string",
      "action_tested": "string",
      "evaluation_chain": {},
      "source_evidence_ids": ["ev-001"]
    }
  ]
}
```

### Envelope Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| version | string | yes | Schema version — always `"1.0.0"` |
| phase | string | yes | One of: `audit`, `defend`, `exploit` |
| run_id | string | yes | Unique run identifier from the run directory name |
| timestamp | string | yes | ISO8601 when evidence indexing completed |
| source_run_dir | string | yes | Path to the original run directory |
| data_file | string | yes | Path to the corresponding Phase 1 normalized JSON |
| status | string | yes | One of: `complete`, `partial`, `failed` |
| depends_on | string[] | yes | Run IDs of upstream runs this evidence depends on |
| provenance | object | yes | Summary statistics of API calls made |
| claims | array | yes | Validated claim records |
| coverage | object | yes | Coverage summary across all modules |
| api_log | array | yes | Filtered API call records (parameters omitted for size) |
| policy_evaluations | array | yes | Policy evaluation records |

### Status Field

- `complete` — agent-log.jsonl found, parsed, all validations passed
- `partial` — agent-log.jsonl found but some records failed validation; valid records included
- `failed` — agent-log.jsonl not found or entirely unparseable; envelope contains empty arrays
</evidence_envelope>

<evidence_normalization_protocol>
## Evidence Normalization Protocol — Dispatch

When invoked, the calling agent provides two values:

- **PHASE**: one of `audit`, `defend`, `exploit` (investigate does not call this middleware — it writes agent-log.jsonl directly)
- **RUN_DIR**: path to the run directory containing raw artifacts

### Dispatch

1. Ensure `./agent-logs/<PHASE>/` directory exists:
   ```bash
   mkdir -p "./agent-logs/$PHASE"
   ```

2. Extract the RUN_ID from the RUN_DIR path:
   ```bash
   RUN_ID=$(basename "$RUN_DIR")
   ```

3. Determine the corresponding data file path:
   ```
   DATA_FILE="./data/$PHASE/$RUN_ID.json"
   ```

4. Read `$RUN_DIR/agent-log.jsonl`:
   - If the file exists, parse each line as JSON
   - If the file does not exist, set status to `failed` and write a minimal envelope

5. Classify each record by `type` field into four buckets:
   - `api_call` records → api_log
   - `policy_eval` records → policy_evaluations
   - `claim` records → claims
   - `coverage_check` records → coverage

6. Run validation (see `<validation>`)

7. Compute provenance summary from api_call records

8. Compute overall coverage from coverage_check records

9. Resolve cross-run dependencies (see `<cross_run_linking>`)

10. Assemble the evidence envelope and write to `./agent-logs/<PHASE>/<RUN_ID>.json`

11. Update `./agent-logs/index.json` per `<evidence_index_management>`
</evidence_normalization_protocol>

<validation>
## Validation Rules

After parsing all records, validate the following constraints. Records that fail validation are logged as warnings and excluded from the envelope. If more than 50% of records fail validation, set status to `partial`. (Note: the 10% threshold in Parse Failure applies to JSON parse errors specifically — malformed lines are a more severe signal than individual claim validation failures, so the threshold is lower.)

### Claim Validation

For every `claim` record:

1. **Source evidence required:** `source_evidence_ids` must contain at least one ID that matches an `api_call`, `policy_eval`, or another `claim` record in the same JSONL file. Exception: IDs in `<run-id>:<evidence-id>` format are cross-run references — validate these against `./agent-logs/index.json` instead of the local JSONL.
   - Violation: `"Warning: claim {id} has no valid source_evidence_ids — excluding"`

2. **Conditional claims need gating conditions:** If `classification` is `"conditional"`, `gating_conditions` must contain at least one non-empty string.
   - Violation: `"Warning: conditional claim {id} has no gating_conditions — downgrading to speculative"`

3. **Confidence reasoning required:** `confidence_reasoning` must be a non-empty string.
   - Violation: `"Warning: claim {id} has empty confidence_reasoning — excluding"`

4. **Confidence range:** `confidence_pct` must be between 0 and 100 inclusive.
   - Violation: `"Warning: claim {id} has confidence_pct out of range — clamping to [0, 100]"`

### API Call Validation

For every `api_call` record:

1. **Required fields present:** `service`, `action`, `response_status` must be non-empty strings.
   - Violation: `"Warning: api_call {id} missing required field — excluding"`

2. **Valid response_status:** Must be one of `success`, `access_denied`, `error`.
   - Violation: `"Warning: api_call {id} has invalid response_status '{value}' — defaulting to 'error'"`

### Policy Evaluation Validation

For every `policy_eval` record:

1. **Evaluation chain complete:** `evaluation_chain` must contain all 7 keys: `identity_policy`, `resource_policy`, `permissions_boundary`, `scp`, `rcp`, `session_policy`, `effective`.
   - Violation: `"Warning: policy_eval {id} has incomplete evaluation_chain — excluding"`

2. **Valid chain values:** Each chain step must be one of: `allow`, `deny`, `implicit_deny`, `no_policy`, `not_evaluated`.
   - Violation: `"Warning: policy_eval {id} has invalid chain value '{value}' — defaulting to 'not_evaluated'"`

### Coverage Check Validation

For every `coverage_check` record:

1. **Coverage percentage range:** `coverage_pct` must be between 0 and 100 inclusive.
   - Violation: `"Warning: coverage_check {id} has coverage_pct out of range — clamping to [0, 100]"`

2. **Non-empty scope_area:** `scope_area` must be a non-empty string.
   - Violation: `"Warning: coverage_check {id} has empty scope_area — excluding"`

3. **Duplicate scope_area detection:** If multiple `coverage_check` records share the same `scope_area`, keep only the one with the latest timestamp. Log: `"Warning: duplicate coverage_check for scope_area '{area}' — keeping latest (id: {id})"`
</validation>

<cross_run_linking>
## Cross-Run Linking

Some evidence records may reference upstream runs (e.g., exploit referencing audit data, defend referencing audit runs).

### Detection

When parsing `agent-log.jsonl`, look for:
1. Claim records whose `source_evidence_ids` contain references in the format `<run-id>:<evidence-id>` (cross-run reference)

Note: Cross-run dependencies are inferred from `<run-id>:<evidence-id>` references in `source_evidence_ids`. There is no separate `depends_on` record type — dependencies are extracted from claim references during validation.

### Validation

For each cross-run reference:

1. Check if `./agent-logs/index.json` exists
2. Look up the referenced `run_id` in the index
3. If found, add the `run_id` to the envelope's `depends_on` array
4. If not found, log: `"Warning: cross-run reference to {run_id} not found in evidence index — dependency not validated"`

### Populate depends_on

The `depends_on` array in the envelope contains validated upstream run IDs. This allows downstream agents to:
- Trace the full provenance chain
- Determine if upstream data is stale
- Understand which audit run informed which exploit run
</cross_run_linking>

<evidence_index_management>
## Index Management — ./agent-logs/index.json

After every successful evidence indexing, update the evidence run index.

### Read or Initialize

```bash
# Ensure ./agent-logs/ exists
mkdir -p ./evidence
```

If `./agent-logs/index.json` exists, read it. Otherwise, initialize:

```json
{
  "version": "1.0.0",
  "updated": "ISO8601",
  "runs": []
}
```

### Append Entry

Add a new entry to the `runs` array:

```json
{
  "run_id": "string",
  "phase": "string",
  "timestamp": "ISO8601",
  "status": "complete | partial | failed",
  "account_id": "<from source run envelope or 'unknown'>",
  "evidence_file": "./agent-logs/<PHASE>/<RUN_ID>.json",
  "data_file": "./data/<PHASE>/<RUN_ID>.json",
  "source_run_dir": "string",
  "depends_on": [],
  "summary": {
    "total_api_calls": 0,
    "successful_api_calls": 0,
    "access_denied_calls": 0,
    "total_claims": 0,
    "guaranteed_claims": 0,
    "conditional_claims": 0,
    "overall_coverage_pct": 0,
    "services_queried": []
  }
}
```

### Deduplication

Before appending, check if a run with the same `run_id` already exists in the `runs` array. If so, replace it (re-indexing overwrites).

### Write

Update the `updated` timestamp and write `./agent-logs/index.json` with pretty-printed JSON (2-space indent).
</evidence_index_management>

<evidence_error_handling>
## Phase 2 Error Handling

Evidence indexing is a best-effort middleware layer. Failures must never block the calling agent.

### agent-log.jsonl Not Found

If `$RUN_DIR/agent-log.jsonl` does not exist:
- Log: `"Warning: agent-log.jsonl not found in <RUN_DIR> — writing failed-status envelope"`
- Write a minimal envelope with status `"failed"` and empty arrays for claims, api_log, policy_evaluations, and coverage
- Still update the index so downstream agents know evidence was expected but unavailable

### Parse Failure

If a JSON line in agent-log.jsonl is not valid JSON:
- Log: `"Warning: invalid JSON at line N in agent-log.jsonl — skipping"`
- Continue parsing remaining lines
- Set status to `partial` if more than 10% of lines fail

### Write Failure

If unable to write to `./agent-logs/`:
- Log: `"Error: cannot write to ./agent-logs/<PHASE>/<RUN_ID>.json — <error>"`
- Return without updating the index

### Index Corruption

If `./agent-logs/index.json` exists but is not valid JSON:
- Log: `"Warning: evidence index.json is corrupted — reinitializing"`
- Back up the corrupted file to `./agent-logs/index.json.bak`
- Reinitialize with a fresh index containing only the current entry

### General Rule

On any unhandled error: log the full error, set status to `failed`, and return. The calling agent's raw artifacts and Phase 1 data normalization are the fallback — evidence indexing is a provenance layer, not a gating requirement.
</evidence_error_handling>

<evidence_schema_reference>
## Schema Reference — Phase 2 Complete Type Definitions

### Evidence Envelope

All evidence files share this top-level structure:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| version | string | yes | Schema version — always "1.0.0" |
| phase | string | yes | One of: audit, defend, exploit |
| run_id | string | yes | Unique run identifier from the run directory name |
| timestamp | string | yes | ISO8601 of evidence indexing |
| source_run_dir | string | yes | Path to the original run directory |
| data_file | string | yes | Path to the corresponding Phase 1 normalized JSON |
| status | string | yes | One of: complete, partial, failed |
| depends_on | string[] | yes | Upstream run IDs this evidence depends on |
| provenance | object | yes | API call summary statistics |
| claims | array | yes | Validated claim records |
| coverage | object | yes | Coverage summary |
| api_log | array | yes | API call records (parameters omitted) |
| policy_evaluations | array | yes | Policy evaluation records |

### Index Entry

Each entry in `./agent-logs/index.json` `runs` array:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| run_id | string | yes | Matches envelope run_id |
| phase | string | yes | Matches envelope phase |
| timestamp | string | yes | ISO8601 of evidence indexing |
| status | string | yes | Matches envelope status |
| account_id | string | yes | AWS account ID or "unknown" |
| evidence_file | string | yes | Relative path to the evidence JSON file |
| data_file | string | yes | Relative path to the Phase 1 normalized JSON file |
| source_run_dir | string | yes | Path to the original run directory |
| depends_on | string[] | yes | Upstream run IDs |
| summary | object | yes | Quick-lookup statistics |

### Directory Layout

```
./agent-logs/
  index.json                                    # Evidence run registry
  audit/
    audit-20260301-143022-all.json              # One file per audit run
    audit-20260301-150510-user-alice.json
  defend/
    defend-20260301-160000.json                 # One file per defend run
  exploit/
    exploit-20260301-170000-user-alice.json     # One file per exploit run
  investigate/
    investigate-20260301-180000.json            # One file per investigate run
```

### Data Hierarchy for Downstream Agents

When a downstream agent needs to consume upstream output, prefer data sources in this order:

1. `./agent-logs/` — Highest fidelity. Claim-level provenance, coverage manifests, policy evaluation chains. Use when you need to understand WHY a claim was made and what supports it.
2. `./data/` — Structured report data. Summaries, graph structures, attack path lists. Use when you need WHAT was found but don't need provenance.
3. `$RUN_DIR/` — Raw artifacts. Markdown reports, results.json, raw JSON. Fallback when normalized data is unavailable. Requires regex parsing.
</evidence_schema_reference>
</phase_2_evidence>
