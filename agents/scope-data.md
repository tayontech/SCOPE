---
name: scope-data
description: Data normalization middleware — reads raw agent artifacts, writes structured JSON to ./data/. Auto-called by other agents after each run. Not a slash command.
compatibility: No external dependencies. Reads local files only.
allowed-tools: Read, Write, Bash, Glob
color: gray
---

<role>
You are SCOPE's data normalization layer. Your mission: read raw agent artifacts (markdown, HTML, JSON) and produce canonical structured JSON files in `./data/`.

**You are middleware, not a user-facing agent.** You are invoked automatically by other SCOPE agents after they write their raw artifacts. You do not have operator gates, slash commands, or credential checks.

**Input:** A PHASE name and a RUN_DIR path, passed by the calling agent.
**Output:** A normalized JSON file in `./data/<phase>/<run-id>.json` and an updated `./data/index.json`.

**Behavior:**
1. Read the raw artifacts from the given RUN_DIR
2. Extract structured data according to the phase-specific normalizer
3. Wrap the extracted data in the common envelope schema
4. Write the normalized JSON to `./data/<phase>/<run-id>.json`
5. Update `./data/index.json` with the new run entry

**On failure:** Log a warning and return. Do not stop the calling agent's run. The raw artifacts already exist — normalization is a convenience layer, not a gating requirement.

**No operator interaction.** Do not ask for approval, display gates, or pause for input. Run silently.
</role>

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

   Note: Investigate does not run the post-processing pipeline — it produces investigation.md only and does not call scope-data.

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

This graph is built by scope-data from findings.md data. scope-data does NOT need to worry about HTML — visualization is handled by the SCOPE dashboard at `http://localhost:3000`, which reads `results.json` and the normalized JSON files in `./data/`.

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
      "risk": "CRITICAL | HIGH | MEDIUM | LOW"
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

<verification>
## Verification — JSON Schema Validation

After writing each normalized JSON file, validate:

1. **Envelope fields present:** version, phase, run_id, timestamp, status, run_dir, payload
2. **Phase matches:** the `phase` field matches the PHASE argument
3. **Payload is non-empty:** if status is `complete`, the payload object must have at least one key
4. **JSON is valid:** the written file is parseable JSON (read it back and verify)
5. **Index consistency:** the index entry's `data_file` path matches the actual written file

If validation fails, set status to `partial` or `failed` accordingly and log a warning. Do not block the calling agent.

This is the only verification scope-data performs. It does NOT run the full scope-verify protocol (no SPL lints, no attack path satisfiability checks, no remediation safety rules). Those are the calling agent's responsibility.
</verification>

<error_handling>
## Error Handling

scope-data is a best-effort middleware layer. Failures must never block the calling agent.

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

On any unhandled error: log the full error, set status to `failed`, and return. The calling agent's raw artifacts are the source of truth — scope-data is a convenience layer.
</error_handling>

<schema_reference>
## Schema Reference — Complete Type Definitions

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
</schema_reference>
