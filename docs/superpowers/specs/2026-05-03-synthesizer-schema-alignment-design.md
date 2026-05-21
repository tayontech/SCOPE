# Synthesizer Schema Alignment & Chain Discovery

**Date:** 2026-05-03
**Scope:** Attack path synthesizer fixes, domain sub-agent output contract updates
**Approach:** Fix-in-place (Approach A) — update agent contracts to match existing schema

---

## Problem Statement

The parallel 4-domain attack path analysis (phases 81-84) is architecturally sound but has three correctness issues:

1. **Schema mismatches** between agent output and `config/schemas/audit.schema.json` — field names differ (`mitre` vs `mitre_techniques`), required metadata missing (`account_id`, `region`)
2. **Shallow chain discovery** — synthesizer connects cross-domain paths only via explicit `cross_domain_refs` pointers, missing 3+ hop chains where intermediate links exist in `graph.json` but weren't tagged by domain agents
3. **Lossy deduplication** — merging findings on `[source, target]` collapses distinct attack vectors between the same node pair

---

## Design

### 1. Schema Alignment

**Files changed:** `agents/shared/attack-domain-template.md`, `agents/subagents/scope-attack-synthesizer.md`
**Files unchanged:** `config/schemas/audit.schema.json` (already correct)

#### Domain sub-agent output contract (`attack-domain-template.md`)

Rename and add fields in the path object spec:

| Field | Current | New |
|-------|---------|-----|
| `mitre` | `["T1078.004"]` | Rename to `mitre_techniques` |
| `description` | absent | Add: one-sentence summary of the attack path |
| `exploitability` | absent | Add: `"proven"`, `"likely"`, or `"theoretical"` |
| `detection_opportunities` | absent | Add: string array of CloudTrail events that reveal this path |
| `remediation` | absent | Add: one-line fix recommendation |

Domain sub-agents already reason about all five of these during analysis. The fields formalize output they currently express only in prose.

Updated path object:

```json
{
  "name": "PassRole to Lambda for secret exfiltration",
  "description": "Developer can pass an admin role to a new Lambda function that reads production secrets",
  "category": "privilege_escalation",
  "severity": "critical",
  "source": "user:developer",
  "target": "data:secrets:prod-db-password",
  "steps": ["Step 1: ...", "Step 2: ..."],
  "affected_resources": ["arn:aws:lambda:..."],
  "mitre_techniques": ["T1078.004", "T1098"],
  "exploitability": "proven",
  "detection_opportunities": ["iam:PassRole", "lambda:CreateFunction", "secretsmanager:GetSecretValue"],
  "remediation": "Restrict iam:PassRole to specific role ARNs via resource condition",
  "research_context": "Real-world evidence or null",
  "cross_domain_refs": ["role:admin-role", "compute:lambda:exfil-fn"]
}
```

#### Synthesizer output contract (`scope-attack-synthesizer.md`)

Add top-level metadata to results output:

```json
{
  "account_id": "123456789012",
  "region": "multi-region",
  "timestamp": "2026-05-03T14:30:00Z",
  "source": "audit",
  "attack_paths": [...]
}
```

- `account_id`: passed from orchestrator via initial dispatch message (already available as `ACCOUNT_ID`)
- `region`: `"multi-region"` when audit covers multiple regions, otherwise the single region string
- `timestamp`: ISO 8601 at time of synthesis
- `source`: always `"audit"`

Carry all new domain path fields (`description`, `exploitability`, `detection_opportunities`, `remediation`, `mitre_techniques`) through merge logic unchanged. For cross-domain chains that combine multiple domain paths, concatenate `detection_opportunities` arrays (dedup), use the terminal path's `remediation`, and combine `mitre_techniques` from all constituent paths.

### 2. Deduplication Fix

**File changed:** `agents/subagents/scope-attack-synthesizer.md`

Replace dedup rule 1:

**Current:** Merge paths when `source` AND `target` match. Keep richer description.

**New:** Merge paths when `source` AND `target` AND `category` match. Keep richer description.

The `category` field distinguishes fundamentally different attack vectors between the same endpoints. A `privilege_escalation` path from `role:dev` to `data:s3:bucket` is a different finding than a `data_exposure` path between the same nodes.

Dedup rules after the fix:

1. **Same source, target, AND category:** merge, keep the entry with more `steps`. If step count is equal, prefer the entry with non-null `research_context`. If still tied, keep the first encountered
2. **Subsumption:** if a cross-domain chain fully contains a single-domain path (same source, same target, superset of steps), keep only the chain
3. **Domain preservation:** unique paths from each domain survive even if they don't connect cross-domain

### 3. Graph-Based N-Hop Chain Discovery

**File changed:** `agents/subagents/scope-attack-synthesizer.md`

Add a second-pass algorithm after the existing cross-domain-ref matching:

**Pass 1 (existing):** Connect domain paths via explicit `cross_domain_refs` pointers.

**Pass 2 (new — Graph-Assisted Chain Discovery):**

For each domain path whose `target` node is not the `source` of any other connected path:

1. Look up the `target` node in `graph.json` edges
2. Walk outbound edges of type: `trust`, `executes_as`, `invokes`, `authenticates_to`
3. At each intermediate node, check if it matches the `source` of any unconnected domain path from a different domain
4. If matched, link the paths into a chain
5. Cap intermediate hops at 2 (max chain length: original path + 2 edges + destination path = 4 segments)

**Edge type traversal rules:**

| Edge Type | Traversal Meaning |
|-----------|-------------------|
| `trust` | Principal can assume target role |
| `executes_as` | Compute resource runs as target role |
| `invokes` | Gateway/trigger invokes compute |
| `authenticates_to` | Identity provider authenticates to role |

**Chain assembly:**

- Combine steps from all constituent paths, inserting graph edge traversal as intermediate steps (e.g., "Assume role:X via trust relationship")
- Chain severity: inherited from terminal path's impact
- Chain `domains`: union of all constituent path domains
- Chain `mitre_techniques`: union of all constituent path techniques
- Chain `detection_opportunities`: union of all constituent path events plus events for intermediate edge traversals (e.g., `sts:AssumeRole` for trust edges)

**Explosion guard:** Maximum 50 chains per synthesis run. If graph traversal produces more, keep the 50 highest-severity chains. This prevents combinatorial blowup in heavily connected environments.

---

## Files Modified

| File | Change |
|------|--------|
| `agents/shared/attack-domain-template.md` | Rename `mitre` to `mitre_techniques`, add `description`, `exploitability`, `detection_opportunities`, `remediation` to path object |
| `agents/subagents/scope-attack-synthesizer.md` | Add top-level metadata, update merge logic for new fields, fix dedup key, add graph-assisted chain discovery |

## Files Not Modified

| File | Reason |
|------|--------|
| `config/schemas/audit.schema.json` | Already correct — agents are the ones out of alignment |
| `agents/subagents/scope-attack-{identity,compute,data,network}.md` | Use `@include attack-domain-template.md` — inherit the contract change |
| `bin/extract-graph.js` | graph.json structure is already sufficient for traversal |
| `agents/scope-audit.md` | Orchestrator dispatch unchanged — `ACCOUNT_ID` already passed to synthesizer |

## Success Criteria

1. Synthesizer output passes `config/schemas/audit.schema.json` validation (currently fails on `mitre` field name and missing metadata)
2. Domain sub-agent outputs include all five new fields
3. Dedup preserves distinct attack vectors between the same node pair when categories differ
4. Graph-assisted pass discovers at least one additional chain in test environments where cross-domain-ref matching alone misses it
5. Chain count capped at 50 per synthesis run
