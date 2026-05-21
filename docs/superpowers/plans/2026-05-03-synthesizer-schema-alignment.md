# Synthesizer Schema Alignment & Chain Discovery — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix schema mismatches between attack path agent output and audit.schema.json, improve deduplication, and add graph-based N-hop chain discovery.

**Architecture:** Two agent instruction files change. The domain sub-agent template (`attack-domain-template.md`) gets field renames and additions to its output contract. The synthesizer (`scope-attack-synthesizer.md`) gets top-level metadata, updated merge logic, fixed dedup keys, and a new graph-assisted chain discovery section.

**Tech Stack:** Markdown agent instructions (no code — these are LLM prompt contracts, not source code)

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `agents/shared/attack-domain-template.md` | Modify | Domain sub-agent output contract — path object fields |
| `agents/subagents/scope-attack-synthesizer.md` | Modify | Synthesizer output contract, dedup logic, chain discovery |

---

### Task 1: Rename `mitre` to `mitre_techniques` in domain template

**Files:**
- Modify: `agents/shared/attack-domain-template.md:63`

- [ ] **Step 1: Read the current output contract**

Open `agents/shared/attack-domain-template.md` and locate the JSON example in the Output Contract section (line 50-71). The path object contains `"mitre": ["T1078.004"]`.

- [ ] **Step 2: Rename the field**

In the JSON example block inside the Output Contract section, replace:

```json
      "mitre": ["T1078.004"],
```

with:

```json
      "mitre_techniques": ["T1078.004"],
```

This is the only occurrence of `"mitre"` as a field name in this file. The field value format (string array of MITRE ATT&CK technique IDs) stays the same.

- [ ] **Step 3: Verify no other references to the old field name**

Run: `grep -n '"mitre"' agents/shared/attack-domain-template.md`
Expected: No matches (the field was renamed)

Run: `grep -n 'mitre_techniques' agents/shared/attack-domain-template.md`
Expected: One match at the JSON example line

- [ ] **Step 4: Commit**

```bash
git add agents/shared/attack-domain-template.md
git commit -m "fix: rename mitre to mitre_techniques in domain template output contract"
```

---

### Task 2: Add new fields to domain template output contract

**Files:**
- Modify: `agents/shared/attack-domain-template.md:50-71`

- [ ] **Step 1: Read the current path object in the Output Contract**

The JSON example currently has these fields per path: `name`, `category`, `severity`, `source`, `target`, `steps`, `affected_resources`, `mitre_techniques` (renamed in Task 1), `research_context`, `cross_domain_refs`.

- [ ] **Step 2: Add the four new fields to the path object example**

In the JSON example block, add the four new fields after `affected_resources` and before `mitre_techniques`. The updated path object should read:

```json
    {
      "name": "Environment-specific description of the attack path",
      "description": "One-sentence summary of what this path enables an attacker to do",
      "category": "privilege_escalation|trust_misconfiguration|data_exposure|lateral_movement|persistence|post_exploitation|network_exposure|excessive_permission",
      "severity": "critical|high|medium|low",
      "source": "node ID from graph (e.g., role:my-role, lambda:my-func)",
      "target": "node ID of what attacker reaches",
      "steps": ["Step 1: specific CLI or action", "Step 2: ..."],
      "affected_resources": ["arn:aws:..."],
      "mitre_techniques": ["T1078.004"],
      "exploitability": "proven|likely|theoretical",
      "detection_opportunities": ["iam:PassRole", "lambda:CreateFunction"],
      "remediation": "One-line fix recommendation",
      "research_context": "Real-world context from scope-research, or null",
      "cross_domain_refs": ["role:some-role", "arn:aws:s3:::some-bucket"]
    }
```

- [ ] **Step 3: Add field descriptions after the JSON example**

After the existing **Severity rules:** section (line 73-78) and before the **Partial Failure** section (line 81), add:

```markdown
**New field guidance:**
- `description`: One sentence. State what the attacker gains. "Developer can escalate to admin via PassRole to Lambda." Not a repeat of `name`.
- `exploitability`: `"proven"` = documented technique with known tooling. `"likely"` = permissions allow it, standard technique. `"theoretical"` = requires specific conditions or undocumented chaining.
- `detection_opportunities`: CloudTrail event names (service:Action format) that would reveal this path in logs. Include every action in the steps that generates a management event.
- `remediation`: Single actionable fix. "Add resource condition to restrict iam:PassRole target roles." Not "review permissions" or "follow least privilege."
```

- [ ] **Step 4: Verify the file is well-formed**

Run: `grep -c 'mitre_techniques\|description\|exploitability\|detection_opportunities\|remediation' agents/shared/attack-domain-template.md`
Expected: At least 5 matches (one per field in the JSON example, plus guidance lines)

- [ ] **Step 5: Commit**

```bash
git add agents/shared/attack-domain-template.md
git commit -m "feat: add description, exploitability, detection_opportunities, remediation to domain template"
```

---

### Task 3: Add top-level metadata to synthesizer output

**Files:**
- Modify: `agents/subagents/scope-attack-synthesizer.md:56-89`

- [ ] **Step 1: Read the current Output section**

The current output JSON at lines 58-88 starts with `"summary": {...}` as the top-level object. The schema requires `account_id`, `source`, `region`, `timestamp` at the top level.

- [ ] **Step 2: Add top-level metadata fields to the output JSON example**

Replace the output JSON example (lines 58-88) with:

```json
{
  "account_id": "$ACCOUNT_ID",
  "source": "audit",
  "region": "$REGIONS (multi-region if >1, otherwise single region)",
  "timestamp": "ISO 8601 timestamp at synthesis time",
  "summary": {
    "severity": "critical",
    "total_paths": 15,
    "critical_count": 3,
    "high_count": 5,
    "medium_count": 4,
    "low_count": 3,
    "domains_analyzed": ["identity", "compute", "data", "network"],
    "domains_failed": [],
    "cross_domain_chains": 4
  },
  "attack_paths": [
    {
      "name": "...",
      "description": "...",
      "category": "...",
      "severity": "...",
      "source": "...",
      "target": "...",
      "steps": ["..."],
      "affected_resources": ["..."],
      "mitre_techniques": ["..."],
      "exploitability": "...",
      "detection_opportunities": ["..."],
      "remediation": "...",
      "research_context": "...",
      "domains": ["compute", "identity"],
      "is_cross_domain": true
    }
  ],
  "graph": {
    "nodes": [],
    "edges": []
  },
  "trust_relationships": [],
  "principals": []
}
```

Key changes from the current version:
- Added `account_id`, `source`, `region`, `timestamp` at top level
- Renamed `mitre` to `mitre_techniques` in the attack_paths example
- Added `description`, `exploitability`, `detection_opportunities`, `remediation` to the attack_paths example
- Added `graph` object (schema requires it — synthesizer should copy graph.json content here)

- [ ] **Step 3: Add metadata instructions after the JSON example**

After the existing note about `domains` and `is_cross_domain` (line 91), add:

```markdown
**Top-level metadata:**
- `account_id`: Use `$ACCOUNT_ID` from orchestrator input. 12-digit string.
- `source`: Always `"audit"`.
- `region`: If audit covered one region, use that region string. If multiple, use `"multi-region"`.
- `timestamp`: ISO 8601 at synthesis time (e.g., `"2026-05-03T14:30:00Z"`).
- `graph`: Copy `graph.json` content (nodes and edges arrays) into this field.
```

- [ ] **Step 4: Verify schema-required fields are present**

Run: `grep -c 'account_id\|"source"\|"region"\|timestamp\|"graph"' agents/subagents/scope-attack-synthesizer.md`
Expected: At least 5 matches

- [ ] **Step 5: Commit**

```bash
git add agents/subagents/scope-attack-synthesizer.md
git commit -m "feat: add schema-required top-level metadata to synthesizer output"
```

---

### Task 4: Fix deduplication logic

**Files:**
- Modify: `agents/subagents/scope-attack-synthesizer.md:49-52`

- [ ] **Step 1: Read the current Deduplication section**

Lines 49-52 contain three rules. Rule 1: "If two paths share the same `source` AND `target`, merge into one (keep the richer description)".

- [ ] **Step 2: Replace the Deduplication section**

Replace the entire Deduplication section (lines 47-52) with:

```markdown
## Deduplication

Multiple domains may report the same finding from different angles. Deduplicate by:
1. If two paths share the same `source`, `target`, AND `category`, merge into one. Keep the entry with more `steps`. If step count is equal, prefer the entry with non-null `research_context`. If still tied, keep the first encountered.
2. If a cross-domain chain subsumes a single-domain path (same source, same target, superset of steps), keep only the chain
3. Preserve unique paths from each domain even if they don't connect cross-domain

The `category` field distinguishes fundamentally different attack vectors. A `privilege_escalation` path and a `data_exposure` path between the same two nodes are distinct findings — both survive dedup.
```

- [ ] **Step 3: Verify the change**

Run: `grep -n 'category' agents/subagents/scope-attack-synthesizer.md`
Expected: At least one match in the Deduplication section mentioning `category` as part of the merge key

- [ ] **Step 4: Commit**

```bash
git add agents/subagents/scope-attack-synthesizer.md
git commit -m "fix: dedup on [source, target, category] to preserve distinct attack vectors"
```

---

### Task 5: Add merge logic for new fields

**Files:**
- Modify: `agents/subagents/scope-attack-synthesizer.md`

- [ ] **Step 1: Read the Cross-Domain Chain Discovery section**

Lines 33-45 describe how to connect paths. The section ends with "Also check `exposed_principals` and `exposed_resources` across domains for quick cross-references." It does not describe how to merge the new fields when combining domain paths into chains.

- [ ] **Step 2: Add field merge rules**

After the existing cross-domain chain discovery section (after line 45) and before the Deduplication section, add:

```markdown
## Field Merge Rules for Cross-Domain Chains

When combining domain paths into a cross-domain chain:
- `name`: Describe the full chain end-to-end (e.g., "Unauthenticated API to admin role assumption via Lambda execution role")
- `description`: Summarize the chain's end-to-end impact in one sentence
- `category`: Use the terminal path's category (the final impact determines the category)
- `severity`: Use the terminal path's severity (what the attacker ultimately reaches determines severity)
- `steps`: Concatenate steps from all constituent paths in order. Insert intermediate steps for graph edge traversals (e.g., "Assume role:X via trust relationship")
- `affected_resources`: Union of all constituent paths' affected resources
- `mitre_techniques`: Union of all constituent paths' techniques (deduplicate)
- `exploitability`: Use the lowest exploitability across constituent paths (chain is only as exploitable as its weakest link: proven > likely > theoretical)
- `detection_opportunities`: Union of all constituent paths' events (deduplicate). Add events for intermediate edge traversals (e.g., `sts:AssumeRole` for trust edges)
- `remediation`: Use the terminal path's remediation (breaking the final link breaks the chain)
- `research_context`: Concatenate non-null research contexts from constituent paths, separated by " | "
- `domains`: Union of all constituent paths' domains
- `is_cross_domain`: `true`
```

- [ ] **Step 3: Verify the section was added**

Run: `grep -n 'Field Merge Rules' agents/subagents/scope-attack-synthesizer.md`
Expected: One match at the new section heading

- [ ] **Step 4: Commit**

```bash
git add agents/subagents/scope-attack-synthesizer.md
git commit -m "feat: add field merge rules for cross-domain chain assembly"
```

---

### Task 6: Add graph-assisted chain discovery

**Files:**
- Modify: `agents/subagents/scope-attack-synthesizer.md`

- [ ] **Step 1: Identify insertion point**

The new section goes after the Field Merge Rules (Task 5) and before the Deduplication section.

- [ ] **Step 2: Add the Graph-Assisted Chain Discovery section**

Insert the following section:

```markdown
## Graph-Assisted Chain Discovery

After the cross-domain-ref matching pass, run a second pass using `graph.json` edges to find chains that explicit `cross_domain_refs` missed.

**Algorithm:**

For each domain path whose `target` node is NOT the `source` of any already-connected path:

1. Look up the `target` node in `graph.json` edges (match on `source` field of edges)
2. Walk outbound edges of these types only: `trust`, `executes_as`, `invokes`, `authenticates_to`
3. At each reached node, check if it matches the `source` of any unconnected domain path from a DIFFERENT domain
4. If matched: link the paths into a chain using the Field Merge Rules above
5. If not matched at hop 1: walk one more hop from the intermediate node (same edge type filter)
6. Cap at 2 intermediate hops maximum (total chain: original path + up to 2 graph edges + destination path)

**Edge type semantics:**

| Edge Type | Traversal Meaning | Detection Event |
|-----------|-------------------|-----------------|
| `trust` | Principal can assume target role | `sts:AssumeRole` |
| `executes_as` | Compute resource runs as target role | (no distinct event — execution is implicit) |
| `invokes` | Gateway/trigger invokes compute | `lambda:Invoke` or API Gateway access log |
| `authenticates_to` | Identity provider authenticates to role | `sts:AssumeRoleWithWebIdentity` |

**Explosion guard:** Maximum 50 cross-domain chains total (from both passes combined). If the graph traversal produces more than 50 chains, keep the 50 highest-severity chains. Within the same severity, prefer chains with fewer hops (more exploitable). This prevents combinatorial blowup in heavily connected environments.

**Do NOT:**
- Traverse `membership` edges (group membership doesn't create attack chains)
- Traverse `service` edges (service principals are origin nodes, not traversal targets)
- Create chains that loop back to the same node
- Re-discover chains already found by the cross-domain-ref pass
```

- [ ] **Step 3: Verify the section was added**

Run: `grep -n 'Graph-Assisted Chain Discovery' agents/subagents/scope-attack-synthesizer.md`
Expected: One match at the new section heading

Run: `grep -n 'Explosion guard' agents/subagents/scope-attack-synthesizer.md`
Expected: One match

- [ ] **Step 4: Commit**

```bash
git add agents/subagents/scope-attack-synthesizer.md
git commit -m "feat: add graph-assisted N-hop chain discovery to synthesizer"
```

---

### Task 7: Verify schema alignment end-to-end

**Files:**
- Read: `config/schemas/audit.schema.json`
- Read: `agents/shared/attack-domain-template.md`
- Read: `agents/subagents/scope-attack-synthesizer.md`

- [ ] **Step 1: Check all schema-required top-level fields exist in synthesizer output**

Run: `grep -E 'account_id|"source"|"region"|timestamp|summary|graph|attack_paths|principals|trust_relationships' agents/subagents/scope-attack-synthesizer.md`

Verify each of these schema-required fields appears in the synthesizer's output JSON example:
- `account_id` (string, 12-digit)
- `source` (const "audit")
- `region` (string)
- `timestamp` (date-time string)
- `summary` (object)
- `graph` (object with nodes/edges)
- `attack_paths` (array)
- `principals` (array)
- `trust_relationships` (array)

- [ ] **Step 2: Check attack_paths entry fields match schema**

The schema requires `name`, `severity`, `category` on each attack_paths entry. It also defines `description`, `exploitability`, `steps`, `mitre_techniques`, `detection_opportunities`, `remediation`, `affected_resources`.

Run: `grep -E 'mitre_techniques|description|exploitability|detection_opportunities|remediation' agents/subagents/scope-attack-synthesizer.md`

Verify all five field names appear in the synthesizer's attack_paths example object.

- [ ] **Step 3: Verify domain template uses matching field names**

Run: `grep -E 'mitre_techniques|description|exploitability|detection_opportunities|remediation' agents/shared/attack-domain-template.md`

Verify all five field names appear in the domain template's path object example.

- [ ] **Step 4: Confirm no old field name remains**

Run: `grep -n '"mitre"' agents/shared/attack-domain-template.md agents/subagents/scope-attack-synthesizer.md`
Expected: No matches (all renamed to `mitre_techniques`)

- [ ] **Step 5: Commit (no-op if no fixes needed)**

If any mismatches were found and fixed in steps 1-4:

```bash
git add agents/shared/attack-domain-template.md agents/subagents/scope-attack-synthesizer.md
git commit -m "fix: resolve remaining schema alignment gaps"
```

If all checks passed with no changes needed, skip this commit.
