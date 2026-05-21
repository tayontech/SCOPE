# observations.md Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement cross-run environmental learning by defining the observations.md format, creating a template, and adding read/write instructions to the 4 boundary agents.

**Architecture:** One new template file (`config/observations.example.md`) plus targeted insertions into 4 agent markdown files. Each agent gets a read block (early in its flow) and a write block (at completion). All edits are markdown — no code changes.

**Tech Stack:** Markdown agent instructions

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `config/observations.example.md` | Create | Format template committed to repo |
| `agents/scope-audit.md` | Modify | Read after Gate 1, write after results export |
| `agents/scope-exploit.md` | Modify | Read after Gate 1, write after Gate 4 |
| `agents/scope-defend.md` | Modify | Read after intake, write after Wave 2 |
| `agents/scope-hunt.md` | Modify | Read after entry point detection, write at end |

---

### Task 1: Create observations.example.md template

**Files:**
- Create: `config/observations.example.md`

- [ ] **Step 1: Create the template file**

Create `config/observations.example.md` with this content:

```markdown
# SCOPE Environment Observations

## Org-Wide Patterns
<!-- Patterns observed across 2+ accounts. Promote here only after seeing in multiple accounts. -->

## Account: REPLACE_WITH_ACCOUNT_ID
### Naming & Structure
### Recurring Gaps
### Known-Good Trusts

## Investigation Baselines
<!-- Hunt-specific: principal behavior baselines, known FP patterns -->

## Deployed Controls
<!-- Defend-specific: SCPs/detections deployed, effectiveness notes -->
```

- [ ] **Step 2: Verify the file exists**

Run: `cat config/observations.example.md | head -5`
Expected: First line is `# SCOPE Environment Observations`

- [ ] **Step 3: Verify observations.md is gitignored**

Run: `grep 'observations.md' .gitignore`
Expected: `config/observations.md` appears (already gitignored)

- [ ] **Step 4: Commit**

```bash
git add config/observations.example.md
git commit -m "feat: add observations.example.md format template for environmental learning"
```

---

### Task 2: Add read/write to scope-audit.md

**Files:**
- Modify: `agents/scope-audit.md`

- [ ] **Step 1: Read the file and locate Gate 1 closing tag**

Open `agents/scope-audit.md`. Find the line `</gate_1_credentials>`. The read instruction goes immediately after this closing tag, before the blank line and `<gate_2_batch_approval>`.

- [ ] **Step 2: Insert read instruction after Gate 1**

After the `</gate_1_credentials>` line, insert:

```markdown

**Load environment observations:** Read `config/observations.md` if it exists. Note account-specific patterns and org-wide observations for this account. Use these to contextualize findings during the run — flag when new findings match or contradict prior observations. Do not treat observations as ground truth (the environment may have changed since the last run).

```

- [ ] **Step 3: Locate the results export closing tag**

Find the line `</results_export>`. The write instruction goes immediately before this closing tag.

- [ ] **Step 4: Insert write instruction before results export close**

Before the `</results_export>` line, insert:

```markdown

**Update environment observations:** Before finishing, append up to 5 concise observations to `config/observations.md`. If the file does not exist, create it using the structure from `config/observations.example.md`. Write to the `## Account: {ACCOUNT_ID}` section (create it if missing, with subsections: Naming & Structure, Recurring Gaps, Known-Good Trusts). Promote a pattern to `## Org-Wide Patterns` only if observed in 2+ accounts across runs. Prefix each entry with today's date (YYYY-MM-DD). Never delete or overwrite existing entries.

Focus on: naming conventions, role structure patterns, service usage patterns, severity trends vs prior observations, new finding categories not previously observed.

```

- [ ] **Step 5: Verify both insertions**

Run: `grep -n 'environment observations' agents/scope-audit.md`
Expected: Two matches — one for "Load environment observations" and one for "Update environment observations"

- [ ] **Step 6: Commit**

```bash
git add agents/scope-audit.md
git commit -m "feat: add observations.md read/write to audit orchestrator"
```

---

### Task 3: Add read/write to scope-exploit.md

**Files:**
- Modify: `agents/scope-exploit.md`

- [ ] **Step 1: Read the file and locate Gate 1 section end**

Open `agents/scope-exploit.md`. Find the `---` separator line that comes after the Gate 1 display block (after "Credential failure:" remediation) and before `### Gate 2 — Permission Discovery`.

- [ ] **Step 2: Insert read instruction between Gate 1 and Gate 2**

After the `---` separator following Gate 1 and the blank line, before `### Gate 2`, insert:

```markdown
**Load environment observations:** Read `config/observations.md` if it exists. Use account-specific patterns to contextualize discovered permissions — note when capabilities match or deviate from prior baselines. Do not treat observations as ground truth.

```

- [ ] **Step 3: Locate the Gate 4 proceed/skip block end**

Find the line `**"proceed":** Write all mandatory artifacts (see `<mandatory_outputs>`).` followed by a blank line and `---` separator, before `<results_json>`.

- [ ] **Step 4: Insert write instruction after Gate 4 options**

After the `---` separator following the Gate 4 proceed/skip options and the blank line, before `<results_json>`, insert:

```markdown
**Update environment observations:** Before finishing, append up to 5 concise observations to `config/observations.md` under the appropriate account section. If the file does not exist, create it using the structure from `config/observations.example.md`. Focus on: permission baselines for this principal type, novel escalation paths not in techniques.json, persistence mechanisms discovered. Prefix each entry with today's date (YYYY-MM-DD). Never delete or overwrite existing entries.

```

- [ ] **Step 5: Verify both insertions**

Run: `grep -n 'environment observations' agents/scope-exploit.md`
Expected: Two matches — one "Load" and one "Update"

- [ ] **Step 6: Commit**

```bash
git add agents/scope-exploit.md
git commit -m "feat: add observations.md read/write to exploit agent"
```

---

### Task 4: Add read/write to scope-defend.md

**Files:**
- Modify: `agents/scope-defend.md`

- [ ] **Step 1: Read the file and locate intake protocol closing tag**

Open `agents/scope-defend.md`. Find the line `</intake_protocol>`. The read instruction goes after this tag, before `<wave1_dispatch>`.

- [ ] **Step 2: Insert read instruction after intake**

After `</intake_protocol>` and the blank line, before `<wave1_dispatch>`, insert:

```markdown
**Load environment observations:** Read `config/observations.md` if it exists. Use to understand: what controls are already deployed in this account, what remediation has been attempted before, detection FP rates. Avoid re-recommending controls already noted as deployed.

```

- [ ] **Step 3: Locate Wave 2 validate closing tag**

Find the line `</wave2_validate>`. The write instruction goes after this tag, before `<results_assembly>`.

- [ ] **Step 4: Insert write instruction after Wave 2**

After `</wave2_validate>` and the blank line, before `<results_assembly>`, insert:

```markdown
**Update environment observations:** Before finishing, append up to 5 concise observations to `config/observations.md` under the appropriate account section and `## Deployed Controls`. If the file does not exist, create it using the structure from `config/observations.example.md`. Focus on: new controls deployed, remediation blockers, detection effectiveness. Prefix each entry with today's date (YYYY-MM-DD). Never delete or overwrite existing entries.

```

- [ ] **Step 5: Verify both insertions**

Run: `grep -n 'environment observations' agents/scope-defend.md`
Expected: Two matches — one "Load" and one "Update"

- [ ] **Step 6: Commit**

```bash
git add agents/scope-defend.md
git commit -m "feat: add observations.md read/write to defend orchestrator"
```

---

### Task 5: Add read/write to scope-hunt.md

**Files:**
- Modify: `agents/scope-hunt.md`

- [ ] **Step 1: Read the file and locate entry point detection closing tag**

Open `agents/scope-hunt.md`. Find the line `</entry_point_detection>`. The read instruction goes after this tag and the blank line, before `<hypothesis_engine>`.

- [ ] **Step 2: Insert read instruction before hypothesis engine**

After `</entry_point_detection>` and the blank line, before `<hypothesis_engine>`, insert:

```markdown
**Load environment observations:** Read `config/observations.md` if it exists. Use investigation baselines and account patterns to contextualize the current alert — recognize repeat actors, known-good trusts, and prior false positive patterns. Do not treat observations as ground truth.

```

- [ ] **Step 3: Locate the end of the file (success_criteria closing tag)**

Find the line `</success_criteria>` at the end of the file. The write instruction goes before this closing tag.

- [ ] **Step 4: Insert write instruction before success_criteria close**

Before the `</success_criteria>` line, insert:

```markdown

**Update environment observations:** Before finishing, append up to 5 concise observations to `config/observations.md` under `## Investigation Baselines` and the appropriate account section. If the file does not exist, create it using the structure from `config/observations.example.md`. Focus on: principal behavior baselines, new IOCs, detection blind spots, false positive patterns. Prefix each entry with today's date (YYYY-MM-DD). Never delete or overwrite existing entries.
```

- [ ] **Step 5: Verify both insertions**

Run: `grep -n 'environment observations' agents/scope-hunt.md`
Expected: Two matches — one "Load" and one "Update"

- [ ] **Step 6: Commit**

```bash
git add agents/scope-hunt.md
git commit -m "feat: add observations.md read/write to hunt agent"
```

---

### Task 6: End-to-end verification

**Files:**
- Read: `config/observations.example.md`
- Read: `agents/scope-audit.md`
- Read: `agents/scope-exploit.md`
- Read: `agents/scope-defend.md`
- Read: `agents/scope-hunt.md`

- [ ] **Step 1: Verify template exists**

Run: `test -f config/observations.example.md && echo "EXISTS" || echo "MISSING"`
Expected: `EXISTS`

- [ ] **Step 2: Verify all 4 agents have both read and write instructions**

Run: `grep -l 'Load environment observations' agents/scope-audit.md agents/scope-exploit.md agents/scope-defend.md agents/scope-hunt.md | wc -l`
Expected: `4`

Run: `grep -l 'Update environment observations' agents/scope-audit.md agents/scope-exploit.md agents/scope-defend.md agents/scope-hunt.md | wc -l`
Expected: `4`

- [ ] **Step 3: Verify all write instructions reference the example template**

Run: `grep -c 'observations.example.md' agents/scope-audit.md agents/scope-exploit.md agents/scope-defend.md agents/scope-hunt.md`
Expected: Each file shows `1` (one reference to the template in the write instruction)

- [ ] **Step 4: Verify observations.md is gitignored but example is not**

Run: `grep 'observations' .gitignore`
Expected: `config/observations.md` listed

Run: `grep 'observations.example' .gitignore`
Expected: No match (the example template is tracked)

- [ ] **Step 5: Commit (no-op if no fixes needed)**

If any checks failed and fixes were applied:

```bash
git add config/observations.example.md agents/scope-audit.md agents/scope-exploit.md agents/scope-defend.md agents/scope-hunt.md
git commit -m "fix: resolve observations.md integration gaps"
```

If all checks passed, skip this commit.
