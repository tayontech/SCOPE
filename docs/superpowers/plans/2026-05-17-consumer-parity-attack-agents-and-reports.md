# Consumer Parity for Coverage Data Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach the four attack-domain agents, the audit orchestrator's findings report, and the defend report to interpret the `<field>_status` annotations and `coverage[]` arrays produced by Plan B's s3 pilot — so the new data isn't just produced but is actually used by downstream consumers.

**Architecture:** Three prompt edits to three files. The four attack-domain agents share `agents/shared/attack-domain-template.md` — one edit propagates to all of them. `agents/scope-audit.md` controls findings.md generation; we add a "Coverage Gaps" requirement to Layer 1. `agents/scope-defend.md` controls executive-summary.md generation; we add a data caveats paragraph. Verification is a single grep-based contract test that pins key instruction phrases so future prompt edits don't accidentally regress the coverage-handling guidance.

**Tech Stack:** Markdown agent prompts. Node test runner for grep-based contract tests.

---

## Source spec

`docs/superpowers/specs/2026-05-17-module-envelope-coverage-design.md` — see "Per-finding annotation" for `<field>_status` semantics, "AccessDenied disposition" for what optional/required/primary denials mean, "Migration order" step 4 ("Tighten consumers") for the consumer-side rollout.

Plan B (commits `baf6907` → `caacb6d`) produced the data this plan consumes:
- s3 bucket findings now have six `<field>_status` annotations (`policy_status`, `acl_status`, `public_access_block_status`, `versioning_status`, `encryption_status`, `logging_status`), each one of `'present' | 'absent' | 'access_denied' | 'error'`.
- s3 envelope now has `coverage[]` (per-check counters and status) and `errors[]` (flat list of failed operations) top-level arrays.
- Crashed scripts produce `status: 'error'` envelopes with `findings: []`, `coverage: []`, and `errors: [{operation, code, message}]`.

## Important context

- **Project root:** `/Users/tayvionp/claude-code/SCOPE`. Branch: `feature/v1.14-sdk-architecture`. Do not switch branches.
- **Plan B's last commit:** `caacb6d`. Plan C builds on top.
- **Pilot scope:** s3 is the only module currently emitting the new fields. Other 15 modules emit envelopes without `coverage`/`errors`. The instructions must work for both: read coverage when present, fall back to existing behavior when absent.
- **Shared template:** `agents/shared/attack-domain-template.md` is `@include`d by all four domain agents (`scope-attack-{identity,compute,data,network}.md`). One edit propagates to all four.
- **Test pattern:** custom Node runner, style of `test/lib-policy-parser.test.js`. New test file for this plan: `test/agent-prompt-coverage-instructions.test.js`. It greps the agent prompt files for key instruction phrases — this is the contract that prevents future prompt edits from regressing.
- **Deferred from this plan:**
  - Synthesizer (`agents/subagents/scope-attack-synthesizer.md`) — currently does not read module envelopes (only domain output files). Wiring it to do so is bigger than Plan C's scope. Deferred to Plan D's per-module rollout phase.
  - Dashboard (`dashboard/src/App.jsx`) — UI for coverage indicators. Spec explicitly defers ("can defer UI until schema is stable").

## File structure

**Files modified:**
- `agents/shared/attack-domain-template.md` — add a "Interpreting Coverage Data" section between "Reasoning Approach" and "scope-research Dispatch". Adds parsing instructions for `<field>_status` and `coverage[]` data, plus guidance on annotating findings when underlying data was access-denied.
- `agents/scope-audit.md` — extend the `<findings_md>` block to require a "Coverage Gaps" subsection in Layer 1 of findings.md, populated from per-module `status` and `coverage[]` data.
- `agents/scope-defend.md` — add a "Data Caveats" requirement to executive-summary.md generation, surfacing the audit run's coverage gaps so the operator knows whether recommendations may be incomplete.

**Files created:**
- `test/agent-prompt-coverage-instructions.test.js` — grep-based contract tests that pin the new instructions in place.

**Files NOT modified:**
- `agents/subagents/scope-attack-{identity,compute,data,network}.md` — these `@include` the shared template, so they inherit the new instructions without their own edits. Touching them is scope creep.
- `agents/subagents/scope-attack-synthesizer.md` — deferred (see above).
- `dashboard/src/App.jsx` — deferred (see above).
- Any `scripts/` file — Plan C is consumer-side only. Producers (s3.js, base-enum.js, coverage.js) ship as-is from Plan B.

---

## Task 1: Teach domain agents to interpret coverage data

**Files:**
- Modify: `agents/shared/attack-domain-template.md` (add a new section)
- Create: `test/agent-prompt-coverage-instructions.test.js`

**Why this is one task:** the shared template is `@include`d by all four domain agents. A single addition to this file is the highest-leverage change in Plan C. The new test file pins multiple instruction phrases at once — having all the assertions in one file keeps the contract auditable.

- [ ] **Step 1: Write the failing contract test**

Create `test/agent-prompt-coverage-instructions.test.js`:

```js
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  PASS: ${name}`);
    passed++;
  } catch (err) {
    console.error(`  FAIL: ${name}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

function readPrompt(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf-8');
}

function assertContains(haystack, needle, label) {
  assert.ok(
    haystack.includes(needle),
    `${label} should contain "${needle}" but does not`
  );
}

// --- attack-domain-template.md: coverage data interpretation ---

const tmpl = readPrompt('agents/shared/attack-domain-template.md');

test('attack-domain-template explains <field>_status semantics', () => {
  assertContains(tmpl, '<field>_status', 'attack-domain-template');
  assertContains(tmpl, "'present'", 'attack-domain-template');
  assertContains(tmpl, "'absent'", 'attack-domain-template');
  assertContains(tmpl, "'access_denied'", 'attack-domain-template');
});

test('attack-domain-template distinguishes access_denied from absent', () => {
  // The two states are operationally different — "we couldn't read it" vs "it doesn't exist".
  // The prompt must make this distinction explicit.
  assertContains(tmpl, 'access_denied', 'attack-domain-template');
  assert.ok(
    /access_denied[\s\S]{0,500}absent|absent[\s\S]{0,500}access_denied/.test(tmpl),
    'attack-domain-template should discuss access_denied and absent in proximity (within ~500 chars)'
  );
});

test('attack-domain-template instructs reading coverage[] and module status', () => {
  assertContains(tmpl, 'coverage[]', 'attack-domain-template');
  assertContains(tmpl, 'module-level', 'attack-domain-template');
});

test('attack-domain-template tells agents to caveat findings on access-denied data', () => {
  // Findings that depend on access-denied underlying data should be flagged
  // so the operator knows the analysis has reduced confidence on those paths.
  assert.ok(
    /caveat|reduced confidence|incomplete|may be missing/i.test(tmpl),
    'attack-domain-template should instruct caveating findings when underlying data was access-denied'
  );
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tayvionp/claude-code/SCOPE && node test/agent-prompt-coverage-instructions.test.js`

Expected: all four tests FAIL — the template doesn't yet mention `<field>_status`, the four status values, `coverage[]`, "module-level", or any caveating language. Exit code 1.

If any test PASSES, the template already has some of this content — read it before editing, you may need to integrate rather than insert.

- [ ] **Step 3: Edit `agents/shared/attack-domain-template.md`**

Open the file. The current structure ends "Reasoning Approach" around line 30 with a `## scope-research Dispatch` heading. Insert a new section BETWEEN them.

Find this block (around line 30-32):

```markdown
Use `config/techniques.json` as a starting point for known attack patterns — but it is NOT a boundary. If you discover a permission combination that creates an attack path not in the catalogue, reason about it and include it.

## scope-research Dispatch
```

Replace with:

```markdown
Use `config/techniques.json` as a starting point for known attack patterns — but it is NOT a boundary. If you discover a permission combination that creates an attack path not in the catalogue, reason about it and include it.

## Interpreting Coverage Data

Module JSONs may include a top-level `status` (`'complete'` / `'partial'` / `'error'`), a `coverage[]` array of per-check entries, and an `errors[]` array of failed operations. Findings inside the module may carry `<field>_status` annotations on individual resources (s3 is the pilot; other modules will add these as they migrate). When present, this data tells you *what was actually checked* — not just what was returned.

**Per-finding `<field>_status` semantics:**

| Value | Meaning | How to treat it |
|---|---|---|
| `'present'` | The API returned data for this field. The corresponding data field (e.g., `policy`) is populated. | Trust the data. Normal analysis. |
| `'absent'` | The API was called successfully and confirmed the field does not exist (e.g., `NoSuchBucketPolicy` for an s3 bucket with no policy). | Trust the absence. "No policy" is a real finding, not a gap. |
| `'access_denied'` | The API call returned AccessDenied. We do NOT know if the field exists. | Do NOT treat as `'absent'`. The bucket *might* have a policy that grants public access — we just can't see it. |
| `'error'` | The API call returned an unexpected error. | Treat as a coverage gap. Note in your reasoning. |

The `'access_denied'` vs `'absent'` distinction matters operationally. "Bucket has no policy" is a benign data point; "we couldn't read the bucket policy" is a blind spot that could hide a critical-severity public-exposure finding.

**Module-level `status` and `coverage[]`:**

- `status: 'complete'` — primary enumeration succeeded; all required checks ran without failures.
- `status: 'partial'` — some required per-resource checks failed (typically access denials on specific resources). Coverage entries with `failed > 0` show which checks. The data is real but incomplete.
- `status: 'error'` — primary list operation failed (e.g., `ListBuckets` denied). Module produced no findings. The script could not do its job; treat the module as unanalyzed.

Read `coverage[]` to understand which specific checks degraded. Each entry has `check`, `scope`, `status`, counts (`succeeded`/`failed`/`skipped`), and `reasons` grouped by error code.

**Caveating findings:**

When a path you generate depends on a field whose `<field>_status` is `'access_denied'` or `'error'`, OR when the module-level `status` is `'partial'` or `'error'`, the finding has reduced confidence — you derived it from incomplete data. Add a caveat to the finding's `description` or `research_context` explaining what data was missing. Example:

> "Path may be incomplete: bucket_policy_status was 'access_denied' on 3 of 12 buckets. If any of those buckets has a public policy, the actual exposure is larger than what this finding describes."

Do NOT downgrade severity just because data was access-denied — the *known* path is still the severity it is. Surface the coverage gap, don't hide it.

## scope-research Dispatch
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node test/agent-prompt-coverage-instructions.test.js`

Expected: all four tests PASS. `4 passed, 0 failed`. Exit code 0.

Run the full suite: `node test/run-all.js`. Expected: green across all 25 test files (24 from Plan B + 1 new).

- [ ] **Step 5: Commit**

```bash
git add agents/shared/attack-domain-template.md test/agent-prompt-coverage-instructions.test.js

git commit -m "feat(agents): teach attack-domain agents to interpret coverage data

The four attack-domain agents (identity, compute, data, network) all
@include agents/shared/attack-domain-template.md. Adding a new
'Interpreting Coverage Data' section to the template propagates the
guidance to all four agents in one edit.

The section covers:

- Per-finding <field>_status semantics (present / absent / access_denied
  / error) with a table of how to treat each. The access_denied vs
  absent distinction is called out explicitly — operationally different.
- Module-level status and coverage[] interpretation: complete / partial
  / error semantics and how to read coverage entries.
- Caveating findings derived from incomplete data: surface the gap in
  the finding's description, do NOT downgrade severity (the known path
  is still its severity).

s3 is the only module emitting these fields today (Plan B pilot).
Instructions are written to work when the fields are present or absent
— other modules' envelopes without coverage/errors continue to be
parsed by existing prompts.

New test/agent-prompt-coverage-instructions.test.js pins the key
instruction phrases via grep so future prompt edits don't accidentally
regress the coverage-handling guidance. Four tests assert the template
mentions <field>_status values, the access_denied vs absent
distinction, coverage[] / module-level status, and caveating language."
```

---

## Task 2: Audit orchestrator's findings.md surfaces coverage gaps

**Files:**
- Modify: `agents/scope-audit.md` (extend the `<findings_md>` section)
- Modify: `test/agent-prompt-coverage-instructions.test.js` (add audit tests)

**Why this matters:** the findings.md report is the operator's primary deliverable. Layer 1 currently mentions "partial modules" in passing. With Plan B's coverage data, we can surface concrete gaps — "12 buckets had bucket_policy access-denied" — instead of a vague "partial modules" hedge.

- [ ] **Step 1: Extend the contract test**

Open `test/agent-prompt-coverage-instructions.test.js`. After the existing four tests (and before the final `console.log` summary), add a new section:

```js
// --- scope-audit.md: findings.md coverage gaps requirement ---

const auditPrompt = readPrompt('agents/scope-audit.md');

test('scope-audit findings.md requires a Coverage Gaps subsection', () => {
  assertContains(auditPrompt, 'Coverage Gaps', 'scope-audit findings_md');
});

test('scope-audit findings.md surfaces module status and coverage entries', () => {
  // The prompt must instruct reading module-level status AND per-check coverage,
  // not just listing module names.
  assertContains(auditPrompt, 'coverage[]', 'scope-audit');
  assertContains(auditPrompt, 'access_denied', 'scope-audit');
});

test('scope-audit findings.md distinguishes partial from error modules', () => {
  // Operator needs to know which modules degraded (partial) vs which produced
  // no data at all (error). They're operationally different.
  assert.ok(
    /partial[\s\S]{0,500}error|error[\s\S]{0,500}partial/.test(auditPrompt),
    'scope-audit findings_md should discuss partial and error module status in proximity'
  );
});
```

- [ ] **Step 2: Run test to verify the new cases fail**

Run: `node test/agent-prompt-coverage-instructions.test.js`

Expected: the original four tests still PASS (Task 1's work). The three new tests FAIL (audit prompt doesn't yet have "Coverage Gaps" subsection, `coverage[]` parsing instructions, or explicit partial-vs-error guidance). Total: 4 passed, 3 failed. Exit code 1.

- [ ] **Step 3: Edit `agents/scope-audit.md` `<findings_md>` block**

Open the file. Find the `<findings_md>` block (around lines 299-315):

```markdown
<findings_md>
## Findings Report

After Gate 4 approval, write `$RUN_DIR/findings.md` — always generated, even with 0 findings.

**0-finding handling:** If attack_paths is empty and no findings across modules, generate a clean-run report: RISK SUMMARY with "low", services analyzed, modules with partial data, and recommended next action to review coverage gaps.

**Three-layer structure (when findings exist):**

1. **Layer 1 — Risk Summary:** Caller ARN, account ID, overall risk rating (highest severity), up to 5 bullet findings (one sentence each with real ARN/name), biggest concern, services analyzed, partial modules.

2. **Layer 2 — Findings by Severity** (`--all`/multi-service: grouped by critical/high/medium/low) **or Effective Permissions** (single ARN: Action | Resource | Effect | Source Policy table).

3. **Layer 3 — Attack Path Narratives:** Ordered by exploitability DESC. Each path includes: name, severity, exploitability, confidence (what was/wasn't verified), MITRE TTPs, narrative paragraph with real policy details, concrete exploit CLI steps (reference only), Splunk detection sketch, remediation actions.

**Rules:** Use REAL ARNs and resource names throughout — never placeholders. End with RECOMMENDED NEXT ACTION referencing defend artifacts and available follow-up commands (`/scope:exploit`, `/scope:audit`, dashboard link).
</findings_md>
```

Replace with:

```markdown
<findings_md>
## Findings Report

After Gate 4 approval, write `$RUN_DIR/findings.md` — always generated, even with 0 findings.

**0-finding handling:** If attack_paths is empty and no findings across modules, generate a clean-run report: RISK SUMMARY with "low", services analyzed, modules with partial data, and recommended next action to review coverage gaps.

**Three-layer structure (when findings exist):**

1. **Layer 1 — Risk Summary:** Caller ARN, account ID, overall risk rating (highest severity), up to 5 bullet findings (one sentence each with real ARN/name), biggest concern, services analyzed, **Coverage Gaps subsection** (see below).

2. **Layer 2 — Findings by Severity** (`--all`/multi-service: grouped by critical/high/medium/low) **or Effective Permissions** (single ARN: Action | Resource | Effect | Source Policy table).

3. **Layer 3 — Attack Path Narratives:** Ordered by exploitability DESC. Each path includes: name, severity, exploitability, confidence (what was/wasn't verified), MITRE TTPs, narrative paragraph with real policy details, concrete exploit CLI steps (reference only), Splunk detection sketch, remediation actions.

### Coverage Gaps subsection

Read every module envelope at `$RUN_DIR/<module>.json`. For each module, inspect its top-level `status` and (when present) its `coverage[]` array. Surface gaps in Layer 1 so the operator knows the analysis is bounded by what was readable, not just by what existed.

For each module where `status === 'partial'`: list the specific checks that degraded. Use the coverage entries — each has `check`, `failed`, `skipped`, and `reasons[]` (with error codes and counts). Example: `s3.bucket_policy: 3 of 12 buckets returned AccessDenied — exposure on those buckets is unknown`.

For each module where `status === 'error'`: list the module as completely unanalyzed. The primary list operation failed; no findings exist for that service. Example: `iam.list_users: AccessDenied — IAM principals were not enumerated; identity findings reflect only what other modules discovered indirectly`.

Distinguish `partial` from `error` clearly: partial means *some* data was collected, error means *no* data was collected. They have different operational meaning — partial findings are real-but-incomplete; error findings are absent entirely.

Also surface per-finding `<field>_status` annotations when relevant: if a bucket finding has `policy_status: 'access_denied'`, the bucket may have a public policy that the audit didn't see. Cross-reference this against the findings actually reported — if any reported finding's confidence is reduced by access denials on related fields, mention it.

If all modules have `status === 'complete'` and no per-finding `<field>_status` is `'access_denied'` or `'error'`, write "No coverage gaps — all enumeration succeeded." Don't fabricate gaps to fill the section.

**Rules:** Use REAL ARNs and resource names throughout — never placeholders. End with RECOMMENDED NEXT ACTION referencing defend artifacts and available follow-up commands (`/scope:exploit`, `/scope:audit`, dashboard link).
</findings_md>
```

- [ ] **Step 4: Run test to verify the new tests pass**

Run: `node test/agent-prompt-coverage-instructions.test.js`

Expected: all 7 tests pass. `7 passed, 0 failed`. Exit code 0.

Run the full suite: `node test/run-all.js`. Expected: green.

- [ ] **Step 5: Commit**

```bash
git add agents/scope-audit.md test/agent-prompt-coverage-instructions.test.js

git commit -m "feat(audit): require Coverage Gaps subsection in findings.md Layer 1

Plan B's coverage[] arrays and <field>_status annotations now flow into
the findings report. The previous Layer 1 mentioned 'partial modules'
in passing — vague. The new Coverage Gaps subsection makes this concrete.

For each module: read \$RUN_DIR/<module>.json's top-level status and
coverage[]. Surface specifics, not summaries:
- partial modules: list which checks degraded with counts and error codes
- error modules: list as completely unanalyzed (primary list failed)
- per-finding <field>_status: when access_denied or error, note the
  affected fields against reported findings to flag reduced confidence

The partial-vs-error distinction is explicit — operator needs to know
which modules degraded vs which produced no data.

If all modules complete and no per-finding statuses are denied or
errored, write 'No coverage gaps — all enumeration succeeded.' Don't
fabricate gaps to fill space.

Three new contract tests in test/agent-prompt-coverage-instructions.test.js
pin the requirement: Coverage Gaps subsection present, coverage[]
parsing instructed, partial vs error distinction maintained."
```

---

## Task 3: Defend executive summary surfaces audit coverage gaps

**Files:**
- Modify: `agents/scope-defend.md` (extend executive-summary.md generation)
- Modify: `test/agent-prompt-coverage-instructions.test.js` (add defend tests)

**Why this matters:** defend reads audit's results.json and produces remediation/guardrail recommendations. If the audit had blind spots (modules with `partial` or `error` status), the defend recommendations may not cover the unseen surface. Operators need this caveat in the executive summary so they don't trust the recommendations as exhaustive.

**Insertion point (verified):** `agents/scope-defend.md:549-560` contains the `### Step 6: Generate executive-summary.md` section. Lines 553-558 are the bullet list of what goes into the summary. The new audit-coverage-caveats bullet inserts into this list.

- [ ] **Step 1: Extend the contract test**

Open `test/agent-prompt-coverage-instructions.test.js`. After the audit tests, add:

```js
// --- scope-defend.md: data caveats from audit coverage ---

const defendPrompt = readPrompt('agents/scope-defend.md');

test('scope-defend executive summary mentions audit coverage gaps', () => {
  assertContains(defendPrompt, 'Coverage', 'scope-defend executive-summary');
  // Should reference the audit's coverage data, not just defend's own validation
  assert.ok(
    /audit[\s\S]{0,500}coverage|coverage[\s\S]{0,500}audit/i.test(defendPrompt),
    'scope-defend should discuss audit coverage in the context of defend output'
  );
});

test('scope-defend explains recommendations may be incomplete on partial audit data', () => {
  // Operator must understand that if audit had blind spots, defend recommendations
  // don't cover the unseen surface. This is the operationally critical caveat.
  assert.ok(
    /incomplete|may not cover|blind spot|unseen|unanalyzed/i.test(defendPrompt),
    'scope-defend should explicitly note that recommendations may be incomplete when audit coverage was partial'
  );
});
```

- [ ] **Step 2: Run test to verify the new tests fail**

Run: `node test/agent-prompt-coverage-instructions.test.js`

Expected: 7 prior tests still PASS. 2 new tests FAIL — defend prompt doesn't yet discuss audit coverage in its executive summary. Total: 7 passed, 2 failed. Exit code 1.

- [ ] **Step 3: Edit `agents/scope-defend.md` executive summary section**

Open `agents/scope-defend.md`. The current bullet list at lines 553-558 reads:

```markdown
- Account ID and audit run context
- Overall risk posture (severity from audit results)
- Key findings count: attack paths analyzed, guardrails generated, detections created, policies replaced, remediation items
- Top 3-5 most critical attack paths (name + one-sentence impact)
- Defensive coverage summary: what percentage of attack paths have at least one control (guardrail, detection, or remediation)
- Validation status and any outstanding warnings
```

Replace with:

```markdown
- Account ID and audit run context
- Overall risk posture (severity from audit results)
- **Audit Coverage Caveats** (place after risk posture, before key findings): Read the module envelopes from the consumed audit run(s) listed in `audit_runs_analyzed`. For each module with `status === 'partial'` or `status === 'error'`, note the gap. Recommendations in this defend run cover only the attack surface that the audit actually saw — if `s3.list_buckets` returned AccessDenied during the audit, no s3 guardrails or detections were generated because no buckets were enumerated. State this explicitly so the operator knows recommendations may be incomplete and may not cover unseen surface area. If all consumed audit runs had `status === 'complete'` end-to-end with no per-finding `<field>_status` denials, write "Audit coverage was complete — no blind spots identified" instead. Don't fabricate gaps to fill space.
- Key findings count: attack paths analyzed, guardrails generated, detections created, policies replaced, remediation items
- Top 3-5 most critical attack paths (name + one-sentence impact)
- Defensive coverage summary: what percentage of attack paths have at least one control (guardrail, detection, or remediation)
- Validation status and any outstanding warnings
```

The Audit Coverage Caveats bullet lands as the third item in the list (after risk posture, before key findings) so it shapes how the rest of the summary is read. The bullet itself is multi-sentence by design — the operator needs the specifics, not a vague "coverage may be incomplete."

- [ ] **Step 4: Run test to verify the new tests pass**

Run: `node test/agent-prompt-coverage-instructions.test.js`

Expected: all 9 tests pass. `9 passed, 0 failed`. Exit code 0.

Run the full suite: `node test/run-all.js`. Expected: green.

- [ ] **Step 5: Commit**

```bash
git add agents/scope-defend.md test/agent-prompt-coverage-instructions.test.js

git commit -m "feat(defend): surface audit coverage gaps in executive summary

When defend generates executive-summary.md, it now reads the audit
run(s) it consumed and surfaces any modules with status partial or
error. Recommendations in defend's output only cover the attack
surface that the audit actually saw — if s3.list_buckets was
AccessDenied, no s3 guardrails are generated because no buckets were
enumerated. The operator needs to know this caveat exists.

The caveat lands near the top of executive-summary.md (after overall
risk rating, before remediation table) so it shapes how the rest of
the document is read.

When the consumed audit runs are all status=complete with no
per-finding <field>_status denials, the section reads 'Audit
coverage was complete — no blind spots identified' instead. Don't
fabricate gaps to fill space.

Two new contract tests in test/agent-prompt-coverage-instructions.test.js
pin the requirement: audit coverage discussed in defend output context;
explicit 'recommendations may be incomplete' language present."
```

---

## Done Criteria

- `test/agent-prompt-coverage-instructions.test.js` — 9 tests pass (4 attack-domain template, 3 audit findings.md, 2 defend executive summary).
- `node test/run-all.js` — green across all test files.
- Three commits on `feature/v1.14-sdk-architecture`, one per task.
- No `agents/subagents/scope-attack-{identity,compute,data,network}.md` were touched directly — they inherit via `@include`.
- No `agents/subagents/scope-attack-synthesizer.md` changes — deferred.
- No `dashboard/src/App.jsx` changes — deferred.
- No `scripts/` changes — Plan C is consumer-side only.

## Out of Scope

- **Synthesizer integration.** `scope-attack-synthesizer.md` currently reads only the 4 domain output files, not the 16 module envelopes. Wiring it to read envelopes for coverage data would be a larger change involving schema decisions about where coverage_summary lives in `results.json`. Defer to Plan D's per-module rollout when the schema picture is clearer.
- **Dashboard UI.** Spec defers explicitly until schema is stable. With only s3 emitting coverage today, there's not enough data variety to design the UI against. Revisit after Plan D lands a few more modules.
- **Per-attack-domain agent edits.** The shared template `@include` propagates this plan's changes to all four domain agents. Individual agent edits aren't needed for Plan C and would be scope creep.
- **Other enum scripts.** Plan D covers their migration to CoverageTracker. Until then, modules without coverage[] continue to work — the prompts in this plan are written to gracefully handle missing fields.
- **Update to `findings.md`'s actual output for past audit runs.** This plan changes the prompt; existing findings.md files in run directories on operators' machines are not rewritten retroactively.
