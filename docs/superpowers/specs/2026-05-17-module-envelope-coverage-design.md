# Module Envelope: Coverage & Errors Contract

**Date:** 2026-05-17
**Scope:** Phase B of the post-review remediation. Items 2/3/4/7 from the recommendations list.
**Status:** Draft — not yet planned with `superpowers:writing-plans`.

---

## Problem

Today's module output exposes only `status: 'complete' | 'partial' | 'error'`. Logs know what failed; the JSON does not. This forces operators and downstream agents to grep logs to answer basic questions:

- Did `s3.GetBucketPolicy` get denied, or does the bucket genuinely have no policy?
- When `iam.status === 'partial'`, which sub-check degraded — service-last-accessed timeout, or a real listing failure?
- When a script crashes mid-run, the run directory has no module JSON at all, only log lines.

Phase A (commit `8063a32`) tightened STS status semantics as a one-off. Phase B generalizes that pattern: every module emits structured coverage, every script always emits an envelope, and "access denied" stops looking like "absent."

---

## Goals

1. **Coverage transparency** — every module declares which checks ran, which were skipped, and why, in machine-readable form.
2. **Status discipline** — `complete` / `partial` / `error` mean the same thing across modules. Optional enrichment failures do not downgrade status.
3. **Machine-readable failures** — distinguish "no policy" from "access denied" in the data, not the log.
4. **Always-on envelope (after bootstrap)** — once CLI args are accepted and `runDir` is known, any runtime failure inside the enum produces an `error` envelope. Pre-bootstrap failures (missing `--run-dir`, unparseable CLI, unwritable directory) still fail loudly to stderr with non-zero exit — there's no envelope file to write because we don't know where to write it. This is the only "silent" path, and it's gated on arguments the operator controls.

Non-goals (deferred):
- IAM enrichment performance (Phase C — needs profiling).
- Migrating engagement reports or dashboard UI to display coverage data. Schema-first; UI catches up after.

---

## Schema Proposal

### Status rules (derived by `CoverageTracker`, shape-validated by `envelope.js`)

| Status | Meaning |
|---|---|
| `complete` | Primary enumeration succeeded. Optional enrichment may have skipped checks — surface those in `coverage[]`, not the status. |
| `partial` | Primary resources were discovered, but required detail/enrichment failed for some of them (e.g., `ListBuckets` succeeded, but >0 `GetBucketPolicy` calls returned an unexpected error). |
| `error` | Primary enumeration failed, or the script crashed before producing reliable output. `findings` may be empty. |

**Split of responsibility:**
- `CoverageTracker.deriveModuleStatus({ primaryChecks, requiredChecks })` owns the actual classification logic — it has the per-check counters and knows which checks were declared primary vs required vs optional. See *Coverage Helpers* below.
- `envelope.js` does *not* know what a "primary check" is. It only validates that `status` is a valid enum value and that the envelope shape (`coverage[]` entries well-formed, `errors[]` entries well-formed) matches the schema. Anything more would require duplicating per-module declarations into a generic library and would invite drift.

"Required" vs "optional" vs "primary" is a per-module declaration — modules know which checks are load-bearing for their purpose. Documented inline in each enum script.

### AccessDenied disposition (the only rule worth memorizing)

`AccessDenied` is the most common failure mode and the easiest place for "status discipline" to silently swallow a real blind spot. Fixed table:

| Failure shape | Module `status` | `coverage[]` entry |
|---|---|---|
| Optional check (e.g., `last_accessed` enrichment) + AccessDenied | `complete` | one entry with `status: "skipped"` |
| Required per-resource check (e.g., `GetBucketPolicy` per bucket) + AccessDenied | `partial` | one entry with `status: "partial"`, `failed > 0` |
| Primary list operation (e.g., `ListBuckets`, `ListRoles`) + AccessDenied | `error` | one entry with `scope: "module_wide"`, `status: "error"`, `succeeded: 0`, `failed: 1`. **Always emitted** — no findings, but `coverage[]` is never empty for a primary failure. |

The first row fixes STS over-flagging. The second row prevents S3/IAM/KMS blind spots from looking harmless. The third row keeps `error` reserved for "the module did not do its primary job" *and* makes that visible in the JSON — a crashed-or-denied module produces a non-empty coverage record explaining what failed, not just an `error` status with empty arrays.

Example module-wide entry for a primary failure:

```jsonc
{
  "check": "list_buckets",
  "scope": "module_wide",
  "status": "error",
  "succeeded": 0,
  "failed": 1,
  "skipped": 0,
  "reasons": [
    { "code": "AccessDeniedException", "count": 1, "sample_resource": null }
  ]
}
```

Each enum script declares its `PRIMARY_CHECKS`, `REQUIRED_CHECKS`, and (implicitly) optional checks near the top so the table is auditable per module:

```js
const PRIMARY_CHECKS = ['list_buckets'];                 // failure ⇒ status: error + module_wide coverage entry
const REQUIRED_CHECKS = ['bucket_policy', 'bucket_acl']; // per-resource failure ⇒ status: partial
// Everything else (e.g., 'last_accessed') is optional ⇒ status stays complete, coverage records skip
```

### New envelope fields

```jsonc
{
  "module": "s3",
  "account_id": "123456789012",
  "region": "us-east-1",
  "status": "complete",
  "timestamp": "2026-05-17T12:00:00Z",
  "findings": [...],

  // NEW
  "coverage": [
    {
      "check": "bucket_policy",
      "status": "complete | partial | skipped | error",
      "scope": "per_resource | module_wide",
      "succeeded": 12,
      "failed": 1,
      "skipped": 0,
      "reasons": [
        { "code": "AccessDeniedException", "count": 1, "sample_resource": "arn:aws:s3:::example" }
      ]
    }
  ],
  "errors": [
    { "operation": "GetBucketPolicy", "resource": "arn:aws:s3:::example", "code": "AccessDeniedException", "message": "..." }
  ]
}
```

### Coverage Helpers (single source of truth)

`coverage[]` and `errors[]` express the same underlying events at different granularities. Letting modules hand-maintain both invites drift. `scripts/lib/coverage.js` exposes a `CoverageTracker` class that updates both through one path:

```js
const tracker = new CoverageTracker();

// Record a successful check
tracker.record({ check: 'bucket_policy', resource: bucketArn, status: 'ok' });

// Record a failure — increments coverage[bucket_policy].failed AND pushes errors[]
tracker.record({
  check: 'bucket_policy',
  resource: bucketArn,
  status: 'failed',
  operation: 'GetBucketPolicy',
  errorCode: err.name,
  errorMessage: err.message,
});

// Record a deliberate skip (e.g. operator passed --skip-last-accessed)
tracker.record({ check: 'last_accessed', status: 'skipped', reason: 'cli_flag' });

// Module-wide failure (primary list operation denied) — special-case helper
tracker.recordModuleFailure({
  check: 'list_buckets',
  operation: 'ListBuckets',
  errorCode: err.name,
  errorMessage: err.message,
});

// At end of run:
const status = tracker.deriveModuleStatus({
  primaryChecks: PRIMARY_CHECKS,
  requiredChecks: REQUIRED_CHECKS,
});
const { coverage, errors } = tracker.toEnvelopeFields();
return createEnvelope({ module, account_id, region, status, findings, coverage, errors });
```

Rules enforced by the tracker:
- Every failed check writes to both arrays through the same call. Modules never push to `errors` directly.
- `coverage[].reasons[]` is reconstructed from the underlying error events on `toEnvelopeFields()` — not stored separately. No drift possible.
- The tracker owns `coverage[].status` derivation (from per-check counters) *and* module-level status derivation (from the primary/required/optional classification passed to `deriveModuleStatus()`). Modules pass in their classification arrays; the tracker applies the AccessDenied disposition table uniformly.
- `recordModuleFailure()` is the single way to produce the "primary list denied" entry from row 3 of the disposition table. It guarantees the `coverage[]` array is never empty when status is `error`.

**Where the line sits between tracker and envelope:**

| Concern | Owner |
|---|---|
| Counting per-check success/fail/skip | `CoverageTracker` |
| Deriving `coverage[].status` per entry | `CoverageTracker` |
| Deriving module-level `status` (`complete`/`partial`/`error`) | `CoverageTracker.deriveModuleStatus()` |
| Building `coverage[]` and `errors[]` arrays | `CoverageTracker.toEnvelopeFields()` |
| Validating envelope shape (required fields, enum values, types) | `envelope.js` |
| Persisting to `$RUN_DIR/{module}.json` | `envelope.js` (`writeEnvelope`) |

`envelope.js` never imports `CoverageTracker`. It rejects malformed input but doesn't recompute anything.

### Per-finding annotation

Replace silent "field absent" with explicit status:

```jsonc
{
  "resource_type": "s3_bucket",
  "resource_id": "example",
  "bucket_policy": null,
  "bucket_policy_status": "access_denied"   // NEW: "present" | "absent" | "access_denied" | "error"
}
```

Pattern applies to: `bucket_policy`, `bucket_acl`, `kms_key_policy`, `sns_policy`, `sqs_policy`, `lambda_resource_policy`, `secret_resource_policy`, `ssm_resource_policy`, IAM `last_used`. Each gets a `<field>_status` sibling.

### Crash envelope (item 7)

**Scope:** The try/catch installs *after* `base-enum.js` has parsed CLI args, resolved `runDir`, and confirmed the directory is writable. Pre-bootstrap failures (missing `--run-dir`, malformed args, unwritable directory) print to stderr and exit non-zero with no envelope — there's nowhere to put one. Everything after that point is covered.

`scripts/lib/base-enum.js` wraps the run in try/catch. On uncaught throw, write:

```jsonc
{
  "module": "iam",
  "account_id": "123456789012",   // or "unknown" — see rule below
  "region": "us-east-1",
  "status": "error",
  "timestamp": "...",
  "findings": [],
  "coverage": [],
  "errors": [
    { "operation": "ListUsers", "code": "AccessDenied", "message": "..." }
  ]
}
```

**Account ID rule for crash envelopes.** The current module schema (`module-envelope.schema.json:14`) requires `^\d{12}$`. The results.json hook path already allows `"unknown"` (line 178-183) but the module-envelope path does not. Two acceptable resolutions:

- **Preferred:** Allow `"unknown"` *only when `status === "error"`*. Encode as a schema `oneOf`: either `pattern: ^\d{12}$`, or `const: "unknown"` with a sibling constraint that `status` must be `"error"`. Hook gets the same conditional.
- **Alternative:** Keep `account_id` strictly `^\d{12}$` and require the script's bootstrap to resolve account ID via STS *before* registering the crash handler. If STS itself crashes, there's no envelope to write — surface the failure to the orchestrator instead. Cleaner schema, harder to implement (STS bootstrap timing is fragile).

Pick the preferred path unless the implementer hits a corner case.

**Empty findings on crash.** The schema currently has `findings: { "type": "array" }` with no minimum length, and the hook checks `findings` is an array (lines 54-55) without requiring entries. Empty `findings: []` is already valid — no schema change needed there.

---

## Files Affected

**Prerequisite — fix the schema/hook module list first:**

`config/schemas/module-envelope.schema.json:11-13` and `config/hooks/scope-schema-validate.sh:25-26,70-71` both hardcode the module enum and only list `iam, sts, s3, kms, secrets, lambda, ec2, rds, sns, sqs, apigateway, codebuild`. Missing: `bedrock`, `cognito`, `dynamodb`, `ssm`. Newer enum scripts already write these module envelopes; if the hook ever fires on their output, valid envelopes get rejected. **Land the module-list update before any of the coverage work** — it's an unrelated correctness bug exposed by this audit and unblocks the rest.

**Schema / lib (foundation commits, independently landable — see Migration Order):**
- `config/schemas/module-envelope.schema.json` — *this* is the per-module schema (not `audit.schema.json`, which validates `results.json`). Add the missing modules to the enum, then add optional `coverage` (array of objects) and `errors` (array of objects) properties. Default to `additionalProperties: true` for now so additive rollout doesn't break consumers that don't read the new fields.
- `config/hooks/scope-schema-validate.sh` — update the `case` block (lines 25-26) and the module-name validation (lines 69-72) to match the schema enum. If `account_id: "unknown"` is allowed on crash envelopes (see Crash Envelope below), add the same `"unknown"` exception to the module-envelope path that already exists on the results.json path (line 178-183).
- `scripts/lib/envelope.js` — extend `createEnvelope()` to accept `coverage` and `errors` arrays. Validates shape only (entries are objects, required keys present, enum values match). **Does not** derive status, count entries, or know what a primary check is — that lives in `CoverageTracker`. Rejects malformed input with a clear error.
- `scripts/lib/base-enum.js` — wrap `run()` in try/catch (installed after `runDir` resolution; see *Crash envelope*) that always emits an envelope.
- `scripts/lib/coverage.js` — NEW. `CoverageTracker` is the authoritative single source of truth for coverage data *and* module status. Owns counters, AccessDenied disposition, `deriveModuleStatus({ primaryChecks, requiredChecks })`, `recordModuleFailure()`, and the `coverage[]`/`errors[]` reconstruction in `toEnvelopeFields()`. See *Coverage Helpers* below.

**Enum scripts (~13 files, 1 commit per module or batched by domain):**
- Apply per-module: declare which checks are required vs optional, emit `coverage[]` entries, annotate per-finding `<field>_status`, ensure errors propagate to `errors[]` array.
- Modules: `iam`, `s3`, `sts` (mostly done — formalize), `lambda`, `ec2`, `kms`, `secrets`, `ssm`, `rds`, `dynamodb`, `apigateway`, `sns`, `sqs`, `cognito`, `bedrock`, `codebuild`.
- STS already has `org_accessible`/`org_status`/`org_error_code` on the identity finding — migrate the data into `coverage[]` for consistency, but **leave the existing fields on the identity finding for one release**. Domain agents may already key off them (verify via `grep -r 'org_accessible\|org_status' agents/`); two-step deprecation prevents a silent break. Mark the duplicate fields as `// DEPRECATED — remove in v1.16` so the cleanup is calendar-anchored.

**Consumers (land *after* pilot data exists, not in the same PR):**

Because `coverage` and `errors` are additive optional fields and `<field>_status` annotations live alongside (not replacing) the existing fields, the schema rollout doesn't break readers that ignore them. Consumer updates can follow once the pilot module (s3) is producing real coverage data — that gives reviewers concrete output to validate parsing rules against, instead of theoretical schemas.

- `agents/subagents/scope-attack-{identity,compute,data,network}.md` — 4 domain agents read per-module JSON. Update parsing instructions to use `<field>_status` for "access denied vs absent" distinction.
- `agents/subagents/scope-attack-synthesizer.md` — if it consumes coverage, surface unreliable findings.
- `dashboard/src/App.jsx` — optional first cut; can defer UI until schema is stable.
- `agents/scope-audit.md`, `agents/scope-defend.md` — findings.md generation should mention coverage gaps in the report.

**Tests:**

Test changes follow the same per-module cadence as the rollout — fixtures do not update wholesale in step 1. The foundation PR stays small and additive.

- **Foundation (step 1):**
  - `test/lib-envelope.test.js` (new) — validate schema acceptance of new optional fields, reject malformed `coverage`/`errors` shapes, reject bad `status` values.
  - `test/lib-coverage.test.js` (new) — `CoverageTracker` unit tests: per-check counters, AccessDenied disposition, `deriveModuleStatus()` with all three table rows, `recordModuleFailure()` produces the module-wide entry, no drift between `coverage[]` and `errors[]` regardless of call order.
  - Existing `test/enum-*.test.js` fixtures stay unchanged — old envelopes (no `coverage`/`errors` fields) are still valid because the new fields are optional.
- **Per-module (steps 3, 5):**
  - Each module's test file and fixture get updated *with the module's migration commit*, not before. Pattern: regenerate `test/fixtures/enum/<module>/expected.json` to include the module's specific coverage entries and `<field>_status` annotations. Keeps every per-module PR self-contained and reviewable.

---

## Migration Order

Each step is landable independently because `coverage` and `errors` are additive optional fields. Consumers that don't read them keep working.

0. **Prerequisite: module-list catchup** — add `bedrock`, `cognito`, `dynamodb`, `ssm` to the schema enum and the hook `case` block. Pre-existing correctness bug; no coupling to coverage work but unblocks it.
1. **Lib + schema (additive, foundation)** — extend `module-envelope.schema.json` with optional `coverage` and `errors` properties. Add `coverage.js` with `CoverageTracker` (owns counters, AccessDenied disposition, `deriveModuleStatus()`, `recordModuleFailure()`). Update `envelope.js` to accept the new fields and validate their *shape* only — status derivation stays in the tracker. Update `scope-schema-validate.sh` for the `account_id: "unknown"` exception (status === "error" only). Tests: new `lib-envelope` + `lib-coverage` unit tests; existing enum fixtures untouched.
2. **Always-on envelope** — `base-enum.js` wraps `run()` in try/catch. Crashed runs produce `status: 'error'` JSON. No behavior change for successful runs.
3. **Pilot module — s3** — broadest policy/ACL surface, exercises all the disposition rules. Implement full coverage + per-finding status. Run end-to-end and verify dashboard still loads (it should — readers ignore the new fields).
4. **Consumer parity (after pilot data exists)** — update 4 attack-domain agents + synthesizer to read `<field>_status` and surface coverage gaps. Use s3's real output as fixture data for the agent prompt updates.
5. **Roll out remaining modules** — batched by domain (identity, compute, data, network). Each script declares `REQUIRED_CHECKS`.
6. **STS cleanup with deprecation window** — migrate org metadata into coverage; leave duplicate fields on the identity finding for one release marked `// DEPRECATED — remove in v1.16`.

---

## Open Questions

1. **Per-finding status vs separate object.** Annotating each finding with `<field>_status` keeps fields colocated but bloats every record. Alternative: a `coverage_per_resource[]` map keyed by ARN. The colocated form is easier for agents to reason about; pick that unless size becomes an issue.
2. **`errors[]` vs `coverage[].reasons[]` overlap.** Resolved by the *Coverage Helpers* design above — both arrays derive from the same `tracker.record()` call, so there's no maintenance drift. Listing here only to flag that consumers will see redundant-looking data; that's intentional for ergonomics.
3. **Multi-region aggregation.** `base-enum.js:80-99` flattens findings across regions but takes the max status. With coverage entries, aggregation needs to merge entries by `check` and sum counters. Spec it explicitly before implementing.

---

## Out of Scope

- IAM performance (Phase C). Coverage may make it easier to skip slow checks via a `--coverage-skip last-accessed` flag, but the perf fix itself is separate.
- Dashboard UI for coverage display. Schema lands first; UI catches up.
- Migrating exploit-mode and hunt-mode outputs to the same envelope. They're different result shapes; treat as separate work.
- Renaming `status: 'partial'` to something more descriptive. Backwards compat says keep it.

---

## Entry Points

- Recommendation list this came from: chat thread 2026-05-17.
- Phase A precedent (status semantics on a single module): commit `8063a32`.
- Existing envelope code: `scripts/lib/envelope.js`, `scripts/lib/base-enum.js:75-102`.
- Existing per-module schema: `config/schemas/module-envelope.schema.json` (this is the one Phase B extends; `audit.schema.json` validates the consolidated `results.json` instead).
- Existing validation hook: `config/hooks/scope-schema-validate.sh` (module-envelope path at lines 22-91; results.json path further down).
