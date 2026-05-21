# Coverage Foundation + S3 Pilot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the per-module envelope `coverage`/`errors` contract end-to-end: schema and hook accept the new fields, `CoverageTracker` lib produces them, `base-enum.js` emits an error envelope on crashes (instead of silent exit), and `scripts/enum/s3.js` becomes the pilot module that actually exercises the design.

**Architecture:** `CoverageTracker` is the single source of truth for per-module coverage data and module-level status derivation. Enum scripts record per-check events; the tracker aggregates them into `coverage[]` and `errors[]` arrays at the end of the run and applies the AccessDenied disposition rules to decide module status. `envelope.js` is reduced to shape/enum validation — it doesn't know what a "primary check" is. The s3 migration is the worked example that other modules will follow.

**Tech Stack:** Plain Node test runner (`node:assert`, custom `test()` wrappers — see `test/lib-policy-parser.test.js` for the canonical style), JSON Schema (consumed by the hook only — no validator dependency in the codebase), bash hook with `jq`.

---

## Source spec

`docs/superpowers/specs/2026-05-17-module-envelope-coverage-design.md` is the design contract. Read the "Status rules", "AccessDenied disposition", "New envelope fields", "Coverage Helpers", and "Per-finding annotation" sections before starting. This plan implements migration order steps 1, 2, and 3.

## Important context

- **Project root:** `/Users/tayvionp/claude-code/SCOPE`. Current branch: `feature/v1.14-sdk-architecture`. Do not switch branches.
- **Tests:** custom Node runner. Every `test/*.test.js` is executed by `node test/run-all.js`. No framework. Match `test/lib-policy-parser.test.js` style: `passed`/`failed` counters, `test()` wrapper, `console.log` PASS/FAIL, exit code reflects failures.
- **Hook source of truth:** `config/hooks/scope-schema-validate.sh`. The installed copy at `.claude/hooks/scope-schema-validate.sh` is gitignored — do NOT edit it directly. Operators regenerate it via `node bin/install.js`.
- **Schema source of truth:** `config/schemas/module-envelope.schema.json`.
- **Plan A precedent:** commit `9e6772e` added bedrock/cognito/dynamodb/ssm to the schema and hook. This plan builds on that.
- **STS precedent:** commit `8063a32` migrated STS to expose `org_accessible`/`org_status`/`org_error_code` as structured metadata on the identity finding. The STS migration to `coverage[]` is **out of scope** for this plan — it's Migration Order step 6 with a deprecation window. Leave STS alone.

## File structure

**Files modified:**
- `config/schemas/module-envelope.schema.json` — add `account_id: "unknown"` support via `oneOf`; add optional `coverage` and `errors` top-level array properties.
- `config/hooks/scope-schema-validate.sh` — accept `account_id: "unknown"` only when `status === "error"`; tolerate (do not validate) the new `coverage`/`errors` fields' inner shape — the schema is the contract, the hook does lightweight checks.
- `scripts/lib/envelope.js` — `createEnvelope()` accepts optional `coverage` and `errors` arrays, validates they are arrays, defaults to `[]`. No status derivation. No tracker import.
- `scripts/lib/base-enum.js` — wrap STS resolution and `run()` invocation in a try/catch that emits an error envelope on uncaught throw, after `runDir` has been resolved.
- `scripts/enum/s3.js` — declare `PRIMARY_CHECKS` and `REQUIRED_CHECKS`, instantiate `CoverageTracker`, record per-check events, annotate per-finding `<field>_status`, derive module status from the tracker.
- `test/fixtures/enum/s3/api-responses.json` and `test/fixtures/enum/s3/expected.json` — regenerated to reflect the new envelope shape.

**Files created:**
- `scripts/lib/coverage.js` — `CoverageTracker` class.
- `test/lib-coverage.test.js` — unit tests for the tracker.
- `test/lib-envelope.test.js` — shape validation tests for envelope.js's new accepted fields.
- `test/lib-base-enum-crash.test.js` — verifies a crashed `run()` produces an error envelope on disk.

**Files NOT modified:**
- `scripts/enum/sts.js` — STS migration to coverage is deferred (Migration Order step 6).
- Any other enum script — they roll out in Plan D (per-domain batches). For now they keep emitting envelopes without `coverage`/`errors` fields, which is valid since those fields are optional.
- Downstream consumers (`agents/subagents/scope-attack-*.md`, dashboard) — they roll out in Plan C after the s3 pilot produces real data.
- `.claude/hooks/*` — gitignored installed copies.

---

## Task 1: Schema + hook accept `account_id: "unknown"` and `coverage`/`errors` fields

**Files:**
- Modify: `config/schemas/module-envelope.schema.json`
- Modify: `config/hooks/scope-schema-validate.sh`
- Test: `test/hook-schema-validate.test.js` (extend, do not replace — the existing tests must still pass)

**Test design context:** the existing hook test (added in Plan A) uses `runHook(envelope, filename)` to drive the hook. Extend it with new tests that exercise the new acceptance rules. Use the same broken-envelope-as-probe pattern where it makes sense; for the `account_id: "unknown"` cases, just send a valid envelope and assert it's accepted (or rejected when the rule is violated).

- [ ] **Step 1: Write the failing tests**

Open `test/hook-schema-validate.test.js`. Find the section that says `// --- Regression guards: existing behavior must still work.` and the test that follows. Insert these new test blocks **before** that comment line (so the regression guards stay at the bottom):

```js
// --- New: account_id: "unknown" rules (Plan B Task 1)

test('hook accepts account_id "unknown" when status is "error"', () => {
  const env = validEnvelope('iam');
  env.account_id = 'unknown';
  env.status = 'error';
  const out = runHook(env, 'iam.json');
  assertAccepted(out, 'unknown account_id with status=error');
});

test('hook blocks account_id "unknown" when status is "complete"', () => {
  const env = validEnvelope('iam');
  env.account_id = 'unknown';
  // status stays "complete"
  const out = runHook(env, 'iam.json');
  assertBlocked(out, 'unknown account_id with status=complete');
});

test('hook blocks account_id "unknown" when status is "partial"', () => {
  const env = validEnvelope('iam');
  env.account_id = 'unknown';
  env.status = 'partial';
  const out = runHook(env, 'iam.json');
  assertBlocked(out, 'unknown account_id with status=partial');
});

// --- New: coverage[] and errors[] optional fields (Plan B Task 1)

test('hook accepts envelope with empty coverage[] and errors[]', () => {
  const env = validEnvelope('iam');
  env.coverage = [];
  env.errors = [];
  const out = runHook(env, 'iam.json');
  assertAccepted(out, 'envelope with empty coverage/errors');
});

test('hook accepts envelope with populated coverage[] and errors[]', () => {
  const env = validEnvelope('iam');
  env.coverage = [
    { check: 'list_users', scope: 'module_wide', status: 'complete', succeeded: 1, failed: 0, skipped: 0, reasons: [] },
  ];
  env.errors = [];
  const out = runHook(env, 'iam.json');
  assertAccepted(out, 'envelope with populated coverage');
});

test('hook still accepts envelope without coverage/errors (backwards compat)', () => {
  const env = validEnvelope('iam');
  // no coverage, no errors fields set
  const out = runHook(env, 'iam.json');
  assertAccepted(out, 'envelope without new optional fields');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node test/hook-schema-validate.test.js`

Expected: FAIL on the three account_id tests (hook doesn't yet understand "unknown"). The `accepts empty coverage[]` and `populated coverage[]` and `without coverage` tests should PASS (hook ignores unknown fields by default). Exit code 1.

If `accepts envelope with empty coverage[]` or `accepts envelope with populated coverage[]` fail, the hook is doing strict additional-property checks that the spec didn't anticipate — stop and investigate `config/hooks/scope-schema-validate.sh` before continuing.

- [ ] **Step 3: Update the schema**

Open `config/schemas/module-envelope.schema.json`. The current `account_id` property (around line 14) reads:

```json
    "account_id": { "type": "string", "pattern": "^\\d{12}$" },
```

Replace with:

```json
    "account_id": {
      "oneOf": [
        { "type": "string", "pattern": "^\\d{12}$" },
        { "const": "unknown" }
      ],
      "description": "12-digit AWS account ID, or 'unknown' when status is 'error' (pre-STS crash). The 'unknown' case is enforced by the validation hook, not the schema."
    },
```

Then add optional `coverage` and `errors` properties. The current `properties` block ends like this (around line 22):

```json
    "error": { "type": "string" },
    "findings": { "type": "array" }
  }
```

Replace with:

```json
    "error": { "type": "string" },
    "findings": { "type": "array" },
    "coverage": {
      "type": "array",
      "description": "Per-check coverage entries produced by CoverageTracker. Optional; absent means no coverage data (backwards compatible).",
      "items": {
        "type": "object",
        "required": ["check", "status"],
        "properties": {
          "check": { "type": "string" },
          "scope": { "type": "string", "enum": ["per_resource", "module_wide"] },
          "status": { "type": "string", "enum": ["complete", "partial", "skipped", "error"] },
          "succeeded": { "type": "integer", "minimum": 0 },
          "failed": { "type": "integer", "minimum": 0 },
          "skipped": { "type": "integer", "minimum": 0 },
          "reasons": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "code": { "type": "string" },
                "count": { "type": "integer", "minimum": 1 },
                "sample_resource": { "type": ["string", "null"] }
              }
            }
          }
        }
      }
    },
    "errors": {
      "type": "array",
      "description": "Flat list of failed operations with full context. Optional; absent means no errors.",
      "items": {
        "type": "object",
        "required": ["operation", "code"],
        "properties": {
          "operation": { "type": "string" },
          "resource": { "type": ["string", "null"] },
          "code": { "type": "string" },
          "message": { "type": "string" }
        }
      }
    }
  }
```

- [ ] **Step 4: Update the hook to enforce the "unknown" rule**

Open `config/hooks/scope-schema-validate.sh`. The current account_id validation in the module-envelope path is around line 76-81:

```bash
    # Validate account_id format
    ACCT_ID=$(jq -r '.account_id // empty' "$FILE_PATH")
    if [ -n "$ACCT_ID" ]; then
      if ! echo "$ACCT_ID" | grep -qE '^[0-9]{12}$'; then
        ERRORS+=("account_id '$ACCT_ID' is not a valid 12-digit AWS account ID")
      fi
    fi
```

Replace with:

```bash
    # Validate account_id format
    # Allow "unknown" only when status is "error" (crash envelope from base-enum.js).
    ACCT_ID=$(jq -r '.account_id // empty' "$FILE_PATH")
    if [ -n "$ACCT_ID" ]; then
      if [ "$ACCT_ID" = "unknown" ]; then
        if [ "$STATUS_VAL" != "error" ]; then
          ERRORS+=("account_id 'unknown' is only allowed when status is 'error' (got status: $STATUS_VAL)")
        fi
      elif ! echo "$ACCT_ID" | grep -qE '^[0-9]{12}$'; then
        ERRORS+=("account_id '$ACCT_ID' is not a valid 12-digit AWS account ID")
      fi
    fi
```

Note: `STATUS_VAL` is already set earlier in this `case` block (around line 58). Verify before you edit by reading the surrounding context.

- [ ] **Step 5: Run tests to verify they pass**

Run: `node test/hook-schema-validate.test.js`

Expected: all tests pass. Count should be `12 passed, 0 failed` (6 from Plan A + 6 from this task). Exit code 0.

Run the full suite: `node test/run-all.js`. Expected: green.

- [ ] **Step 6: Commit**

```bash
git add config/schemas/module-envelope.schema.json \
        config/hooks/scope-schema-validate.sh \
        test/hook-schema-validate.test.js

git commit -m "feat(schema): allow account_id 'unknown' for error envelopes and add coverage/errors fields

The module envelope schema now permits two new shapes that Phase B work
relies on:

1. account_id may be the literal 'unknown' instead of a 12-digit pattern,
   but the validation hook enforces this is only legal when status is
   'error'. This unblocks the always-on envelope: if a script crashes
   before STS resolves an account ID, it can still emit a valid error
   envelope rather than exiting with no JSON.

2. New optional top-level fields coverage[] and errors[] are now declared
   in the schema. Modules that don't emit them continue to validate
   (backwards compatible). When emitted, the items have strict shapes:
   coverage entries declare check/status/scope/counts/reasons; errors
   entries declare operation/code/resource/message.

Hook validation extended to enforce the unknown+status='error' coupling.
Three new hook tests cover the unknown account_id rules (accepted with
status=error, blocked with status=complete or partial). Three more cover
the new optional fields (empty, populated, absent — all accepted).
Existing Plan A tests still pass.

Foundation for the rest of Phase B (CoverageTracker, always-on envelope,
s3 pilot). See docs/superpowers/specs/2026-05-17-module-envelope-coverage-design.md."
```

---

## Task 2: `envelope.js` accepts optional `coverage` and `errors` arrays

**Files:**
- Modify: `scripts/lib/envelope.js`
- Create: `test/lib-envelope.test.js`

**Design constraint:** `envelope.js` must NOT import or know about `CoverageTracker`. Its job is shape validation only. If `coverage` is provided, validate it's an array (don't validate item shapes — that's the schema's job, the test is in Task 1). Same for `errors`. If absent, default to `undefined` (don't auto-include empty arrays in the output) so backwards compatibility holds — existing modules that don't pass these continue to produce envelopes that look exactly as they did before.

- [ ] **Step 1: Write the failing tests**

Create `test/lib-envelope.test.js`:

```js
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createEnvelope, writeEnvelope } = require('../scripts/lib/envelope');

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

function baseArgs(overrides = {}) {
  return {
    module: 's3',
    account_id: '123456789012',
    region: 'us-east-1',
    status: 'complete',
    findings: [],
    ...overrides,
  };
}

// --- Backwards compatibility: envelope works without new fields ---

test('omits coverage when not provided', () => {
  const env = createEnvelope(baseArgs());
  assert.ok(!('coverage' in env), `expected coverage absent, got: ${JSON.stringify(env.coverage)}`);
});

test('omits errors when not provided', () => {
  const env = createEnvelope(baseArgs());
  assert.ok(!('errors' in env), `expected errors absent, got: ${JSON.stringify(env.errors)}`);
});

// --- New: accepts optional coverage and errors arrays ---

test('includes coverage when provided', () => {
  const coverage = [{ check: 'list_buckets', status: 'complete', succeeded: 5, failed: 0, skipped: 0 }];
  const env = createEnvelope(baseArgs({ coverage }));
  assert.deepStrictEqual(env.coverage, coverage);
});

test('includes errors when provided', () => {
  const errors = [{ operation: 'GetBucketPolicy', code: 'AccessDeniedException', resource: 'arn:aws:s3:::foo', message: 'denied' }];
  const env = createEnvelope(baseArgs({ errors }));
  assert.deepStrictEqual(env.errors, errors);
});

test('includes both coverage and errors when both provided', () => {
  const coverage = [{ check: 'list_buckets', status: 'complete', succeeded: 1, failed: 0, skipped: 0 }];
  const errors = [{ operation: 'X', code: 'Y' }];
  const env = createEnvelope(baseArgs({ coverage, errors }));
  assert.deepStrictEqual(env.coverage, coverage);
  assert.deepStrictEqual(env.errors, errors);
});

// --- Shape validation ---

test('rejects non-array coverage', () => {
  assert.throws(
    () => createEnvelope(baseArgs({ coverage: 'not-an-array' })),
    /coverage must be an array/
  );
});

test('rejects non-array errors', () => {
  assert.throws(
    () => createEnvelope(baseArgs({ errors: { not: 'array' } })),
    /errors must be an array/
  );
});

test('accepts empty arrays explicitly', () => {
  const env = createEnvelope(baseArgs({ coverage: [], errors: [] }));
  assert.deepStrictEqual(env.coverage, []);
  assert.deepStrictEqual(env.errors, []);
});

// --- Crash envelope shape: account_id "unknown" + status error ---

test('accepts account_id "unknown" when status is "error"', () => {
  const env = createEnvelope(baseArgs({ account_id: 'unknown', status: 'error' }));
  assert.strictEqual(env.account_id, 'unknown');
  assert.strictEqual(env.status, 'error');
});

// --- Regression: existing behavior preserved ---

test('rejects missing module', () => {
  const args = baseArgs();
  delete args.module;
  assert.throws(() => createEnvelope(args), /missing required fields/i);
});

test('rejects invalid status', () => {
  assert.throws(
    () => createEnvelope(baseArgs({ status: 'bogus' })),
    /Invalid status/
  );
});

test('writeEnvelope writes JSON to <runDir>/<module>.json', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-env-test-'));
  try {
    const env = createEnvelope(baseArgs());
    const filePath = writeEnvelope(tmp, env);
    assert.strictEqual(filePath, path.join(tmp, 's3.json'));
    const written = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    assert.strictEqual(written.module, 's3');
    assert.strictEqual(written.account_id, '123456789012');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node test/lib-envelope.test.js`

Expected: the new tests (`includes coverage when provided`, `includes errors when provided`, `rejects non-array coverage`, `rejects non-array errors`, `accepts empty arrays`) FAIL because `createEnvelope` doesn't yet accept those parameters. The "omits coverage when not provided", "rejects missing module", "rejects invalid status", and `writeEnvelope` tests should PASS — they test current behavior. The "account_id unknown" test FAILS because current code rejects non-string-shaped account_id only if status validation runs first; the actual validator only checks required fields, so this likely passes — verify by reading the output. Exit code 1 if any failed.

- [ ] **Step 3: Update `scripts/lib/envelope.js`**

Open `scripts/lib/envelope.js`. The current `createEnvelope` (lines 20-46) reads:

```js
function createEnvelope({ module, account_id, region, status, findings = [] }) {
  // Validate required fields
  const missing = REQUIRED_FIELDS.filter((f) => {
    const val = { module, account_id, region, status }[f];
    return !val || typeof val !== 'string';
  });
  if (missing.length > 0) {
    throw new Error(`Envelope missing required fields: ${missing.join(', ')}`);
  }

  if (!VALID_STATUSES.has(status)) {
    throw new Error(`Invalid status "${status}". Must be one of: ${[...VALID_STATUSES].join(', ')}`);
  }

  if (!Array.isArray(findings)) {
    throw new Error('findings must be an array');
  }

  return {
    module,
    account_id,
    region,
    status,
    timestamp: new Date().toISOString(),
    findings,
  };
}
```

Replace with:

```js
function createEnvelope({ module, account_id, region, status, findings = [], coverage, errors }) {
  // Validate required fields
  const missing = REQUIRED_FIELDS.filter((f) => {
    const val = { module, account_id, region, status }[f];
    return !val || typeof val !== 'string';
  });
  if (missing.length > 0) {
    throw new Error(`Envelope missing required fields: ${missing.join(', ')}`);
  }

  if (!VALID_STATUSES.has(status)) {
    throw new Error(`Invalid status "${status}". Must be one of: ${[...VALID_STATUSES].join(', ')}`);
  }

  if (!Array.isArray(findings)) {
    throw new Error('findings must be an array');
  }

  // coverage and errors are optional. If provided, they must be arrays.
  // envelope.js validates shape only — it does not derive status, count
  // entries, or know what a "primary check" is. That's CoverageTracker's job.
  if (coverage !== undefined && !Array.isArray(coverage)) {
    throw new Error('coverage must be an array');
  }
  if (errors !== undefined && !Array.isArray(errors)) {
    throw new Error('errors must be an array');
  }

  const envelope = {
    module,
    account_id,
    region,
    status,
    timestamp: new Date().toISOString(),
    findings,
  };

  // Only include the new fields in the output when callers opt in by passing
  // them. Existing modules that don't pass coverage/errors produce envelopes
  // that look exactly as they did before.
  if (coverage !== undefined) envelope.coverage = coverage;
  if (errors !== undefined) envelope.errors = errors;

  return envelope;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node test/lib-envelope.test.js`

Expected: all tests pass. `12 passed, 0 failed`. Exit code 0.

Run the full suite: `node test/run-all.js`. Expected: green. Pay attention to `enum-*.test.js` — none of them pass `coverage`/`errors` to `createEnvelope` so they should all still pass unchanged.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/envelope.js test/lib-envelope.test.js

git commit -m "feat(envelope): accept optional coverage and errors arrays

createEnvelope() now accepts two new optional parameters. When provided,
they're validated as arrays and included in the output. When omitted,
they're left out entirely — existing modules that don't pass them produce
envelopes byte-for-byte identical to before this change. Backwards
compatible.

The lib stays a shape validator only. It does not import CoverageTracker,
does not derive module status, and does not know which checks are
'primary' or 'required'. That logic lives entirely in CoverageTracker
(Task 3) so per-module classification stays out of the generic lib.

New test/lib-envelope.test.js covers:
- backwards compat (omits new fields when not provided)
- new fields included when provided
- shape rejection (non-array coverage/errors throw)
- account_id 'unknown' with status 'error' accepted at the envelope
  level (hook enforces the cross-field rule; envelope just builds the JSON)
- existing required-field and status-enum validation regressed against"
```

---

## Task 3: `CoverageTracker` class

**Files:**
- Create: `scripts/lib/coverage.js`
- Create: `test/lib-coverage.test.js`

**API recap (from spec):**

```js
const tracker = new CoverageTracker();
tracker.record({ check, resource, status: 'ok' });
tracker.record({ check, resource, status: 'failed', operation, errorCode, errorMessage });
tracker.record({ check, status: 'skipped', reason });
tracker.recordModuleFailure({ check, operation, errorCode, errorMessage });
const status = tracker.deriveModuleStatus({ primaryChecks, requiredChecks });
const { coverage, errors } = tracker.toEnvelopeFields();
```

**Status derivation rules (from the disposition table):**
- If any check in `primaryChecks` has `recordModuleFailure` recorded against it → return `'error'`.
- Else if any check in `requiredChecks` has `failed > 0` per-resource events → return `'partial'`.
- Else → return `'complete'`.

**Coverage entry status (per check):**
- Recorded via `recordModuleFailure` → `'error'`, `scope: 'module_wide'`, `succeeded: 0`, `failed: 1`.
- Has `failed > 0` per-resource events → `'partial'`, `scope: 'per_resource'`.
- Only `skipped` events recorded → `'skipped'`.
- Only `ok` events recorded → `'complete'`.
- Mix of `ok` and `skipped` (no failures) → `'complete'`.

**errors[] derivation:**
- Every `record` with `status: 'failed'` produces an `errors[]` entry: `{ operation, resource, code, message }`.
- Every `recordModuleFailure` produces an `errors[]` entry: `{ operation, code, message, resource: null }`.
- Skipped events do NOT produce errors entries.

**reasons[] derivation per check:**
- Group failed events by `errorCode`, count occurrences, capture the first `resource` as `sample_resource`.
- For module-wide failures, `count: 1`, `sample_resource: null`.

- [ ] **Step 1: Write the failing tests**

Create `test/lib-coverage.test.js`:

```js
'use strict';

const assert = require('node:assert');
const { CoverageTracker } = require('../scripts/lib/coverage');

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

// --- record() + counters ---

test('counts a single successful event', () => {
  const t = new CoverageTracker();
  t.record({ check: 'bucket_policy', resource: 'arn:aws:s3:::foo', status: 'ok' });
  const { coverage } = t.toEnvelopeFields();
  assert.strictEqual(coverage.length, 1);
  assert.strictEqual(coverage[0].check, 'bucket_policy');
  assert.strictEqual(coverage[0].succeeded, 1);
  assert.strictEqual(coverage[0].failed, 0);
  assert.strictEqual(coverage[0].skipped, 0);
  assert.strictEqual(coverage[0].status, 'complete');
  assert.strictEqual(coverage[0].scope, 'per_resource');
});

test('aggregates multiple events for the same check', () => {
  const t = new CoverageTracker();
  t.record({ check: 'bucket_policy', resource: 'b1', status: 'ok' });
  t.record({ check: 'bucket_policy', resource: 'b2', status: 'ok' });
  t.record({ check: 'bucket_policy', resource: 'b3', status: 'failed',
             operation: 'GetBucketPolicy', errorCode: 'AccessDeniedException', errorMessage: 'denied' });
  const { coverage } = t.toEnvelopeFields();
  assert.strictEqual(coverage.length, 1);
  assert.strictEqual(coverage[0].succeeded, 2);
  assert.strictEqual(coverage[0].failed, 1);
  assert.strictEqual(coverage[0].status, 'partial');
});

test('groups multiple checks into separate coverage entries', () => {
  const t = new CoverageTracker();
  t.record({ check: 'bucket_policy', resource: 'b1', status: 'ok' });
  t.record({ check: 'bucket_acl', resource: 'b1', status: 'ok' });
  const { coverage } = t.toEnvelopeFields();
  assert.strictEqual(coverage.length, 2);
  const checks = coverage.map((c) => c.check).sort();
  assert.deepStrictEqual(checks, ['bucket_acl', 'bucket_policy']);
});

// --- errors[] derivation ---

test('failed events produce errors[] entries with full context', () => {
  const t = new CoverageTracker();
  t.record({ check: 'bucket_policy', resource: 'arn:aws:s3:::foo', status: 'failed',
             operation: 'GetBucketPolicy', errorCode: 'AccessDeniedException', errorMessage: 'denied' });
  const { errors } = t.toEnvelopeFields();
  assert.strictEqual(errors.length, 1);
  assert.deepStrictEqual(errors[0], {
    operation: 'GetBucketPolicy',
    resource: 'arn:aws:s3:::foo',
    code: 'AccessDeniedException',
    message: 'denied',
  });
});

test('skipped events do NOT produce errors[] entries', () => {
  const t = new CoverageTracker();
  t.record({ check: 'last_accessed', status: 'skipped', reason: 'access_denied' });
  const { errors } = t.toEnvelopeFields();
  assert.deepStrictEqual(errors, []);
});

test('ok events do NOT produce errors[] entries', () => {
  const t = new CoverageTracker();
  t.record({ check: 'bucket_policy', resource: 'b1', status: 'ok' });
  const { errors } = t.toEnvelopeFields();
  assert.deepStrictEqual(errors, []);
});

// --- reasons[] derivation ---

test('reasons[] groups failures by errorCode with counts', () => {
  const t = new CoverageTracker();
  t.record({ check: 'bucket_policy', resource: 'b1', status: 'failed',
             operation: 'GetBucketPolicy', errorCode: 'AccessDeniedException', errorMessage: 'denied' });
  t.record({ check: 'bucket_policy', resource: 'b2', status: 'failed',
             operation: 'GetBucketPolicy', errorCode: 'AccessDeniedException', errorMessage: 'denied' });
  t.record({ check: 'bucket_policy', resource: 'b3', status: 'failed',
             operation: 'GetBucketPolicy', errorCode: 'NoSuchBucket', errorMessage: 'gone' });
  const { coverage } = t.toEnvelopeFields();
  const entry = coverage.find((c) => c.check === 'bucket_policy');
  const reasons = entry.reasons.sort((a, b) => a.code.localeCompare(b.code));
  assert.strictEqual(reasons.length, 2);
  assert.strictEqual(reasons[0].code, 'AccessDeniedException');
  assert.strictEqual(reasons[0].count, 2);
  assert.strictEqual(reasons[0].sample_resource, 'b1');
  assert.strictEqual(reasons[1].code, 'NoSuchBucket');
  assert.strictEqual(reasons[1].count, 1);
  assert.strictEqual(reasons[1].sample_resource, 'b3');
});

// --- skipped status semantics ---

test('check with only skipped events has status "skipped"', () => {
  const t = new CoverageTracker();
  t.record({ check: 'last_accessed', status: 'skipped', reason: 'access_denied' });
  const { coverage } = t.toEnvelopeFields();
  assert.strictEqual(coverage[0].status, 'skipped');
  assert.strictEqual(coverage[0].skipped, 1);
});

test('check with mix of ok and skipped (no failures) has status "complete"', () => {
  const t = new CoverageTracker();
  t.record({ check: 'last_accessed', resource: 'u1', status: 'ok' });
  t.record({ check: 'last_accessed', resource: 'u2', status: 'skipped', reason: 'access_denied' });
  const { coverage } = t.toEnvelopeFields();
  assert.strictEqual(coverage[0].status, 'complete');
});

// --- recordModuleFailure ---

test('recordModuleFailure produces module_wide error entry', () => {
  const t = new CoverageTracker();
  t.recordModuleFailure({ check: 'list_buckets', operation: 'ListBuckets',
                          errorCode: 'AccessDeniedException', errorMessage: 'denied' });
  const { coverage, errors } = t.toEnvelopeFields();
  assert.strictEqual(coverage.length, 1);
  assert.strictEqual(coverage[0].check, 'list_buckets');
  assert.strictEqual(coverage[0].scope, 'module_wide');
  assert.strictEqual(coverage[0].status, 'error');
  assert.strictEqual(coverage[0].succeeded, 0);
  assert.strictEqual(coverage[0].failed, 1);
  assert.strictEqual(coverage[0].skipped, 0);
  assert.strictEqual(coverage[0].reasons.length, 1);
  assert.strictEqual(coverage[0].reasons[0].code, 'AccessDeniedException');
  assert.strictEqual(coverage[0].reasons[0].count, 1);
  assert.strictEqual(coverage[0].reasons[0].sample_resource, null);
  assert.strictEqual(errors.length, 1);
  assert.deepStrictEqual(errors[0], {
    operation: 'ListBuckets',
    resource: null,
    code: 'AccessDeniedException',
    message: 'denied',
  });
});

// --- deriveModuleStatus ---

test('deriveModuleStatus returns "complete" when nothing failed', () => {
  const t = new CoverageTracker();
  t.record({ check: 'bucket_policy', resource: 'b1', status: 'ok' });
  t.record({ check: 'last_accessed', status: 'skipped', reason: 'cli_flag' });
  const status = t.deriveModuleStatus({
    primaryChecks: ['list_buckets'],
    requiredChecks: ['bucket_policy'],
  });
  assert.strictEqual(status, 'complete');
});

test('deriveModuleStatus returns "partial" when a required check has failures', () => {
  const t = new CoverageTracker();
  t.record({ check: 'bucket_policy', resource: 'b1', status: 'ok' });
  t.record({ check: 'bucket_policy', resource: 'b2', status: 'failed',
             operation: 'GetBucketPolicy', errorCode: 'AccessDeniedException', errorMessage: 'd' });
  const status = t.deriveModuleStatus({
    primaryChecks: ['list_buckets'],
    requiredChecks: ['bucket_policy'],
  });
  assert.strictEqual(status, 'partial');
});

test('deriveModuleStatus returns "complete" when an OPTIONAL check has failures recorded as skipped', () => {
  // Optional check + access denied → script records as 'skipped', not 'failed'.
  // Tracker should not downgrade status for this.
  const t = new CoverageTracker();
  t.record({ check: 'last_accessed', status: 'skipped', reason: 'access_denied' });
  const status = t.deriveModuleStatus({
    primaryChecks: ['list_buckets'],
    requiredChecks: ['bucket_policy'],
    // last_accessed is NOT in either list — it's optional
  });
  assert.strictEqual(status, 'complete');
});

test('deriveModuleStatus returns "error" when a primary check failed module-wide', () => {
  const t = new CoverageTracker();
  t.recordModuleFailure({ check: 'list_buckets', operation: 'ListBuckets',
                          errorCode: 'AccessDeniedException', errorMessage: 'denied' });
  const status = t.deriveModuleStatus({
    primaryChecks: ['list_buckets'],
    requiredChecks: ['bucket_policy'],
  });
  assert.strictEqual(status, 'error');
});

test('deriveModuleStatus prefers "error" over "partial" when both conditions hold', () => {
  // Primary failed AND a required check has failures — error wins.
  const t = new CoverageTracker();
  t.recordModuleFailure({ check: 'list_buckets', operation: 'ListBuckets',
                          errorCode: 'X', errorMessage: 'x' });
  t.record({ check: 'bucket_policy', resource: 'b1', status: 'failed',
             operation: 'GetBucketPolicy', errorCode: 'AccessDeniedException', errorMessage: 'd' });
  const status = t.deriveModuleStatus({
    primaryChecks: ['list_buckets'],
    requiredChecks: ['bucket_policy'],
  });
  assert.strictEqual(status, 'error');
});

// --- input validation ---

test('record() throws on missing check', () => {
  const t = new CoverageTracker();
  assert.throws(
    () => t.record({ resource: 'b1', status: 'ok' }),
    /check is required/
  );
});

test('record() throws on invalid status', () => {
  const t = new CoverageTracker();
  assert.throws(
    () => t.record({ check: 'x', resource: 'r', status: 'bogus' }),
    /invalid status/
  );
});

test('recordModuleFailure() throws on missing check', () => {
  const t = new CoverageTracker();
  assert.throws(
    () => t.recordModuleFailure({ operation: 'X', errorCode: 'Y', errorMessage: 'z' }),
    /check is required/
  );
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node test/lib-coverage.test.js`

Expected: every test fails with `Cannot find module '../scripts/lib/coverage'` (the module doesn't exist yet). Exit code 1.

- [ ] **Step 3: Implement `scripts/lib/coverage.js`**

Create `scripts/lib/coverage.js`:

```js
'use strict';

/**
 * CoverageTracker is the single source of truth for per-module coverage data.
 * Enum scripts record per-check events as they enumerate; the tracker aggregates
 * them into coverage[] and errors[] arrays at the end of the run, and applies
 * the AccessDenied disposition rules from
 * docs/superpowers/specs/2026-05-17-module-envelope-coverage-design.md to
 * decide module-level status.
 *
 * envelope.js does NOT know about this class. The tracker outputs plain arrays
 * that any caller can pass into createEnvelope().
 */

const VALID_RECORD_STATUSES = new Set(['ok', 'failed', 'skipped']);
const VALID_MODULE_STATUSES = new Set(['complete', 'partial', 'error']);

class CoverageTracker {
  constructor() {
    // Internal event log. One entry per record() / recordModuleFailure() call.
    // {check, resource, status, operation?, errorCode?, errorMessage?, reason?, moduleWide}
    this._events = [];
  }

  /**
   * Record a per-resource check outcome.
   *
   * For 'ok':       { check, resource, status: 'ok' }
   * For 'failed':   { check, resource, status: 'failed', operation, errorCode, errorMessage }
   * For 'skipped':  { check, [resource], status: 'skipped', reason }
   *
   * AccessDenied disposition: if a check is OPTIONAL and returns AccessDenied,
   * the caller records it as 'skipped' (reason: 'access_denied'), not 'failed'.
   * If a check is REQUIRED, the caller records it as 'failed'. The classification
   * is the caller's responsibility — declared in the enum script's
   * PRIMARY_CHECKS / REQUIRED_CHECKS arrays.
   */
  record({ check, resource, status, operation, errorCode, errorMessage, reason }) {
    if (!check || typeof check !== 'string') {
      throw new Error('CoverageTracker.record: check is required');
    }
    if (!VALID_RECORD_STATUSES.has(status)) {
      throw new Error(
        `CoverageTracker.record: invalid status '${status}'. Must be one of: ${[...VALID_RECORD_STATUSES].join(', ')}`
      );
    }
    if (status === 'failed') {
      if (!operation) throw new Error('CoverageTracker.record: operation is required for failed events');
      if (!errorCode) throw new Error('CoverageTracker.record: errorCode is required for failed events');
    }
    this._events.push({
      check,
      resource: resource ?? null,
      status,
      operation: operation ?? null,
      errorCode: errorCode ?? null,
      errorMessage: errorMessage ?? null,
      reason: reason ?? null,
      moduleWide: false,
    });
  }

  /**
   * Record a module-wide primary failure. Use this only when a primary list
   * operation (e.g., ListBuckets, ListRoles) fails so the script can't
   * enumerate anything. Produces a coverage entry with scope='module_wide',
   * status='error', and a single errors[] entry.
   */
  recordModuleFailure({ check, operation, errorCode, errorMessage }) {
    if (!check || typeof check !== 'string') {
      throw new Error('CoverageTracker.recordModuleFailure: check is required');
    }
    if (!operation) {
      throw new Error('CoverageTracker.recordModuleFailure: operation is required');
    }
    if (!errorCode) {
      throw new Error('CoverageTracker.recordModuleFailure: errorCode is required');
    }
    this._events.push({
      check,
      resource: null,
      status: 'failed',
      operation,
      errorCode,
      errorMessage: errorMessage ?? null,
      reason: null,
      moduleWide: true,
    });
  }

  /**
   * Derive the module-level status from recorded events and the caller's
   * classification of which checks are primary vs required vs optional.
   *
   * Disposition table (from spec):
   * - Primary check failed (module_wide) → 'error'
   * - Required per-resource check has any failures → 'partial'
   * - Otherwise → 'complete'
   *
   * 'error' beats 'partial' beats 'complete'.
   */
  deriveModuleStatus({ primaryChecks = [], requiredChecks = [] } = {}) {
    const primary = new Set(primaryChecks);
    const required = new Set(requiredChecks);

    const hasPrimaryFailure = this._events.some(
      (e) => e.moduleWide && e.status === 'failed' && primary.has(e.check)
    );
    if (hasPrimaryFailure) return 'error';

    const hasRequiredFailure = this._events.some(
      (e) => !e.moduleWide && e.status === 'failed' && required.has(e.check)
    );
    if (hasRequiredFailure) return 'partial';

    return 'complete';
  }

  /**
   * Build the coverage[] and errors[] arrays for the envelope.
   * Returns { coverage, errors }.
   */
  toEnvelopeFields() {
    // Group events by check.
    const byCheck = new Map();
    for (const e of this._events) {
      if (!byCheck.has(e.check)) byCheck.set(e.check, []);
      byCheck.get(e.check).push(e);
    }

    const coverage = [];
    for (const [check, events] of byCheck) {
      coverage.push(this._buildCoverageEntry(check, events));
    }

    const errors = [];
    for (const e of this._events) {
      if (e.status !== 'failed') continue;
      errors.push({
        operation: e.operation,
        resource: e.resource,
        code: e.errorCode,
        message: e.errorMessage,
      });
    }

    return { coverage, errors };
  }

  _buildCoverageEntry(check, events) {
    const moduleWideFailure = events.find((e) => e.moduleWide && e.status === 'failed');
    if (moduleWideFailure) {
      return {
        check,
        scope: 'module_wide',
        status: 'error',
        succeeded: 0,
        failed: 1,
        skipped: 0,
        reasons: [
          { code: moduleWideFailure.errorCode, count: 1, sample_resource: null },
        ],
      };
    }

    let succeeded = 0, failed = 0, skipped = 0;
    const reasonsByCode = new Map(); // code → { count, sample_resource }

    for (const e of events) {
      if (e.status === 'ok') {
        succeeded++;
      } else if (e.status === 'skipped') {
        skipped++;
      } else if (e.status === 'failed') {
        failed++;
        if (!reasonsByCode.has(e.errorCode)) {
          reasonsByCode.set(e.errorCode, { code: e.errorCode, count: 0, sample_resource: e.resource });
        }
        reasonsByCode.get(e.errorCode).count++;
      }
    }

    let status;
    if (failed > 0) {
      status = 'partial';
    } else if (succeeded === 0 && skipped > 0) {
      status = 'skipped';
    } else {
      status = 'complete';
    }

    return {
      check,
      scope: 'per_resource',
      status,
      succeeded,
      failed,
      skipped,
      reasons: [...reasonsByCode.values()],
    };
  }
}

module.exports = { CoverageTracker, VALID_RECORD_STATUSES, VALID_MODULE_STATUSES };
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node test/lib-coverage.test.js`

Expected: every test passes. Count should be `17 passed, 0 failed`. Exit code 0.

Run the full suite: `node test/run-all.js`. Expected: green across all 22 test files.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/coverage.js test/lib-coverage.test.js

git commit -m "feat(coverage): add CoverageTracker for per-module coverage and status

CoverageTracker is the single source of truth for per-module coverage data
and module-level status derivation. Enum scripts record per-check events
via record() or recordModuleFailure(); the tracker aggregates them and
applies the AccessDenied disposition table from the spec to decide module
status.

API:
- record({check, resource, status, operation?, errorCode?, errorMessage?, reason?})
- recordModuleFailure({check, operation, errorCode, errorMessage})
- deriveModuleStatus({primaryChecks, requiredChecks}) → 'complete'|'partial'|'error'
- toEnvelopeFields() → {coverage, errors}

The tracker owns:
- Per-check counters (succeeded/failed/skipped)
- Per-check coverage status derivation
- Module-level status derivation given the script's classification
- errors[] reconstruction from failed events
- reasons[] grouping by errorCode

Per the spec's design, envelope.js does not import this class. Modules
pass the tracker's output into createEnvelope() — the lib stays a shape
validator.

Disposition rules enforced by deriveModuleStatus:
- Primary check failed (recordModuleFailure) → 'error'
- Required check has per-resource failures → 'partial'
- Otherwise → 'complete'
- 'error' wins over 'partial' if both conditions hold

17 unit tests cover happy paths, multi-check aggregation, reasons[]
grouping by errorCode, skipped semantics, module-wide failure shape,
status precedence (error > partial > complete), and input validation."
```

---

## Task 4: Always-on envelope in `base-enum.js`

**Files:**
- Modify: `scripts/lib/base-enum.js`
- Create: `test/lib-base-enum-crash.test.js`

**Design context:** the try/catch installs **after** `runDir` is resolved (line 35) but should be wide enough to cover the STS resolution at line 47-57. If STS fails, we still want an error envelope on disk with `account_id: "unknown"` (allowed by Task 1's schema/hook change). The existing catch at line 104-107 handles `run()` failures — extend it to write an envelope instead of just exiting.

The pre-bootstrap exits (lines 35-44, missing `--run-dir` or `--region`) stay as stderr + non-zero exit — there's no envelope file to write because we don't know where to write it.

- [ ] **Step 1: Write the failing test**

Create `test/lib-base-enum-crash.test.js`:

```js
'use strict';

const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

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

const ROOT = path.join(__dirname, '..');

// Create a one-off enum script that uses baseEnum and throws inside run().
function makeCrashingEnumScript(tmpDir, errorMessage) {
  const scriptPath = path.join(tmpDir, 'crash-enum.js');
  fs.writeFileSync(scriptPath, `
const { baseEnum } = require('${path.join(ROOT, 'scripts/lib/base-enum').replace(/\\/g, '/')}');
async function run() {
  throw new Error(${JSON.stringify(errorMessage)});
}
baseEnum({ module: 'iam', run });
`);
  return scriptPath;
}

test('crash inside run() produces an error envelope on disk', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-crash-test-'));
  try {
    const scriptPath = makeCrashingEnumScript(tmpDir, 'simulated crash from run()');
    // Pass --account-id so STS is not invoked; isolates the crash to run().
    const result = spawnSync('node', [
      scriptPath,
      '--run-dir', tmpDir,
      '--account-id', '123456789012',
      '--region', 'us-east-1',
    ], { encoding: 'utf-8' });

    const envelopePath = path.join(tmpDir, 'iam.json');
    assert.ok(fs.existsSync(envelopePath), `envelope file should exist at ${envelopePath}; stderr was: ${result.stderr}`);

    const env = JSON.parse(fs.readFileSync(envelopePath, 'utf-8'));
    assert.strictEqual(env.module, 'iam');
    assert.strictEqual(env.account_id, '123456789012');
    assert.strictEqual(env.region, 'us-east-1');
    assert.strictEqual(env.status, 'error');
    assert.deepStrictEqual(env.findings, []);
    assert.ok(Array.isArray(env.errors), 'errors should be an array');
    assert.strictEqual(env.errors.length, 1);
    assert.strictEqual(env.errors[0].code, 'Error');
    assert.ok(
      env.errors[0].message.includes('simulated crash from run()'),
      `expected crash message in errors[0].message, got: ${env.errors[0].message}`
    );

    // Script exits non-zero so the operator/CI sees the failure.
    assert.notStrictEqual(result.status, 0, 'crashed enum should exit non-zero');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('successful run still produces a clean envelope (regression)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-crash-test-'));
  try {
    const scriptPath = path.join(tmpDir, 'ok-enum.js');
    fs.writeFileSync(scriptPath, `
const { baseEnum } = require('${path.join(ROOT, 'scripts/lib/base-enum').replace(/\\/g, '/')}');
async function run() {
  return { findings: [], status: 'complete' };
}
baseEnum({ module: 'iam', run });
`);
    const result = spawnSync('node', [
      scriptPath,
      '--run-dir', tmpDir,
      '--account-id', '123456789012',
      '--region', 'us-east-1',
    ], { encoding: 'utf-8' });

    assert.strictEqual(result.status, 0, `expected exit 0, got ${result.status}; stderr: ${result.stderr}`);
    const env = JSON.parse(fs.readFileSync(path.join(tmpDir, 'iam.json'), 'utf-8'));
    assert.strictEqual(env.status, 'complete');
    assert.ok(!('coverage' in env), 'envelope without coverage should not include the key');
    assert.ok(!('errors' in env), 'envelope without errors should not include the key');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node test/lib-base-enum-crash.test.js`

Expected: FAIL on `crash inside run() produces an error envelope on disk` with `envelope file should exist at ... iam.json` (current base-enum.js exits 1 to stderr without writing). The second test (`successful run still produces a clean envelope`) should PASS. Exit code 1.

- [ ] **Step 3: Update `scripts/lib/base-enum.js`**

Open `scripts/lib/base-enum.js`. The current try/catch at line 61-107 covers both the success path and the multi-region path, with a single catch at the end that does `console.error` + `process.exit(1)`. Replace the catch body to also write an error envelope.

Find this block (around line 104-107):

```js
    } catch (err) {
      console.error(`Fatal error in ${module}: ${err.message}`);
      process.exit(1);
    }
```

Replace with:

```js
    } catch (err) {
      // Always-on envelope: write an error envelope to $RUN_DIR/<module>.json
      // so the operator and downstream consumers can see the failure in
      // structured form. The script still exits non-zero to surface the error.
      try {
        const envelope = createEnvelope({
          module,
          account_id: accountId || 'unknown',
          region: global ? 'global' : (args.region || 'unknown'),
          status: 'error',
          findings: [],
          coverage: [],
          errors: [{
            operation: `${module}.run`,
            resource: null,
            code: err.name || 'Error',
            message: err.message,
          }],
        });
        writeEnvelope(args.runDir, envelope);
      } catch (writeErr) {
        // Writing the error envelope failed too. Last resort: stderr.
        console.error(`Failed to write error envelope: ${writeErr.message}`);
      }
      console.error(`Fatal error in ${module}: ${err.message}`);
      process.exit(1);
    }
```

Important: this catch already has `accountId`, `args`, `module`, and `global` in scope. The new code reuses them. The STS resolution at line 47-57 still has its own `process.exit(1)` path — leave that for now (it pre-dates the try/catch and pre-resolves account_id). The acceptance criterion is: a throw inside `run()` produces an envelope on disk.

There's one more piece: the multi-region path at line 87-90 catches per-region throws but currently sets `hasErrors = true` and continues. That's fine — it eventually flows through `createEnvelope` and `writeEnvelope` at line 92-99. Leave it alone.

- [ ] **Step 4: Run tests to verify they pass**

Run: `node test/lib-base-enum-crash.test.js`

Expected: both tests pass. `2 passed, 0 failed`. Exit code 0.

Run the full suite: `node test/run-all.js`. Expected: green. All existing `enum-*.test.js` files invoke `run()` directly (not through `baseEnum`), so they don't exercise the new code path and shouldn't change behavior.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/base-enum.js test/lib-base-enum-crash.test.js

git commit -m "feat(base-enum): always emit an envelope on run() crash

base-enum.js previously exited non-zero with a stderr message when run()
threw an uncaught error, leaving no JSON on disk. Downstream consumers
(orchestrators, dashboard, attack-paths agents) had to grep logs to
discover that a module had failed.

Now: any throw inside run() produces an envelope at \$RUN_DIR/<module>.json
with status='error', findings=[], coverage=[], and errors=[] containing
the operation name, error code, and message. The script still exits
non-zero so CI and orchestrators see the failure.

When accountId resolution succeeded before the crash, the real account ID
is used. When it hadn't (pre-STS crash), the envelope uses 'unknown',
which is allowed by the schema and hook for status='error' envelopes
(Task 1).

Pre-bootstrap failures (missing --run-dir or --region) are unchanged —
they exit non-zero to stderr without an envelope because the runDir to
write to is not yet known.

Two new tests cover the crash path (envelope produced, expected shape)
and the success path (no regression, no spurious coverage/errors keys
on successful envelopes)."
```

---

## Task 5: Pilot — migrate `scripts/enum/s3.js` to `CoverageTracker` and regenerate fixture

**Files:**
- Modify: `scripts/lib/base-enum.js` (forward coverage/errors through)
- Modify: `scripts/enum/s3.js`
- Modify: `test/enum-s3.test.js` (add coverage assertions)
- Modify: `test/fixtures/enum/s3/expected.json` (regenerate)

**Single-task discipline:** the s3 code change and the fixture regeneration ship in one commit. Committing failing tests is not allowed — the test must pass at the commit point. The fixture is part of the contract change.

**Design — what s3.js needs:**

1. **Classification declarations** near the top of the file:
   ```js
   const PRIMARY_CHECKS = ['list_buckets'];
   const REQUIRED_CHECKS = ['bucket_policy', 'bucket_acl', 'public_access_block'];
   // Optional: bucket_versioning, bucket_encryption, bucket_logging
   ```

2. **CoverageTracker instance** created at the start of `run()`.

3. **Per-check recording:**
   - `ListBuckets` success → `tracker.record({ check: 'list_buckets', resource: null, status: 'ok' })`
   - `ListBuckets` failure → `tracker.recordModuleFailure({ check: 'list_buckets', operation: 'ListBuckets', errorCode, errorMessage })` then return early.
   - `GetBucketPolicy` success with policy → `tracker.record({ check: 'bucket_policy', resource: bucketArn, status: 'ok' })`. Also annotate finding: `bucketFinding.bucket_policy_status = 'present'`.
   - `GetBucketPolicy` "no policy" (NoSuchBucketPolicy) → `tracker.record({ check: 'bucket_policy', resource: bucketArn, status: 'ok' })` AND annotate `bucketFinding.bucket_policy_status = 'absent'`.
   - `GetBucketPolicy` AccessDenied → `tracker.record({ check: 'bucket_policy', resource: bucketArn, status: 'failed', operation: 'GetBucketPolicy', errorCode: 'AccessDeniedException', errorMessage: err.message })` AND annotate `bucketFinding.bucket_policy_status = 'access_denied'`.
   - `GetBucketPolicy` other error → `status: 'failed'`, errorCode = err.name. Annotate `bucketFinding.bucket_policy_status = 'error'`.
   - Same pattern for `bucket_acl`, `public_access_block`, `bucket_versioning`, `bucket_encryption`, `bucket_logging` (use the matching check names).

4. **Per-finding annotations:** every bucket finding gains six new fields: `bucket_policy_status`, `bucket_acl_status`, `public_access_block_status`, `versioning_status`, `encryption_status`, `logging_status`. Values are one of `'present' | 'absent' | 'access_denied' | 'error'`.

5. **At end of run:**
   ```js
   const status = tracker.deriveModuleStatus({ primaryChecks: PRIMARY_CHECKS, requiredChecks: REQUIRED_CHECKS });
   const { coverage, errors } = tracker.toEnvelopeFields();
   return { findings, status, coverage, errors };
   ```

6. **`base-enum.js` `createEnvelope()` call** at line 66-72 already accepts findings + status; need to pass `coverage` and `errors` through too.

**Important:** the existing `run()` already accumulates an `errors` array starting at line 157 — that's a local variable used to drive `status = 'partial'` (line 283). With the tracker in place, that local variable becomes redundant. Remove it. The tracker is the new source of truth.

Wait — also: `base-enum.js` already accepts `coverage` and `errors` in its `createEnvelope` call? Let me check. **Engineer: re-read `scripts/lib/base-enum.js` line 65-72 before starting Task 5.** If `coverage` and `errors` aren't being passed through from the `run()` result, you need to add that too. The relevant code is:

```js
const result = await run({ runDir: args.runDir, region, accountId, logger });
const envelope = createEnvelope({
  module,
  account_id: accountId,
  region,
  status: result.status || 'complete',
  findings: result.findings || [],
});
```

It needs to become:

```js
const result = await run({ runDir: args.runDir, region, accountId, logger });
const envelope = createEnvelope({
  module,
  account_id: accountId,
  region,
  status: result.status || 'complete',
  findings: result.findings || [],
  coverage: result.coverage,
  errors: result.errors,
});
```

Same change needed for the multi-region path at line 92-98. Apply both.

- [ ] **Step 1: Update `scripts/lib/base-enum.js` to pass `coverage`/`errors` through**

Open `scripts/lib/base-enum.js`. Find the single-region createEnvelope call (around line 65-72):

```js
        const result = await run({ runDir: args.runDir, region, accountId, logger });
        const envelope = createEnvelope({
          module,
          account_id: accountId,
          region,
          status: result.status || 'complete',
          findings: result.findings || [],
        });
```

Replace with:

```js
        const result = await run({ runDir: args.runDir, region, accountId, logger });
        const envelope = createEnvelope({
          module,
          account_id: accountId,
          region,
          status: result.status || 'complete',
          findings: result.findings || [],
          coverage: result.coverage,
          errors: result.errors,
        });
```

Find the multi-region accumulator block (around line 78-99). The current code accumulates `allFindings` but does not accumulate coverage or errors across regions. For Task 5's scope (single-region s3 pilot), the simplest correct behavior is: in the multi-region path, do not forward `coverage`/`errors` — they are per-region and the spec's multi-region aggregation rule is an open question (Open Question #3 in the spec). Leave the multi-region createEnvelope call unchanged:

```js
        const envelope = createEnvelope({
          module,
          account_id: accountId,
          region: 'multi',
          status: hasErrors ? 'partial' : 'complete',
          findings: allFindings,
        });
```

**Do not** add coverage/errors here. The spec explicitly defers multi-region aggregation. Document this as a known limitation in the commit message.

- [ ] **Step 2: Run all tests — should still pass (no behavior change yet for s3)**

Run: `node test/run-all.js`

Expected: green. base-enum.js now forwards `coverage` and `errors` if `run()` returns them, but no run() returns them yet — s3 hasn't been migrated. All existing fixtures pass.

If this fails, the createEnvelope change has a bug — `envelope.js` accepts `undefined` for those fields and omits them, so the output should be unchanged for existing modules. Re-read Task 2's envelope.js and confirm `coverage: result.coverage` with `result.coverage === undefined` produces a no-op.

- [ ] **Step 3: Write a behavior test for s3 with coverage**

Open `test/enum-s3.test.js`. The current test asserts `result.findings` deep-equals the expected fixture. With coverage in play, we need to also assert that the result has `coverage` and `errors` arrays. Find the assertion block (around line 50-52 — the engineer should grep for `deepStrictEqual(result.findings`) and add coverage assertions.

**Engineer: read the current `test/enum-s3.test.js` before editing.** The existing test passes a fixture-driven mock. After Task 5, `run()` will additionally return `coverage` and `errors`. Add these assertions to the existing test:

After the existing `assert.deepStrictEqual(result.findings, expected.findings);` line:

```js
    // Coverage assertions (Plan B Task 5)
    assert.ok(Array.isArray(result.coverage), 'expected result.coverage to be an array');
    assert.ok(Array.isArray(result.errors), 'expected result.errors to be an array');

    // ListBuckets succeeded → list_buckets coverage entry exists with status 'complete'
    const listBucketsEntry = result.coverage.find((c) => c.check === 'list_buckets');
    assert.ok(listBucketsEntry, 'expected list_buckets entry in coverage');
    assert.strictEqual(listBucketsEntry.status, 'complete');
    assert.strictEqual(listBucketsEntry.scope, 'per_resource');

    // Bucket policy / acl / pab checks should have entries
    for (const check of ['bucket_policy', 'bucket_acl', 'public_access_block']) {
      assert.ok(result.coverage.find((c) => c.check === check), `expected ${check} entry in coverage`);
    }

    // Status should be 'complete' for the happy-path fixture
    assert.strictEqual(result.status, 'complete');
```

- [ ] **Step 4: Run the s3 test to verify it fails**

Run: `node test/enum-s3.test.js`

Expected: FAIL — current s3.js doesn't return coverage. Error message: `expected result.coverage to be an array`. Exit code 1.

- [ ] **Step 5: Migrate `scripts/enum/s3.js`**

Open `scripts/enum/s3.js`. This is the biggest change in the plan. Read the entire current file before starting.

**Add imports at the top** (after the existing requires around line 16-18):

```js
const { CoverageTracker } = require('../lib/coverage');
```

**Add classification constants** below the imports, before `// --- Helpers ---`:

```js
// Check classification — drives module status derivation in CoverageTracker.
// Primary: the script can't enumerate anything if this fails — module status becomes 'error'.
// Required: per-bucket detail the script's purpose depends on — failures degrade to 'partial'.
// Anything not listed here is optional — failures recorded as 'skipped' do not affect status.
const PRIMARY_CHECKS = ['list_buckets'];
const REQUIRED_CHECKS = ['bucket_policy', 'bucket_acl', 'public_access_block'];
```

**Update the `run()` function** (line 132-287). The full replacement is below — paste it in over the current `run()` definition. Read it once start-to-finish before pasting; key differences from current:

- Removes local `errors` array (tracker owns errors now).
- Removes local `status` variable mutation (tracker derives at the end).
- Wraps each per-bucket API call so success/failure/absent goes through `tracker.record()`.
- Adds `<field>_status` annotations to each bucketFinding.
- Returns `{ findings, status, coverage, errors }` instead of `{ findings, status }`.

```js
async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const s3Client = opts.clients?.s3 ?? new S3Client({ region: 'us-east-1' });

  const logger = opts.logger || createLogger(runDir, 's3');
  logger.log('info', 'S3_Enumeration_Start', { region });

  const tracker = new CoverageTracker();

  // ListBuckets — primary. Failure means the module can't do its job.
  let allBuckets;
  try {
    logger.log('api_call', 'ListBuckets', { service: 's3' });
    const resp = await withRetry(() => s3Client.send(new ListBucketsCommand({})));
    allBuckets = resp.Buckets || [];
    tracker.record({ check: 'list_buckets', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'ListBuckets', { error: err.message });
    tracker.recordModuleFailure({
      check: 'list_buckets',
      operation: 'ListBuckets',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
    await logger.flush();
    const status = tracker.deriveModuleStatus({
      primaryChecks: PRIMARY_CHECKS,
      requiredChecks: REQUIRED_CHECKS,
    });
    const { coverage, errors } = tracker.toEnvelopeFields();
    return { findings: [], status, coverage, errors };
  }

  const findings = [];

  for (const bucket of allBuckets) {
    const bucketName = bucket.Name;
    const bucketArn = `arn:aws:s3:::${bucketName}`;
    let bucketRegion;

    try {
      logger.log('api_call', 'GetBucketLocation', { bucket: bucketName });
      const locResp = await withRetry(() =>
        s3Client.send(new GetBucketLocationCommand({ Bucket: bucketName }))
      );
      bucketRegion = normalizeBucketRegion(locResp.LocationConstraint);
    } catch (err) {
      logger.log('warning', 'GetBucketLocation', { bucket: bucketName, error: err.message });
      // GetBucketLocation is optional enrichment for routing — record as skipped
      // since we can't proceed with this bucket, but module status isn't impacted.
      tracker.record({
        check: 'bucket_location',
        resource: bucketArn,
        status: 'skipped',
        reason: err.name || 'error',
      });
      continue;
    }

    // Only enumerate buckets in the requested region
    if (bucketRegion !== region) continue;

    const regionalClient = s3Client;

    const bucketFinding = {
      resource_type: 's3_bucket',
      resource_id: bucketName,
      arn: bucketArn,
      region: bucketRegion,
      policy: null,
      bucket_policy_status: 'absent',
      public_access_block: null,
      public_access_block_status: 'absent',
      versioning: null,
      versioning_status: 'absent',
      encryption: null,
      encryption_status: 'absent',
      logging: null,
      logging_status: 'absent',
      acl_grants: null,
      bucket_acl_status: 'absent',
      findings: [],
    };

    // --- GetBucketPolicy (required) ---
    try {
      logger.log('api_call', 'GetBucketPolicy', { bucket: bucketName });
      const policyResp = await safeGetBucketConfig(
        () => regionalClient.send(new GetBucketPolicyCommand({ Bucket: bucketName })),
        ['NoSuchBucketPolicy']
      );
      if (policyResp) {
        bucketFinding.policy = policyResp.Policy;
        bucketFinding.bucket_policy_status = 'present';
      } else {
        bucketFinding.bucket_policy_status = 'absent';
      }
      tracker.record({ check: 'bucket_policy', resource: bucketArn, status: 'ok' });
    } catch (err) {
      const code = err.name || 'Error';
      logger.log('warning', 'GetBucketPolicy', { bucket: bucketName, error: err.message });
      bucketFinding.bucket_policy_status = code === 'AccessDenied' || code === 'AccessDeniedException'
        ? 'access_denied' : 'error';
      tracker.record({
        check: 'bucket_policy',
        resource: bucketArn,
        status: 'failed',
        operation: 'GetBucketPolicy',
        errorCode: code,
        errorMessage: err.message,
      });
    }

    // --- GetPublicAccessBlock (required) ---
    try {
      logger.log('api_call', 'GetPublicAccessBlock', { bucket: bucketName });
      const pabResp = await safeGetBucketConfig(
        () => regionalClient.send(new GetPublicAccessBlockCommand({ Bucket: bucketName })),
        ['NoSuchPublicAccessBlockConfiguration']
      );
      if (pabResp) {
        bucketFinding.public_access_block = pabResp.PublicAccessBlockConfiguration;
        bucketFinding.public_access_block_status = 'present';
      } else {
        bucketFinding.public_access_block_status = 'absent';
      }
      tracker.record({ check: 'public_access_block', resource: bucketArn, status: 'ok' });
    } catch (err) {
      const code = err.name || 'Error';
      logger.log('warning', 'GetPublicAccessBlock', { bucket: bucketName, error: err.message });
      bucketFinding.public_access_block_status = code === 'AccessDenied' || code === 'AccessDeniedException'
        ? 'access_denied' : 'error';
      tracker.record({
        check: 'public_access_block',
        resource: bucketArn,
        status: 'failed',
        operation: 'GetPublicAccessBlock',
        errorCode: code,
        errorMessage: err.message,
      });
    }

    // --- GetBucketVersioning (optional) ---
    try {
      logger.log('api_call', 'GetBucketVersioning', { bucket: bucketName });
      const verResp = await withRetry(() =>
        regionalClient.send(new GetBucketVersioningCommand({ Bucket: bucketName }))
      );
      bucketFinding.versioning = { Status: verResp.Status || null, MFADelete: verResp.MFADelete || null };
      bucketFinding.versioning_status = verResp.Status ? 'present' : 'absent';
      tracker.record({ check: 'bucket_versioning', resource: bucketArn, status: 'ok' });
    } catch (err) {
      const code = err.name || 'Error';
      logger.log('warning', 'GetBucketVersioning', { bucket: bucketName, error: err.message });
      bucketFinding.versioning_status = code === 'AccessDenied' || code === 'AccessDeniedException'
        ? 'access_denied' : 'error';
      // Optional check → record as skipped on access denied, so module status stays complete.
      if (code === 'AccessDenied' || code === 'AccessDeniedException') {
        tracker.record({
          check: 'bucket_versioning',
          resource: bucketArn,
          status: 'skipped',
          reason: 'access_denied',
        });
      } else {
        tracker.record({
          check: 'bucket_versioning',
          resource: bucketArn,
          status: 'skipped',
          reason: code,
        });
      }
    }

    // --- GetBucketEncryption (optional) ---
    try {
      logger.log('api_call', 'GetBucketEncryption', { bucket: bucketName });
      const encResp = await safeGetBucketConfig(
        () => regionalClient.send(new GetBucketEncryptionCommand({ Bucket: bucketName })),
        ['ServerSideEncryptionConfigurationNotFoundError']
      );
      if (encResp) {
        bucketFinding.encryption = encResp.ServerSideEncryptionConfiguration;
        bucketFinding.encryption_status = 'present';
      } else {
        bucketFinding.encryption_status = 'absent';
      }
      tracker.record({ check: 'bucket_encryption', resource: bucketArn, status: 'ok' });
    } catch (err) {
      const code = err.name || 'Error';
      logger.log('warning', 'GetBucketEncryption', { bucket: bucketName, error: err.message });
      bucketFinding.encryption_status = code === 'AccessDenied' || code === 'AccessDeniedException'
        ? 'access_denied' : 'error';
      tracker.record({
        check: 'bucket_encryption',
        resource: bucketArn,
        status: 'skipped',
        reason: code === 'AccessDenied' || code === 'AccessDeniedException' ? 'access_denied' : code,
      });
    }

    // --- GetBucketLogging (optional) ---
    try {
      logger.log('api_call', 'GetBucketLogging', { bucket: bucketName });
      const logResp = await withRetry(() =>
        regionalClient.send(new GetBucketLoggingCommand({ Bucket: bucketName }))
      );
      bucketFinding.logging = logResp.LoggingEnabled || null;
      bucketFinding.logging_status = logResp.LoggingEnabled ? 'present' : 'absent';
      tracker.record({ check: 'bucket_logging', resource: bucketArn, status: 'ok' });
    } catch (err) {
      const code = err.name || 'Error';
      logger.log('warning', 'GetBucketLogging', { bucket: bucketName, error: err.message });
      bucketFinding.logging_status = code === 'AccessDenied' || code === 'AccessDeniedException'
        ? 'access_denied' : 'error';
      tracker.record({
        check: 'bucket_logging',
        resource: bucketArn,
        status: 'skipped',
        reason: code === 'AccessDenied' || code === 'AccessDeniedException' ? 'access_denied' : code,
      });
    }

    // --- GetBucketAcl (required) ---
    try {
      logger.log('api_call', 'GetBucketAcl', { bucket: bucketName });
      const aclResp = await withRetry(() =>
        regionalClient.send(new GetBucketAclCommand({ Bucket: bucketName }))
      );
      bucketFinding.acl_grants = (aclResp.Grants || []).map((g) => ({
        grantee_type: g.Grantee?.Type || null,
        grantee_id: g.Grantee?.ID || null,
        grantee_uri: g.Grantee?.URI || null,
        permission: g.Permission || null,
      }));
      bucketFinding.bucket_acl_status = 'present';
      tracker.record({ check: 'bucket_acl', resource: bucketArn, status: 'ok' });
    } catch (err) {
      const code = err.name || 'Error';
      logger.log('warning', 'GetBucketAcl', { bucket: bucketName, error: err.message });
      bucketFinding.bucket_acl_status = code === 'AccessDenied' || code === 'AccessDeniedException'
        ? 'access_denied' : 'error';
      tracker.record({
        check: 'bucket_acl',
        resource: bucketArn,
        status: 'failed',
        operation: 'GetBucketAcl',
        errorCode: code,
        errorMessage: err.message,
      });
    }

    // Generate findings
    bucketFinding.findings = generateFindings(bucketFinding);
    findings.push(bucketFinding);
  }

  await logger.flush();
  const status = tracker.deriveModuleStatus({
    primaryChecks: PRIMARY_CHECKS,
    requiredChecks: REQUIRED_CHECKS,
  });
  const { coverage, errors } = tracker.toEnvelopeFields();
  return { findings, status, coverage, errors };
}
```

- [ ] **Step 6: Capture the actual output to regenerate the fixture**

The test will fail right now because `expected.json` doesn't have the new `*_status` fields, `coverage`, or `errors`. That's expected. To regenerate the fixture, capture the actual `run()` result:

Add a temporary debug print to `test/enum-s3.test.js` — right after the `const result = await run(...)` call:

```js
    // TEMPORARY — remove before commit
    require('node:fs').writeFileSync('/tmp/s3-actual.json', JSON.stringify(result, null, 2));
```

Then run: `node test/enum-s3.test.js` (will still fail on the deepStrictEqual — that's fine, we just need the file written).

Read `/tmp/s3-actual.json`. **Verify by eye before treating it as the new fixture:**

- The `findings` array has the same number of buckets as before, with all existing fields preserved.
- Each bucket finding has six new `*_status` fields. For the happy-path fixture, they should be `'present'` (when the fixture API responses return data) or `'absent'` (when they don't, e.g., NoSuchBucketPolicy).
- The `coverage` array has entries for `list_buckets` (status 'complete', scope 'per_resource'), `bucket_policy`, `bucket_acl`, `public_access_block`, plus optionally `bucket_versioning`, `bucket_encryption`, `bucket_logging` if the fixture exercises them.
- The `errors` array is empty (happy-path fixture has no API failures).
- The top-level `status` is `'complete'`.

If anything looks wrong, **stop and fix s3.js first**. Do not proceed until the actual output is what you want it to be. Rubber-stamping a buggy result into the fixture would lock the bug in.

- [ ] **Step 7: Update `test/fixtures/enum/s3/expected.json`**

Open `test/fixtures/enum/s3/expected.json` and replace its contents with the validated actual output from `/tmp/s3-actual.json`. The new fixture must have:

- `module: "s3"`, `account_id: "123456789012"`, `region: "us-east-1"`, `status: "complete"` (or whatever the tracker derived).
- The existing `findings` array, but every bucket finding now includes the six `*_status` fields with their actual values.
- A new `coverage` array matching what the tracker emitted.
- A new `errors` array (likely empty for the happy-path fixture).

Copy the JSON from `/tmp/s3-actual.json` verbatim, preserving formatting.

- [ ] **Step 8: Remove the temporary debug print**

Remove the `require('node:fs').writeFileSync(...)` line you added in step 6. The committed test file must not contain debug prints or temp paths.

- [ ] **Step 9: Run the s3 test and the full suite — both must be green before commit**

Run: `node test/enum-s3.test.js`

Expected: PASS. `1 tests: 1 passed, 0 failed`. Exit code 0.

Run: `node test/run-all.js`

Expected: all test files green end-to-end. Exit code 0.

If either fails, do NOT commit. Fix the problem first. Committing red tests is forbidden by this plan.

- [ ] **Step 10: Commit**

```bash
git add scripts/lib/base-enum.js \
        scripts/enum/s3.js \
        test/enum-s3.test.js \
        test/fixtures/enum/s3/expected.json

git commit -m "feat(s3): pilot CoverageTracker integration with regenerated fixture

scripts/enum/s3.js is the first module migrated to the per-module coverage
contract. The script now:

- Declares PRIMARY_CHECKS=['list_buckets'] and REQUIRED_CHECKS=['bucket_policy',
  'bucket_acl', 'public_access_block']. Versioning, encryption, and logging
  are optional — denials record as skipped, not failed.
- Instantiates a CoverageTracker, records per-bucket events as it enumerates,
  and derives module status from the tracker at the end.
- Annotates every bucket finding with six new <field>_status fields
  (bucket_policy_status, bucket_acl_status, public_access_block_status,
  versioning_status, encryption_status, logging_status), each one of
  'present' | 'absent' | 'access_denied' | 'error'. Downstream consumers
  can distinguish 'no policy' from 'access denied' without grepping logs.
- On ListBuckets failure, calls recordModuleFailure and returns early —
  module status becomes 'error' with a module_wide coverage entry.

scripts/lib/base-enum.js forwards result.coverage and result.errors into
createEnvelope() for the single-region path. The multi-region path does
NOT forward them — multi-region aggregation is an open question in the
spec (Open Question #3) and is deferred.

test/enum-s3.test.js gets new coverage assertions covering: list_buckets
entry present with status 'complete', bucket_policy/bucket_acl/public_access_block
entries present, top-level status 'complete' for the happy-path fixture.
test/fixtures/enum/s3/expected.json regenerated to match the new envelope
shape — full test suite is green at this commit.

This is the worked example other enum modules will follow in Plan D
(per-domain rollout)."
```

---

## Done Criteria

- All three new test files (`test/lib-envelope.test.js`, `test/lib-coverage.test.js`, `test/lib-base-enum-crash.test.js`) pass.
- `test/hook-schema-validate.test.js` and `test/schema-module-envelope.test.js` from Plan A still pass.
- `test/enum-s3.test.js` passes against the regenerated fixture.
- `node test/run-all.js` is green end-to-end.
- Five commits on `feature/v1.14-sdk-architecture`: schema/hook updates, envelope.js extension, CoverageTracker, base-enum.js crash envelope, s3 migration (with fixture regeneration in the same commit so no commit ships failing tests).
- No other enum scripts were touched. No agent prompts, no dashboard code. STS still has its existing `org_*` fields on the identity finding (deferred to a separate cleanup).

## Out of Scope

- **STS migration to coverage[].** Per the spec's deprecation window — leave `org_accessible`/`org_status`/`org_error_code` on the identity finding for one release. Migration is Plan E.
- **Other enum modules.** Plan D rolls them out per domain. They keep emitting envelopes without `coverage`/`errors` for now, which is valid since the fields are optional.
- **Downstream consumers** (4 attack-domain agents, synthesizer, dashboard). Plan C updates them to read `<field>_status` after this plan produces pilot data they can validate against.
- **Multi-region coverage aggregation.** Open Question #3 in the spec — deferred until we have real multi-region usage to design against.
- **Engagement reports / findings.md updates** to surface coverage gaps. Plan C concern.
