# Data Domain Coverage Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the five Data domain enum modules (`kms`, `secrets`, `rds`, `dynamodb`, `ssm`) to use `CoverageTracker` with per-finding `<field>_status` annotations — following the s3 worked example and Plan D Network precedent. Lift the `classifyError()` helper introduced in apigateway to a shared lib first.

**Architecture:** Same as Plan D. Each module declares `PRIMARY_CHECKS`/`REQUIRED_CHECKS`, instantiates a `CoverageTracker`, records per-resource events, annotates findings with `<field>_status` siblings (defaulting to `null`), returns `{findings, status, coverage, errors}`. Task 0 (Foundation) lifts the `classifyError()` helper from `apigateway.js` to `scripts/lib/coverage.js` so 6+ enum scripts share one definition instead of duplicating it. No schema, hook, or consumer-agent changes — those landed in Plans A/B/C.

**Tech Stack:** Same as Plan D. Node test runner, custom assertion style, JSON fixtures driven by mocked AWS SDK clients.

---

## Source spec and precedent

- **Spec:** `docs/superpowers/specs/2026-05-17-module-envelope-coverage-design.md`. AccessDenied disposition table is the operative rule.
- **Worked examples:**
  - `caacb6d` — s3 pilot (Plan B), the canonical reference.
  - `672ae85`/`a446e09` — sns (simplest single-resource-call module).
  - `d87f3bc` — sqs (same shape as sns).
  - `e6e24ea` — apigateway (multi-call complex module with two primary list ops).
- **Lessons baked in from Plan D:**
  - All `<field>_status` defaults are `null`, never `'absent'`. The states emitted by branches are `'present' | 'access_denied' | 'error'` (and optionally `'absent'` only when the API explicitly signals "no data exists" — e.g., `NoSuchBucketPolicy` for s3 was a real absent signal).
  - For optional checks, AccessDenied records as `status: 'skipped', reason: 'access_denied'` (module stays 'complete'). Required check AccessDenied records as `status: 'failed'` (module degrades to 'partial').
  - `classifyError(err)` returns `'access_denied'` when `err.name` is `AccessDenied`/`AccessDeniedException`, else `'error'`. Used only for the `<field>_status` field value — the tracker gets the raw `err.name || 'Error'` as errorCode.

## Important context

- **Project root:** `/Users/tayvionp/claude-code/SCOPE`. Branch: `feature/v1.14-sdk-architecture`.
- **Plan D Network's last commit:** `e6e24ea`. This plan builds on top.
- **Test pattern:** custom Node runner. Each module has `test/enum-<module>.test.js` + `test/fixtures/enum/<module>/{api-responses,expected}.json`. Migration includes regenerating `expected.json` via capture-verify-copy discipline.
- **Single commit per task, all tests green.** Fixture regen happens in the same commit as the code migration.
- **Other domains deferred:**
  - Compute (lambda, ec2, codebuild) — separate plan.
  - Identity (cognito, iam) — separate plan (iam may deserve its own).
  - STS migration — separate plan, has deprecation window.

## Migration template

Same as Plan D's Network plan. Read `docs/superpowers/plans/2026-05-17-network-domain-coverage-rollout.md` "Migration template" section for the six-step pattern. The pattern applies identically in this plan, except for one difference: `classifyError()` is now imported from `../lib/coverage` (after Task 0) rather than defined inline.

---

## Task 0: Lift `classifyError()` to `scripts/lib/coverage.js`

**Why this task exists:** apigateway introduced an inline `classifyError(err)` helper at `scripts/enum/apigateway.js`. Reviewer suggested lifting it when a second module needs it. Plan D-Data has 5 modules that will all use the same helper (or duplicate it). Lift once, consume many.

**Files:**
- Modify: `scripts/lib/coverage.js` — add and export `classifyError()`.
- Modify: `scripts/enum/apigateway.js` — remove inline definition, import from lib.
- Modify: `test/lib-coverage.test.js` — add unit tests for `classifyError()`.

- [ ] **Step 1: Write failing tests for `classifyError`**

Open `test/lib-coverage.test.js`. Find the existing `const { CoverageTracker } = require('../scripts/lib/coverage');` line at the top. Change it to:

```js
const { CoverageTracker, classifyError } = require('../scripts/lib/coverage');
```

After the existing tests and BEFORE the final `console.log` summary, insert:

```js
// --- classifyError ---

test('classifyError returns "access_denied" for AccessDenied', () => {
  const err = new Error('denied'); err.name = 'AccessDenied';
  assert.strictEqual(classifyError(err), 'access_denied');
});

test('classifyError returns "access_denied" for AccessDeniedException', () => {
  const err = new Error('denied'); err.name = 'AccessDeniedException';
  assert.strictEqual(classifyError(err), 'access_denied');
});

test('classifyError returns "error" for other named errors', () => {
  const err = new Error('boom'); err.name = 'ThrottlingException';
  assert.strictEqual(classifyError(err), 'error');
});

test('classifyError returns "error" for unnamed errors', () => {
  const err = new Error('boom');
  assert.strictEqual(classifyError(err), 'error');
});

test('classifyError returns "error" for null/undefined err', () => {
  assert.strictEqual(classifyError(null), 'error');
  assert.strictEqual(classifyError(undefined), 'error');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/tayvionp/claude-code/SCOPE && node test/lib-coverage.test.js`

Expected: FAIL on the 5 new `classifyError` tests because the function isn't exported yet. The existing 22 tests should still pass.

If the destructure `const { CoverageTracker, classifyError }` fails earlier (e.g., the module doesn't load), the existing 22 tests will also fail — that's fine, the next step adds the export.

- [ ] **Step 3: Add `classifyError` to `scripts/lib/coverage.js`**

Open `scripts/lib/coverage.js`. After the `VALID_RECORD_STATUSES` / `VALID_MODULE_STATUSES` constants near the top, before the `class CoverageTracker` declaration, add:

```js
/**
 * Classifies an AWS SDK error for the purpose of the `<field>_status`
 * annotation on per-resource findings. Returns 'access_denied' when the
 * error name is AccessDenied or AccessDeniedException; 'error' otherwise.
 *
 * This is for the user-facing field-status disposition only. The CoverageTracker
 * itself records the raw err.name as errorCode — the classification here is
 * an additional, coarser bucket for the finding annotation.
 */
function classifyError(err) {
  if (!err) return 'error';
  const code = err.name || err.Code || '';
  if (code === 'AccessDenied' || code === 'AccessDeniedException') return 'access_denied';
  return 'error';
}
```

Update the module exports at the bottom of the file. Current:

```js
module.exports = { CoverageTracker, VALID_RECORD_STATUSES, VALID_MODULE_STATUSES };
```

Change to:

```js
module.exports = { CoverageTracker, classifyError, VALID_RECORD_STATUSES, VALID_MODULE_STATUSES };
```

- [ ] **Step 4: Update `scripts/enum/apigateway.js` to import from lib**

Open `scripts/enum/apigateway.js`. Find the inline `classifyError` definition (the function that returns `'access_denied'` or `'error'` based on `err.name`). Delete it.

Find the `CoverageTracker` import:

```js
const { CoverageTracker } = require('../lib/coverage');
```

Change to:

```js
const { CoverageTracker, classifyError } = require('../lib/coverage');
```

All the existing call sites in apigateway.js (`classifyError(err)`) continue to work because the lifted function has the same signature.

- [ ] **Step 5: Run tests to verify everything passes**

Run: `node test/lib-coverage.test.js` — expected `27 passed, 0 failed` (22 existing + 5 new).

Run: `node test/enum-apigateway.test.js` — expected `1 tests: 1 passed, 0 failed` (apigateway still works with the lifted helper).

Run: `node test/run-all.js` — expected: green across all 25 test files.

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/coverage.js scripts/enum/apigateway.js test/lib-coverage.test.js

git commit -m "refactor(coverage): lift classifyError() helper to shared lib

apigateway.js introduced classifyError(err) as an inline helper in commit
e6e24ea. The Data domain rollout (kms, secrets, rds, dynamodb, ssm) will
need the same helper. Lifting now to scripts/lib/coverage.js avoids
duplicating five copies.

API unchanged from apigateway's inline version: returns 'access_denied'
for AccessDenied/AccessDeniedException, 'error' otherwise. Used for the
user-facing <field>_status annotation on findings — the CoverageTracker
itself records the raw err.name as errorCode, so error fidelity is
preserved end-to-end.

Five new unit tests cover both AccessDenied variants, an unrelated
named error, an unnamed error, and null/undefined input. apigateway.js
updated to import from the lib; behavior unchanged."
```

---

## Task 1: Migrate `scripts/enum/kms.js`

**Module shape:** `ListKeys` (paginated, Marker tokenKey) → per-key: `DescribeKey` (filter to customer-managed) → `GetKeyPolicy`, `ListGrants`, `GetKeyRotationStatus`.

**Classification:**
- `PRIMARY_CHECKS = ['list_keys']`
- `REQUIRED_CHECKS = ['describe_key', 'key_policy', 'grants']`
- Optional: `rotation_status` — some key types don't support rotation (`UnsupportedOperationException`). Record as `'skipped'` with `reason: 'unsupported'` when that fires.

**Per-finding annotations:** `policy_status`, `grants_status`, `rotation_status` (default `null`). The `describe_key` gate determines whether the finding exists at all — if DescribeKey fails, the key is skipped entirely (matching current behavior).

**Files:**
- Modify: `scripts/enum/kms.js`
- Modify: `test/enum-kms.test.js`
- Modify: `test/fixtures/enum/kms/expected.json`

- [ ] **Step 1: Add coverage assertions to the test**

Open `test/enum-kms.test.js`. After the existing assertion block (where the test checks `result.status` and `result.findings` against expected), insert:

```js
    // Coverage assertions (Plan D-Data Task 1)
    assert.ok(Array.isArray(result.coverage), 'expected result.coverage to be an array');
    assert.ok(Array.isArray(result.errors), 'expected result.errors to be an array');
    const listKeysEntry = result.coverage.find((c) => c.check === 'list_keys');
    assert.ok(listKeysEntry, 'expected list_keys entry in coverage');
    assert.strictEqual(listKeysEntry.status, 'complete', 'list_keys should be complete in happy-path fixture');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node test/enum-kms.test.js`

Expected: FAIL with `expected result.coverage to be an array`. Exit code 1.

- [ ] **Step 3: Migrate `scripts/enum/kms.js`**

Open the file. Replace its contents entirely with:

```js
'use strict';

const {
  KMSClient,
  ListKeysCommand,
  DescribeKeyCommand,
  GetKeyPolicyCommand,
  ListGrantsCommand,
  GetKeyRotationStatusCommand,
} = require('@aws-sdk/client-kms');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { extractPolicyPrincipals } = require('../lib/policy-parser');
const { CoverageTracker, classifyError } = require('../lib/coverage');

// Check classification.
const PRIMARY_CHECKS = ['list_keys'];
const REQUIRED_CHECKS = ['describe_key', 'key_policy', 'grants'];

// --- Helpers ---

function generateFindings(key) {
  const findings = [];

  if (!key.rotation_enabled) {
    findings.push({
      type: 'no_rotation',
      severity: 'medium',
      detail: 'Key rotation is not enabled',
    });
  }

  if (key.key_state === 'PendingDeletion') {
    findings.push({
      type: 'pending_deletion',
      severity: 'low',
      detail: 'Key is pending deletion',
    });
  }

  if (key.policy_principals && key.policy_principals.includes('*')) {
    findings.push({
      type: 'wildcard_principal',
      severity: 'high',
      detail: 'Key policy allows wildcard principal',
    });
  }

  if (key.grants && key.grants.length > 0) {
    findings.push({
      type: 'has_grants',
      severity: 'low',
      detail: `Key has ${key.grants.length} grant(s)`,
    });
  }

  return findings;
}

// --- Run (dependency-injectable) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const client = opts.clients?.kms ?? new KMSClient({ region });

  const logger = opts.logger || createLogger(runDir, 'kms');
  logger.log('info', 'KMS_Enumeration_Start', { region });

  const tracker = new CoverageTracker();
  const findings = [];

  // ListKeys — primary.
  let allKeys;
  try {
    logger.log('api_call', 'ListKeys', { service: 'kms' });
    allKeys = await paginate(client, ListKeysCommand, 'Keys', {
      tokenKey: 'Marker',
      responseTokenKey: 'NextMarker',
    });
    tracker.record({ check: 'list_keys', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'ListKeys', { error: err.message });
    tracker.recordModuleFailure({
      check: 'list_keys',
      operation: 'ListKeys',
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

  // Per-key: DescribeKey (required gate), GetKeyPolicy, ListGrants, GetKeyRotationStatus.
  for (const keyEntry of allKeys) {
    const keyId = keyEntry.KeyId;

    // DescribeKey — required gate. If it fails, skip the key entirely.
    let keyMetadata;
    try {
      logger.log('api_call', 'DescribeKey', { key_id: keyId });
      const descResp = await withRetry(() =>
        client.send(new DescribeKeyCommand({ KeyId: keyId }))
      );
      keyMetadata = descResp.KeyMetadata;
      tracker.record({ check: 'describe_key', resource: keyId, status: 'ok' });
    } catch (err) {
      logger.log('warning', 'DescribeKey', { key_id: keyId, error: err.message });
      tracker.record({
        check: 'describe_key',
        resource: keyId,
        status: 'failed',
        operation: 'DescribeKey',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
      continue;
    }

    // Skip AWS-managed keys (not a failure — just filtered out of findings).
    if (keyMetadata.KeyManager !== 'CUSTOMER') continue;

    const keyArn = keyMetadata.Arn;
    const keyFinding = {
      resource_type: 'kms_key',
      resource_id: keyId,
      arn: keyArn,
      region,
      key_state: keyMetadata.KeyState,
      usage: keyMetadata.KeyUsage,
      origin: keyMetadata.Origin,
      description: keyMetadata.Description || '',
      rotation_enabled: false,
      rotation_status: null,
      policy_principals: [],
      policy_status: null,
      grants: [],
      grants_status: null,
      findings: [],
    };

    // GetKeyPolicy — required.
    try {
      logger.log('api_call', 'GetKeyPolicy', { key_id: keyId });
      const policyResp = await withRetry(() =>
        client.send(new GetKeyPolicyCommand({ KeyId: keyId, PolicyName: 'default' }))
      );
      keyFinding.policy_principals = extractPolicyPrincipals(policyResp.Policy);
      keyFinding.policy_status = 'present';
      tracker.record({ check: 'key_policy', resource: keyArn, status: 'ok' });
    } catch (err) {
      logger.log('warning', 'GetKeyPolicy', { key_id: keyId, error: err.message });
      keyFinding.policy_status = classifyError(err);
      tracker.record({
        check: 'key_policy',
        resource: keyArn,
        status: 'failed',
        operation: 'GetKeyPolicy',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    // ListGrants — required.
    try {
      logger.log('api_call', 'ListGrants', { key_id: keyId });
      const grants = await paginate(client, ListGrantsCommand, 'Grants', {
        params: { KeyId: keyId },
        tokenKey: 'Marker',
        responseTokenKey: 'NextMarker',
      });
      keyFinding.grants = grants.map((g) => ({
        grant_id: g.GrantId,
        grantee_principal: g.GranteePrincipal,
        operations: g.Operations || [],
        retiring_principal: g.RetiringPrincipal || null,
      }));
      keyFinding.grants_status = 'present';
      tracker.record({ check: 'grants', resource: keyArn, status: 'ok' });
    } catch (err) {
      logger.log('warning', 'ListGrants', { key_id: keyId, error: err.message });
      keyFinding.grants_status = classifyError(err);
      tracker.record({
        check: 'grants',
        resource: keyArn,
        status: 'failed',
        operation: 'ListGrants',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    // GetKeyRotationStatus — optional (some key types don't support rotation).
    try {
      logger.log('api_call', 'GetKeyRotationStatus', { key_id: keyId });
      const rotResp = await withRetry(() =>
        client.send(new GetKeyRotationStatusCommand({ KeyId: keyId }))
      );
      keyFinding.rotation_enabled = rotResp.KeyRotationEnabled || false;
      keyFinding.rotation_status = 'present';
      tracker.record({ check: 'rotation_status', resource: keyArn, status: 'ok' });
    } catch (err) {
      const code = err.name || err.Code || '';
      logger.log('warning', 'GetKeyRotationStatus', { key_id: keyId, error: err.message });
      if (code === 'UnsupportedOperationException') {
        keyFinding.rotation_enabled = null;
        keyFinding.rotation_status = 'unsupported';
        tracker.record({ check: 'rotation_status', resource: keyArn, status: 'skipped', reason: 'unsupported' });
      } else {
        keyFinding.rotation_status = classifyError(err);
        tracker.record({
          check: 'rotation_status',
          resource: keyArn,
          status: 'skipped',
          reason: code === 'AccessDenied' || code === 'AccessDeniedException' ? 'access_denied' : code,
        });
      }
    }

    keyFinding.findings = generateFindings(keyFinding);
    findings.push(keyFinding);
  }

  await logger.flush();
  const status = tracker.deriveModuleStatus({
    primaryChecks: PRIMARY_CHECKS,
    requiredChecks: REQUIRED_CHECKS,
  });
  const { coverage, errors } = tracker.toEnvelopeFields();
  return { findings, status, coverage, errors };
}

if (require.main === module) {
  baseEnum({ module: 'kms', run });
}

module.exports = { run };
```

- [ ] **Step 4: Capture actual output**

Add TEMPORARY debug print to `test/enum-kms.test.js` after `const result = await run(...)`:

```js
    // TEMPORARY — remove before commit
    require('node:fs').writeFileSync('/tmp/kms-actual.json', JSON.stringify(result, null, 2));
```

Run: `node test/enum-kms.test.js`. Read `/tmp/kms-actual.json`. Verify by eye:
- Each customer-managed key finding has `policy_status`, `grants_status`, `rotation_status` fields.
- For happy-path fixture, these should be `'present'` (or `'unsupported'` for rotation_status if the fixture includes a key with UnsupportedOperationException).
- Coverage has entries for `list_keys`, `describe_key`, `key_policy`, `grants`, `rotation_status`.
- Errors empty.
- Top-level status `'complete'`.

- [ ] **Step 5: Update `test/fixtures/enum/kms/expected.json`**

Copy `/tmp/kms-actual.json` contents into `test/fixtures/enum/kms/expected.json`.

- [ ] **Step 6: Remove the temporary debug print**

```bash
grep -nE "/tmp/|TEMPORARY|writeFileSync" test/enum-kms.test.js
```

Should output nothing.

- [ ] **Step 7: Run tests**

Run: `node test/enum-kms.test.js` — expected `1 passed, 0 failed`.

Run: `node test/run-all.js` — expected: green across all 25 files.

- [ ] **Step 8: Commit**

```bash
git add scripts/enum/kms.js \
        test/enum-kms.test.js \
        test/fixtures/enum/kms/expected.json

git commit -m "feat(kms): migrate to CoverageTracker

KMS has the classic gated-enumeration shape: list_keys → describe_key
(per-key gate; AWS-managed keys filtered out) → three additional checks
(key_policy, grants, rotation_status). Classification:

- PRIMARY_CHECKS=['list_keys']
- REQUIRED_CHECKS=['describe_key', 'key_policy', 'grants']
- Optional: rotation_status — some key types don't support rotation
  (UnsupportedOperationException); records as 'skipped' with
  reason='unsupported'. AccessDenied on rotation_status also records
  as skipped (optional check disposition).

DescribeKey failure → record(failed) and skip the key entirely. This
matches the original 'continue' behavior but now produces a coverage
entry rather than a silent skip.

Per-finding annotations: policy_status, grants_status, rotation_status
all default to null. rotation_status has an additional 'unsupported'
value for the UnsupportedOperationException case.

Uses the lifted classifyError() helper from scripts/lib/coverage.js
(Plan D-Data Task 0). Full suite green."
```

---

## Task 2: Migrate `scripts/enum/secrets.js`

**Module shape:** `ListSecrets` (paginated) → per-secret: `GetResourcePolicy`. Simple, similar to sns/sqs.

**Classification:**
- `PRIMARY_CHECKS = ['list_secrets']`
- `REQUIRED_CHECKS = ['resource_policy']`
- No optional checks.

**Per-finding annotation:** `resource_policy_status` per secret (default `null`).

**Special handling:** `ResourceNotFoundException` means the secret was deleted between list and get. Current code does `continue` (skips the finding entirely). New behavior: record as `'skipped'` with `reason: 'resource_not_found'` and still emit the finding with `resource_policy_status: null` (the secret existed at list time; we know its metadata even if the resource policy lookup raced).

Actually, the simpler approach: skip the finding entirely (preserve current behavior), but record a skipped event so the coverage entry reflects it. The disposition table calls this "skipped" — the operator can see the race happened.

**Files:**
- Modify: `scripts/enum/secrets.js`
- Modify: `test/enum-secrets.test.js`
- Modify: `test/fixtures/enum/secrets/expected.json`

- [ ] **Step 1: Add coverage assertions**

Open `test/enum-secrets.test.js`. After the existing assertions, add:

```js
    // Coverage assertions (Plan D-Data Task 2)
    assert.ok(Array.isArray(result.coverage), 'expected result.coverage to be an array');
    assert.ok(Array.isArray(result.errors), 'expected result.errors to be an array');
    const listSecretsEntry = result.coverage.find((c) => c.check === 'list_secrets');
    assert.ok(listSecretsEntry, 'expected list_secrets entry in coverage');
    assert.strictEqual(listSecretsEntry.status, 'complete', 'list_secrets should be complete in happy-path fixture');
```

- [ ] **Step 2: Run test to verify it fails**

`node test/enum-secrets.test.js`. Expected: FAIL on `expected result.coverage to be an array`.

- [ ] **Step 3: Migrate `scripts/enum/secrets.js`**

Replace the file contents with:

```js
'use strict';

const {
  SecretsManagerClient,
  ListSecretsCommand,
  GetResourcePolicyCommand,
} = require('@aws-sdk/client-secrets-manager');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { extractPolicyPrincipals } = require('../lib/policy-parser');
const { CoverageTracker, classifyError } = require('../lib/coverage');

// Check classification.
const PRIMARY_CHECKS = ['list_secrets'];
const REQUIRED_CHECKS = ['resource_policy'];

// --- Helpers ---

function generateFindings(secret) {
  const findings = [];

  if (!secret.rotation_enabled) {
    findings.push({
      type: 'no_rotation',
      severity: 'medium',
      detail: 'Secret rotation is not enabled',
    });
  }

  if (secret.resource_policy_principals && secret.resource_policy_principals.includes('*')) {
    findings.push({
      type: 'wildcard_principal',
      severity: 'high',
      detail: 'Secret resource policy allows wildcard principal',
    });
  }

  if (secret.last_accessed_date) {
    const daysSinceAccess = Math.floor(
      (Date.now() - new Date(secret.last_accessed_date).getTime()) / (1000 * 60 * 60 * 24)
    );
    if (daysSinceAccess >= 90) {
      findings.push({
        type: 'stale_secret',
        severity: 'low',
        detail: `Secret not accessed in ${daysSinceAccess} days`,
      });
    }
  }

  return findings;
}

// --- Run (dependency-injectable) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const client = opts.clients?.secrets ?? new SecretsManagerClient({ region });

  const logger = opts.logger || createLogger(runDir, 'secrets');
  logger.log('info', 'Secrets_Enumeration_Start', { region });

  const tracker = new CoverageTracker();
  const findings = [];

  // ListSecrets — primary.
  let allSecrets;
  try {
    logger.log('api_call', 'ListSecrets', { service: 'secretsmanager' });
    allSecrets = await paginate(client, ListSecretsCommand, 'SecretList', {});
    tracker.record({ check: 'list_secrets', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'ListSecrets', { error: err.message });
    tracker.recordModuleFailure({
      check: 'list_secrets',
      operation: 'ListSecrets',
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

  // Per-secret: GetResourcePolicy (required).
  for (const secret of allSecrets) {
    const secretName = secret.Name;
    const secretArn = secret.ARN;

    const secretFinding = {
      resource_type: 'secrets_secret',
      resource_id: secretName,
      arn: secretArn,
      region,
      rotation_enabled: secret.RotationEnabled || false,
      last_rotated_date: secret.LastRotatedDate?.toISOString() || null,
      last_accessed_date: secret.LastAccessedDate?.toISOString() || null,
      kms_key_id: secret.KmsKeyId || null,
      resource_policy_principals: [],
      resource_policy_status: null,
      findings: [],
    };

    try {
      logger.log('api_call', 'GetResourcePolicy', { secret: secretName });
      const policyResp = await withRetry(() =>
        client.send(new GetResourcePolicyCommand({ SecretId: secretArn }))
      );
      if (policyResp.ResourcePolicy) {
        secretFinding.resource_policy_principals = extractPolicyPrincipals(policyResp.ResourcePolicy);
        secretFinding.resource_policy_status = 'present';
      } else {
        secretFinding.resource_policy_status = 'absent';
      }
      tracker.record({ check: 'resource_policy', resource: secretArn, status: 'ok' });
    } catch (err) {
      const code = err.name || err.Code || '';
      if (code === 'ResourceNotFoundException') {
        // Secret deleted between list and get — race condition, not a failure.
        logger.log('warning', 'GetResourcePolicy', { secret: secretName, error: 'ResourceNotFound' });
        tracker.record({
          check: 'resource_policy',
          resource: secretArn,
          status: 'skipped',
          reason: 'resource_not_found',
        });
        continue;
      }
      logger.log('warning', 'GetResourcePolicy', { secret: secretName, error: err.message });
      secretFinding.resource_policy_status = classifyError(err);
      tracker.record({
        check: 'resource_policy',
        resource: secretArn,
        status: 'failed',
        operation: 'GetResourcePolicy',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    secretFinding.findings = generateFindings(secretFinding);
    findings.push(secretFinding);
  }

  await logger.flush();
  const status = tracker.deriveModuleStatus({
    primaryChecks: PRIMARY_CHECKS,
    requiredChecks: REQUIRED_CHECKS,
  });
  const { coverage, errors } = tracker.toEnvelopeFields();
  return { findings, status, coverage, errors };
}

if (require.main === module) {
  baseEnum({ module: 'secrets', run });
}

module.exports = { run };
```

- [ ] **Step 4: Capture and verify actual output**

Add TEMPORARY debug print, run, read `/tmp/secrets-actual.json`. Each secret finding should have `resource_policy_status` set to `'present'` (if the fixture's secret has a policy) or `'absent'` (if not). Coverage should have `list_secrets` and `resource_policy` entries.

- [ ] **Step 5: Update `test/fixtures/enum/secrets/expected.json`**

Copy validated `/tmp/secrets-actual.json` into the fixture.

- [ ] **Step 6: Remove debug print**

```bash
grep -nE "/tmp/|TEMPORARY|writeFileSync" test/enum-secrets.test.js
```
Should output nothing.

- [ ] **Step 7: Run tests**

Both `node test/enum-secrets.test.js` and `node test/run-all.js` must be green.

- [ ] **Step 8: Commit**

```bash
git add scripts/enum/secrets.js \
        test/enum-secrets.test.js \
        test/fixtures/enum/secrets/expected.json

git commit -m "feat(secrets): migrate to CoverageTracker

Simple single-resource-call shape, same as sns/sqs. PRIMARY=['list_secrets'],
REQUIRED=['resource_policy']. Per-secret annotation:
resource_policy_status (null default; 'present' when policy returned;
'absent' when API returned no policy; 'access_denied'/'error' on failure).

Race-condition handling: ResourceNotFoundException (secret deleted
between list and get) records as 'skipped' with reason='resource_not_found'
and continues. Operator sees the race in coverage but module status
stays clean. This preserves the existing 'continue' behavior."
```

---

## Task 3: Migrate `scripts/enum/rds.js`

**Module shape:** TWO list operations (similar to apigateway): `DescribeDBInstances` and `DescribeDBSnapshots`. Per-snapshot: `DescribeDBSnapshotAttributes` (drives public/shared determination).

**Classification:**
- `PRIMARY_CHECKS = ['describe_db_instances']` — instances are the primary surface; without them the module has no findings.
- `REQUIRED_CHECKS = ['describe_db_snapshots', 'snapshot_attributes']` — snapshots are second-class; their list failing should degrade to 'partial' (matches current code's behavior where DescribeDBSnapshots failure set status partial).

**Per-finding annotations:**
- Instance findings: no `<field>_status` — instances are a single API call with all data inline.
- Snapshot findings: `snapshot_attributes_status` (null default; `'present'` when attributes returned; `'access_denied'`/`'error'` on failure).

**Files:**
- Modify: `scripts/enum/rds.js`
- Modify: `test/enum-rds.test.js`
- Modify: `test/fixtures/enum/rds/expected.json`

- [ ] **Step 1: Add coverage assertions**

Open `test/enum-rds.test.js`. Add after existing assertions:

```js
    // Coverage assertions (Plan D-Data Task 3)
    assert.ok(Array.isArray(result.coverage), 'expected result.coverage to be an array');
    assert.ok(Array.isArray(result.errors), 'expected result.errors to be an array');
    const instancesEntry = result.coverage.find((c) => c.check === 'describe_db_instances');
    assert.ok(instancesEntry, 'expected describe_db_instances entry in coverage');
    assert.strictEqual(instancesEntry.status, 'complete', 'describe_db_instances should be complete in happy-path fixture');
    const snapshotsEntry = result.coverage.find((c) => c.check === 'describe_db_snapshots');
    assert.ok(snapshotsEntry, 'expected describe_db_snapshots entry in coverage');
```

- [ ] **Step 2: Run test to verify it fails**

Expected: FAIL on `expected result.coverage to be an array`.

- [ ] **Step 3: Migrate `scripts/enum/rds.js`**

Replace the file contents with:

```js
'use strict';

const {
  RDSClient,
  DescribeDBInstancesCommand,
  DescribeDBSnapshotsCommand,
  DescribeDBSnapshotAttributesCommand,
} = require('@aws-sdk/client-rds');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { CoverageTracker, classifyError } = require('../lib/coverage');

// Check classification.
const PRIMARY_CHECKS = ['describe_db_instances'];
const REQUIRED_CHECKS = ['describe_db_snapshots', 'snapshot_attributes'];

// --- Findings generation ---

function generateInstanceFindings(instance) {
  const findings = [];

  if (instance.publicly_accessible) {
    findings.push({ type: 'publicly_accessible', severity: 'high', detail: 'DB instance is publicly accessible' });
  }
  if (!instance.storage_encrypted) {
    findings.push({ type: 'no_encryption', severity: 'high', detail: 'DB instance storage is not encrypted' });
  }
  if (!instance.iam_auth_enabled) {
    findings.push({ type: 'no_iam_auth', severity: 'low', detail: 'IAM authentication is not enabled' });
  }
  if (!instance.deletion_protection) {
    findings.push({ type: 'no_deletion_protection', severity: 'low', detail: 'Deletion protection is not enabled' });
  }

  return findings;
}

function generateSnapshotFindings(snapshot) {
  const findings = [];

  if (snapshot.public) {
    findings.push({ type: 'public_snapshot', severity: 'critical', detail: 'DB snapshot is publicly accessible (shared with all)' });
  }
  if (!snapshot.encrypted) {
    findings.push({ type: 'unencrypted_snapshot', severity: 'high', detail: 'DB snapshot is not encrypted' });
  }
  if (snapshot.shared_with && snapshot.shared_with.length > 0) {
    findings.push({ type: 'shared_snapshot', severity: 'medium', detail: `Snapshot shared with ${snapshot.shared_with.length} account(s)` });
  }

  return findings;
}

// --- Run (dependency-injectable) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const client = opts.clients?.rds ?? new RDSClient({ region });

  const logger = opts.logger || createLogger(runDir, 'rds');
  logger.log('info', 'RDS_Enumeration_Start', { region });

  const tracker = new CoverageTracker();
  const findings = [];

  // --- DB Instances (primary) ---
  let allInstances;
  try {
    logger.log('api_call', 'DescribeDBInstances', { service: 'rds' });
    allInstances = await paginate(client, DescribeDBInstancesCommand, 'DBInstances', {
      tokenKey: 'Marker',
      responseTokenKey: 'Marker',
    });
    tracker.record({ check: 'describe_db_instances', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'DescribeDBInstances', { error: err.message });
    tracker.recordModuleFailure({
      check: 'describe_db_instances',
      operation: 'DescribeDBInstances',
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

  for (const db of allInstances) {
    const instanceFinding = {
      resource_type: 'rds_instance',
      resource_id: db.DBInstanceIdentifier,
      arn: db.DBInstanceArn,
      region,
      engine: db.Engine,
      engine_version: db.EngineVersion,
      publicly_accessible: db.PubliclyAccessible || false,
      storage_encrypted: db.StorageEncrypted || false,
      kms_key_id: db.KmsKeyId || null,
      iam_auth_enabled: db.IAMDatabaseAuthenticationEnabled || false,
      deletion_protection: db.DeletionProtection || false,
      security_groups: (db.VpcSecurityGroups || []).map((sg) => ({
        id: sg.VpcSecurityGroupId,
        status: sg.Status,
      })),
      multi_az: db.MultiAZ || false,
      findings: [],
    };

    instanceFinding.findings = generateInstanceFindings(instanceFinding);
    findings.push(instanceFinding);
  }

  // --- DB Snapshots (required, manual only) ---
  let allSnapshots = [];
  try {
    logger.log('api_call', 'DescribeDBSnapshots', { service: 'rds', type: 'manual' });
    allSnapshots = await paginate(client, DescribeDBSnapshotsCommand, 'DBSnapshots', {
      params: { SnapshotType: 'manual' },
      tokenKey: 'Marker',
      responseTokenKey: 'Marker',
    });
    tracker.record({ check: 'describe_db_snapshots', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'DescribeDBSnapshots', { error: err.message });
    tracker.record({
      check: 'describe_db_snapshots',
      resource: null,
      status: 'failed',
      operation: 'DescribeDBSnapshots',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
  }

  for (const snap of allSnapshots) {
    const snapshotArn = snap.DBSnapshotArn;
    const snapshotFinding = {
      resource_type: 'rds_snapshot',
      resource_id: snap.DBSnapshotIdentifier,
      arn: snapshotArn,
      region,
      engine: snap.Engine,
      encrypted: snap.Encrypted || false,
      kms_key_id: snap.KmsKeyId || null,
      db_instance_identifier: snap.DBInstanceIdentifier,
      public: false,
      shared_with: [],
      snapshot_attributes_status: null,
      findings: [],
    };

    // DescribeDBSnapshotAttributes (required) — drives public/shared determination.
    try {
      logger.log('api_call', 'DescribeDBSnapshotAttributes', { snapshot: snap.DBSnapshotIdentifier });
      const attrResp = await withRetry(() =>
        client.send(new DescribeDBSnapshotAttributesCommand({
          DBSnapshotIdentifier: snap.DBSnapshotIdentifier,
        }))
      );
      const attrResult = attrResp.DBSnapshotAttributesResult;
      if (attrResult && attrResult.DBSnapshotAttributes) {
        for (const attr of attrResult.DBSnapshotAttributes) {
          if (attr.AttributeName === 'restore') {
            const values = attr.AttributeValues || [];
            if (values.includes('all')) snapshotFinding.public = true;
            snapshotFinding.shared_with = values.filter((v) => v !== 'all');
          }
        }
      }
      snapshotFinding.snapshot_attributes_status = 'present';
      tracker.record({ check: 'snapshot_attributes', resource: snapshotArn, status: 'ok' });
    } catch (err) {
      logger.log('warning', 'DescribeDBSnapshotAttributes', {
        snapshot: snap.DBSnapshotIdentifier,
        error: err.message,
      });
      snapshotFinding.snapshot_attributes_status = classifyError(err);
      tracker.record({
        check: 'snapshot_attributes',
        resource: snapshotArn,
        status: 'failed',
        operation: 'DescribeDBSnapshotAttributes',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    snapshotFinding.findings = generateSnapshotFindings(snapshotFinding);
    findings.push(snapshotFinding);
  }

  await logger.flush();
  const status = tracker.deriveModuleStatus({
    primaryChecks: PRIMARY_CHECKS,
    requiredChecks: REQUIRED_CHECKS,
  });
  const { coverage, errors } = tracker.toEnvelopeFields();
  return { findings, status, coverage, errors };
}

if (require.main === module) {
  baseEnum({ module: 'rds', run });
}

module.exports = { run };
```

- [ ] **Step 4: Capture actual output**

Add TEMPORARY debug print, run, read `/tmp/rds-actual.json`. Verify:
- Instance findings have no `*_status` field (no per-call annotation needed for single-call resources).
- Snapshot findings have `snapshot_attributes_status: 'present'` (happy path).
- Coverage has `describe_db_instances`, `describe_db_snapshots`, and `snapshot_attributes` (if the fixture has snapshots).
- Top-level status `'complete'`.

- [ ] **Step 5: Update fixture**

Copy validated output to `test/fixtures/enum/rds/expected.json`.

- [ ] **Step 6: Remove debug print**

Grep should return nothing.

- [ ] **Step 7: Run tests**

Both green.

- [ ] **Step 8: Commit**

```bash
git add scripts/enum/rds.js \
        test/enum-rds.test.js \
        test/fixtures/enum/rds/expected.json

git commit -m "feat(rds): migrate to CoverageTracker

RDS has two list operations: DescribeDBInstances (primary — the main
surface) and DescribeDBSnapshots (required but secondary). The original
code treated DescribeDBSnapshots failure as 'partial', matching the
new classification:

- PRIMARY_CHECKS=['describe_db_instances'] — instance list failure
  becomes status=error via recordModuleFailure + early return.
- REQUIRED_CHECKS=['describe_db_snapshots', 'snapshot_attributes'] —
  either failure degrades module to 'partial'.

Snapshot findings get a snapshot_attributes_status annotation tracking
the per-snapshot DescribeDBSnapshotAttributes call. Instance findings
have no <field>_status — instances are a single API call, no per-detail
annotations needed.

Local errors[] / let status removed; tracker is the source of truth."
```

---

## Task 4: Migrate `scripts/enum/dynamodb.js`

**Module shape:** `ListTables` (custom pagination via ExclusiveStartTableName) → per-table: `DescribeTable` (required gate), `DescribeContinuousBackups`, `ListBackups`, `GetResourcePolicy`.

**Note:** The original code already swallows errors from `DescribeContinuousBackups`, `ListBackups`, and `GetResourcePolicy` silently (returns `null`/`0`). These are effectively optional today. The migration formalizes that.

**Classification:**
- `PRIMARY_CHECKS = ['list_tables']`
- `REQUIRED_CHECKS = ['describe_table']` — without DescribeTable, no finding for the table.
- Optional: `continuous_backups`, `list_backups`, `resource_policy` — all currently silently fail; record as `'skipped'` on AccessDenied.

**Per-finding annotations:**
- `continuous_backups_status`, `backups_status`, `resource_policy_status` — default `null`.
- No annotation for DescribeTable since it's the gate (failure means no finding at all).

**Files:**
- Modify: `scripts/enum/dynamodb.js`
- Modify: `test/enum-dynamodb.test.js`
- Modify: `test/fixtures/enum/dynamodb/expected.json`

- [ ] **Step 1: Add coverage assertions**

```js
    // Coverage assertions (Plan D-Data Task 4)
    assert.ok(Array.isArray(result.coverage), 'expected result.coverage to be an array');
    assert.ok(Array.isArray(result.errors), 'expected result.errors to be an array');
    const listTablesEntry = result.coverage.find((c) => c.check === 'list_tables');
    assert.ok(listTablesEntry, 'expected list_tables entry in coverage');
    assert.strictEqual(listTablesEntry.status, 'complete', 'list_tables should be complete in happy-path fixture');
```

- [ ] **Step 2: Run to verify fail**

Expected: FAIL on `expected result.coverage to be an array`.

- [ ] **Step 3: Migrate `scripts/enum/dynamodb.js`**

Replace the file with:

```js
'use strict';

const {
  DynamoDBClient,
  ListTablesCommand,
  DescribeTableCommand,
  DescribeContinuousBackupsCommand,
  ListBackupsCommand,
  GetResourcePolicyCommand,
} = require('@aws-sdk/client-dynamodb');

const { withRetry, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { CoverageTracker, classifyError } = require('../lib/coverage');

// Check classification.
const PRIMARY_CHECKS = ['list_tables'];
const REQUIRED_CHECKS = ['describe_table'];

// --- Pagination for ListTables (uses ExclusiveStartTableName, not NextToken) ---

async function listAllTables(client, logger) {
  const allTables = [];
  let exclusiveStart = undefined;

  do {
    const params = {};
    if (exclusiveStart) params.ExclusiveStartTableName = exclusiveStart;

    logger.log('api_call', 'ListTables', { ExclusiveStartTableName: exclusiveStart || null });
    const response = await withRetry(() => client.send(new ListTablesCommand(params)));

    if (Array.isArray(response.TableNames)) allTables.push(...response.TableNames);

    exclusiveStart = response.LastEvaluatedTableName || null;
  } while (exclusiveStart);

  return allTables;
}

// --- Run (exported for testing) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const logger = opts.logger || createLogger(runDir, 'dynamodb');
  const client = opts.clients?.dynamodb ?? new DynamoDBClient({ region });

  const tracker = new CoverageTracker();
  const findings = [];

  // ListTables — primary.
  let tableNames;
  try {
    tableNames = await listAllTables(client, logger);
    tracker.record({ check: 'list_tables', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'ListTables', { error: err.message });
    tracker.recordModuleFailure({
      check: 'list_tables',
      operation: 'ListTables',
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

  logger.log('info', 'TablesDiscovered', { count: tableNames.length });

  for (const tableName of tableNames) {
    // DescribeTable — required gate.
    let table;
    try {
      logger.log('api_call', 'DescribeTable', { table: tableName });
      const response = await withRetry(() =>
        client.send(new DescribeTableCommand({ TableName: tableName }))
      );
      table = response.Table;
      tracker.record({ check: 'describe_table', resource: tableName, status: 'ok' });
    } catch (err) {
      logger.log('error', 'DescribeTable_Failed', { table: tableName, error: err.message });
      tracker.record({
        check: 'describe_table',
        resource: tableName,
        status: 'failed',
        operation: 'DescribeTable',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
      continue;
    }

    const tableArn = table.TableArn;

    // Encryption / streams / global / deletion protection / table class — all from DescribeTable.
    const sse = table.SSEDescription || {};
    const encryptionType = sse.SSEType || 'AES256';
    const kmsKeyId = sse.KMSMasterKeyArn || null;
    const streamSpec = table.StreamSpecification || {};
    const streamEnabled = streamSpec.StreamEnabled || false;
    const streamViewType = streamSpec.StreamViewType || null;
    const isGlobalTable = !!(table.GlobalTableVersion || (table.Replicas && table.Replicas.length > 0));
    const replicas = (table.Replicas || []).map((r) => ({ region: r.RegionName, status: r.ReplicaStatus }));
    const deletionProtection = table.DeletionProtectionEnabled || false;
    const tableClass = table.TableClassSummary?.TableClass || 'STANDARD';

    const tableFinding = {
      resource_type: 'dynamodb_table',
      resource_id: tableName,
      arn: tableArn,
      region,
      encryption_type: encryptionType,
      kms_key_id: kmsKeyId,
      stream_enabled: streamEnabled,
      stream_view_type: streamViewType,
      is_global_table: isGlobalTable,
      replicas,
      deletion_protection: deletionProtection,
      table_class: tableClass,
      point_in_time_recovery: null,
      continuous_backups_status_value: null,
      continuous_backups_status: null,
      backup_count: 0,
      backups_status: null,
      resource_policy: null,
      resource_policy_status: null,
      findings: [],
    };

    // DescribeContinuousBackups — optional.
    try {
      logger.log('api_call', 'DescribeContinuousBackups', { table: tableName });
      const response = await withRetry(() =>
        client.send(new DescribeContinuousBackupsCommand({ TableName: tableName }))
      );
      const desc = response.ContinuousBackupsDescription;
      if (desc) {
        tableFinding.continuous_backups_status_value = desc.ContinuousBackupsStatus || null;
        tableFinding.point_in_time_recovery =
          desc.PointInTimeRecoveryDescription?.PointInTimeRecoveryStatus === 'ENABLED';
      }
      tableFinding.continuous_backups_status = 'present';
      tracker.record({ check: 'continuous_backups', resource: tableArn, status: 'ok' });
    } catch (err) {
      logger.log('warning', 'DescribeContinuousBackups_Failed', { table: tableName, error: err.message });
      tableFinding.continuous_backups_status = classifyError(err);
      tracker.record({
        check: 'continuous_backups',
        resource: tableArn,
        status: 'skipped',
        reason: tableFinding.continuous_backups_status,
      });
    }

    // ListBackups — optional.
    try {
      logger.log('api_call', 'ListBackups', { table: tableName });
      const response = await withRetry(() =>
        client.send(new ListBackupsCommand({ TableName: tableName }))
      );
      tableFinding.backup_count = response.BackupSummaries ? response.BackupSummaries.length : 0;
      tableFinding.backups_status = 'present';
      tracker.record({ check: 'list_backups', resource: tableArn, status: 'ok' });
    } catch (err) {
      logger.log('warning', 'ListBackups_Failed', { table: tableName, error: err.message });
      tableFinding.backups_status = classifyError(err);
      tracker.record({
        check: 'list_backups',
        resource: tableArn,
        status: 'skipped',
        reason: tableFinding.backups_status,
      });
    }

    // GetResourcePolicy — optional.
    try {
      logger.log('api_call', 'GetResourcePolicy', { arn: tableArn });
      const response = await withRetry(() =>
        client.send(new GetResourcePolicyCommand({ ResourceArn: tableArn }))
      );
      if (response.Policy) {
        try {
          tableFinding.resource_policy = JSON.parse(response.Policy);
        } catch {
          tableFinding.resource_policy = response.Policy;
        }
        tableFinding.resource_policy_status = 'present';
      } else {
        tableFinding.resource_policy_status = 'absent';
      }
      tracker.record({ check: 'resource_policy', resource: tableArn, status: 'ok' });
    } catch (err) {
      const code = err.name || err.Code || '';
      if (code === 'ResourceNotFoundException' || code === 'PolicyNotFoundException' ||
          code === 'UnknownOperationException') {
        tableFinding.resource_policy_status = 'absent';
        tracker.record({ check: 'resource_policy', resource: tableArn, status: 'ok' });
      } else {
        logger.log('warning', 'GetResourcePolicy_Failed', { arn: tableArn, error: err.message });
        tableFinding.resource_policy_status = classifyError(err);
        tracker.record({
          check: 'resource_policy',
          resource: tableArn,
          status: 'skipped',
          reason: tableFinding.resource_policy_status,
        });
      }
    }

    findings.push(tableFinding);
  }

  await logger.flush();
  const status = tracker.deriveModuleStatus({
    primaryChecks: PRIMARY_CHECKS,
    requiredChecks: REQUIRED_CHECKS,
  });
  const { coverage, errors } = tracker.toEnvelopeFields();
  return { findings, status, coverage, errors };
}

if (require.main === module) {
  baseEnum({ module: 'dynamodb', run });
}

module.exports = { run };
```

Note: the `continuous_backups_status_value` field preserves the original data (the AWS attribute named `ContinuousBackupsStatus`, with values like `'ENABLED'`/`'DISABLED'`) while `continuous_backups_status` is the new disposition-status field (`'present'`/`'absent'`/`'access_denied'`/`'error'`). The name collision in the original code (`continuous_backups_status` was being used for the AWS data field) is the reason for the rename.

- [ ] **Step 4: Capture actual output**

Add TEMPORARY debug print, run, read `/tmp/dynamodb-actual.json`. Verify table findings have the three new status fields and coverage has entries for list_tables, describe_table, continuous_backups, list_backups, resource_policy.

- [ ] **Step 5: Update fixture**

Copy validated output to `test/fixtures/enum/dynamodb/expected.json`.

- [ ] **Step 6: Remove debug print**

Grep should return nothing.

- [ ] **Step 7: Run tests**

Both green.

- [ ] **Step 8: Commit**

```bash
git add scripts/enum/dynamodb.js \
        test/enum-dynamodb.test.js \
        test/fixtures/enum/dynamodb/expected.json

git commit -m "feat(dynamodb): migrate to CoverageTracker

DynamoDB has the most optional-heavy shape in the Data domain: ListTables
→ DescribeTable (required gate) → three best-effort calls
(DescribeContinuousBackups, ListBackups, GetResourcePolicy). The original
code already swallowed errors from the three best-effort calls silently;
the migration formalizes that by recording them as 'skipped' on failure,
which keeps module status 'complete' (optional check disposition).

- PRIMARY_CHECKS=['list_tables']
- REQUIRED_CHECKS=['describe_table'] — DescribeTable failure means the
  table is skipped entirely (matches original 'continue' behavior).
- Optional: continuous_backups, list_backups, resource_policy.

Per-finding annotations on tables: continuous_backups_status,
backups_status, resource_policy_status (all default null).

Naming collision fix: the original code used 'continuous_backups_status'
for the AWS-returned attribute (ENABLED/DISABLED). That field is renamed
to 'continuous_backups_status_value' (preserves the data) so the new
disposition-status field can use the conventional name. Downstream
consumers reading the original field will need updating in a follow-up
if they exist; grep found none in the current codebase."
```

**Important:** the implementer should grep for any reader of the original `continuous_backups_status` field before committing. If found, either rename the reader too or revert the rename and pick a different name for the disposition field.

- [ ] **Step 8a: Pre-commit check for stale field readers**

```bash
grep -rn "continuous_backups_status" --include="*.js" --include="*.md" --include="*.json" \
  scripts/ agents/ dashboard/ test/ config/ 2>&1 | grep -v "continuous_backups_status_value" | grep -v "dynamodb.js"
```

Expected: only the new `dynamodb.js` reference (which is the disposition field) plus any test/fixture references for the new shape. If anything else shows up that reads the original ENABLED/DISABLED value, address it before committing — either rename that reader to `continuous_backups_status_value` or rename the disposition field in `dynamodb.js` to something else (e.g., `continuous_backups_check_status`).

---

## Task 5: Migrate `scripts/enum/ssm.js`

**Module shape:** `DescribeParameters` (paginated) → per-parameter: `GetResourcePolicies`. The resource-policy call mostly returns AccessDenied/InvalidResourceId because AWS only supports resource policies on OpsItemGroup (not parameters). This is documented in the existing code.

**Classification:**
- `PRIMARY_CHECKS = ['describe_parameters']`
- `REQUIRED_CHECKS = []` — parameter metadata IS the data; it comes from the list response. No per-resource required check.
- Optional: `resource_policy` — AWS doesn't really support this for parameters; failures are normal. Record as `'skipped'` with the right reason.

**Per-finding annotation:** `resource_policy_status` per parameter (default `null`).

**Files:**
- Modify: `scripts/enum/ssm.js`
- Modify: `test/enum-ssm.test.js`
- Modify: `test/fixtures/enum/ssm/expected.json`

- [ ] **Step 1: Add coverage assertions**

```js
    // Coverage assertions (Plan D-Data Task 5)
    assert.ok(Array.isArray(result.coverage), 'expected result.coverage to be an array');
    assert.ok(Array.isArray(result.errors), 'expected result.errors to be an array');
    const describeEntry = result.coverage.find((c) => c.check === 'describe_parameters');
    assert.ok(describeEntry, 'expected describe_parameters entry in coverage');
    assert.strictEqual(describeEntry.status, 'complete', 'describe_parameters should be complete in happy-path fixture');
```

- [ ] **Step 2: Run to verify fail**

Expected: FAIL on `expected result.coverage to be an array`.

- [ ] **Step 3: Migrate `scripts/enum/ssm.js`**

Replace the file with:

```js
'use strict';

const {
  SSMClient,
  DescribeParametersCommand,
  GetResourcePoliciesCommand,
} = require('@aws-sdk/client-ssm');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { CoverageTracker, classifyError } = require('../lib/coverage');

// Check classification.
// SSM Parameter Store metadata IS the data — DescribeParameters returns names,
// types, KMS keys, modification dates, etc. The per-parameter GetResourcePolicies
// call only works for OpsItemGroup, not parameters, so it's always-best-effort.
const PRIMARY_CHECKS = ['describe_parameters'];
const REQUIRED_CHECKS = [];

// --- Run (exported for testing) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const logger = opts.logger || createLogger(runDir, 'ssm');
  const client = opts.clients?.ssm ?? new SSMClient({ region });

  const tracker = new CoverageTracker();
  const findings = [];

  // DescribeParameters — primary. Metadata only, never reads values.
  let parameters;
  try {
    logger.log('api_call', 'DescribeParameters', { note: 'metadata only — no value access' });
    parameters = await paginate(client, DescribeParametersCommand, 'Parameters', {
      tokenKey: 'NextToken',
      responseTokenKey: 'NextToken',
    });
    tracker.record({ check: 'describe_parameters', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'DescribeParameters', { error: err.message });
    tracker.recordModuleFailure({
      check: 'describe_parameters',
      operation: 'DescribeParameters',
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

  logger.log('info', 'ParametersDiscovered', { count: parameters.length });

  for (const param of parameters) {
    const paramArn = `arn:aws:ssm:${region}:${accountId}:parameter${param.Name.startsWith('/') ? '' : '/'}${param.Name}`;
    const kmsKeyId = param.Type === 'SecureString' ? (param.KeyId || 'alias/aws/ssm') : null;

    const paramFinding = {
      resource_type: 'ssm_parameter',
      resource_id: param.Name,
      arn: paramArn,
      region,
      type: param.Type || null,
      tier: param.Tier || 'Standard',
      kms_key_id: kmsKeyId,
      data_type: param.DataType || null,
      last_modified: param.LastModifiedDate ? (param.LastModifiedDate instanceof Date ? param.LastModifiedDate.toISOString() : String(param.LastModifiedDate)) : null,
      version: param.Version || null,
      has_resource_policy: false,
      resource_policy: null,
      resource_policy_status: null,
      findings: [],
    };

    // GetResourcePolicies — optional. AWS only supports resource policies on
    // OpsItemGroup, not parameters; typical responses for parameters are
    // AccessDenied / InvalidResourceId / ResourceNotFoundException.
    try {
      logger.log('api_call', 'GetResourcePolicies', { parameter: param.Name });
      const response = await withRetry(() =>
        client.send(new GetResourcePoliciesCommand({ ResourceArn: paramArn }))
      );
      const entry = (response.Policies || [])[0];
      if (entry?.Policy) {
        try {
          paramFinding.resource_policy = JSON.parse(entry.Policy);
        } catch {
          paramFinding.resource_policy = entry.Policy;
        }
        paramFinding.has_resource_policy = true;
        paramFinding.resource_policy_status = 'present';
      } else {
        paramFinding.resource_policy_status = 'absent';
      }
      tracker.record({ check: 'resource_policy', resource: paramArn, status: 'ok' });
    } catch (err) {
      const code = err.name || err.Code || '';
      // Expected "not supported / not configured" errors → record as ok-absent,
      // not as a failure (these are the AWS-doesn't-support-this signals).
      if (code === 'ResourceNotFoundException' || code === 'PolicyNotFoundException' ||
          code === 'ParameterNotFoundException' || code === 'InvalidResourceId') {
        paramFinding.resource_policy_status = 'absent';
        tracker.record({ check: 'resource_policy', resource: paramArn, status: 'ok' });
      } else {
        logger.log('warning', 'GetResourcePolicies_Failed', { parameter: param.Name, error: err.message });
        paramFinding.resource_policy_status = classifyError(err);
        tracker.record({
          check: 'resource_policy',
          resource: paramArn,
          status: 'skipped',
          reason: paramFinding.resource_policy_status,
        });
      }
    }

    findings.push(paramFinding);
  }

  await logger.flush();
  const status = tracker.deriveModuleStatus({
    primaryChecks: PRIMARY_CHECKS,
    requiredChecks: REQUIRED_CHECKS,
  });
  const { coverage, errors } = tracker.toEnvelopeFields();
  return { findings, status, coverage, errors };
}

if (require.main === module) {
  baseEnum({ module: 'ssm', run });
}

module.exports = { run };
```

- [ ] **Step 4: Capture actual output**

Add TEMPORARY debug print, run, read `/tmp/ssm-actual.json`. Verify each parameter has `resource_policy_status` (likely `'absent'` for happy-path fixture since the API mock returns `{Policies: []}` per Phase A's fixture cleanup). Coverage has `describe_parameters` and `resource_policy` entries.

- [ ] **Step 5: Update fixture**

Copy validated output to `test/fixtures/enum/ssm/expected.json`.

- [ ] **Step 6: Remove debug print**

Grep should return nothing.

- [ ] **Step 7: Run tests**

Both green.

- [ ] **Step 8: Commit**

```bash
git add scripts/enum/ssm.js \
        test/enum-ssm.test.js \
        test/fixtures/enum/ssm/expected.json

git commit -m "feat(ssm): migrate to CoverageTracker

SSM has the simplest classification in the Data domain because parameter
metadata IS the data — DescribeParameters returns names, types, KMS
keys, mod dates. No per-resource required check needed.

- PRIMARY_CHECKS=['describe_parameters']
- REQUIRED_CHECKS=[] — nothing required per parameter beyond what the
  list response already gave us.
- Optional: resource_policy — AWS only supports resource policies on
  OpsItemGroup (not parameters); typical responses are AccessDenied /
  InvalidResourceId / ResourceNotFoundException, all recorded as
  ok-absent rather than failures. Genuine AccessDenied on policy
  records as 'skipped' with classifyError disposition.

Per-finding annotation: resource_policy_status (null default; 'present'
when policy returned; 'absent' for the AWS-doesn't-support cases or
when policy genuinely doesn't exist; 'access_denied'/'error' otherwise).

The has_resource_policy boolean field preserved from the original code
(downstream may key off it)."
```

---

## Done Criteria

- All 5 Data modules emit envelopes with `coverage[]`, `errors[]`, and per-finding `<field>_status` annotations.
- `classifyError()` lives in `scripts/lib/coverage.js` and is consumed by 6 enum scripts (apigateway + 5 new).
- `node test/run-all.js` is green end-to-end. All 25 (still 25) test files pass.
- 6 commits on `feature/v1.14-sdk-architecture`, one per task. No failing intermediate state.
- No schema, hook, or consumer-agent changes — Plans A/B/C already handled those.

## Out of Scope

- Compute domain (lambda, ec2, codebuild) — separate plan.
- Identity domain (cognito, iam) — separate plan (iam may deserve its own).
- STS migration — separate plan (deprecation window applies).
- Multi-region coverage aggregation — still deferred (Open Question #3).
- Partial/error path tests per module (like s3 got in Plan B Task 5) — valuable but adds churn. Manual diagnostics during review prove the disposition table works.
- Refactoring the `<field>_status` pattern into a shared helper — each module has slightly different structure (gated vs non-gated, single-call vs multi-call), so the inline try/catch reads more clearly than a helper would. Revisit when 10+ modules done.
