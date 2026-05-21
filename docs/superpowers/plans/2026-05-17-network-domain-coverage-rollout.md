# Network Domain Coverage Rollout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the three Network domain enum modules (`sns`, `sqs`, `apigateway`) to use `CoverageTracker` with per-finding `<field>_status` annotations — following the s3 worked example from Plan B.

**Architecture:** Each module declares `PRIMARY_CHECKS` and `REQUIRED_CHECKS` constants at the top of the file, instantiates a `CoverageTracker` in `run()`, records per-resource events as it enumerates, annotates each finding with `<field>_status` siblings, and returns `{ findings, status, coverage, errors }` derived from the tracker. `base-enum.js` already forwards `coverage`/`errors` into the envelope from Plan B Task 5. No changes to lib code, schema, hook, or consumer agents — this is module-by-module application of the existing pattern.

**Tech Stack:** Same as Plan B. Node test runner, custom assertion style, JSON fixtures driven by mocked AWS SDK clients.

---

## Source spec and precedent

- **Spec:** `docs/superpowers/specs/2026-05-17-module-envelope-coverage-design.md` — see "AccessDenied disposition" for the three-row table that drives classification, and "Migration order" step 5 ("Roll out remaining modules — batched by domain").
- **Worked example:** Commit `caacb6d` (Plan B Task 5 + review fixes). The s3 migration is the canonical template. Reference it heavily.
- **CoverageTracker API:** `scripts/lib/coverage.js`. The class is documented inline; `record()`, `recordModuleFailure()`, `deriveModuleStatus()`, and `toEnvelopeFields()` are stable.
- **Naming conventions (from Plan B Task 5 fixes):**
  - Status field names: drop module-name prefixes. Use `<thing>_status` matching the data field's name (e.g., `policy_status` matches `policy`).
  - Coverage check names: prefix per-resource checks with the resource type when needed for namespace clarity, but stay short and consistent within a module.

## Important context

- **Project root:** `/Users/tayvionp/claude-code/SCOPE`. Branch: `feature/v1.14-sdk-architecture`. Do not switch branches.
- **Plan C's last commit:** `9bc65ff`. Plan D builds on top.
- **Test pattern:** custom Node runner. Each module has `test/enum-<module>.test.js` and `test/fixtures/enum/<module>/{api-responses,expected}.json`. Migration includes regenerating `expected.json` via the capture-verify-copy discipline that Plan B's Task 5 used.
- **No commit ships failing tests.** Each task ends in one commit with all tests green. The fixture regen happens in the same task as the code migration — same commit.
- **Other domains deferred:**
  - Data domain (kms, secrets, rds, dynamodb, ssm) — separate plan.
  - Compute domain (lambda, ec2, codebuild) — separate plan.
  - Identity domain (cognito, iam) — separate plan (iam likely deserves its own due to size).
  - STS migration to `coverage[]` — separate plan, has a one-release deprecation window.

## Migration template (applies to every task in this plan)

Every module migration follows the same six-step pattern, derived from the s3 pilot:

1. **Add imports** — `const { CoverageTracker } = require('../lib/coverage');`
2. **Declare classification constants** near the top of the file:
   ```js
   const PRIMARY_CHECKS = [<list operation name>];
   const REQUIRED_CHECKS = [<per-resource checks load-bearing for the script's purpose>];
   // Anything not listed is optional — record as 'skipped' on AccessDenied, status stays 'complete'.
   ```
3. **Remove local `errors` array and `let status` variable** — the tracker replaces both. Modules currently set `status = 'partial'` when `errors.length > 0`; that mutation is replaced by `tracker.deriveModuleStatus()` at the end.
4. **Wire each AWS call site to the tracker:**
   - Primary list operation success → `tracker.record({ check: <primary>, resource: null, status: 'ok' })`. Failure → `tracker.recordModuleFailure({ check: <primary>, operation, errorCode, errorMessage })` then derive status, build envelope fields, return early with `findings: []`.
   - Per-resource required check success → `tracker.record({ check, resource: <arn>, status: 'ok' })` AND set finding's `<field>_status` to `'present'` (or `'absent'` if the API returned a "not configured" signal).
   - Per-resource required check failure on AccessDenied → `tracker.record({ check, resource, status: 'failed', operation, errorCode, errorMessage })` AND set `<field>_status: 'access_denied'`.
   - Per-resource required check failure on other error → `status: 'failed'`, errorCode = `err.name`, `<field>_status: 'error'`.
   - Optional check failure on AccessDenied → `tracker.record({ check, resource, status: 'skipped', reason: 'access_denied' })`. Status stays 'complete'.
5. **At end of `run()`:**
   ```js
   const status = tracker.deriveModuleStatus({ primaryChecks: PRIMARY_CHECKS, requiredChecks: REQUIRED_CHECKS });
   const { coverage, errors } = tracker.toEnvelopeFields();
   return { findings, status, coverage, errors };
   ```
6. **Update the test and regenerate the fixture** — add coverage assertions to the existing `test/enum-<module>.test.js`, capture the actual `run()` output via temporary debug print, verify by eye that the new shape matches expectations, copy into `expected.json`, remove the debug print, run tests until green.

The s3 commit (`caacb6d`) shows all six steps applied to a real module. Reference it when in doubt.

## File structure

**Per task — three files modified, one commit:**

For each module M ∈ {sns, sqs, apigateway}:
- Modify: `scripts/enum/<M>.js`
- Modify: `test/enum-<M>.test.js` (add coverage assertions)
- Modify: `test/fixtures/enum/<M>/expected.json` (regenerated)

**No changes to:**
- `scripts/lib/*` — the lib is stable from Plan B.
- `config/schemas/*` or `config/hooks/*` — schema/hook accept these envelope shapes already.
- `agents/*` — consumer agents already know how to interpret `<field>_status` and `coverage[]` (Plan C).
- Any non-target enum script.

---

## Task 1: Migrate `scripts/enum/sns.js`

**Module shape:** simple. `ListTopics` (paginated) → per-topic `GetTopicAttributes` (single call that returns policy, KMS key, and subscription counts in one shot).

**Classification decisions:**
- `PRIMARY_CHECKS = ['list_topics']` — if `ListTopics` fails, no findings.
- `REQUIRED_CHECKS = ['topic_attributes']` — per-topic attributes ARE the data; without them a topic is just an ARN, no policy/principals/KMS context. Failure → status: 'partial' on that topic.
- No optional checks — `GetTopicAttributes` is the only per-resource call.

**Per-finding annotation:** add a single `topic_attributes_status` field per topic finding. Values: `'present'` (attributes returned) | `'access_denied'` (denied) | `'error'` (other failure). No `'absent'` state — there's no equivalent of "topic exists but has no attributes."

**Files:**
- Modify: `scripts/enum/sns.js`
- Modify: `test/enum-sns.test.js`
- Modify: `test/fixtures/enum/sns/expected.json`

- [ ] **Step 1: Add coverage assertions to the existing test**

Open `test/enum-sns.test.js`. Find the existing `assert` block (the test currently checks `result.status` and `result.findings` against the fixture's expected values). After the existing assertions and BEFORE the `console.log('  PASS: ...')` line for the basic scenario test, insert:

```js
    // Coverage assertions (Plan D Task 1)
    assert.ok(Array.isArray(result.coverage), 'expected result.coverage to be an array');
    assert.ok(Array.isArray(result.errors), 'expected result.errors to be an array');
    const listTopicsEntry = result.coverage.find((c) => c.check === 'list_topics');
    assert.ok(listTopicsEntry, 'expected list_topics entry in coverage');
    assert.strictEqual(listTopicsEntry.status, 'complete', 'list_topics should be complete in happy-path fixture');
    const attrsEntry = result.coverage.find((c) => c.check === 'topic_attributes');
    assert.ok(attrsEntry, 'expected topic_attributes entry in coverage');
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node test/enum-sns.test.js`

Expected: FAIL with `expected result.coverage to be an array` — `run()` doesn't yet return coverage. Exit code 1.

- [ ] **Step 3: Migrate `scripts/enum/sns.js`**

Open `scripts/enum/sns.js`. The current file is 97 lines. Replace it entirely with:

```js
'use strict';

const {
  SNSClient,
  ListTopicsCommand,
  GetTopicAttributesCommand,
} = require('@aws-sdk/client-sns');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { extractPolicyPrincipals } = require('../lib/policy-parser');
const { CoverageTracker } = require('../lib/coverage');

// Check classification — drives module status derivation in CoverageTracker.
// Primary: ListTopics failing means no topics enumerated; module status becomes 'error'.
// Required: GetTopicAttributes failing per-topic degrades module to 'partial'.
const PRIMARY_CHECKS = ['list_topics'];
const REQUIRED_CHECKS = ['topic_attributes'];

// --- Helpers ---

/**
 * Extracts topic name from ARN (last segment after ':').
 */
function topicNameFromArn(arn) {
  if (!arn) return null;
  const parts = arn.split(':');
  return parts[parts.length - 1];
}

// --- Exported run() for testing ---

async function run(opts = {}) {
  const { runDir, region } = opts;
  const accountId = opts.accountId;

  if (!runDir || !region) {
    throw new Error('runDir and region are required');
  }

  const client = opts.clients?.sns ?? new SNSClient({ region });

  const logger = opts.logger || createLogger(runDir, 'sns');
  logger.log('info', 'SNS_Enumeration_Start', { region });

  const tracker = new CoverageTracker();
  const findings = [];

  // ListTopics — primary. Failure means the module can't do its job.
  let topics;
  try {
    logger.log('api_call', 'ListTopics', { region });
    topics = await paginate(client, ListTopicsCommand, 'Topics', {});
    tracker.record({ check: 'list_topics', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'ListTopics', { error: err.message });
    tracker.recordModuleFailure({
      check: 'list_topics',
      operation: 'ListTopics',
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

  // Per-topic: GetTopicAttributes (required)
  for (const topic of topics) {
    const topicArn = topic.TopicArn;
    const topicName = topicNameFromArn(topicArn);

    const topicFinding = {
      resource_type: 'sns_topic',
      resource_id: topicName,
      arn: topicArn,
      region,
      resource_policy: null,
      kms_key_id: null,
      subscriptions_confirmed: 0,
      topic_attributes_status: 'absent',
      findings: [],
    };

    try {
      logger.log('api_call', 'GetTopicAttributes', { topic: topicArn });
      const resp = await withRetry(() =>
        client.send(new GetTopicAttributesCommand({ TopicArn: topicArn }))
      );
      const attrs = resp.Attributes || {};

      const policy = attrs.Policy || null;
      const principals = extractPolicyPrincipals(policy);
      const kmsKeyId = attrs.KmsMasterKeyId || null;
      const subscriptionsConfirmed = parseInt(attrs.SubscriptionsConfirmed, 10) || 0;

      topicFinding.resource_policy = principals.length > 0 ? { principals } : null;
      topicFinding.kms_key_id = kmsKeyId;
      topicFinding.subscriptions_confirmed = subscriptionsConfirmed;
      topicFinding.topic_attributes_status = 'present';

      tracker.record({ check: 'topic_attributes', resource: topicArn, status: 'ok' });
    } catch (err) {
      const code = err.name || 'Error';
      logger.log('warning', 'GetTopicAttributes', { topic: topicArn, error: err.message });
      topicFinding.topic_attributes_status = code === 'AccessDenied' || code === 'AccessDeniedException'
        ? 'access_denied' : 'error';
      tracker.record({
        check: 'topic_attributes',
        resource: topicArn,
        status: 'failed',
        operation: 'GetTopicAttributes',
        errorCode: code,
        errorMessage: err.message,
      });
    }

    findings.push(topicFinding);
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
  baseEnum({ module: 'sns', run });
}

module.exports = { run };
```

- [ ] **Step 4: Capture actual output to regenerate the fixture**

Add a TEMPORARY debug print to `test/enum-sns.test.js` immediately after the `const result = await run(...)` line:

```js
    // TEMPORARY — remove before commit
    require('node:fs').writeFileSync('/tmp/sns-actual.json', JSON.stringify(result, null, 2));
```

Run: `node test/enum-sns.test.js` (will still fail on deepStrictEqual — that's fine, we just need the file written).

Read `/tmp/sns-actual.json`. Verify by eye:
- Each topic finding has the new `topic_attributes_status` field.
- For the happy-path fixture, all values should be `'present'`.
- `coverage` array has entries for `list_topics` (status 'complete', scope 'per_resource') and `topic_attributes`.
- `errors` is empty.
- Top-level `status` is `'complete'`.

If anything looks wrong, STOP and fix `sns.js` before proceeding.

- [ ] **Step 5: Update `test/fixtures/enum/sns/expected.json`**

Replace the contents of `test/fixtures/enum/sns/expected.json` with the verified `/tmp/sns-actual.json` contents. Preserve formatting.

- [ ] **Step 6: Remove the temporary debug print**

Remove the `require('node:fs').writeFileSync(...)` line from `test/enum-sns.test.js`. Verify by grep:

```bash
grep -n "/tmp/\|TEMPORARY\|writeFileSync" test/enum-sns.test.js
```

Expected: no output.

- [ ] **Step 7: Run the test and the full suite — both must be green before commit**

Run: `node test/enum-sns.test.js` — expected: `1 tests: 1 passed, 0 failed`. Exit code 0.

Run: `node test/run-all.js` — expected: green across all 25 test files.

If either fails, do NOT commit. Fix the problem first.

- [ ] **Step 8: Commit**

```bash
git add scripts/enum/sns.js \
        test/enum-sns.test.js \
        test/fixtures/enum/sns/expected.json

git commit -m "feat(sns): migrate to CoverageTracker

Follows the s3 pilot pattern (commit caacb6d) for the SNS module:

- PRIMARY_CHECKS=['list_topics'] — ListTopics failure becomes status=error
  via recordModuleFailure and early return.
- REQUIRED_CHECKS=['topic_attributes'] — per-topic GetTopicAttributes
  failure degrades module to 'partial'. SNS has only one per-resource
  call (attributes returns policy + KMS + subscription counts in one
  shot), so the classification is simpler than s3.
- New per-finding annotation: topic_attributes_status — one of
  'present' | 'access_denied' | 'error'. No 'absent' state since
  there's no 'topic exists but no attributes' shape.
- Local errors[] array and let status removed; tracker is the source
  of truth.
- Returns {findings, status, coverage, errors} from tracker.

test/enum-sns.test.js gets coverage assertions for both checks. Fixture
regenerated to include topic_attributes_status, coverage[], and errors[].
Full suite green."
```

---

## Task 2: Migrate `scripts/enum/sqs.js`

**Module shape:** same simple shape as sns. `ListQueues` → per-queue `GetQueueAttributes` (single call returns policy, KMS, redrive, visibility).

**Classification decisions:**
- `PRIMARY_CHECKS = ['list_queues']`
- `REQUIRED_CHECKS = ['queue_attributes']`
- No optional checks.

**Per-finding annotation:** `queue_attributes_status` per queue. Values: `'present'` | `'access_denied'` | `'error'`.

**Files:**
- Modify: `scripts/enum/sqs.js`
- Modify: `test/enum-sqs.test.js`
- Modify: `test/fixtures/enum/sqs/expected.json`

- [ ] **Step 1: Add coverage assertions to the existing test**

Open `test/enum-sqs.test.js`. After the existing `assert.deepStrictEqual(result.findings, expected.findings)` (or equivalent) line, insert:

```js
    // Coverage assertions (Plan D Task 2)
    assert.ok(Array.isArray(result.coverage), 'expected result.coverage to be an array');
    assert.ok(Array.isArray(result.errors), 'expected result.errors to be an array');
    const listQueuesEntry = result.coverage.find((c) => c.check === 'list_queues');
    assert.ok(listQueuesEntry, 'expected list_queues entry in coverage');
    assert.strictEqual(listQueuesEntry.status, 'complete', 'list_queues should be complete in happy-path fixture');
    const attrsEntry = result.coverage.find((c) => c.check === 'queue_attributes');
    assert.ok(attrsEntry, 'expected queue_attributes entry in coverage');
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node test/enum-sqs.test.js`

Expected: FAIL with `expected result.coverage to be an array`. Exit code 1.

- [ ] **Step 3: Migrate `scripts/enum/sqs.js`**

Open `scripts/enum/sqs.js`. The current file is 118 lines. Replace it entirely with:

```js
'use strict';

const {
  SQSClient,
  ListQueuesCommand,
  GetQueueAttributesCommand,
} = require('@aws-sdk/client-sqs');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { extractPolicyPrincipals } = require('../lib/policy-parser');
const { CoverageTracker } = require('../lib/coverage');

// Check classification.
const PRIMARY_CHECKS = ['list_queues'];
const REQUIRED_CHECKS = ['queue_attributes'];

// --- Helpers ---

/**
 * Extracts queue name from URL (last segment after '/').
 */
function queueNameFromUrl(url) {
  if (!url) return null;
  const parts = url.split('/');
  return parts[parts.length - 1];
}

/**
 * Extracts DLQ ARN from RedrivePolicy JSON string.
 */
function extractDlqArn(redrivePolicyJson) {
  if (!redrivePolicyJson) return null;
  try {
    const policy = JSON.parse(redrivePolicyJson);
    return policy.deadLetterTargetArn || null;
  } catch {
    return null;
  }
}

// --- Exported run() for testing ---

async function run(opts = {}) {
  const { runDir, region } = opts;
  const accountId = opts.accountId;

  if (!runDir || !region) {
    throw new Error('runDir and region are required');
  }

  const client = opts.clients?.sqs ?? new SQSClient({ region });

  const logger = opts.logger || createLogger(runDir, 'sqs');
  logger.log('info', 'SQS_Enumeration_Start', { region });

  const tracker = new CoverageTracker();
  const findings = [];

  // ListQueues — primary.
  let queueUrls;
  try {
    logger.log('api_call', 'ListQueues', { region });
    queueUrls = await paginate(client, ListQueuesCommand, 'QueueUrls', {});
    tracker.record({ check: 'list_queues', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'ListQueues', { error: err.message });
    tracker.recordModuleFailure({
      check: 'list_queues',
      operation: 'ListQueues',
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

  // Per-queue: GetQueueAttributes (All) — required.
  for (const queueUrl of queueUrls) {
    const queueName = queueNameFromUrl(queueUrl);

    const queueFinding = {
      resource_type: 'sqs_queue',
      resource_id: queueName,
      arn: null,
      region,
      queue_url: queueUrl,
      resource_policy: null,
      fifo: false,
      dlq_arn: null,
      kms_key_id: null,
      visibility_timeout: 30,
      queue_attributes_status: null,
      findings: [],
    };

    try {
      logger.log('api_call', 'GetQueueAttributes', { queue: queueUrl });
      const resp = await withRetry(() =>
        client.send(new GetQueueAttributesCommand({
          QueueUrl: queueUrl,
          AttributeNames: ['All'],
        }))
      );
      const attrs = resp.Attributes || {};

      const queueArn = attrs.QueueArn || null;
      const policy = attrs.Policy || null;
      const principals = extractPolicyPrincipals(policy);
      const isFifo = (attrs.FifoQueue === 'true');
      const dlqArn = extractDlqArn(attrs.RedrivePolicy);
      const kmsKeyId = attrs.KmsMasterKeyId || null;
      const visibilityTimeout = parseInt(attrs.VisibilityTimeout, 10) || 30;

      queueFinding.arn = queueArn;
      queueFinding.resource_policy = principals.length > 0 ? { principals } : null;
      queueFinding.fifo = isFifo;
      queueFinding.dlq_arn = dlqArn;
      queueFinding.kms_key_id = kmsKeyId;
      queueFinding.visibility_timeout = visibilityTimeout;
      queueFinding.queue_attributes_status = 'present';

      tracker.record({ check: 'queue_attributes', resource: queueArn || queueUrl, status: 'ok' });
    } catch (err) {
      const code = err.name || 'Error';
      logger.log('warning', 'GetQueueAttributes', { queue: queueUrl, error: err.message });
      queueFinding.queue_attributes_status = code === 'AccessDenied' || code === 'AccessDeniedException'
        ? 'access_denied' : 'error';
      tracker.record({
        check: 'queue_attributes',
        resource: queueUrl,
        status: 'failed',
        operation: 'GetQueueAttributes',
        errorCode: code,
        errorMessage: err.message,
      });
    }

    findings.push(queueFinding);
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
  baseEnum({ module: 'sqs', run });
}

module.exports = { run };
```

- [ ] **Step 4: Capture actual output**

Add the TEMPORARY debug print to `test/enum-sqs.test.js` after `const result = await run(...)`:

```js
    // TEMPORARY — remove before commit
    require('node:fs').writeFileSync('/tmp/sqs-actual.json', JSON.stringify(result, null, 2));
```

Run: `node test/enum-sqs.test.js`. Read `/tmp/sqs-actual.json`. Verify by eye:
- Each queue finding has `queue_attributes_status: 'present'` (happy path).
- Coverage has `list_queues` (complete) and `queue_attributes` entries.
- Errors empty.
- Top-level status 'complete'.

- [ ] **Step 5: Update `test/fixtures/enum/sqs/expected.json`**

Copy `/tmp/sqs-actual.json` contents into `test/fixtures/enum/sqs/expected.json`.

- [ ] **Step 6: Remove the temporary debug print**

Remove the writeFileSync line from `test/enum-sqs.test.js`. Verify:

```bash
grep -n "/tmp/\|TEMPORARY\|writeFileSync" test/enum-sqs.test.js
```

Expected: no output.

- [ ] **Step 7: Run the test and the full suite**

Run: `node test/enum-sqs.test.js` — expected: `1 tests: 1 passed, 0 failed`.

Run: `node test/run-all.js` — expected: green across all 25 test files.

- [ ] **Step 8: Commit**

```bash
git add scripts/enum/sqs.js \
        test/enum-sqs.test.js \
        test/fixtures/enum/sqs/expected.json

git commit -m "feat(sqs): migrate to CoverageTracker

Same shape as sns (commit <SNS_COMMIT_SHA>): single per-resource call
(GetQueueAttributes with AttributeNames=['All']) returns all the
data — policy, KMS, redrive, visibility timeout — in one shot.

- PRIMARY_CHECKS=['list_queues']
- REQUIRED_CHECKS=['queue_attributes']
- queue_attributes_status per queue: 'present' | 'access_denied' | 'error'

Local errors[]/let status removed. Returns {findings, status, coverage,
errors} from tracker. Full suite green."
```

(Substitute the actual SNS commit SHA in `<SNS_COMMIT_SHA>` when running this — it's the Task 1 commit.)

---

## Task 3: Migrate `scripts/enum/apigateway.js`

**Module shape:** the most complex of the Network three. Two parallel enumerations against two SDK clients: REST APIs (`APIGatewayClient`) and HTTP/WebSocket APIs (`ApiGatewayV2Client`). Each has its own list operation and several per-API detail calls.

**Classification decisions (read the rationale carefully — apigateway has TWO list operations):**

For simplicity and consistency with the disposition table, both list ops are PRIMARY:
- `PRIMARY_CHECKS = ['get_rest_apis', 'get_apis']`
- `REQUIRED_CHECKS = ['rest_authorizers', 'rest_stages', 'rest_resources', 'v2_authorizers', 'v2_stages', 'v2_integrations']`

**Tradeoff:** if EITHER list operation fails, module status becomes `'error'` (per the CoverageTracker rule that any primary failure → error). In practice, `apigateway:GET*` IAM permissions cover both v1 and v2 together, so they fail or succeed in tandem. The edge case where REST list succeeds but V2 list fails (or vice versa) is rare in real environments. Accepting this asymmetry keeps the migration aligned with the disposition table without a synthetic check.

**Per-finding annotations** (apply to ALL three resource types — REST, HTTP, WebSocket — uniformly):
- `authorizers_status`: `'present'` if the authorizers call succeeded (regardless of whether the result is empty or populated), `'access_denied'` on AccessDenied, `'error'` on other failures.
- `stages_status`: same pattern.
- `lambda_integrations_status`: same pattern (sourced from `GetResources` for REST, `GetIntegrations` for V2).

Note: the existing code has REST APIs using `GetResources` to find lambda integrations, while V2 uses `GetIntegrations` directly. Both produce the same `lambda_integrations` field; both get the same `lambda_integrations_status` annotation tied to whichever call sourced it.

**Files:**
- Modify: `scripts/enum/apigateway.js`
- Modify: `test/enum-apigateway.test.js`
- Modify: `test/fixtures/enum/apigateway/expected.json`

- [ ] **Step 1: Add coverage assertions to the existing test**

Open `test/enum-apigateway.test.js`. After the existing assertion block, insert:

```js
    // Coverage assertions (Plan D Task 3)
    assert.ok(Array.isArray(result.coverage), 'expected result.coverage to be an array');
    assert.ok(Array.isArray(result.errors), 'expected result.errors to be an array');
    const restListEntry = result.coverage.find((c) => c.check === 'get_rest_apis');
    assert.ok(restListEntry, 'expected get_rest_apis entry in coverage');
    const v2ListEntry = result.coverage.find((c) => c.check === 'get_apis');
    assert.ok(v2ListEntry, 'expected get_apis entry in coverage');
    assert.strictEqual(result.status, 'complete', 'happy-path fixture should yield status complete');
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node test/enum-apigateway.test.js`

Expected: FAIL with `expected result.coverage to be an array`. Exit code 1.

- [ ] **Step 3: Migrate `scripts/enum/apigateway.js`**

Open `scripts/enum/apigateway.js`. The file is 292 lines and has two parallel helper functions (`enumerateRestApis`, `enumerateV2Apis`) plus the top-level `run()`. Both helpers need migration. Replace the file entirely with:

```js
'use strict';

const {
  APIGatewayClient,
  GetRestApisCommand,
  GetAuthorizersCommand: GetRestAuthorizersCommand,
  GetStagesCommand: GetRestStagesCommand,
  GetResourcesCommand,
} = require('@aws-sdk/client-api-gateway');

const {
  ApiGatewayV2Client,
  GetApisCommand,
  GetAuthorizersCommand: GetV2AuthorizersCommand,
  GetStagesCommand: GetV2StagesCommand,
  GetIntegrationsCommand,
} = require('@aws-sdk/client-apigatewayv2');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { CoverageTracker } = require('../lib/coverage');

// Check classification.
// Both list ops are primary because each is the entry point for its API class.
// Tradeoff documented in the plan: either list failing → status='error', which
// is strict if only one half fails. In practice apigateway:GET* covers both
// v1 and v2 IAM-wise, so they fail or succeed together.
const PRIMARY_CHECKS = ['get_rest_apis', 'get_apis'];
const REQUIRED_CHECKS = [
  'rest_authorizers', 'rest_stages', 'rest_resources',
  'v2_authorizers', 'v2_stages', 'v2_integrations',
];

// --- Helpers ---

function extractLambdaIntegrations(integrations) {
  const lambdaArns = new Set();
  for (const integration of integrations) {
    const uri = integration.IntegrationUri || integration.uri || '';
    const match = uri.match(/arn:aws:lambda:[^:]+:\d+:function:[^/]+/);
    if (match) lambdaArns.add(match[0]);
  }
  return [...lambdaArns];
}

function extractRestLambdaIntegrations(resources) {
  const lambdaArns = new Set();
  for (const resource of resources) {
    const methods = resource.resourceMethods || {};
    for (const method of Object.values(methods)) {
      const integration = method.methodIntegration;
      if (!integration) continue;
      const uri = integration.uri || '';
      const match = uri.match(/arn:aws:lambda:[^:]+:\d+:function:[^/]+/);
      if (match) lambdaArns.add(match[0]);
    }
  }
  return [...lambdaArns];
}

function parseResourcePolicy(policyStr) {
  if (!policyStr) return null;
  try {
    const decoded = decodeURIComponent(policyStr);
    JSON.parse(decoded);
    return decoded;
  } catch {
    try {
      JSON.parse(policyStr);
      return policyStr;
    } catch {
      return null;
    }
  }
}

function classifyError(err) {
  const code = err.name || 'Error';
  if (code === 'AccessDenied' || code === 'AccessDeniedException') return 'access_denied';
  return 'error';
}

// --- REST API Enumeration ---

async function enumerateRestApis(client, region, logger, tracker) {
  const findings = [];

  let restApis;
  try {
    logger.log('api_call', 'GetRestApis', { region });
    restApis = await paginate(client, GetRestApisCommand, 'items', {
      tokenKey: 'position',
      responseTokenKey: 'position',
    });
    tracker.record({ check: 'get_rest_apis', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'GetRestApis', { error: err.message });
    tracker.recordModuleFailure({
      check: 'get_rest_apis',
      operation: 'GetRestApis',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
    return findings;
  }

  for (const api of restApis) {
    const apiId = api.id;
    const apiName = api.name;
    const apiArn = `arn:aws:apigateway:${region}::/restapis/${apiId}`;

    const apiFinding = {
      resource_type: 'apigateway_rest_api',
      resource_id: apiId,
      arn: apiArn,
      region,
      name: apiName,
      api_type: 'REST',
      authorizers: [],
      authorizers_status: null,
      stages: [],
      stages_status: null,
      lambda_integrations: [],
      lambda_integrations_status: null,
      resource_policy: parseResourcePolicy(api.policy),
      findings: [],
    };

    // GetAuthorizers
    try {
      logger.log('api_call', 'GetAuthorizers', { apiId });
      const authResp = await withRetry(() =>
        client.send(new GetRestAuthorizersCommand({ restApiId: apiId }))
      );
      apiFinding.authorizers = (authResp.items || []).map((a) => ({
        type: a.type || null,
        name: a.name || null,
      }));
      apiFinding.authorizers_status = 'present';
      tracker.record({ check: 'rest_authorizers', resource: apiArn, status: 'ok' });
    } catch (err) {
      const dispoStatus = classifyError(err);
      logger.log('warning', 'GetAuthorizers', { apiId, error: err.message });
      apiFinding.authorizers_status = dispoStatus;
      tracker.record({
        check: 'rest_authorizers',
        resource: apiArn,
        status: 'failed',
        operation: 'GetAuthorizers',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    // GetStages
    try {
      logger.log('api_call', 'GetStages', { apiId });
      const stageResp = await withRetry(() =>
        client.send(new GetRestStagesCommand({ restApiId: apiId }))
      );
      apiFinding.stages = (stageResp.item || []).map((s) => s.stageName);
      apiFinding.stages_status = 'present';
      tracker.record({ check: 'rest_stages', resource: apiArn, status: 'ok' });
    } catch (err) {
      const dispoStatus = classifyError(err);
      logger.log('warning', 'GetStages', { apiId, error: err.message });
      apiFinding.stages_status = dispoStatus;
      tracker.record({
        check: 'rest_stages',
        resource: apiArn,
        status: 'failed',
        operation: 'GetStages',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    // GetResources (drives lambda_integrations)
    try {
      logger.log('api_call', 'GetResources', { apiId });
      const resources = await paginate(client, GetResourcesCommand, 'items', {
        params: { restApiId: apiId, embed: ['methods'] },
        tokenKey: 'position',
        responseTokenKey: 'position',
      });
      apiFinding.lambda_integrations = extractRestLambdaIntegrations(resources);
      apiFinding.lambda_integrations_status = 'present';
      tracker.record({ check: 'rest_resources', resource: apiArn, status: 'ok' });
    } catch (err) {
      const dispoStatus = classifyError(err);
      logger.log('warning', 'GetResources', { apiId, error: err.message });
      apiFinding.lambda_integrations_status = dispoStatus;
      tracker.record({
        check: 'rest_resources',
        resource: apiArn,
        status: 'failed',
        operation: 'GetResources',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    findings.push(apiFinding);
  }

  return findings;
}

// --- HTTP/WebSocket API Enumeration ---

async function enumerateV2Apis(client, region, logger, tracker) {
  const findings = [];

  let apis;
  try {
    logger.log('api_call', 'GetApis', { region });
    apis = await paginate(client, GetApisCommand, 'Items', {});
    tracker.record({ check: 'get_apis', resource: null, status: 'ok' });
  } catch (err) {
    logger.log('error', 'GetApis', { error: err.message });
    tracker.recordModuleFailure({
      check: 'get_apis',
      operation: 'GetApis',
      errorCode: err.name || 'Error',
      errorMessage: err.message,
    });
    return findings;
  }

  for (const api of apis) {
    const apiId = api.ApiId;
    const apiName = api.Name;
    const protocolType = api.ProtocolType;
    const apiArn = `arn:aws:apigateway:${region}::/apis/${apiId}`;
    const resourceType = protocolType === 'WEBSOCKET'
      ? 'apigateway_websocket_api'
      : 'apigateway_http_api';

    const apiFinding = {
      resource_type: resourceType,
      resource_id: apiId,
      arn: apiArn,
      region,
      name: apiName,
      api_type: protocolType,
      authorizers: [],
      authorizers_status: null,
      stages: [],
      stages_status: null,
      lambda_integrations: [],
      lambda_integrations_status: null,
      resource_policy: null, // HTTP/WebSocket APIs do not have resource policies
      findings: [],
    };

    // GetAuthorizers (v2)
    try {
      logger.log('api_call', 'GetAuthorizersV2', { apiId });
      const authResp = await withRetry(() =>
        client.send(new GetV2AuthorizersCommand({ ApiId: apiId }))
      );
      apiFinding.authorizers = (authResp.Items || []).map((a) => ({
        type: a.AuthorizerType || null,
        name: a.Name || null,
      }));
      apiFinding.authorizers_status = 'present';
      tracker.record({ check: 'v2_authorizers', resource: apiArn, status: 'ok' });
    } catch (err) {
      const dispoStatus = classifyError(err);
      logger.log('warning', 'GetAuthorizersV2', { apiId, error: err.message });
      apiFinding.authorizers_status = dispoStatus;
      tracker.record({
        check: 'v2_authorizers',
        resource: apiArn,
        status: 'failed',
        operation: 'GetAuthorizers',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    // GetStages (v2)
    try {
      logger.log('api_call', 'GetStagesV2', { apiId });
      const stageResp = await withRetry(() =>
        client.send(new GetV2StagesCommand({ ApiId: apiId }))
      );
      apiFinding.stages = (stageResp.Items || []).map((s) => s.StageName);
      apiFinding.stages_status = 'present';
      tracker.record({ check: 'v2_stages', resource: apiArn, status: 'ok' });
    } catch (err) {
      const dispoStatus = classifyError(err);
      logger.log('warning', 'GetStagesV2', { apiId, error: err.message });
      apiFinding.stages_status = dispoStatus;
      tracker.record({
        check: 'v2_stages',
        resource: apiArn,
        status: 'failed',
        operation: 'GetStages',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    // GetIntegrations (v2)
    try {
      logger.log('api_call', 'GetIntegrations', { apiId });
      const intResp = await withRetry(() =>
        client.send(new GetIntegrationsCommand({ ApiId: apiId }))
      );
      apiFinding.lambda_integrations = extractLambdaIntegrations(intResp.Items || []);
      apiFinding.lambda_integrations_status = 'present';
      tracker.record({ check: 'v2_integrations', resource: apiArn, status: 'ok' });
    } catch (err) {
      const dispoStatus = classifyError(err);
      logger.log('warning', 'GetIntegrations', { apiId, error: err.message });
      apiFinding.lambda_integrations_status = dispoStatus;
      tracker.record({
        check: 'v2_integrations',
        resource: apiArn,
        status: 'failed',
        operation: 'GetIntegrations',
        errorCode: err.name || 'Error',
        errorMessage: err.message,
      });
    }

    findings.push(apiFinding);
  }

  return findings;
}

// --- Run (exported for testing) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const logger = opts.logger || createLogger(runDir, 'apigateway');
  logger.log('info', 'APIGateway_Enumeration_Start', { region });

  const tracker = new CoverageTracker();

  const restClient = opts.clients?.apigateway ?? new APIGatewayClient({ region });
  const restFindings = await enumerateRestApis(restClient, region, logger, tracker);

  const v2Client = opts.clients?.apigatewayV2 ?? new ApiGatewayV2Client({ region });
  const v2Findings = await enumerateV2Apis(v2Client, region, logger, tracker);

  const findings = [...restFindings, ...v2Findings];

  await logger.flush();
  const status = tracker.deriveModuleStatus({
    primaryChecks: PRIMARY_CHECKS,
    requiredChecks: REQUIRED_CHECKS,
  });
  const { coverage, errors } = tracker.toEnvelopeFields();
  return { findings, status, coverage, errors };
}

if (require.main === module) {
  baseEnum({ module: 'apigateway', run });
}

module.exports = { run };
```

- [ ] **Step 4: Capture actual output**

Add TEMPORARY debug print to `test/enum-apigateway.test.js`:

```js
    // TEMPORARY — remove before commit
    require('node:fs').writeFileSync('/tmp/apigateway-actual.json', JSON.stringify(result, null, 2));
```

Run: `node test/enum-apigateway.test.js`. Read `/tmp/apigateway-actual.json`. Verify by eye:
- Each API finding (REST/HTTP/WebSocket) has all three `*_status` fields: `authorizers_status`, `stages_status`, `lambda_integrations_status`.
- For happy-path fixture, all are `'present'`.
- Coverage has entries for the list ops (`get_rest_apis`, `get_apis`) and per-API checks the fixture exercises.
- Errors empty.
- Top-level status `'complete'`.

If the fixture only exercises REST APIs (no V2), the `get_apis` entry will still appear in coverage (the V2 enumeration runs and returns no results), but per-resource checks like `v2_authorizers` won't have entries because no V2 APIs were iterated over. That's fine.

- [ ] **Step 5: Update `test/fixtures/enum/apigateway/expected.json`**

Copy `/tmp/apigateway-actual.json` contents into `test/fixtures/enum/apigateway/expected.json`.

- [ ] **Step 6: Remove the temporary debug print**

Verify:

```bash
grep -n "/tmp/\|TEMPORARY\|writeFileSync" test/enum-apigateway.test.js
```

Expected: no output.

- [ ] **Step 7: Run the test and the full suite**

Run: `node test/enum-apigateway.test.js` — expected: `1 tests: 1 passed, 0 failed`.

Run: `node test/run-all.js` — expected: green across all 25 test files.

- [ ] **Step 8: Commit**

```bash
git add scripts/enum/apigateway.js \
        test/enum-apigateway.test.js \
        test/fixtures/enum/apigateway/expected.json

git commit -m "feat(apigateway): migrate to CoverageTracker

The most complex Network module: two parallel enumerations against the
v1 (APIGatewayClient) and v2 (ApiGatewayV2Client) SDK clients, each with
its own list operation and 2-3 per-API detail calls.

Classification:
- PRIMARY_CHECKS=['get_rest_apis', 'get_apis'] — both list ops are
  primary. Either failure becomes status=error. In practice
  apigateway:GET* IAM permissions cover both v1 and v2, so they fail
  or succeed together; the asymmetry is rare.
- REQUIRED_CHECKS covers the six per-API detail checks:
  rest_authorizers, rest_stages, rest_resources, v2_authorizers,
  v2_stages, v2_integrations.

Per-finding annotations (applied to REST, HTTP, and WebSocket API
findings uniformly):
- authorizers_status, stages_status, lambda_integrations_status.
- 'present' on success, 'access_denied' on AccessDenied, 'error'
  otherwise. No 'absent' — there's no API-confirmed-empty signal.

The classifyError() helper introduced here may be lifted into
scripts/lib/coverage.js or scripts/lib/policy-parser.js if more
modules need it in Plan D's other domains — defer the lift until at
least two modules want it.

Local errors[] arrays removed from both helpers. Both helpers now take
a tracker arg and return only their findings; the top-level run()
combines and derives status from the tracker.

Full suite green."
```

---

## Done Criteria

- All three Network modules (`sns`, `sqs`, `apigateway`) emit envelopes with `coverage[]`, `errors[]`, and per-finding `<field>_status` annotations.
- `node test/run-all.js` is green end-to-end.
- Three commits on `feature/v1.14-sdk-architecture`, one per task. Each commit's tests pass at the commit point (no failing intermediate state).
- No lib changes, no schema changes, no hook changes, no agent prompt changes.
- No other enum scripts touched.

## Out of Scope

- **Other domains** — Data (kms, secrets, rds, dynamodb, ssm), Compute (lambda, ec2, codebuild), Identity (cognito, iam). Each gets its own plan. IAM likely deserves a dedicated plan due to its complexity.
- **STS coverage migration** — Plan E. STS has a one-release deprecation window for its existing `org_*` fields.
- **Multi-region coverage aggregation** — still deferred (Open Question #3 in the spec). Multi-region path in `base-enum.js` continues to drop coverage/errors.
- **Helper consolidation** — if `classifyError()` (introduced in apigateway) proves useful in other modules, lift it to `scripts/lib/` in a follow-up. Don't preemptively lift in this plan.
- **Test fixture diversity** — current fixtures exercise happy paths only. Adding partial/error path tests per module (like the s3 pilot got in Plan B Task 5) is valuable but out of scope here to keep each task's diff small. The s3 pattern proves the disposition table works; module-specific edge-case tests can be added in follow-ups.
