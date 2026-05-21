'use strict';

const assert = require('node:assert');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const HOOK = path.join(__dirname, '..', '..', 'config', 'hooks', 'scope-schema-validate.sh');

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

// Runs the hook with a synthetic PostToolUse payload pointing at a temp file
// we just wrote. Returns { stdout, stderr, code }.
function runHook(envelopeBody, filename) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-hook-test-'));
  try {
    const filePath = path.join(tmpDir, filename);
    fs.writeFileSync(filePath, JSON.stringify(envelopeBody, null, 2));
    const hookInput = JSON.stringify({
      tool_name: 'Write',
      tool_input: { file_path: filePath },
    });
    const result = spawnSync('bash', [HOOK], { input: hookInput, encoding: 'utf-8' });
    return { stdout: result.stdout, stderr: result.stderr, code: result.status };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function validEnvelope(moduleName) {
  return {
    module: moduleName,
    account_id: '123456789012',
    region: 'us-east-1',
    timestamp: '2026-05-17T12:00:00Z',
    status: 'complete',
    resources: [],
  };
}

function assertAccepted(out, label) {
  if (!out.stdout || out.stdout.trim() === '') return; // empty stdout = accepted
  let parsed;
  try { parsed = JSON.parse(out.stdout); } catch { return; } // non-JSON stdout = not a block decision
  assert.notStrictEqual(
    parsed.decision,
    'block',
    `hook blocked ${label}: ${parsed.reason || '(no reason)'}`
  );
}

function assertBlocked(out, label) {
  assert.ok(out.stdout && out.stdout.trim() !== '', `expected stdout for blocked ${label}, got empty`);
  let parsed;
  try { parsed = JSON.parse(out.stdout); } catch (e) {
    throw new Error(`expected JSON decision for blocked ${label}, got non-JSON: ${out.stdout}`);
  }
  assert.strictEqual(parsed.decision, 'block', `expected decision:block for ${label}, got: ${parsed.decision}`);
}

// --- New-module recognition: send a deliberately invalid envelope for each
// new module. If the hook recognizes the filename, it validates the envelope,
// sees missing required `resources`, and emits a block decision. If the hook
// doesn't recognize the filename, the file falls through to the default arm
// and the bad envelope is silently accepted — that's the bug.
for (const mod of ['bedrock', 'cognito', 'dynamodb', 'ssm']) {
  test(`hook recognizes ${mod}.json and validates its envelope`, () => {
    const env = validEnvelope(mod);
    delete env.resources; // make it invalid
    const out = runHook(env, `${mod}.json`);
    assertBlocked(out, `${mod} (missing resources)`);
  });
}

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

test('hook blocks account_id "unknown" when status field is absent', () => {
  const env = validEnvelope('iam');
  env.account_id = 'unknown';
  delete env.status;
  const out = runHook(env, 'iam.json');
  assertBlocked(out, 'unknown account_id with no status field');
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

// --- Regression guards: existing behavior must still work.

test('hook accepts a valid iam envelope', () => {
  const out = runHook(validEnvelope('iam'), 'iam.json');
  assertAccepted(out, 'iam');
});

test('hook blocks an iam envelope with an unknown module field value', () => {
  const env = validEnvelope('iam');
  env.module = 'invalidmod';
  const out = runHook(env, 'iam.json'); // filename routes to module-envelope path
  assertBlocked(out, 'invalidmod');
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
