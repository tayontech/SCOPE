#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { run } = require('../scripts/enum/rds');

const FIXTURES = path.join(__dirname, 'fixtures', 'enum', 'rds');
const apiResponses = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'api-responses.json'), 'utf-8'));
const expected = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'expected.json'), 'utf-8'));

function makeMockClient(responses) {
  const callCounts = {};
  return {
    send(command) {
      const name = command.constructor.name;
      callCounts[name] = (callCounts[name] || 0) + 1;
      const val = responses[name];
      if (Array.isArray(val)) return Promise.resolve(val[callCounts[name] - 1] ?? val[val.length - 1]);
      if (val !== undefined) return Promise.resolve(val);
      return Promise.reject(new Error(`Unexpected command: ${name}`));
    }
  };
}

let passed = 0;
let failed = 0;

async function runTests() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-rds-test-'));

  try {
    const mockRds = makeMockClient(apiResponses);

    const result = await run({
      runDir: tmpDir,
      region: 'us-east-1',
      accountId: '123456789012',
      clients: { rds: mockRds },
    });

    try {
      assert.strictEqual(result.status, expected.status);
      assert.deepStrictEqual(result.findings, expected.findings);
      console.log('  PASS: rds enum output matches expected');
      passed++;
    } catch (err) {
      console.error('  FAIL: rds enum output mismatch');
      console.error(`    ${err.message}`);
      failed++;
    }
  } catch (err) {
    console.error('  FAIL: run() threw an error');
    console.error(`    ${err.message}`);
    failed++;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

runTests().then(() => {
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
});
