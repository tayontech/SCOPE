'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { run } = require('../scripts/enum/sts');
const FIXTURES = path.join(__dirname, 'fixtures', 'enum', 'sts');
const apiResponses = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'api-responses.json'), 'utf-8'));
const expected = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'expected.json'), 'utf-8'));

function makeMockClient(responses) {
  const callCounts = {};
  return {
    send(command) {
      const name = command.constructor.name;
      callCounts[name] = (callCounts[name] || 0) + 1;
      const val = Array.isArray(responses[name])
        ? responses[name][callCounts[name] - 1] ?? responses[name][responses[name].length - 1]
        : responses[name];
      if (val !== undefined) {
        if (val && val._error) {
          const err = new Error(val.message || 'Mock error');
          err.name = val.name || 'Error';
          return Promise.reject(err);
        }
        return Promise.resolve(val);
      }
      return Promise.reject(new Error(`Unexpected command: ${name}`));
    }
  };
}

let passed = 0;
let failed = 0;

async function runTests() {
  // Test: STS identity with org access denied (partial status)
  try {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-test-sts-'));
    const mockSts = makeMockClient(apiResponses);
    const mockOrg = makeMockClient(apiResponses);
    const result = await run({ runDir: tmpDir, clients: { sts: mockSts, organizations: mockOrg } });
    assert.strictEqual(result.status, expected.status);
    assert.deepStrictEqual(result.findings, expected.findings);
    console.log('  PASS: sts identity with org access denied');
    passed++;
    fs.rmSync(tmpDir, { recursive: true });
  } catch (err) {
    console.error('  FAIL: sts identity with org access denied');
    console.error(`    ${err.message}`);
    failed++;
  }

  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => { console.error(`Fatal: ${err.message}`); process.exit(1); });
