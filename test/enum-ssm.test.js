'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { run } = require('../scripts/enum/ssm');
const FIXTURES = path.join(__dirname, 'fixtures', 'enum', 'ssm');

function makeMockClient(responses) {
  const callCounts = {};
  return {
    send(command) {
      const name = command.constructor.name;
      callCounts[name] = (callCounts[name] || 0) + 1;
      const val = responses[name];
      if (Array.isArray(val)) {
        return Promise.resolve(val[callCounts[name] - 1] ?? val[val.length - 1]);
      }
      if (val !== undefined) return Promise.resolve(val);
      return Promise.reject(new Error(`Unexpected command: ${name}`));
    }
  };
}

let passed = 0;
let failed = 0;

async function runTests() {
  const apiResponses = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'api-responses.json'), 'utf-8'));
  const expected = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'expected.json'), 'utf-8'));

  // --- Test: basic scenario ---
  try {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-test-ssm-'));

    const mockSsm = makeMockClient({
      DescribeParametersCommand: apiResponses['DescribeParametersCommand'],
      GetResourcePolicyCommand: apiResponses['GetResourcePolicyCommand'],
    });

    const result = await run({
      runDir: tmpDir,
      region: 'us-east-1',
      accountId: '123456789012',
      clients: { ssm: mockSsm },
    });

    assert.strictEqual(result.status, expected.status);
    assert.deepStrictEqual(result.findings, expected.findings);
    console.log('  PASS: ssm basic scenario');
    passed++;
    fs.rmSync(tmpDir, { recursive: true });
  } catch (err) {
    console.error('  FAIL: ssm basic scenario');
    console.error(`    ${err.message}`);
    failed++;
  }

  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => {
  console.error(`Fatal: ${err.message}`);
  process.exit(1);
});
