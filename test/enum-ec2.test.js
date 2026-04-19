'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { run } = require('../scripts/enum/ec2');

const FIXTURES = path.join(__dirname, 'fixtures', 'enum', 'ec2');
const apiResponses = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'api-responses.json'), 'utf-8'));
const expected = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'expected.json'), 'utf-8'));

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

let passed = 0, failed = 0;

async function runTests() {
  // --- Test: ec2 basic scenario ---
  try {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-test-ec2-'));

    const mockEc2 = makeMockClient(apiResponses);
    const mockSts = makeMockClient({
      GetCallerIdentityCommand: apiResponses.GetCallerIdentityCommand
    });
    // elbv2 and elb both use DescribeLoadBalancersCommand — return empty list
    const mockElbv2 = makeMockClient({
      DescribeLoadBalancersCommand: apiResponses.DescribeLoadBalancersCommand
    });
    const mockElb = makeMockClient({
      DescribeLoadBalancersCommand: apiResponses.DescribeLoadBalancersCommand
    });

    await run({
      runDir: tmpDir,
      region: 'us-east-1',
      clients: {
        ec2: mockEc2,
        sts: mockSts,
        elbv2: mockElbv2,
        elb: mockElb
      }
    });

    const actual = JSON.parse(fs.readFileSync(path.join(tmpDir, 'ec2.json'), 'utf-8'));
    delete actual.timestamp;

    assert.deepStrictEqual(actual, expected);
    console.log('  PASS: ec2 basic scenario');
    passed++;
    fs.rmSync(tmpDir, { recursive: true });
  } catch (err) {
    console.error('  FAIL: ec2 basic scenario');
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
