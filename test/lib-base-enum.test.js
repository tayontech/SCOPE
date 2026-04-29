#!/usr/bin/env node
'use strict';

const assert = require('assert');
const { parseArgs } = require('../scripts/lib/base-enum');

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

test('parseArgs extracts all flags', () => {
  const args = parseArgs(['node', 'script.js', '--run-dir', '/tmp/test', '--account-id', '123456789012', '--region', 'us-east-1,us-west-2']);
  assert.strictEqual(args.runDir, '/tmp/test');
  assert.strictEqual(args.accountId, '123456789012');
  assert.strictEqual(args.region, 'us-east-1,us-west-2');
});

test('parseArgs handles missing flags', () => {
  const args = parseArgs(['node', 'script.js', '--run-dir', '/tmp/test']);
  assert.strictEqual(args.runDir, '/tmp/test');
  assert.strictEqual(args.accountId, null);
  assert.strictEqual(args.region, null);
});

test('parseArgs handles empty argv', () => {
  const args = parseArgs(['node', 'script.js']);
  assert.strictEqual(args.runDir, null);
  assert.strictEqual(args.accountId, null);
  assert.strictEqual(args.region, null);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
