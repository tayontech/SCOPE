#!/usr/bin/env node
'use strict';

const assert = require('assert');
const { extractPolicyPrincipals } = require('../scripts/lib/policy-parser');

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

test('extracts wildcard principal', () => {
  const policy = JSON.stringify({
    Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: '*' }],
  });
  const result = extractPolicyPrincipals(policy);
  assert.deepStrictEqual(result, ['*']);
});

test('extracts AWS principals', () => {
  const policy = JSON.stringify({
    Statement: [{ Effect: 'Allow', Principal: { AWS: ['arn:aws:iam::123456789012:root', 'arn:aws:iam::999999999999:role/cross'] }, Action: '*', Resource: '*' }],
  });
  const result = extractPolicyPrincipals(policy);
  assert.strictEqual(result.length, 2);
  assert.ok(result.includes('arn:aws:iam::123456789012:root'));
  assert.ok(result.includes('arn:aws:iam::999999999999:role/cross'));
});

test('extracts Service principals', () => {
  const policy = JSON.stringify({
    Statement: [{ Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: '*', Resource: '*' }],
  });
  const result = extractPolicyPrincipals(policy);
  assert.deepStrictEqual(result, ['lambda.amazonaws.com']);
});

test('skips Deny statements', () => {
  const policy = JSON.stringify({
    Statement: [{ Effect: 'Deny', Principal: '*', Action: '*', Resource: '*' }],
  });
  const result = extractPolicyPrincipals(policy);
  assert.deepStrictEqual(result, []);
});

test('returns empty for null input', () => {
  assert.deepStrictEqual(extractPolicyPrincipals(null), []);
});

test('returns empty for invalid JSON', () => {
  assert.deepStrictEqual(extractPolicyPrincipals('not-json'), []);
});

test('deduplicates principals', () => {
  const policy = JSON.stringify({
    Statement: [
      { Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::123456789012:root' }, Action: 's3:Get*', Resource: '*' },
      { Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::123456789012:root' }, Action: 's3:Put*', Resource: '*' },
    ],
  });
  const result = extractPolicyPrincipals(policy);
  assert.strictEqual(result.length, 1);
});

test('handles pre-parsed object input', () => {
  const policy = {
    Statement: [{ Effect: 'Allow', Principal: { Service: 'sns.amazonaws.com' }, Action: 'sqs:SendMessage', Resource: '*' }],
  };
  const result = extractPolicyPrincipals(policy);
  assert.deepStrictEqual(result, ['sns.amazonaws.com']);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
