#!/usr/bin/env node
'use strict';

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const SCRIPT = path.join(__dirname, '..', 'bin', 'extract-graph.js');
const FIXTURES = path.join(__dirname, 'fixtures', 'extract-graph');

// Get all scenario directories
const scenarios = fs.readdirSync(FIXTURES).filter(d =>
  fs.statSync(path.join(FIXTURES, d)).isDirectory()
);

let passed = 0;
let failed = 0;

for (const scenario of scenarios) {
  const scenarioDir = path.join(FIXTURES, scenario);
  const expectedFile = path.join(scenarioDir, 'expected.json');
  const expected = JSON.parse(fs.readFileSync(expectedFile, 'utf-8'));

  try {
    const stdout = execSync(`node "${SCRIPT}" "${scenarioDir}"`, { encoding: 'utf-8' });
    const actual = JSON.parse(stdout);
    assert.deepStrictEqual(actual, expected);
    console.log(`  PASS: ${scenario}`);
    passed++;
  } catch (err) {
    console.error(`  FAIL: ${scenario}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

// Test: no args = exit 1
try {
  execSync(`node "${SCRIPT}"`, { encoding: 'utf-8', stdio: 'pipe' });
  console.error('  FAIL: no-args (expected exit 1, got exit 0)');
  failed++;
} catch (err) {
  if (err.status === 1) {
    console.log('  PASS: no-args exits 1');
    passed++;
  } else {
    console.error(`  FAIL: no-args (expected exit 1, got exit ${err.status})`);
    failed++;
  }
}

// Test: nonexistent dir = exit 1
try {
  execSync(`node "${SCRIPT}" "/nonexistent/path"`, { encoding: 'utf-8', stdio: 'pipe' });
  console.error('  FAIL: bad-dir (expected exit 1, got exit 0)');
  failed++;
} catch (err) {
  if (err.status === 1) {
    console.log('  PASS: bad-dir exits 1');
    passed++;
  } else {
    console.error(`  FAIL: bad-dir (expected exit 1, got exit ${err.status})`);
    failed++;
  }
}

console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
