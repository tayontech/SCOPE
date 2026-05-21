'use strict';
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const testDir = __dirname;
const tests = fs.readdirSync(testDir)
  .filter(f => f.endsWith('.test.js'))
  .sort();

console.log(`Running ${tests.length} test files...\n`);
let ok = true;
for (const t of tests) {
  console.log(`--- ${t} ---`);
  try {
    execSync(`node ${path.join(testDir, t)}`, { stdio: 'inherit' });
  } catch {
    ok = false;
    break; // D-04: fail-fast
  }
}
process.exit(ok ? 0 : 1);
