#!/usr/bin/env node
'use strict';

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const os = require('os');

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

// Test: module envelopes using the current top-level resources contract
try {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-extract-graph-resources-'));
  fs.writeFileSync(path.join(tmpDir, 'iam.json'), JSON.stringify({
    module: 'iam',
    status: 'complete',
    resources: [
      {
        resource_type: 'iam_user',
        resource_id: 'alice',
        groups: ['Developers']
      },
      {
        resource_type: 'iam_group',
        resource_id: 'Developers'
      },
      {
        resource_type: 'iam_role',
        resource_id: 'LambdaExecRole',
        trust_relationships: [
          { principal: 'lambda.amazonaws.com', trust_type: 'service' }
        ]
      }
    ]
  }));

  const stdout = execSync(`node "${SCRIPT}" "${tmpDir}"`, { encoding: 'utf-8' });
  const actual = JSON.parse(stdout);
  assert.ok(actual.nodes.some(n => n.id === 'user:alice'));
  assert.ok(actual.nodes.some(n => n.id === 'group:Developers'));
  assert.ok(actual.nodes.some(n => n.id === 'role:LambdaExecRole'));
  assert.ok(actual.edges.some(e =>
    e.source === 'svc:lambda.amazonaws.com'
    && e.target === 'role:LambdaExecRole'
    && e.edge_type === 'service'
  ));
  assert.ok(actual.edges.some(e =>
    e.source === 'user:alice'
    && e.target === 'group:Developers'
    && e.edge_type === 'membership'
  ));
  console.log('  PASS: resources-contract input');
  passed++;
  fs.rmSync(tmpDir, { recursive: true });
} catch (err) {
  console.error('  FAIL: resources-contract input');
  console.error(`    ${err.message}`);
  failed++;
}

// Test: current audit layout stores module envelopes under modules/<service>/<region>.json
try {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-extract-graph-modules-layout-'));
  const iamDir = path.join(tmpDir, 'modules', 'iam');
  const lambdaDir = path.join(tmpDir, 'modules', 'lambda');
  fs.mkdirSync(iamDir, { recursive: true });
  fs.mkdirSync(lambdaDir, { recursive: true });
  fs.writeFileSync(path.join(iamDir, 'global.json'), JSON.stringify({
    module: 'iam',
    status: 'complete',
    resources: [
      {
        resource_type: 'iam_role',
        resource_id: 'LambdaExecRole',
        trust_relationships: [
          { principal: 'lambda.amazonaws.com', trust_type: 'service' }
        ]
      }
    ]
  }));
  fs.writeFileSync(path.join(lambdaDir, 'us-east-1.json'), JSON.stringify({
    module: 'lambda',
    status: 'complete',
    resources: [
      {
        resource_type: 'lambda_function',
        resource_id: 'hello',
        role: 'arn:aws:iam::123456789012:role/LambdaExecRole'
      }
    ]
  }));

  const stdout = execSync(`node "${SCRIPT}" "${tmpDir}"`, { encoding: 'utf-8' });
  const actual = JSON.parse(stdout);
  assert.ok(actual.nodes.some(n => n.id === 'role:LambdaExecRole'));
  assert.ok(actual.nodes.some(n => n.id === 'compute:lambda:hello'));
  assert.ok(actual.edges.some(e =>
    e.source === 'compute:lambda:hello'
    && e.target === 'role:LambdaExecRole'
    && e.edge_type === 'executes_as'
  ));
  console.log('  PASS: modules-layout input');
  passed++;
  fs.rmSync(tmpDir, { recursive: true });
} catch (err) {
  console.error('  FAIL: modules-layout input');
  console.error(`    ${err.message}`);
  failed++;
}

// Test: every emitted edge endpoint has a corresponding node so dashboard filters do not drop edges.
try {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-extract-graph-endpoints-'));
  fs.writeFileSync(path.join(tmpDir, 'iam.json'), JSON.stringify({
    module: 'iam',
    status: 'complete',
    resources: [
      {
        resource_type: 'iam_role',
        resource_id: 'RootTrustedRole',
        is_service_linked: false,
        trust_relationships: [
          {
            principal: 'arn:aws:iam::123456789012:root',
            trust_type: 'same-account'
          }
        ]
      }
    ]
  }));

  const stdout = execSync(`node "${SCRIPT}" "${tmpDir}"`, { encoding: 'utf-8' });
  const actual = JSON.parse(stdout);
  const nodeIds = new Set(actual.nodes.map((n) => n.id));
  const missingEndpoints = actual.edges
    .flatMap((edge) => [edge.source, edge.target])
    .filter((id) => !nodeIds.has(id));
  assert.deepStrictEqual(missingEndpoints, []);
  assert.ok(actual.nodes.some((n) => n.id === 'external:arn:aws:iam::123456789012:root'));
  console.log('  PASS: edge endpoints have nodes');
  passed++;
  fs.rmSync(tmpDir, { recursive: true });
} catch (err) {
  console.error('  FAIL: edge endpoints have nodes');
  console.error(`    ${err.message}`);
  failed++;
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
