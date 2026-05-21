'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const SCHEMA_PATH = path.join(__dirname, '..', 'config', 'schemas', 'audit.schema.json');

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

const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf-8'));
const nodeTypes = schema.properties.graph.properties.nodes.items.properties.type.enum;
const edgeTypes = schema.properties.graph.properties.edges.items.properties.edge_type.enum;

test('audit schema allows graph node types emitted by extract-graph', () => {
  const emittedTypes = [
    'user',
    'role',
    'group',
    'external',
    'data',
    'compute',
    'gateway',
    'messaging',
    'ai',
    'idp',
    'oidc',
  ];
  const missing = emittedTypes.filter((type) => !nodeTypes.includes(type));
  assert.deepStrictEqual(missing, []);
});

test('audit schema allows graph edge types emitted by extract-graph', () => {
  const emittedTypes = [
    'trust',
    'service',
    'membership',
    'executes_as',
    'invokes',
    'authenticates_to',
  ];
  const missing = emittedTypes.filter((type) => !edgeTypes.includes(type));
  assert.deepStrictEqual(missing, []);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
