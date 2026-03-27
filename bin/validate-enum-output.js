#!/usr/bin/env node
// SCOPE Enumeration Output Validator
// Validates a module envelope JSON file against required envelope and finding fields.
// Used by all 12 enumeration agents to verify output correctness.
//
// Usage:
//   node bin/validate-enum-output.js <path-to-envelope.json>
//
// Exit codes:
//   0 — validation passed
//   1 — validation failed (missing/invalid fields) or usage error

'use strict';

const fs = require('fs');
const path = require('path');

const VALID_MODULES = ['iam', 'sts', 's3', 'kms', 'secrets', 'lambda', 'ec2', 'rds', 'sns', 'sqs', 'apigateway', 'codebuild'];
const VALID_STATUSES = ['complete', 'partial', 'error'];

function main() {
  const filePath = process.argv[2];

  if (!filePath) {
    console.error('Usage: node bin/validate-enum-output.js <path-to-envelope.json>');
    process.exit(1);
  }

  const resolved = path.resolve(filePath);

  // Read file
  let raw;
  try {
    raw = fs.readFileSync(resolved, 'utf-8');
  } catch (err) {
    console.error(`[FAIL] Cannot read file: ${err.message}`);
    process.exit(1);
  }

  // Parse JSON
  let envelope;
  try {
    envelope = JSON.parse(raw);
  } catch (err) {
    console.error(`[FAIL] Invalid JSON: ${err.message}`);
    process.exit(1);
  }

  const errors = [];

  // --- Envelope-level field validation ---

  // module
  if (envelope.module === undefined || envelope.module === null) {
    errors.push('[FAIL] Missing required field: module');
  } else if (typeof envelope.module !== 'string') {
    errors.push(`[FAIL] Field "module" must be a string, got ${typeof envelope.module}`);
  } else if (!VALID_MODULES.includes(envelope.module)) {
    errors.push(`[FAIL] Field "module" has invalid value "${envelope.module}" — must be one of: ${VALID_MODULES.join(', ')}`);
  }

  // account_id
  if (envelope.account_id === undefined || envelope.account_id === null) {
    errors.push('[FAIL] Missing required field: account_id');
  } else if (typeof envelope.account_id !== 'string') {
    errors.push(`[FAIL] Field "account_id" must be a string, got ${typeof envelope.account_id}`);
  } else if (!/^\d{12}$/.test(envelope.account_id)) {
    errors.push(`[FAIL] Field "account_id" must match pattern ^\\d{12}$ — got "${envelope.account_id}"`);
  }

  // region
  if (envelope.region === undefined || envelope.region === null) {
    errors.push('[FAIL] Missing required field: region');
  } else if (typeof envelope.region !== 'string') {
    errors.push(`[FAIL] Field "region" must be a string, got ${typeof envelope.region}`);
  }

  // timestamp
  if (envelope.timestamp === undefined || envelope.timestamp === null) {
    errors.push('[FAIL] Missing required field: timestamp');
  } else if (typeof envelope.timestamp !== 'string') {
    errors.push(`[FAIL] Field "timestamp" must be a string, got ${typeof envelope.timestamp}`);
  }

  // status
  if (envelope.status === undefined || envelope.status === null) {
    errors.push('[FAIL] Missing required field: status');
  } else if (typeof envelope.status !== 'string') {
    errors.push(`[FAIL] Field "status" must be a string, got ${typeof envelope.status}`);
  } else if (!VALID_STATUSES.includes(envelope.status)) {
    errors.push(`[FAIL] Field "status" has invalid value "${envelope.status}" — must be one of: ${VALID_STATUSES.join(', ')}`);
  }

  // findings
  if (envelope.findings === undefined || envelope.findings === null) {
    errors.push('[FAIL] Missing required field: findings');
  } else if (!Array.isArray(envelope.findings)) {
    errors.push(`[FAIL] Field "findings" must be an array, got ${typeof envelope.findings}`);
  }

  // If envelope has critical errors at this point, bail before per-finding checks
  if (errors.length > 0) {
    for (const e of errors) console.error(e);
    console.error(`\n[FAIL] ${errors.length} validation error(s) — ${resolved}`);
    process.exit(1);
  }

  // --- Per-finding field validation ---
  const findings = envelope.findings;
  const FINDING_REQUIRED = ['resource_type', 'resource_id', 'arn', 'region', 'findings'];

  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i];
    const prefix = `findings[${i}]`;

    if (typeof finding !== 'object' || finding === null || Array.isArray(finding)) {
      errors.push(`[FAIL] ${prefix}: must be an object`);
      continue;
    }

    for (const field of FINDING_REQUIRED) {
      if (finding[field] === undefined || finding[field] === null) {
        errors.push(`[FAIL] ${prefix}: missing required field "${field}"`);
      }
    }

    // findings inner array check
    if (finding.findings !== undefined && finding.findings !== null && !Array.isArray(finding.findings)) {
      errors.push(`[FAIL] ${prefix}.findings must be an array, got ${typeof finding.findings}`);
    }
  }

  if (errors.length > 0) {
    for (const e of errors) console.error(e);
    console.error(`\n[FAIL] ${errors.length} validation error(s) — ${resolved}`);
    process.exit(1);
  }

  console.log(`[OK] ${resolved} passes validation (${findings.length} findings checked)`);
  process.exit(0);
}

main();
