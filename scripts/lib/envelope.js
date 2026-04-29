'use strict';

const fs = require('fs');
const path = require('path');

const REQUIRED_FIELDS = ['module', 'account_id', 'region', 'status'];
const VALID_STATUSES = new Set(['complete', 'partial', 'error']);

/**
 * Creates a standard module envelope for enum output.
 *
 * @param {Object} params
 * @param {string} params.module - Module name (e.g., 'iam', 's3', 'bedrock')
 * @param {string} params.account_id - AWS account ID
 * @param {string} params.region - AWS region
 * @param {string} params.status - One of: 'complete', 'partial', 'error'
 * @param {Array} [params.findings=[]] - Array of finding objects
 * @returns {Object} The envelope object with timestamp added
 */
function createEnvelope({ module, account_id, region, status, findings = [] }) {
  // Validate required fields
  const missing = REQUIRED_FIELDS.filter((f) => {
    const val = { module, account_id, region, status }[f];
    return !val || typeof val !== 'string';
  });
  if (missing.length > 0) {
    throw new Error(`Envelope missing required fields: ${missing.join(', ')}`);
  }

  if (!VALID_STATUSES.has(status)) {
    throw new Error(`Invalid status "${status}". Must be one of: ${[...VALID_STATUSES].join(', ')}`);
  }

  if (!Array.isArray(findings)) {
    throw new Error('findings must be an array');
  }

  return {
    module,
    account_id,
    region,
    status,
    timestamp: new Date().toISOString(),
    findings,
  };
}

/**
 * Writes an envelope to the run directory as {module}.json.
 *
 * @param {string} runDir - Path to the run directory
 * @param {Object} envelope - The envelope object (from createEnvelope)
 * @returns {string} The file path written
 */
function writeEnvelope(runDir, envelope) {
  if (!runDir || typeof runDir !== 'string') {
    throw new Error('runDir is required');
  }
  if (!envelope || !envelope.module) {
    throw new Error('envelope with module field is required');
  }

  const filePath = path.join(runDir, `${envelope.module}.json`);
  fs.mkdirSync(runDir, { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(envelope, null, 2) + '\n', 'utf8');
  return filePath;
}

/**
 * Safely converts a Date to ISO string. Returns null if the date is invalid or missing.
 * Protects against Invalid Date objects that throw on toISOString().
 */
function safeISOString(d) {
  try {
    return d?.toISOString() ?? null;
  } catch {
    return null;
  }
}

module.exports = { createEnvelope, writeEnvelope, safeISOString };
