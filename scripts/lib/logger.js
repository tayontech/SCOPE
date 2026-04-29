'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Creates a structured JSONL logger that writes to $RUN_DIR/agent-log.jsonl.
 *
 * @param {string} runDir - Path to the run directory
 * @param {string} [moduleName] - Optional module name for log records
 * @returns {Object} Logger instance with log() and flush() methods
 */
function createLogger(runDir, moduleName) {
  if (!runDir || typeof runDir !== 'string') {
    throw new Error('runDir is required for logger');
  }

  const logPath = path.join(runDir, 'agent-log.jsonl');
  let stream = null;

  function ensureStream() {
    if (!stream) {
      fs.mkdirSync(runDir, { recursive: true });
      stream = fs.createWriteStream(logPath, { flags: 'a', encoding: 'utf8' });
    }
    return stream;
  }

  /**
   * Appends a structured log record.
   *
   * @param {string} type - Record type (e.g., 'api_call', 'error', 'info')
   * @param {string} action - Action description (e.g., 'ListUsers', 'DescribeBuckets')
   * @param {Object} [details={}] - Additional details
   */
  function log(type, action, details = {}) {
    const record = {
      timestamp: new Date().toISOString(),
      type,
      module: moduleName || null,
      action,
      details,
    };
    ensureStream().write(JSON.stringify(record) + '\n');
  }

  /**
   * Ensures all buffered writes are flushed to disk.
   *
   * @returns {Promise<void>}
   */
  function flush() {
    return new Promise((resolve, reject) => {
      if (!stream) {
        resolve();
        return;
      }
      stream.end((err) => {
        if (err) reject(err);
        else {
          stream = null;
          resolve();
        }
      });
    });
  }

  return { log, flush };
}

module.exports = { createLogger };
