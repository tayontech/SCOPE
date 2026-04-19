'use strict';

const THROTTLE_CODES = new Set([
  'ThrottlingException',
  'TooManyRequestsException',
  'Throttling',
  'RequestLimitExceeded',
  'BandwidthLimitExceeded',
]);

/**
 * Wraps an async function with exponential backoff retry on AWS throttling errors.
 *
 * @param {Function} fn - Async function to call (receives no arguments; use a closure)
 * @param {Object} [opts]
 * @param {number} [opts.maxRetries=3] - Maximum retry attempts
 * @param {number} [opts.baseDelayMs=1000] - Base delay in ms (doubled each retry)
 * @param {AbortSignal} [opts.signal] - Optional abort signal
 * @returns {Promise<*>} Result of fn()
 */
async function withRetry(fn, opts = {}) {
  const maxRetries = opts.maxRetries ?? 3;
  const baseDelayMs = opts.baseDelayMs ?? 1000;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (opts.signal?.aborted) {
      throw new Error('Operation aborted');
    }
    try {
      return await fn();
    } catch (err) {
      const code = err.name || err.Code || err.__type || '';
      const httpStatus = err.$metadata?.httpStatusCode;
      const isThrottle = THROTTLE_CODES.has(code) || httpStatus === 429 || httpStatus === 503;
      if (!isThrottle || attempt >= maxRetries) {
        throw err;
      }
      const delay = baseDelayMs * Math.pow(2, attempt);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
}

/**
 * Paginates an AWS SDK v3 command, collecting all items across pages.
 *
 * Uses the standard NextToken / Marker pagination patterns in AWS SDK v3.
 * The caller provides a key to extract from each response (e.g., 'Users', 'Buckets').
 *
 * @param {Object} client - AWS SDK v3 client instance
 * @param {Function} CommandClass - The Command constructor (e.g., ListUsersCommand)
 * @param {string} paginationKey - Response key containing items (e.g., 'Users')
 * @param {Object} [opts]
 * @param {Object} [opts.params={}] - Additional params for the command
 * @param {string} [opts.tokenKey='NextToken'] - Request token field name
 * @param {string} [opts.responseTokenKey] - Response token field name (defaults to tokenKey)
 * @param {number} [opts.maxRetries=3] - Retry config passed to withRetry
 * @param {AbortSignal} [opts.signal] - Optional abort signal
 * @returns {Promise<Array>} All collected items across all pages
 */
async function paginate(client, CommandClass, paginationKey, opts = {}) {
  const params = { ...opts.params };
  const tokenKey = opts.tokenKey || 'NextToken';
  const responseTokenKey = opts.responseTokenKey || tokenKey;
  const retryOpts = { maxRetries: opts.maxRetries ?? 3, signal: opts.signal };

  const allItems = [];
  let nextToken = undefined;

  do {
    if (nextToken) {
      params[tokenKey] = nextToken;
    }

    const response = await withRetry(
      () => client.send(new CommandClass(params)),
      retryOpts
    );

    const items = response[paginationKey];
    if (Array.isArray(items)) {
      allItems.push(...items);
    }

    nextToken = response[responseTokenKey];
    // Some APIs use 'Marker' for request but 'NextMarker' for response
    if (!nextToken && response.NextMarker) {
      nextToken = response.NextMarker;
    }
    if (!nextToken && response.IsTruncated && response.Marker) {
      nextToken = response.Marker;
    }
  } while (nextToken);

  return allItems;
}

module.exports = { withRetry, paginate };
