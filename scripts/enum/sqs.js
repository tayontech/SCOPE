'use strict';

const {
  SQSClient,
  ListQueuesCommand,
  GetQueueAttributesCommand,
} = require('@aws-sdk/client-sqs');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { extractPolicyPrincipals } = require('../lib/policy-parser');

// --- Helpers ---

/**
 * Extracts queue name from URL (last segment after '/').
 */
function queueNameFromUrl(url) {
  if (!url) return null;
  const parts = url.split('/');
  return parts[parts.length - 1];
}

/**
 * Extracts DLQ ARN from RedrivePolicy JSON string.
 */
function extractDlqArn(redrivePolicyJson) {
  if (!redrivePolicyJson) return null;
  try {
    const policy = JSON.parse(redrivePolicyJson);
    return policy.deadLetterTargetArn || null;
  } catch {
    return null;
  }
}

// --- Exported run() for testing ---

async function run(opts = {}) {
  const { runDir, region } = opts;
  const accountId = opts.accountId;

  if (!runDir || !region) {
    throw new Error('runDir and region are required');
  }

  const client = opts.clients?.sqs ?? new SQSClient({ region });

  const logger = opts.logger || createLogger(runDir, 'sqs');
  logger.log('info', 'SQS_Enumeration_Start', { region });

  const findings = [];
  let status = 'complete';
  const errors = [];

  // List all queues (paginated via NextToken)
  let queueUrls;
  try {
    logger.log('api_call', 'ListQueues', { region });
    queueUrls = await paginate(client, ListQueuesCommand, 'QueueUrls', {});
  } catch (err) {
    logger.log('error', 'ListQueues', { error: err.message });
    await logger.flush();
    throw new Error(`ListQueues failed: ${err.message}`);
  }

  // Per-queue: GetQueueAttributes (All)
  for (const queueUrl of queueUrls) {
    const queueName = queueNameFromUrl(queueUrl);

    try {
      logger.log('api_call', 'GetQueueAttributes', { queue: queueUrl });
      const resp = await withRetry(() =>
        client.send(new GetQueueAttributesCommand({
          QueueUrl: queueUrl,
          AttributeNames: ['All'],
        }))
      );
      const attrs = resp.Attributes || {};

      const queueArn = attrs.QueueArn || null;
      const policy = attrs.Policy || null;
      const principals = extractPolicyPrincipals(policy);
      const isFifo = (attrs.FifoQueue === 'true');
      const dlqArn = extractDlqArn(attrs.RedrivePolicy);
      const kmsKeyId = attrs.KmsMasterKeyId || null;
      const visibilityTimeout = parseInt(attrs.VisibilityTimeout, 10) || 30;

      findings.push({
        resource_type: 'sqs_queue',
        resource_id: queueName,
        arn: queueArn,
        region,
        queue_url: queueUrl,
        resource_policy: principals.length > 0 ? { principals } : null,
        fifo: isFifo,
        dlq_arn: dlqArn,
        kms_key_id: kmsKeyId,
        visibility_timeout: visibilityTimeout,
        findings: [],
      });
    } catch (err) {
      errors.push({ resource: queueUrl, error: err.message });
      logger.log('warning', 'GetQueueAttributes', { queue: queueUrl, error: err.message });
    }
  }

  if (errors.length > 0) status = 'partial';

  await logger.flush();
  return { findings, status };
}

if (require.main === module) {
  baseEnum({ module: 'sqs', run });
}

module.exports = { run };
