'use strict';

const {
  SNSClient,
  ListTopicsCommand,
  GetTopicAttributesCommand,
} = require('@aws-sdk/client-sns');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { extractPolicyPrincipals } = require('../lib/policy-parser');

// --- Helpers ---

/**
 * Extracts topic name from ARN (last segment after ':').
 */
function topicNameFromArn(arn) {
  if (!arn) return null;
  const parts = arn.split(':');
  return parts[parts.length - 1];
}

// --- Exported run() for testing ---

async function run(opts = {}) {
  const { runDir, region } = opts;
  const accountId = opts.accountId;

  if (!runDir || !region) {
    throw new Error('runDir and region are required');
  }

  const client = opts.clients?.sns ?? new SNSClient({ region });

  const logger = opts.logger || createLogger(runDir, 'sns');
  logger.log('info', 'SNS_Enumeration_Start', { region });

  const findings = [];
  let status = 'complete';
  const errors = [];

  // List all topics (paginated via NextToken)
  let topics;
  try {
    logger.log('api_call', 'ListTopics', { region });
    topics = await paginate(client, ListTopicsCommand, 'Topics', {});
  } catch (err) {
    logger.log('error', 'ListTopics', { error: err.message });
    await logger.flush();
    throw new Error(`ListTopics failed: ${err.message}`);
  }

  // Per-topic: GetTopicAttributes
  for (const topic of topics) {
    const topicArn = topic.TopicArn;
    const topicName = topicNameFromArn(topicArn);

    try {
      logger.log('api_call', 'GetTopicAttributes', { topic: topicArn });
      const resp = await withRetry(() =>
        client.send(new GetTopicAttributesCommand({ TopicArn: topicArn }))
      );
      const attrs = resp.Attributes || {};

      const policy = attrs.Policy || null;
      const principals = extractPolicyPrincipals(policy);
      const kmsKeyId = attrs.KmsMasterKeyId || null;
      const subscriptionsConfirmed = parseInt(attrs.SubscriptionsConfirmed, 10) || 0;

      findings.push({
        resource_type: 'sns_topic',
        resource_id: topicName,
        arn: topicArn,
        region,
        resource_policy: principals.length > 0 ? { principals } : null,
        kms_key_id: kmsKeyId,
        subscriptions_confirmed: subscriptionsConfirmed,
        findings: [],
      });
    } catch (err) {
      errors.push({ resource: topicArn, error: err.message });
      logger.log('warning', 'GetTopicAttributes', { topic: topicArn, error: err.message });
    }
  }

  if (errors.length > 0) status = 'partial';

  await logger.flush();
  return { findings, status };
}

if (require.main === module) {
  baseEnum({ module: 'sns', run });
}

module.exports = { run };
