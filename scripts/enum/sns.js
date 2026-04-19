'use strict';

const {
  SNSClient,
  ListTopicsCommand,
  GetTopicAttributesCommand,
} = require('@aws-sdk/client-sns');
const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');

const { withRetry, paginate, createEnvelope, writeEnvelope, createLogger } = require('../lib');

// --- CLI ---

function parseArgs(argv) {
  const args = { runDir: null, region: null };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--run-dir' && argv[i + 1]) {
      args.runDir = argv[++i];
    } else if (argv[i] === '--region' && argv[i + 1]) {
      args.region = argv[++i];
    } else if (argv[i] === '--help' || argv[i] === '-h') {
      console.log('Usage: node scripts/enum/sns.js --run-dir <dir> --region <region>');
      console.log('');
      console.log('Options:');
      console.log('  --run-dir  Path to the run output directory (required)');
      console.log('  --region   AWS region to enumerate (required)');
      console.log('  --help     Show this help message');
      process.exit(0);
    }
  }
  return args;
}

// --- Helpers ---

/**
 * Extracts principals from a resource policy JSON string.
 */
function extractPrincipals(policyJson) {
  if (!policyJson) return [];
  try {
    const doc = JSON.parse(policyJson);
    const statements = Array.isArray(doc.Statement) ? doc.Statement : [];
    const principals = new Set();

    for (const stmt of statements) {
      if (stmt.Effect !== 'Allow') continue;
      const principal = stmt.Principal;
      if (!principal) continue;

      if (typeof principal === 'string') {
        principals.add(principal);
      } else if (typeof principal === 'object') {
        for (const key of ['AWS', 'Service', 'Federated']) {
          const val = principal[key];
          if (!val) continue;
          if (typeof val === 'string') principals.add(val);
          else if (Array.isArray(val)) val.forEach((v) => principals.add(v));
        }
      }
    }
    return [...principals];
  } catch {
    return [];
  }
}

/**
 * Extracts topic name from ARN (last segment after ':').
 */
function topicNameFromArn(arn) {
  if (!arn) return null;
  const parts = arn.split(':');
  return parts[parts.length - 1];
}

// --- Main ---

async function main() {
  const args = parseArgs(process.argv);

  if (!args.runDir || !args.region) {
    console.error('Error: --run-dir and --region are required');
    console.error('Usage: node scripts/enum/sns.js --run-dir <dir> --region <region>');
    process.exit(1);
  }

  const logger = createLogger(args.runDir);
  logger.log('info', 'SNS_Enumeration_Start', { region: args.region });

  // Get account ID via STS
  const stsClient = new STSClient({ region: args.region });
  let accountId;
  try {
    const identity = await withRetry(() => stsClient.send(new GetCallerIdentityCommand({})));
    accountId = identity.Account;
  } catch (err) {
    logger.log('error', 'GetCallerIdentity', { error: err.message });
    await logger.flush();
    console.error(`FATAL: GetCallerIdentity failed: ${err.message}`);
    process.exit(1);
  }

  const client = new SNSClient({ region: args.region });
  const findings = [];
  let status = 'complete';
  const errors = [];

  // List all topics (paginated via NextToken)
  let topics;
  try {
    logger.log('api_call', 'ListTopics', { region: args.region });
    topics = await paginate(client, ListTopicsCommand, 'Topics', {});
  } catch (err) {
    logger.log('error', 'ListTopics', { error: err.message });
    const envelope = createEnvelope({
      module: 'sns',
      account_id: accountId,
      region: args.region,
      status: 'error',
      findings: [],
    });
    writeEnvelope(args.runDir, envelope);
    await logger.flush();
    process.exit(1);
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
      const principals = extractPrincipals(policy);
      const kmsKeyId = attrs.KmsMasterKeyId || null;
      const subscriptionsConfirmed = parseInt(attrs.SubscriptionsConfirmed, 10) || 0;

      findings.push({
        resource_type: 'sns_topic',
        resource_id: topicName,
        arn: topicArn,
        region: args.region,
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

  const envelope = createEnvelope({
    module: 'sns',
    account_id: accountId,
    region: args.region,
    status,
    findings,
  });

  const outPath = writeEnvelope(args.runDir, envelope);
  logger.log('info', 'SNS_Enumeration_Complete', {
    status,
    topics: findings.length,
    errors: errors.length,
    output: outPath,
  });

  await logger.flush();
  console.log(`SNS enumeration complete: ${outPath} (${findings.length} topics, status: ${status})`);
}

main().catch((err) => {
  console.error(`Fatal error: ${err.message}`);
  process.exit(1);
});
