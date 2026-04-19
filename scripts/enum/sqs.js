'use strict';

const {
  SQSClient,
  ListQueuesCommand,
  GetQueueAttributesCommand,
} = require('@aws-sdk/client-sqs');
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
      console.log('Usage: node scripts/enum/sqs.js --run-dir <dir> --region <region>');
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

// --- Main ---

async function main() {
  const args = parseArgs(process.argv);

  if (!args.runDir || !args.region) {
    console.error('Error: --run-dir and --region are required');
    console.error('Usage: node scripts/enum/sqs.js --run-dir <dir> --region <region>');
    process.exit(1);
  }

  const logger = createLogger(args.runDir);
  logger.log('info', 'SQS_Enumeration_Start', { region: args.region });

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

  const client = new SQSClient({ region: args.region });
  const findings = [];
  let status = 'complete';
  const errors = [];

  // List all queues (paginated via NextToken)
  let queueUrls;
  try {
    logger.log('api_call', 'ListQueues', { region: args.region });
    queueUrls = await paginate(client, ListQueuesCommand, 'QueueUrls', {});
  } catch (err) {
    logger.log('error', 'ListQueues', { error: err.message });
    const envelope = createEnvelope({
      module: 'sqs',
      account_id: accountId,
      region: args.region,
      status: 'error',
      findings: [],
    });
    writeEnvelope(args.runDir, envelope);
    await logger.flush();
    process.exit(1);
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
      const principals = extractPrincipals(policy);
      const isFifo = (attrs.FifoQueue === 'true');
      const dlqArn = extractDlqArn(attrs.RedrivePolicy);
      const kmsKeyId = attrs.KmsMasterKeyId || null;
      const visibilityTimeout = parseInt(attrs.VisibilityTimeout, 10) || 30;

      findings.push({
        resource_type: 'sqs_queue',
        resource_id: queueName,
        arn: queueArn,
        region: args.region,
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

  const envelope = createEnvelope({
    module: 'sqs',
    account_id: accountId,
    region: args.region,
    status,
    findings,
  });

  const outPath = writeEnvelope(args.runDir, envelope);
  logger.log('info', 'SQS_Enumeration_Complete', {
    status,
    queues: findings.length,
    errors: errors.length,
    output: outPath,
  });

  await logger.flush();
  console.log(`SQS enumeration complete: ${outPath} (${findings.length} queues, status: ${status})`);
}

main().catch((err) => {
  console.error(`Fatal error: ${err.message}`);
  process.exit(1);
});
