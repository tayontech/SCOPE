'use strict';

const {
  SSMClient,
  DescribeParametersCommand,
  GetResourcePolicyCommand,
} = require('@aws-sdk/client-ssm');

const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
const { withRetry, paginate, createEnvelope, writeEnvelope, createLogger } = require('../lib');

// --- Argument parsing ---

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--run-dir' && argv[i + 1]) {
      args.runDir = argv[++i];
    } else if (argv[i] === '--region' && argv[i + 1]) {
      args.region = argv[++i];
    } else if (argv[i] === '--regions' && argv[i + 1]) {
      args.regions = argv[++i];
    } else if (argv[i] === '--help' || argv[i] === '-h') {
      console.log('Usage: node scripts/enum/ssm.js --run-dir <dir> --region <region>');
      console.log('       node scripts/enum/ssm.js --run-dir <dir> --regions <r1,r2,...>');
      console.log('');
      console.log('Options:');
      console.log('  --run-dir  Path to the run output directory (required)');
      console.log('  --region   AWS region to enumerate (required, or use --regions)');
      console.log('  --regions  Comma-separated list of regions to enumerate');
      console.log('  --help     Show this help message');
      process.exit(0);
    }
  }
  return args;
}

// --- Resource policy (per-parameter) ---

async function getResourcePolicy(client, parameterName, logger) {
  logger.log('api_call', 'GetResourcePolicy', { parameter: parameterName });
  try {
    const response = await withRetry(() =>
      client.send(new GetResourcePolicyCommand({ ResourceArn: parameterName }))
    );
    if (response.Policy) {
      try {
        return JSON.parse(response.Policy);
      } catch {
        return response.Policy;
      }
    }
    return null;
  } catch (err) {
    // No policy set, or API not available for this parameter
    if (err.name === 'ResourceNotFoundException' || err.name === 'PolicyNotFoundException' ||
        err.name === 'ParameterNotFoundException' || err.name === 'InvalidResourceId' ||
        err.name === 'AccessDeniedException') {
      return null;
    }
    logger.log('warning', 'GetResourcePolicy_Failed', { parameter: parameterName, error: err.message });
    return null;
  }
}

// --- Run (exported for testing) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;

  const logger = opts.logger || createLogger(runDir);
  let status = 'complete';
  const partialErrors = [];

  // Get account ID
  const stsClient = opts.clients?.sts ?? new STSClient({ region });
  logger.log('api_call', 'GetCallerIdentity', {});
  const identity = await withRetry(() => stsClient.send(new GetCallerIdentityCommand({})));
  const accountId = identity.Account;

  // SSM client
  const client = opts.clients?.ssm ?? new SSMClient({ region });

  // DescribeParameters — paginated (metadata only, NEVER reads values)
  logger.log('api_call', 'DescribeParameters', { note: 'metadata only — no value access' });
  const parameters = await paginate(client, DescribeParametersCommand, 'Parameters', {
    tokenKey: 'NextToken',
    responseTokenKey: 'NextToken',
  });

  logger.log('info', 'ParametersDiscovered', { count: parameters.length });

  // Enumerate each parameter
  const findings = [];

  for (const param of parameters) {
    try {
      // Build ARN: arn:aws:ssm:{region}:{account}:parameter{name}
      // SSM parameter names start with / so the ARN has no separator
      const paramArn = `arn:aws:ssm:${region}:${accountId}:parameter${param.Name.startsWith('/') ? '' : '/'}${param.Name}`;

      // KMS key for SecureString parameters
      const kmsKeyId = param.Type === 'SecureString' ? (param.KeyId || 'alias/aws/ssm') : null;

      // Resource policy
      const resourcePolicy = await getResourcePolicy(client, paramArn, logger);

      findings.push({
        resource_type: 'ssm_parameter',
        resource_id: param.Name,
        arn: paramArn,
        region,
        type: param.Type || null,
        tier: param.Tier || 'Standard',
        kms_key_id: kmsKeyId,
        data_type: param.DataType || null,
        last_modified: param.LastModifiedDate ? (param.LastModifiedDate instanceof Date ? param.LastModifiedDate.toISOString() : String(param.LastModifiedDate)) : null,
        version: param.Version || null,
        has_resource_policy: resourcePolicy !== null,
        resource_policy: resourcePolicy,
        findings: [],
      });
    } catch (err) {
      partialErrors.push({ parameter: param.Name, error: err.message });
      logger.log('error', 'ParameterEnumeration_Failed', { parameter: param.Name, error: err.message });
    }
  }

  if (partialErrors.length > 0) {
    status = 'partial';
  }

  if (opts.returnOnly) {
    await logger.flush();
    return findings;
  }

  const envelope = createEnvelope({
    module: 'ssm',
    account_id: accountId,
    region,
    status,
    findings,
  });

  const outputPath = writeEnvelope(runDir, envelope);
  logger.log('info', 'SSM_Enumeration_Complete', {
    status,
    parameters: findings.length,
    secure_string_count: findings.filter((f) => f.type === 'SecureString').length,
    errors: partialErrors.length,
    output: outputPath,
  });

  await logger.flush();
}

// --- CLI entry point ---

async function main() {
  const args = parseArgs(process.argv);
  if (!args.runDir || (!args.region && !args.regions)) {
    console.error('Error: --run-dir and --region (or --regions) are required');
    console.error('Usage: node scripts/enum/ssm.js --run-dir <dir> --region <region>');
    console.error('       node scripts/enum/ssm.js --run-dir <dir> --regions <r1,r2,...>');
    process.exit(1);
  }

  const regionList = args.regions ? args.regions.split(',') : [args.region];

  try {
    if (regionList.length === 1) {
      await run({ runDir: args.runDir, region: regionList[0].trim() });
    } else {
      const allFindings = [];
      for (const region of regionList) {
        const findings = await run({ runDir: args.runDir, region: region.trim(), returnOnly: true });
        if (Array.isArray(findings)) allFindings.push(...findings);
      }
      const envelope = createEnvelope({ module: 'ssm', account_id: null, region: 'multi', status: 'complete', findings: allFindings });
      writeEnvelope(args.runDir, envelope);
    }
    process.exit(0);
  } catch (err) {
    console.error(`Fatal error: ${err.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { run };
