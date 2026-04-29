'use strict';

const {
  SSMClient,
  DescribeParametersCommand,
  GetResourcePolicyCommand,
} = require('@aws-sdk/client-ssm');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');

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
  const accountId = opts.accountId;

  const logger = opts.logger || createLogger(runDir, 'ssm');
  let status = 'complete';
  const partialErrors = [];

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

  await logger.flush();
  return { findings, status };
}

if (require.main === module) {
  baseEnum({ module: 'ssm', run });
}

module.exports = { run };
