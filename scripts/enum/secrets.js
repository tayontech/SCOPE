'use strict';

const {
  SecretsManagerClient,
  ListSecretsCommand,
  GetResourcePolicyCommand,
} = require('@aws-sdk/client-secrets-manager');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { extractPolicyPrincipals } = require('../lib/policy-parser');

// --- Helpers ---

function generateFindings(secret) {
  const findings = [];

  if (!secret.rotation_enabled) {
    findings.push({
      type: 'no_rotation',
      severity: 'medium',
      detail: 'Secret rotation is not enabled',
    });
  }

  if (secret.resource_policy_principals && secret.resource_policy_principals.includes('*')) {
    findings.push({
      type: 'wildcard_principal',
      severity: 'high',
      detail: 'Secret resource policy allows wildcard principal',
    });
  }

  // Stale secret (not accessed in 90+ days)
  if (secret.last_accessed_date) {
    const daysSinceAccess = Math.floor(
      (Date.now() - new Date(secret.last_accessed_date).getTime()) / (1000 * 60 * 60 * 24)
    );
    if (daysSinceAccess >= 90) {
      findings.push({
        type: 'stale_secret',
        severity: 'low',
        detail: `Secret not accessed in ${daysSinceAccess} days`,
      });
    }
  }

  return findings;
}

// --- Run (dependency-injectable) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const client = opts.clients?.secrets ?? new SecretsManagerClient({ region });

  const logger = opts.logger || createLogger(runDir, 'secrets');
  logger.log('info', 'Secrets_Enumeration_Start', { region });

  const findings = [];
  let status = 'complete';
  const errors = [];

  // ListSecrets (paginated)
  let allSecrets;
  try {
    logger.log('api_call', 'ListSecrets', { service: 'secretsmanager' });
    allSecrets = await paginate(client, ListSecretsCommand, 'SecretList', {});
  } catch (err) {
    logger.log('error', 'ListSecrets', { error: err.message });
    await logger.flush();
    throw new Error(`ListSecrets failed: ${err.message}`);
  }

  // Per-secret: GetResourcePolicy
  for (const secret of allSecrets) {
    const secretName = secret.Name;
    const secretArn = secret.ARN;

    const secretFinding = {
      resource_type: 'secrets_secret',
      resource_id: secretName,
      arn: secretArn,
      region,
      rotation_enabled: secret.RotationEnabled || false,
      last_rotated_date: secret.LastRotatedDate?.toISOString() || null,
      last_accessed_date: secret.LastAccessedDate?.toISOString() || null,
      kms_key_id: secret.KmsKeyId || null,
      resource_policy_principals: [],
      findings: [],
    };

    // GetResourcePolicy
    try {
      logger.log('api_call', 'GetResourcePolicy', { secret: secretName });
      const policyResp = await withRetry(() =>
        client.send(new GetResourcePolicyCommand({ SecretId: secretArn }))
      );
      if (policyResp.ResourcePolicy) {
        secretFinding.resource_policy_principals = extractPolicyPrincipals(policyResp.ResourcePolicy);
      }
    } catch (err) {
      const code = err.name || err.Code || '';
      if (code === 'ResourceNotFoundException') {
        // Secret may have been deleted between list and get
        logger.log('warning', 'GetResourcePolicy', { secret: secretName, error: 'ResourceNotFound' });
        continue;
      }
      errors.push({ resource: secretName, error: err.message });
      logger.log('warning', 'GetResourcePolicy', { secret: secretName, error: err.message });
    }

    secretFinding.findings = generateFindings(secretFinding);
    findings.push(secretFinding);
  }

  if (errors.length > 0) status = 'partial';

  await logger.flush();
  return { findings, status };
}

if (require.main === module) {
  baseEnum({ module: 'secrets', run });
}

module.exports = { run };
