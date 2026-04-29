'use strict';

const {
  KMSClient,
  ListKeysCommand,
  DescribeKeyCommand,
  GetKeyPolicyCommand,
  ListGrantsCommand,
  GetKeyRotationStatusCommand,
} = require('@aws-sdk/client-kms');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { extractPolicyPrincipals } = require('../lib/policy-parser');

// --- Helpers ---

function generateFindings(key) {
  const findings = [];

  if (!key.rotation_enabled) {
    findings.push({
      type: 'no_rotation',
      severity: 'medium',
      detail: 'Key rotation is not enabled',
    });
  }

  if (key.key_state === 'PendingDeletion') {
    findings.push({
      type: 'pending_deletion',
      severity: 'low',
      detail: 'Key is pending deletion',
    });
  }

  // Wildcard principal in policy
  if (key.policy_principals && key.policy_principals.includes('*')) {
    findings.push({
      type: 'wildcard_principal',
      severity: 'high',
      detail: 'Key policy allows wildcard principal',
    });
  }

  // Grants to external accounts
  if (key.grants && key.grants.length > 0) {
    findings.push({
      type: 'has_grants',
      severity: 'low',
      detail: `Key has ${key.grants.length} grant(s)`,
    });
  }

  return findings;
}

// --- Run (dependency-injectable) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const client = opts.clients?.kms ?? new KMSClient({ region });

  const logger = opts.logger || createLogger(runDir, 'kms');
  logger.log('info', 'KMS_Enumeration_Start', { region });

  const findings = [];
  let status = 'complete';
  const errors = [];

  // ListKeys (paginated)
  let allKeys;
  try {
    logger.log('api_call', 'ListKeys', { service: 'kms' });
    allKeys = await paginate(client, ListKeysCommand, 'Keys', {});
  } catch (err) {
    logger.log('error', 'ListKeys', { error: err.message });
    await logger.flush();
    throw new Error(`ListKeys failed: ${err.message}`);
  }

  // Per-key: DescribeKey, filter to customer-managed
  for (const keyEntry of allKeys) {
    const keyId = keyEntry.KeyId;

    let keyMetadata;
    try {
      logger.log('api_call', 'DescribeKey', { key_id: keyId });
      const descResp = await withRetry(() =>
        client.send(new DescribeKeyCommand({ KeyId: keyId }))
      );
      keyMetadata = descResp.KeyMetadata;
    } catch (err) {
      errors.push({ resource: keyId, error: err.message });
      logger.log('warning', 'DescribeKey', { key_id: keyId, error: err.message });
      continue;
    }

    // Skip AWS-managed keys
    if (keyMetadata.KeyManager !== 'CUSTOMER') continue;

    const keyFinding = {
      resource_type: 'kms_key',
      resource_id: keyId,
      arn: keyMetadata.Arn,
      region,
      key_state: keyMetadata.KeyState,
      usage: keyMetadata.KeyUsage,
      origin: keyMetadata.Origin,
      description: keyMetadata.Description || '',
      rotation_enabled: false,
      policy_principals: [],
      grants: [],
      findings: [],
    };

    // GetKeyPolicy
    try {
      logger.log('api_call', 'GetKeyPolicy', { key_id: keyId });
      const policyResp = await withRetry(() =>
        client.send(new GetKeyPolicyCommand({ KeyId: keyId, PolicyName: 'default' }))
      );
      keyFinding.policy_principals = extractPolicyPrincipals(policyResp.Policy);
    } catch (err) {
      errors.push({ resource: keyId, error: `GetKeyPolicy: ${err.message}` });
      logger.log('warning', 'GetKeyPolicy', { key_id: keyId, error: err.message });
    }

    // ListGrants
    try {
      logger.log('api_call', 'ListGrants', { key_id: keyId });
      const grants = await paginate(client, ListGrantsCommand, 'Grants', {
        params: { KeyId: keyId },
      });
      keyFinding.grants = grants.map((g) => ({
        grant_id: g.GrantId,
        grantee_principal: g.GranteePrincipal,
        operations: g.Operations || [],
        retiring_principal: g.RetiringPrincipal || null,
      }));
    } catch (err) {
      errors.push({ resource: keyId, error: `ListGrants: ${err.message}` });
      logger.log('warning', 'ListGrants', { key_id: keyId, error: err.message });
    }

    // GetKeyRotationStatus
    try {
      logger.log('api_call', 'GetKeyRotationStatus', { key_id: keyId });
      const rotResp = await withRetry(() =>
        client.send(new GetKeyRotationStatusCommand({ KeyId: keyId }))
      );
      keyFinding.rotation_enabled = rotResp.KeyRotationEnabled || false;
    } catch (err) {
      // Some key types don't support rotation status
      const code = err.name || err.Code || '';
      if (code === 'UnsupportedOperationException') {
        keyFinding.rotation_enabled = null;
      } else {
        errors.push({ resource: keyId, error: `GetKeyRotationStatus: ${err.message}` });
        logger.log('warning', 'GetKeyRotationStatus', { key_id: keyId, error: err.message });
      }
    }

    keyFinding.findings = generateFindings(keyFinding);
    findings.push(keyFinding);
  }

  if (errors.length > 0) status = 'partial';

  await logger.flush();
  return { findings, status };
}

if (require.main === module) {
  baseEnum({ module: 'kms', run });
}

module.exports = { run };
