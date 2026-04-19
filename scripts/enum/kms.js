'use strict';

const {
  KMSClient,
  ListKeysCommand,
  DescribeKeyCommand,
  GetKeyPolicyCommand,
  ListGrantsCommand,
  GetKeyRotationStatusCommand,
} = require('@aws-sdk/client-kms');
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
      console.log('Usage: node scripts/enum/kms.js --run-dir <dir> --region <region>');
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

function parsePolicyPrincipals(policyJson) {
  if (!policyJson) return [];
  try {
    const doc = JSON.parse(policyJson);
    const statements = Array.isArray(doc.Statement) ? doc.Statement : [];
    const principals = [];
    for (const stmt of statements) {
      if (stmt.Effect !== 'Allow') continue;
      const p = stmt.Principal;
      if (!p) continue;
      if (typeof p === 'string') {
        principals.push(p);
      } else if (typeof p === 'object') {
        for (const key of ['AWS', 'Service', 'Federated']) {
          const val = p[key];
          if (!val) continue;
          if (typeof val === 'string') principals.push(val);
          else if (Array.isArray(val)) principals.push(...val);
        }
      }
    }
    return [...new Set(principals)];
  } catch {
    return [];
  }
}

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

  const client = opts.clients?.kms ?? new KMSClient({ region });
  const stsClient = opts.clients?.sts ?? new STSClient({});

  const logger = createLogger(runDir);
  logger.log('info', 'KMS_Enumeration_Start', { region });

  // Get account ID
  let accountId;
  try {
    const identity = await withRetry(() => stsClient.send(new GetCallerIdentityCommand({})));
    accountId = identity.Account;
  } catch (err) {
    logger.log('error', 'GetCallerIdentity', { error: err.message });
    await logger.flush();
    throw new Error(`GetCallerIdentity failed: ${err.message}`);
  }

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
    const envelope = createEnvelope({
      module: 'kms',
      account_id: accountId,
      region,
      status: 'error',
      findings: [],
    });
    writeEnvelope(runDir, envelope);
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
      keyFinding.policy_principals = parsePolicyPrincipals(policyResp.Policy);
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

  const envelope = createEnvelope({
    module: 'kms',
    account_id: accountId,
    region,
    status,
    findings,
  });

  const outPath = writeEnvelope(runDir, envelope);
  logger.log('info', 'KMS_Enumeration_Complete', {
    status,
    customer_keys: findings.length,
    total_keys: allKeys.length,
    errors: errors.length,
    output: outPath,
  });

  await logger.flush();
  console.log(`KMS enumeration complete: ${outPath} (${findings.length} customer-managed keys, status: ${status})`);
}

// --- Main (CLI entry point) ---

async function main() {
  const args = parseArgs(process.argv);
  if (!args.runDir || !args.region) {
    console.error('Error: --run-dir and --region are required');
    console.error('Usage: node scripts/enum/kms.js --run-dir <dir> --region <region>');
    process.exit(1);
  }
  try {
    await run({ runDir: args.runDir, region: args.region });
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
