'use strict';

const {
  SecretsManagerClient,
  ListSecretsCommand,
  GetResourcePolicyCommand,
} = require('@aws-sdk/client-secrets-manager');
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
      console.log('Usage: node scripts/enum/secrets.js --run-dir <dir> --region <region>');
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

// --- Main ---

async function main() {
  const args = parseArgs(process.argv);

  if (!args.runDir || !args.region) {
    console.error('Error: --run-dir and --region are required');
    console.error('Usage: node scripts/enum/secrets.js --run-dir <dir> --region <region>');
    process.exit(1);
  }

  const logger = createLogger(args.runDir);
  logger.log('info', 'Secrets_Enumeration_Start', { region: args.region });

  // Get account ID
  const stsClient = new STSClient({});
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

  const client = new SecretsManagerClient({ region: args.region });
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
    const envelope = createEnvelope({
      module: 'secrets',
      account_id: accountId,
      region: args.region,
      status: 'error',
      findings: [],
    });
    writeEnvelope(args.runDir, envelope);
    await logger.flush();
    process.exit(1);
  }

  // Per-secret: GetResourcePolicy
  for (const secret of allSecrets) {
    const secretName = secret.Name;
    const secretArn = secret.ARN;

    const secretFinding = {
      resource_type: 'secrets_secret',
      resource_id: secretName,
      arn: secretArn,
      region: args.region,
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
        secretFinding.resource_policy_principals = parsePolicyPrincipals(policyResp.ResourcePolicy);
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

  const envelope = createEnvelope({
    module: 'secrets',
    account_id: accountId,
    region: args.region,
    status,
    findings,
  });

  const outPath = writeEnvelope(args.runDir, envelope);
  logger.log('info', 'Secrets_Enumeration_Complete', {
    status,
    secrets: findings.length,
    errors: errors.length,
    output: outPath,
  });

  await logger.flush();
  console.log(`Secrets enumeration complete: ${outPath} (${findings.length} secrets, status: ${status})`);
}

main().catch((err) => {
  console.error(`Fatal error: ${err.message}`);
  process.exit(1);
});
