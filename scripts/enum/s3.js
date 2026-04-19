'use strict';

const {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
  GetBucketPolicyCommand,
  GetPublicAccessBlockCommand,
  GetBucketVersioningCommand,
  GetBucketEncryptionCommand,
  GetBucketLoggingCommand,
  GetBucketAclCommand,
} = require('@aws-sdk/client-s3');
const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');

const { withRetry, createEnvelope, writeEnvelope, createLogger } = require('../lib');

// --- CLI ---

function parseArgs(argv) {
  const args = { runDir: null, region: null, regions: null };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--run-dir' && argv[i + 1]) {
      args.runDir = argv[++i];
    } else if (argv[i] === '--region' && argv[i + 1]) {
      args.region = argv[++i];
    } else if (argv[i] === '--regions' && argv[i + 1]) {
      args.regions = argv[++i];
    } else if (argv[i] === '--help' || argv[i] === '-h') {
      console.log('Usage: node scripts/enum/s3.js --run-dir <dir> --region <region>');
      console.log('       node scripts/enum/s3.js --run-dir <dir> --regions <r1,r2,...>');
      console.log('');
      console.log('Options:');
      console.log('  --run-dir  Path to the run output directory (required)');
      console.log('  --region   AWS region to enumerate buckets for (required, or use --regions)');
      console.log('  --regions  Comma-separated list of regions to enumerate');
      console.log('  --help     Show this help message');
      process.exit(0);
    }
  }
  return args;
}

// --- Helpers ---

/**
 * Normalizes the LocationConstraint response to a region string.
 * null/empty means us-east-1 (S3 legacy behavior).
 */
function normalizeBucketRegion(locationConstraint) {
  if (!locationConstraint || locationConstraint === '') return 'us-east-1';
  if (locationConstraint === 'EU') return 'eu-west-1';
  return locationConstraint;
}

/**
 * Safely calls an S3 API, returning null for expected "not configured" errors.
 */
async function safeGetBucketConfig(fn, notFoundCodes) {
  try {
    return await withRetry(fn);
  } catch (err) {
    const code = err.name || err.Code || '';
    if (notFoundCodes.includes(code)) {
      return null;
    }
    throw err;
  }
}

// --- Findings generation ---

function generateFindings(bucket) {
  const findings = [];

  // Public access check via ACL
  if (bucket.acl_grants) {
    const publicGrants = bucket.acl_grants.filter(
      (g) => g.grantee_uri && (
        g.grantee_uri.includes('AllUsers') ||
        g.grantee_uri.includes('AuthenticatedUsers')
      )
    );
    if (publicGrants.length > 0) {
      findings.push({
        type: 'public_acl',
        severity: 'high',
        detail: `Bucket has ${publicGrants.length} public ACL grant(s)`,
      });
    }
  }

  // Public access block not set
  if (!bucket.public_access_block) {
    findings.push({
      type: 'no_public_access_block',
      severity: 'medium',
      detail: 'No public access block configuration set',
    });
  } else {
    const pab = bucket.public_access_block;
    if (!pab.BlockPublicAcls || !pab.IgnorePublicAcls || !pab.BlockPublicPolicy || !pab.RestrictPublicBuckets) {
      findings.push({
        type: 'partial_public_access_block',
        severity: 'medium',
        detail: 'Public access block is not fully restrictive',
      });
    }
  }

  // No encryption
  if (!bucket.encryption) {
    findings.push({
      type: 'no_encryption',
      severity: 'medium',
      detail: 'No default server-side encryption configured',
    });
  }

  // No versioning
  if (!bucket.versioning || bucket.versioning.Status !== 'Enabled') {
    findings.push({
      type: 'no_versioning',
      severity: 'low',
      detail: 'Bucket versioning is not enabled',
    });
  }

  // Overly permissive policy (wildcard principal)
  if (bucket.policy) {
    try {
      const doc = JSON.parse(bucket.policy);
      const statements = Array.isArray(doc.Statement) ? doc.Statement : [];
      for (const stmt of statements) {
        if (stmt.Effect !== 'Allow') continue;
        const principal = stmt.Principal;
        if (principal === '*' || (principal && principal.AWS === '*')) {
          findings.push({
            type: 'public_policy',
            severity: 'high',
            detail: 'Bucket policy allows wildcard principal',
          });
          break;
        }
      }
    } catch {
      // unparseable policy — skip
    }
  }

  return findings;
}

// --- Run (dependency-injectable) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;

  const s3Client = opts.clients?.s3 ?? new S3Client({ region: 'us-east-1' });
  const stsClient = opts.clients?.sts ?? new STSClient({});

  const logger = createLogger(runDir);
  logger.log('info', 'S3_Enumeration_Start', { region });

  // Get account ID via STS
  let accountId;
  try {
    const identity = await withRetry(() => stsClient.send(new GetCallerIdentityCommand({})));
    accountId = identity.Account;
  } catch (err) {
    logger.log('error', 'GetCallerIdentity', { error: err.message });
    await logger.flush();
    throw new Error(`GetCallerIdentity failed: ${err.message}`);
  }

  // ListBuckets is global — use the provided s3 client (defaults to us-east-1)
  let allBuckets;
  try {
    logger.log('api_call', 'ListBuckets', { service: 's3' });
    const resp = await withRetry(() => s3Client.send(new ListBucketsCommand({})));
    allBuckets = resp.Buckets || [];
  } catch (err) {
    logger.log('error', 'ListBuckets', { error: err.message });
    const envelope = createEnvelope({
      module: 's3',
      account_id: accountId,
      region,
      status: 'error',
      findings: [],
    });
    writeEnvelope(runDir, envelope);
    await logger.flush();
    throw new Error(`ListBuckets failed: ${err.message}`);
  }

  // Discover bucket regions and filter to requested region
  const findings = [];
  let status = 'complete';
  const errors = [];

  for (const bucket of allBuckets) {
    const bucketName = bucket.Name;
    let bucketRegion;

    try {
      logger.log('api_call', 'GetBucketLocation', { bucket: bucketName });
      const locResp = await withRetry(() =>
        s3Client.send(new GetBucketLocationCommand({ Bucket: bucketName }))
      );
      bucketRegion = normalizeBucketRegion(locResp.LocationConstraint);
    } catch (err) {
      // Can't determine region — skip bucket
      errors.push({ resource: bucketName, error: err.message });
      logger.log('warning', 'GetBucketLocation', { bucket: bucketName, error: err.message });
      continue;
    }

    // Only enumerate buckets in the requested region
    if (bucketRegion !== region) continue;

    // Use the provided client for regional requests too
    const regionalClient = s3Client;

    const bucketFinding = {
      resource_type: 's3_bucket',
      resource_id: bucketName,
      arn: `arn:aws:s3:::${bucketName}`,
      region: bucketRegion,
      policy: null,
      public_access_block: null,
      versioning: null,
      encryption: null,
      logging: null,
      acl_grants: null,
      findings: [],
    };

    // GetBucketPolicy
    try {
      logger.log('api_call', 'GetBucketPolicy', { bucket: bucketName });
      const policyResp = await safeGetBucketConfig(
        () => regionalClient.send(new GetBucketPolicyCommand({ Bucket: bucketName })),
        ['NoSuchBucketPolicy']
      );
      bucketFinding.policy = policyResp ? policyResp.Policy : null;
    } catch (err) {
      errors.push({ resource: bucketName, error: `GetBucketPolicy: ${err.message}` });
      logger.log('warning', 'GetBucketPolicy', { bucket: bucketName, error: err.message });
    }

    // GetPublicAccessBlock
    try {
      logger.log('api_call', 'GetPublicAccessBlock', { bucket: bucketName });
      const pabResp = await safeGetBucketConfig(
        () => regionalClient.send(new GetPublicAccessBlockCommand({ Bucket: bucketName })),
        ['NoSuchPublicAccessBlockConfiguration']
      );
      bucketFinding.public_access_block = pabResp ? pabResp.PublicAccessBlockConfiguration : null;
    } catch (err) {
      errors.push({ resource: bucketName, error: `GetPublicAccessBlock: ${err.message}` });
      logger.log('warning', 'GetPublicAccessBlock', { bucket: bucketName, error: err.message });
    }

    // GetBucketVersioning
    try {
      logger.log('api_call', 'GetBucketVersioning', { bucket: bucketName });
      const verResp = await withRetry(() =>
        regionalClient.send(new GetBucketVersioningCommand({ Bucket: bucketName }))
      );
      bucketFinding.versioning = { Status: verResp.Status || null, MFADelete: verResp.MFADelete || null };
    } catch (err) {
      errors.push({ resource: bucketName, error: `GetBucketVersioning: ${err.message}` });
      logger.log('warning', 'GetBucketVersioning', { bucket: bucketName, error: err.message });
    }

    // GetBucketEncryption
    try {
      logger.log('api_call', 'GetBucketEncryption', { bucket: bucketName });
      const encResp = await safeGetBucketConfig(
        () => regionalClient.send(new GetBucketEncryptionCommand({ Bucket: bucketName })),
        ['ServerSideEncryptionConfigurationNotFoundError']
      );
      bucketFinding.encryption = encResp
        ? encResp.ServerSideEncryptionConfiguration
        : null;
    } catch (err) {
      errors.push({ resource: bucketName, error: `GetBucketEncryption: ${err.message}` });
      logger.log('warning', 'GetBucketEncryption', { bucket: bucketName, error: err.message });
    }

    // GetBucketLogging
    try {
      logger.log('api_call', 'GetBucketLogging', { bucket: bucketName });
      const logResp = await withRetry(() =>
        regionalClient.send(new GetBucketLoggingCommand({ Bucket: bucketName }))
      );
      bucketFinding.logging = logResp.LoggingEnabled || null;
    } catch (err) {
      errors.push({ resource: bucketName, error: `GetBucketLogging: ${err.message}` });
      logger.log('warning', 'GetBucketLogging', { bucket: bucketName, error: err.message });
    }

    // GetBucketAcl
    try {
      logger.log('api_call', 'GetBucketAcl', { bucket: bucketName });
      const aclResp = await withRetry(() =>
        regionalClient.send(new GetBucketAclCommand({ Bucket: bucketName }))
      );
      bucketFinding.acl_grants = (aclResp.Grants || []).map((g) => ({
        grantee_type: g.Grantee?.Type || null,
        grantee_id: g.Grantee?.ID || null,
        grantee_uri: g.Grantee?.URI || null,
        permission: g.Permission || null,
      }));
    } catch (err) {
      errors.push({ resource: bucketName, error: `GetBucketAcl: ${err.message}` });
      logger.log('warning', 'GetBucketAcl', { bucket: bucketName, error: err.message });
    }

    // Generate findings
    bucketFinding.findings = generateFindings(bucketFinding);
    findings.push(bucketFinding);
  }

  if (errors.length > 0) status = 'partial';

  if (opts.returnOnly) {
    await logger.flush();
    return findings;
  }

  const envelope = createEnvelope({
    module: 's3',
    account_id: accountId,
    region,
    status,
    findings,
  });

  const outPath = writeEnvelope(runDir, envelope);
  logger.log('info', 'S3_Enumeration_Complete', {
    status,
    buckets_in_region: findings.length,
    total_buckets: allBuckets.length,
    errors: errors.length,
    output: outPath,
  });

  await logger.flush();
  console.log(`S3 enumeration complete: ${outPath} (${findings.length} buckets in ${region}, status: ${status})`);
}

// --- Main (CLI entry point) ---

async function main() {
  const args = parseArgs(process.argv);
  if (!args.runDir || (!args.region && !args.regions)) {
    console.error('Error: --run-dir and --region (or --regions) are required');
    console.error('Usage: node scripts/enum/s3.js --run-dir <dir> --region <region>');
    console.error('       node scripts/enum/s3.js --run-dir <dir> --regions <r1,r2,...>');
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
      const envelope = createEnvelope({ module: 's3', account_id: null, region: 'multi', status: 'complete', findings: allFindings });
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
