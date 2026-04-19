'use strict';

const {
  RDSClient,
  DescribeDBInstancesCommand,
  DescribeDBSnapshotsCommand,
  DescribeDBSnapshotAttributesCommand,
} = require('@aws-sdk/client-rds');
const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');

const { withRetry, paginate, createEnvelope, writeEnvelope, createLogger } = require('../lib');

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
      console.log('Usage: node scripts/enum/rds.js --run-dir <dir> --region <region>');
      console.log('       node scripts/enum/rds.js --run-dir <dir> --regions <r1,r2,...>');
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

// --- Findings generation ---

function generateInstanceFindings(instance) {
  const findings = [];

  if (instance.publicly_accessible) {
    findings.push({
      type: 'publicly_accessible',
      severity: 'high',
      detail: 'DB instance is publicly accessible',
    });
  }

  if (!instance.storage_encrypted) {
    findings.push({
      type: 'no_encryption',
      severity: 'high',
      detail: 'DB instance storage is not encrypted',
    });
  }

  if (!instance.iam_auth_enabled) {
    findings.push({
      type: 'no_iam_auth',
      severity: 'low',
      detail: 'IAM authentication is not enabled',
    });
  }

  if (!instance.deletion_protection) {
    findings.push({
      type: 'no_deletion_protection',
      severity: 'low',
      detail: 'Deletion protection is not enabled',
    });
  }

  return findings;
}

function generateSnapshotFindings(snapshot) {
  const findings = [];

  if (snapshot.public) {
    findings.push({
      type: 'public_snapshot',
      severity: 'critical',
      detail: 'DB snapshot is publicly accessible (shared with all)',
    });
  }

  if (!snapshot.encrypted) {
    findings.push({
      type: 'unencrypted_snapshot',
      severity: 'high',
      detail: 'DB snapshot is not encrypted',
    });
  }

  if (snapshot.shared_with && snapshot.shared_with.length > 0) {
    findings.push({
      type: 'shared_snapshot',
      severity: 'medium',
      detail: `Snapshot shared with ${snapshot.shared_with.length} account(s)`,
    });
  }

  return findings;
}

// --- Run (dependency-injectable) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;

  const client = opts.clients?.rds ?? new RDSClient({ region });
  const stsClient = opts.clients?.sts ?? new STSClient({});

  const logger = createLogger(runDir);
  logger.log('info', 'RDS_Enumeration_Start', { region });

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

  // --- DB Instances (Marker pagination) ---
  let allInstances;
  try {
    logger.log('api_call', 'DescribeDBInstances', { service: 'rds' });
    allInstances = await paginate(client, DescribeDBInstancesCommand, 'DBInstances', {
      tokenKey: 'Marker',
      responseTokenKey: 'Marker',
    });
  } catch (err) {
    logger.log('error', 'DescribeDBInstances', { error: err.message });
    const envelope = createEnvelope({
      module: 'rds',
      account_id: accountId,
      region,
      status: 'error',
      findings: [],
    });
    writeEnvelope(runDir, envelope);
    await logger.flush();
    throw new Error(`DescribeDBInstances failed: ${err.message}`);
  }

  for (const db of allInstances) {
    const instanceFinding = {
      resource_type: 'rds_instance',
      resource_id: db.DBInstanceIdentifier,
      arn: db.DBInstanceArn,
      region,
      engine: db.Engine,
      engine_version: db.EngineVersion,
      publicly_accessible: db.PubliclyAccessible || false,
      storage_encrypted: db.StorageEncrypted || false,
      kms_key_id: db.KmsKeyId || null,
      iam_auth_enabled: db.IAMDatabaseAuthenticationEnabled || false,
      deletion_protection: db.DeletionProtection || false,
      security_groups: (db.VpcSecurityGroups || []).map((sg) => ({
        id: sg.VpcSecurityGroupId,
        status: sg.Status,
      })),
      multi_az: db.MultiAZ || false,
      findings: [],
    };

    instanceFinding.findings = generateInstanceFindings(instanceFinding);
    findings.push(instanceFinding);
  }

  // --- DB Snapshots (manual only, Marker pagination) ---
  let allSnapshots;
  try {
    logger.log('api_call', 'DescribeDBSnapshots', { service: 'rds', type: 'manual' });
    allSnapshots = await paginate(client, DescribeDBSnapshotsCommand, 'DBSnapshots', {
      params: { SnapshotType: 'manual' },
      tokenKey: 'Marker',
      responseTokenKey: 'Marker',
    });
  } catch (err) {
    errors.push({ resource: 'snapshots', error: err.message });
    logger.log('error', 'DescribeDBSnapshots', { error: err.message });
    allSnapshots = [];
    status = 'partial';
  }

  for (const snap of allSnapshots) {
    const snapshotFinding = {
      resource_type: 'rds_snapshot',
      resource_id: snap.DBSnapshotIdentifier,
      arn: snap.DBSnapshotArn,
      region,
      engine: snap.Engine,
      encrypted: snap.Encrypted || false,
      kms_key_id: snap.KmsKeyId || null,
      db_instance_identifier: snap.DBInstanceIdentifier,
      public: false,
      shared_with: [],
      findings: [],
    };

    // DescribeDBSnapshotAttributes — check for public/shared
    try {
      logger.log('api_call', 'DescribeDBSnapshotAttributes', { snapshot: snap.DBSnapshotIdentifier });
      const attrResp = await withRetry(() =>
        client.send(new DescribeDBSnapshotAttributesCommand({
          DBSnapshotIdentifier: snap.DBSnapshotIdentifier,
        }))
      );
      const attrResult = attrResp.DBSnapshotAttributesResult;
      if (attrResult && attrResult.DBSnapshotAttributes) {
        for (const attr of attrResult.DBSnapshotAttributes) {
          if (attr.AttributeName === 'restore') {
            const values = attr.AttributeValues || [];
            if (values.includes('all')) {
              snapshotFinding.public = true;
            }
            // Account IDs that are not 'all'
            snapshotFinding.shared_with = values.filter((v) => v !== 'all');
          }
        }
      }
    } catch (err) {
      errors.push({ resource: snap.DBSnapshotIdentifier, error: err.message });
      logger.log('warning', 'DescribeDBSnapshotAttributes', {
        snapshot: snap.DBSnapshotIdentifier,
        error: err.message,
      });
    }

    snapshotFinding.findings = generateSnapshotFindings(snapshotFinding);
    findings.push(snapshotFinding);
  }

  if (errors.length > 0 && status === 'complete') status = 'partial';

  if (opts.returnOnly) {
    await logger.flush();
    return findings;
  }

  const envelope = createEnvelope({
    module: 'rds',
    account_id: accountId,
    region,
    status,
    findings,
  });

  const outPath = writeEnvelope(runDir, envelope);
  logger.log('info', 'RDS_Enumeration_Complete', {
    status,
    instances: allInstances.length,
    snapshots: allSnapshots.length,
    errors: errors.length,
    output: outPath,
  });

  await logger.flush();
  console.log(`RDS enumeration complete: ${outPath} (${allInstances.length} instances, ${allSnapshots.length} snapshots, status: ${status})`);
}

// --- Main (CLI entry point) ---

async function main() {
  const args = parseArgs(process.argv);
  if (!args.runDir || (!args.region && !args.regions)) {
    console.error('Error: --run-dir and --region (or --regions) are required');
    console.error('Usage: node scripts/enum/rds.js --run-dir <dir> --region <region>');
    console.error('       node scripts/enum/rds.js --run-dir <dir> --regions <r1,r2,...>');
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
        allFindings.push(...findings);
      }
      const envelope = createEnvelope({ module: 'rds', account_id: null, region: 'multi', status: 'complete', findings: allFindings });
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
