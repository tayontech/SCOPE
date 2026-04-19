'use strict';

const {
  DynamoDBClient,
  ListTablesCommand,
  DescribeTableCommand,
  DescribeContinuousBackupsCommand,
  ListBackupsCommand,
  GetResourcePolicyCommand,
} = require('@aws-sdk/client-dynamodb');

const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
const { withRetry, createEnvelope, writeEnvelope, createLogger } = require('../lib');

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
      console.log('Usage: node scripts/enum/dynamodb.js --run-dir <dir> --region <region>');
      console.log('       node scripts/enum/dynamodb.js --run-dir <dir> --regions <r1,r2,...>');
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

// --- Pagination for ListTables (uses ExclusiveStartTableName, not NextToken) ---

async function listAllTables(client, logger) {
  const allTables = [];
  let exclusiveStart = undefined;

  do {
    const params = {};
    if (exclusiveStart) {
      params.ExclusiveStartTableName = exclusiveStart;
    }

    logger.log('api_call', 'ListTables', { ExclusiveStartTableName: exclusiveStart || null });
    const response = await withRetry(() => client.send(new ListTablesCommand(params)));

    if (Array.isArray(response.TableNames)) {
      allTables.push(...response.TableNames);
    }

    exclusiveStart = response.LastEvaluatedTableName || null;
  } while (exclusiveStart);

  return allTables;
}

// --- Per-table enrichment ---

async function describeTable(client, tableName, logger) {
  logger.log('api_call', 'DescribeTable', { table: tableName });
  const response = await withRetry(() =>
    client.send(new DescribeTableCommand({ TableName: tableName }))
  );
  return response.Table;
}

async function describeContinuousBackups(client, tableName, logger) {
  logger.log('api_call', 'DescribeContinuousBackups', { table: tableName });
  try {
    const response = await withRetry(() =>
      client.send(new DescribeContinuousBackupsCommand({ TableName: tableName }))
    );
    const desc = response.ContinuousBackupsDescription;
    if (!desc) return null;
    return {
      continuous_backups_status: desc.ContinuousBackupsStatus || null,
      point_in_time_recovery:
        desc.PointInTimeRecoveryDescription?.PointInTimeRecoveryStatus === 'ENABLED',
    };
  } catch (err) {
    logger.log('warning', 'DescribeContinuousBackups_Failed', { table: tableName, error: err.message });
    return null;
  }
}

async function listBackups(client, tableName, logger) {
  logger.log('api_call', 'ListBackups', { table: tableName });
  try {
    const response = await withRetry(() =>
      client.send(new ListBackupsCommand({ TableName: tableName }))
    );
    return response.BackupSummaries ? response.BackupSummaries.length : 0;
  } catch (err) {
    logger.log('warning', 'ListBackups_Failed', { table: tableName, error: err.message });
    return 0;
  }
}

async function getResourcePolicy(client, tableArn, logger) {
  logger.log('api_call', 'GetResourcePolicy', { arn: tableArn });
  try {
    const response = await withRetry(() =>
      client.send(new GetResourcePolicyCommand({ ResourceArn: tableArn }))
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
    // ResourceNotFoundException or AccessDeniedException — no policy exists or not supported
    if (err.name === 'ResourceNotFoundException' || err.name === 'PolicyNotFoundException' ||
        err.name === 'UnknownOperationException' || err.name === 'AccessDeniedException') {
      return null;
    }
    logger.log('warning', 'GetResourcePolicy_Failed', { arn: tableArn, error: err.message });
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

  // DynamoDB client
  const client = opts.clients?.dynamodb ?? new DynamoDBClient({ region });

  // List all tables
  const tableNames = await listAllTables(client, logger);
  logger.log('info', 'TablesDiscovered', { count: tableNames.length });

  // Enumerate each table
  const findings = [];

  for (const tableName of tableNames) {
    try {
      const table = await describeTable(client, tableName, logger);

      // Encryption
      const sse = table.SSEDescription || {};
      const encryptionType = sse.SSEType || 'AES256'; // Default encryption if no SSE description
      const kmsKeyId = sse.KMSMasterKeyArn || null;

      // Streams
      const streamSpec = table.StreamSpecification || {};
      const streamEnabled = streamSpec.StreamEnabled || false;
      const streamViewType = streamSpec.StreamViewType || null;

      // Global table detection
      const isGlobalTable = !!(table.GlobalTableVersion || (table.Replicas && table.Replicas.length > 0));
      const replicas = (table.Replicas || []).map((r) => ({
        region: r.RegionName,
        status: r.ReplicaStatus,
      }));

      // Deletion protection
      const deletionProtection = table.DeletionProtectionEnabled || false;

      // Table class
      const tableClass = table.TableClassSummary?.TableClass || 'STANDARD';

      // Point-in-time recovery + continuous backups
      const backupInfo = await describeContinuousBackups(client, tableName, logger);

      // Manual backup count
      const backupCount = await listBackups(client, tableName, logger);

      // Resource policy
      const resourcePolicy = await getResourcePolicy(client, table.TableArn, logger);

      findings.push({
        resource_type: 'dynamodb_table',
        resource_id: tableName,
        arn: table.TableArn,
        region,
        encryption_type: encryptionType,
        kms_key_id: kmsKeyId,
        stream_enabled: streamEnabled,
        stream_view_type: streamViewType,
        is_global_table: isGlobalTable,
        replicas,
        deletion_protection: deletionProtection,
        table_class: tableClass,
        point_in_time_recovery: backupInfo ? backupInfo.point_in_time_recovery : null,
        continuous_backups_status: backupInfo ? backupInfo.continuous_backups_status : null,
        backup_count: backupCount,
        resource_policy: resourcePolicy,
        findings: [],
      });
    } catch (err) {
      partialErrors.push({ table: tableName, error: err.message });
      logger.log('error', 'TableEnumeration_Failed', { table: tableName, error: err.message });
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
    module: 'dynamodb',
    account_id: accountId,
    region,
    status,
    findings,
  });

  const outputPath = writeEnvelope(runDir, envelope);
  logger.log('info', 'DynamoDB_Enumeration_Complete', {
    status,
    tables: findings.length,
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
    console.error('Usage: node scripts/enum/dynamodb.js --run-dir <dir> --region <region>');
    console.error('       node scripts/enum/dynamodb.js --run-dir <dir> --regions <r1,r2,...>');
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
      const envelope = createEnvelope({ module: 'dynamodb', account_id: null, region: 'multi', status: 'complete', findings: allFindings });
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
