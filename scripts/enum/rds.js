'use strict';

const {
  RDSClient,
  DescribeDBInstancesCommand,
  DescribeDBSnapshotsCommand,
  DescribeDBSnapshotAttributesCommand,
} = require('@aws-sdk/client-rds');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');

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
  const accountId = opts.accountId;

  const client = opts.clients?.rds ?? new RDSClient({ region });

  const logger = opts.logger || createLogger(runDir, 'rds');
  logger.log('info', 'RDS_Enumeration_Start', { region });

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

  await logger.flush();
  return { findings, status };
}

if (require.main === module) {
  baseEnum({ module: 'rds', run });
}

module.exports = { run };
