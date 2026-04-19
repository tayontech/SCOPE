'use strict';

const {
  CodeBuildClient,
  ListProjectsCommand,
  BatchGetProjectsCommand,
} = require('@aws-sdk/client-codebuild');

const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');

const { withRetry, paginate, createEnvelope, writeEnvelope, createLogger } = require('../lib');

// --- Constants ---

const SECRET_PATTERNS = /password|secret|token|key|credential|api.?key|auth/i;

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
      console.log('Usage: node scripts/enum/codebuild.js --run-dir <dir> --region <region>');
      console.log('       node scripts/enum/codebuild.js --run-dir <dir> --regions <r1,r2,...>');
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

// --- Helpers ---

/**
 * Chunk an array into groups of a given size.
 */
function chunk(arr, size) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}

// --- Exported run() for testing ---

async function run(opts = {}) {
  const { runDir, region } = opts;

  if (!runDir || !region) {
    throw new Error('runDir and region are required');
  }

  const stsClient = opts.clients?.sts ?? new STSClient({ region });
  const codebuild = opts.clients?.codebuild ?? new CodeBuildClient({ region });

  const logger = createLogger(runDir);
  logger.log('info', 'CodeBuild_Enumeration_Start', { region });

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

  // List all project names (paginated)
  logger.log('api_call', 'ListProjects', { service: 'codebuild' });
  let projectNames;
  try {
    projectNames = await paginate(codebuild, ListProjectsCommand, 'projects', {
      tokenKey: 'nextToken',
      responseTokenKey: 'nextToken',
    });
  } catch (err) {
    logger.log('error', 'ListProjects', { error: err.message });
    const envelope = createEnvelope({
      module: 'codebuild',
      account_id: accountId,
      region,
      status: 'error',
      findings: [],
    });
    writeEnvelope(runDir, envelope);
    await logger.flush();
    throw new Error(`ListProjects failed: ${err.message}`);
  }

  if (!projectNames || projectNames.length === 0) {
    const envelope = createEnvelope({
      module: 'codebuild',
      account_id: accountId,
      region,
      status: 'complete',
      findings: [],
    });
    const outPath = writeEnvelope(runDir, envelope);
    logger.log('info', 'CodeBuild_Enumeration_Complete', {
      status: 'complete',
      projects: 0,
      output: outPath,
    });
    await logger.flush();
    console.log(`CodeBuild enumeration complete: ${outPath} (0 projects, status: complete)`);
    return;
  }

  // BatchGetProjects — up to 100 per call
  const findings = [];
  const errors = [];
  const batches = chunk(projectNames, 100);

  for (const batch of batches) {
    try {
      logger.log('api_call', 'BatchGetProjects', { service: 'codebuild', count: batch.length });
      const resp = await withRetry(() =>
        codebuild.send(new BatchGetProjectsCommand({ names: batch }))
      );

      for (const project of resp.projects || []) {
        // Extract env var NAMES only — NEVER include values
        const envVars = project.environment?.environmentVariables || [];
        const envVarNames = envVars.map((v) => v.name);
        const secretPatternNames = envVarNames.filter((n) => SECRET_PATTERNS.test(n));

        const finding = {
          resource_type: 'codebuild_project',
          resource_id: project.name,
          arn: project.arn || null,
          region,
          service_role: project.serviceRole || null,
          source_type: project.source?.type || null,
          source_location: project.source?.location || null,
          source_buildspec: project.source?.buildspec ? true : false,
          environment_type: project.environment?.type || null,
          environment_image: project.environment?.image || null,
          environment_compute_type: project.environment?.computeType || null,
          privileged_mode: project.environment?.privilegedMode || false,
          vpc_config: project.vpcConfig
            ? {
                vpc_id: project.vpcConfig.vpcId || null,
                subnets: project.vpcConfig.subnets || [],
                security_group_ids: project.vpcConfig.securityGroupIds || [],
              }
            : null,
          env_var_names: envVarNames,
          secret_pattern_names: secretPatternNames,
          encryption_key: project.encryptionKey || null,
          last_modified: project.lastModified ? project.lastModified.toISOString() : null,
          findings: [],
        };

        // Findings
        if (secretPatternNames.length > 0) {
          finding.findings.push({
            type: 'secret_env_vars',
            severity: 'high',
            detail: `Project has ${secretPatternNames.length} env var(s) matching secret patterns: ${secretPatternNames.join(', ')}`,
          });
        }

        if (project.environment?.privilegedMode) {
          finding.findings.push({
            type: 'privileged_mode',
            severity: 'medium',
            detail: 'Build environment runs in privileged mode (Docker daemon access)',
          });
        }

        if (!project.vpcConfig) {
          finding.findings.push({
            type: 'no_vpc',
            severity: 'info',
            detail: 'Project builds do not run inside a VPC',
          });
        }

        findings.push(finding);
      }

      // Track projects that failed to load
      for (const name of resp.projectsNotFound || []) {
        errors.push({ resource: name, error: 'Project not found in BatchGetProjects response' });
        logger.log('warning', 'BatchGetProjects_NotFound', { project: name });
      }
    } catch (err) {
      errors.push({ resource: `batch(${batch.length})`, error: err.message });
      logger.log('error', 'BatchGetProjects', { error: err.message });
    }
  }

  let status = 'complete';
  if (errors.length > 0) status = 'partial';

  if (opts.returnOnly) {
    await logger.flush();
    return findings;
  }

  const envelope = createEnvelope({
    module: 'codebuild',
    account_id: accountId,
    region,
    status,
    findings,
  });

  const outPath = writeEnvelope(runDir, envelope);

  logger.log('info', 'CodeBuild_Enumeration_Complete', {
    status,
    projects: findings.length,
    errors: errors.length,
    output: outPath,
  });

  await logger.flush();
  console.log(`CodeBuild enumeration complete: ${outPath} (${findings.length} projects, status: ${status})`);
}

// --- CLI entry point ---

async function main() {
  const args = parseArgs(process.argv);

  if (!args.runDir || (!args.region && !args.regions)) {
    console.error('Error: --run-dir and --region (or --regions) are required');
    console.error('Usage: node scripts/enum/codebuild.js --run-dir <dir> --region <region>');
    console.error('       node scripts/enum/codebuild.js --run-dir <dir> --regions <r1,r2,...>');
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
      const envelope = createEnvelope({ module: 'codebuild', account_id: null, region: 'multi', status: 'complete', findings: allFindings });
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
