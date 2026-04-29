'use strict';

const {
  CodeBuildClient,
  ListProjectsCommand,
  BatchGetProjectsCommand,
} = require('@aws-sdk/client-codebuild');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');

// --- Constants ---

const SECRET_PATTERNS = /password|secret|token|key|credential|api.?key|auth/i;

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
  const accountId = opts.accountId;

  if (!runDir || !region) {
    throw new Error('runDir and region are required');
  }

  const codebuild = opts.clients?.codebuild ?? new CodeBuildClient({ region });

  const logger = opts.logger || createLogger(runDir, 'codebuild');
  logger.log('info', 'CodeBuild_Enumeration_Start', { region });

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
    await logger.flush();
    throw new Error(`ListProjects failed: ${err.message}`);
  }

  if (!projectNames || projectNames.length === 0) {
    await logger.flush();
    return { findings: [], status: 'complete' };
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

  await logger.flush();
  return { findings, status };
}

if (require.main === module) {
  baseEnum({ module: 'codebuild', run });
}

module.exports = { run };
