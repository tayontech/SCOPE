'use strict';

const {
  LambdaClient,
  ListFunctionsCommand,
  GetFunctionUrlConfigCommand,
  GetPolicyCommand,
} = require('@aws-sdk/client-lambda');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');
const { extractPolicyPrincipals } = require('../lib/policy-parser');

// --- Constants ---

const SECRET_PATTERNS = /password|secret|token|key|credential|api.?key|auth/i;

// --- Helpers ---

/**
 * Safely calls an API that may throw ResourceNotFoundException.
 * Returns null when the resource doesn't exist (expected, not an error).
 */
async function safeGetResource(fn) {
  try {
    return await withRetry(fn);
  } catch (err) {
    const code = err.name || err.Code || '';
    if (code === 'ResourceNotFoundException') {
      return null;
    }
    throw err;
  }
}

// --- Run (dependency-injectable) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const lambda = opts.clients?.lambda ?? new LambdaClient({ region });

  const logger = opts.logger || createLogger(runDir, 'lambda');
  logger.log('info', 'Lambda_Enumeration_Start', { region });

  // List all functions (paginated via Marker/NextMarker)
  logger.log('api_call', 'ListFunctions', { service: 'lambda' });
  let functions;
  try {
    functions = await paginate(lambda, ListFunctionsCommand, 'Functions', {
      tokenKey: 'Marker',
      responseTokenKey: 'NextMarker',
    });
  } catch (err) {
    logger.log('error', 'ListFunctions', { error: err.message });
    await logger.flush();
    throw new Error(`ListFunctions failed: ${err.message}`);
  }

  const findings = [];
  const errors = [];

  for (const func of functions) {
    // Get function URL config
    let functionUrl = null;
    try {
      logger.log('api_call', 'GetFunctionUrlConfig', { function: func.FunctionName });
      const urlResp = await safeGetResource(() =>
        lambda.send(new GetFunctionUrlConfigCommand({ FunctionName: func.FunctionName }))
      );
      if (urlResp) {
        functionUrl = urlResp.FunctionUrl || null;
      }
    } catch (err) {
      errors.push({ resource: func.FunctionName, error: `GetFunctionUrlConfig: ${err.message}` });
      logger.log('warning', 'GetFunctionUrlConfig', { function: func.FunctionName, error: err.message });
    }

    // Get resource policy
    let resourcePolicyPrincipals = [];
    try {
      logger.log('api_call', 'GetPolicy', { function: func.FunctionName });
      const policyResp = await safeGetResource(() =>
        lambda.send(new GetPolicyCommand({ FunctionName: func.FunctionName }))
      );
      if (policyResp && policyResp.Policy) {
        resourcePolicyPrincipals = extractPolicyPrincipals(policyResp.Policy);
      }
    } catch (err) {
      errors.push({ resource: func.FunctionName, error: `GetPolicy: ${err.message}` });
      logger.log('warning', 'GetPolicy', { function: func.FunctionName, error: err.message });
    }

    // Environment variable analysis (names only, never values)
    const envVarNames = Object.keys(func.Environment?.Variables || {});
    const secretPatternNames = envVarNames.filter((n) => SECRET_PATTERNS.test(n));

    // Layers
    const layers = (func.Layers || []).map((l) => ({
      arn: l.Arn,
      code_size: l.CodeSize || null,
    }));

    const finding = {
      resource_type: 'lambda_function',
      resource_id: func.FunctionName,
      arn: func.FunctionArn,
      runtime: func.Runtime || null,
      role: func.Role || null,
      handler: func.Handler || null,
      code_size: func.CodeSize || null,
      timeout: func.Timeout || null,
      memory_size: func.MemorySize || null,
      last_modified: func.LastModified || null,
      layers,
      function_url: functionUrl,
      resource_policy_principals: resourcePolicyPrincipals,
      env_var_names: envVarNames,
      secret_pattern_names: secretPatternNames,
      findings: [],
    };

    // Findings
    if (secretPatternNames.length > 0) {
      finding.findings.push({
        type: 'secret_env_vars',
        severity: 'high',
        detail: `Function has ${secretPatternNames.length} env var(s) matching secret patterns: ${secretPatternNames.join(', ')}`,
      });
    }

    if (functionUrl) {
      finding.findings.push({
        type: 'function_url_enabled',
        severity: 'info',
        detail: `Function URL enabled: ${functionUrl}`,
      });
    }

    if (resourcePolicyPrincipals.includes('*')) {
      finding.findings.push({
        type: 'wildcard_resource_policy',
        severity: 'high',
        detail: 'Resource policy allows wildcard (*) principal',
      });
    }

    findings.push(finding);
  }

  let status = 'complete';
  if (errors.length > 0) status = 'partial';

  await logger.flush();
  return { findings, status };
}

if (require.main === module) {
  baseEnum({ module: 'lambda', run });
}

module.exports = { run };
