'use strict';

const {
  LambdaClient,
  ListFunctionsCommand,
  GetFunctionUrlConfigCommand,
  GetPolicyCommand,
} = require('@aws-sdk/client-lambda');

const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');

const { withRetry, paginate, createEnvelope, writeEnvelope, createLogger } = require('../lib');

// --- Constants ---

const SECRET_PATTERNS = /password|secret|token|key|credential|api.?key|auth/i;

// --- CLI ---

function parseArgs(argv) {
  const args = { runDir: null, region: null };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--run-dir' && argv[i + 1]) {
      args.runDir = argv[++i];
    } else if (argv[i] === '--region' && argv[i + 1]) {
      args.region = argv[++i];
    } else if (argv[i] === '--help' || argv[i] === '-h') {
      console.log('Usage: node scripts/enum/lambda.js --run-dir <dir> --region <region>');
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

/**
 * Extract principal ARNs from a Lambda resource policy JSON string.
 */
function extractPolicyPrincipals(policyJson) {
  try {
    const doc = JSON.parse(policyJson);
    const statements = Array.isArray(doc.Statement) ? doc.Statement : [];
    const principals = new Set();

    for (const stmt of statements) {
      if (!stmt.Principal) continue;
      const principal = stmt.Principal;

      if (typeof principal === 'string') {
        principals.add(principal);
      } else if (typeof principal === 'object') {
        for (const key of ['AWS', 'Service', 'Federated']) {
          const val = principal[key];
          if (!val) continue;
          if (typeof val === 'string') principals.add(val);
          else if (Array.isArray(val)) val.forEach((v) => principals.add(v));
        }
      }
    }

    return [...principals];
  } catch {
    return [];
  }
}

// --- Main ---

async function main() {
  const args = parseArgs(process.argv);

  if (!args.runDir || !args.region) {
    console.error('Error: --run-dir and --region are required');
    console.error('Usage: node scripts/enum/lambda.js --run-dir <dir> --region <region>');
    process.exit(1);
  }

  const logger = createLogger(args.runDir);
  logger.log('info', 'Lambda_Enumeration_Start', { region: args.region });

  // Get account ID via STS
  const stsClient = new STSClient({ region: args.region });
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

  const lambda = new LambdaClient({ region: args.region });

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
    const envelope = createEnvelope({
      module: 'lambda',
      account_id: accountId,
      region: args.region,
      status: 'error',
      findings: [],
    });
    writeEnvelope(args.runDir, envelope);
    await logger.flush();
    console.error(`FATAL: ListFunctions failed: ${err.message}`);
    process.exit(1);
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
    let rawPolicy = null;
    try {
      logger.log('api_call', 'GetPolicy', { function: func.FunctionName });
      const policyResp = await safeGetResource(() =>
        lambda.send(new GetPolicyCommand({ FunctionName: func.FunctionName }))
      );
      if (policyResp && policyResp.Policy) {
        rawPolicy = policyResp.Policy;
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

  const envelope = createEnvelope({
    module: 'lambda',
    account_id: accountId,
    region: args.region,
    status,
    findings,
  });

  const outPath = writeEnvelope(args.runDir, envelope);

  logger.log('info', 'Lambda_Enumeration_Complete', {
    status,
    functions_total: findings.length,
    errors: errors.length,
    output: outPath,
  });

  await logger.flush();
  console.log(`Lambda enumeration complete: ${outPath} (${findings.length} functions, status: ${status})`);
}

main().catch((err) => {
  console.error(`Fatal error: ${err.message}`);
  process.exit(1);
});
