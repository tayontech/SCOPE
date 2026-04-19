'use strict';

const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
const {
  OrganizationsClient,
  DescribeOrganizationCommand,
  ListPoliciesCommand,
  DescribePolicyCommand,
  ListTargetsForPolicyCommand,
} = require('@aws-sdk/client-organizations');

const { withRetry, paginate, createEnvelope, writeEnvelope, createLogger } = require('../lib');

// --- Argument parsing ---

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--run-dir' && argv[i + 1]) {
      args.runDir = argv[++i];
    }
  }
  return args;
}

function usage() {
  console.error('Usage: node scripts/enum/sts.js --run-dir <directory>');
  console.error('');
  console.error('Options:');
  console.error('  --run-dir  Path to the run output directory (required)');
  process.exit(1);
}

// --- Principal type detection ---

function derivePrincipalType(arn) {
  if (!arn) return 'unknown';
  if (arn.includes(':assumed-role/')) return 'assumed-role';
  if (arn.includes(':role/')) return 'role';
  if (arn.includes(':user/')) return 'user';
  if (arn.includes(':federated-user/')) return 'federated-user';
  if (arn.includes(':root')) return 'root';
  return 'unknown';
}

// --- Run (DI-injectable) ---

async function run(opts = {}) {
  const { runDir } = opts;
  const stsClient = opts.clients && opts.clients.sts ? opts.clients.sts : new STSClient({});
  const orgsClient = opts.clients && opts.clients.organizations ? opts.clients.organizations : new OrganizationsClient({});

  const logger = createLogger(runDir);
  const findings = [];
  let status = 'complete';

  // --- Step 1: GetCallerIdentity (fatal on failure) ---
  let identity;
  try {
    logger.log('api_call', 'GetCallerIdentity', { service: 'sts' });
    identity = await withRetry(() => stsClient.send(new GetCallerIdentityCommand({})));
  } catch (err) {
    logger.log('error', 'GetCallerIdentity', { error: err.message });
    await logger.flush();
    console.error(`FATAL: GetCallerIdentity failed: ${err.message}`);
    throw err;
  }

  const accountId = identity.Account;
  const callerArn = identity.Arn;
  const userId = identity.UserId;

  findings.push({
    resource_type: 'sts_identity',
    resource_id: 'caller',
    arn: callerArn,
    region: 'global',
    account_id: accountId,
    user_id: userId,
    principal_type: derivePrincipalType(callerArn),
    findings: [],
  });

  logger.log('info', 'CallerIdentity resolved', { account_id: accountId, arn: callerArn });

  // --- Step 2: Organizations discovery (best-effort) ---
  let orgAccessible = false;

  try {
    logger.log('api_call', 'DescribeOrganization', { service: 'organizations' });
    const orgResp = await withRetry(() => orgsClient.send(new DescribeOrganizationCommand({})));
    const org = orgResp.Organization;

    orgAccessible = true;
    findings.push({
      resource_type: 'sts_organization',
      resource_id: org.Id,
      arn: org.Arn,
      region: 'global',
      master_account_id: org.MasterAccountId,
      available_policy_types: (org.AvailablePolicyTypes || [])
        .filter((pt) => pt.Status === 'ENABLED')
        .map((pt) => pt.Type),
      findings: [],
    });

    logger.log('info', 'Organization discovered', { org_id: org.Id });
  } catch (err) {
    const code = err.name || err.Code || '';
    if (
      code === 'AccessDeniedException' ||
      code === 'AWSOrganizationsNotInUseException' ||
      code === 'AccessDenied'
    ) {
      logger.log('info', 'Organizations not accessible', { error: code });
      status = 'partial';
    } else {
      logger.log('error', 'DescribeOrganization unexpected error', { error: err.message });
      status = 'partial';
    }
  }

  // --- Step 3: SCP enumeration (only if org is accessible) ---
  if (orgAccessible) {
    try {
      logger.log('api_call', 'ListPolicies', { service: 'organizations', filter: 'SERVICE_CONTROL_POLICY' });
      const policies = await paginate(orgsClient, ListPoliciesCommand, 'Policies', {
        params: { Filter: 'SERVICE_CONTROL_POLICY' },
      });

      for (const policySummary of policies) {
        try {
          // Get full policy document
          logger.log('api_call', 'DescribePolicy', { service: 'organizations', policy_id: policySummary.Id });
          const policyResp = await withRetry(() =>
            orgsClient.send(new DescribePolicyCommand({ PolicyId: policySummary.Id }))
          );
          const policy = policyResp.Policy;

          // Get targets for this policy
          logger.log('api_call', 'ListTargetsForPolicy', { service: 'organizations', policy_id: policySummary.Id });
          const targets = await paginate(orgsClient, ListTargetsForPolicyCommand, 'Targets', {
            params: { PolicyId: policySummary.Id },
          });

          // Parse policy document JSON
          let policyDocument = {};
          try {
            policyDocument = JSON.parse(policy.PolicySummary ? policy.Content : policy.Content);
          } catch (parseErr) {
            policyDocument = { raw: policy.Content };
          }

          findings.push({
            resource_type: 'sts_scp',
            resource_id: policySummary.Id,
            arn: policySummary.Arn,
            region: 'global',
            name: policySummary.Name,
            description: policySummary.Description || '',
            policy_document: policyDocument,
            targets: targets.map((t) => ({
              target_id: t.TargetId,
              type: t.Type,
              name: t.Name,
            })),
            findings: [],
          });
        } catch (scpErr) {
          logger.log('error', 'SCP enumeration failed for policy', {
            policy_id: policySummary.Id,
            error: scpErr.message,
          });
          status = 'partial';
        }
      }
    } catch (err) {
      logger.log('error', 'ListPolicies failed', { error: err.message });
      status = 'partial';
    }
  }

  // --- Step 4: Build envelope and write ---
  const envelope = createEnvelope({
    module: 'sts',
    account_id: accountId,
    region: 'global',
    status,
    findings,
  });

  const outPath = writeEnvelope(runDir, envelope);
  logger.log('info', 'Envelope written', { path: outPath, findings_count: findings.length, status });
  await logger.flush();

  console.log(`STS enumeration complete: ${outPath} (${findings.length} findings, status: ${status})`);
}

// --- Main (CLI entrypoint) ---

async function main() {
  const args = parseArgs(process.argv);
  if (!args.runDir) {
    usage();
  }
  try {
    await run({ runDir: args.runDir });
    process.exit(0);
  } catch (err) {
    console.error(`Fatal error: ${err.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`Fatal error: ${err.message}`);
    process.exit(1);
  });
}
module.exports = { run };
