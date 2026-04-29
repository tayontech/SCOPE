'use strict';

const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
const { createEnvelope, writeEnvelope } = require('./envelope');
const { createLogger } = require('./logger');

/**
 * Parses standard CLI arguments for enum scripts.
 * Accepts: --run-dir <path>, --account-id <id>, --region <region>[,region2,...]
 */
function parseArgs(argv) {
  const args = { runDir: null, accountId: null, region: null };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--run-dir' && argv[i + 1]) args.runDir = argv[++i];
    else if (argv[i] === '--account-id' && argv[i + 1]) args.accountId = argv[++i];
    else if (argv[i] === '--region' && argv[i + 1]) args.region = argv[++i];
  }
  return args;
}

/**
 * Shared entry point for all enum scripts.
 * Handles CLI parsing, account ID resolution, multi-region iteration,
 * logger creation, and envelope writing.
 *
 * @param {Object} config
 * @param {string} config.module - Module name (e.g., 's3', 'ec2')
 * @param {Function} config.run - async ({ runDir, region, accountId, logger, clients }) => { findings, status }
 * @param {boolean} [config.global=false] - If true, script is global (no --region required)
 */
function baseEnum({ module, run, global = false }) {
  async function main() {
    const args = parseArgs(process.argv);

    if (!args.runDir) {
      console.error(`Error: --run-dir is required`);
      console.error(`Usage: node scripts/enum/${module}.js --run-dir <dir> --account-id <id> [--region <region>[,r2,...]]`);
      process.exit(1);
    }
    if (!global && !args.region) {
      console.error(`Error: --region is required for ${module}`);
      console.error(`Usage: node scripts/enum/${module}.js --run-dir <dir> --account-id <id> --region <region>[,r2,...]`);
      process.exit(1);
    }

    // Resolve account ID: from CLI arg or STS fallback
    let accountId = args.accountId;
    if (!accountId) {
      try {
        const stsClient = new STSClient({});
        const identity = await stsClient.send(new GetCallerIdentityCommand({}));
        accountId = identity.Account;
      } catch (err) {
        console.error(`GetCallerIdentity failed: ${err.message}`);
        process.exit(1);
      }
    }

    const logger = createLogger(args.runDir, module);

    try {
      if (global || !args.region.includes(',')) {
        // Single region or global
        const region = global ? 'global' : args.region.trim();
        const result = await run({ runDir: args.runDir, region, accountId, logger });
        const envelope = createEnvelope({
          module,
          account_id: accountId,
          region,
          status: result.status || 'complete',
          findings: result.findings || [],
        });
        writeEnvelope(args.runDir, envelope);
        await logger.flush();
        const count = (result.findings || []).length;
        console.log(`${module} enumeration complete: ${args.runDir}/${module}.json (${count} findings, status: ${result.status || 'complete'})`);
      } else {
        // Multi-region
        const regions = args.region.split(',').map(r => r.trim());
        const allFindings = [];
        let hasErrors = false;
        for (const region of regions) {
          try {
            const result = await run({ runDir: args.runDir, region, accountId, logger });
            if (Array.isArray(result.findings)) allFindings.push(...result.findings);
            if (result.status === 'partial' || result.status === 'error') hasErrors = true;
          } catch (err) {
            logger.log('error', `${module}_region_error`, { region, error: err.message });
            hasErrors = true;
          }
        }
        const envelope = createEnvelope({
          module,
          account_id: accountId,
          region: 'multi',
          status: hasErrors ? 'partial' : 'complete',
          findings: allFindings,
        });
        writeEnvelope(args.runDir, envelope);
        await logger.flush();
        console.log(`${module} enumeration complete: ${args.runDir}/${module}.json (${allFindings.length} findings across ${regions.length} regions)`);
      }
      process.exit(0);
    } catch (err) {
      console.error(`Fatal error in ${module}: ${err.message}`);
      process.exit(1);
    }
  }

  main();
}

module.exports = { baseEnum, parseArgs };
