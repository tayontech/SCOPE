'use strict';

const { AccountClient, ListRegionsCommand } = require('@aws-sdk/client-account');

const FALLBACK_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
  'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
  'ap-northeast-3', 'ap-south-1', 'sa-east-1', 'ca-central-1',
];

/**
 * Discovers enabled AWS regions using the Account API (ListRegions).
 * Uses a different API surface than regions.js (EC2 DescribeRegions) —
 * do NOT import or call getEnabledRegions() from this module.
 *
 * @param {import('@aws-sdk/client-account').AccountClient} [client] - Optional injected AccountClient for testing
 * @returns {Promise<string[]>} Sorted array of enabled region name strings
 */
async function discoverEnabledRegions(client) {
  const accountClient = client ?? new AccountClient({});
  const resp = await accountClient.send(
    new ListRegionsCommand({ RegionOptStatusContains: ['ENABLED', 'ENABLED_BY_DEFAULT'] })
  );
  return (resp.Regions || []).map((r) => r.RegionName).sort();
}

async function main() {
  try {
    const regions = await discoverEnabledRegions();
    process.stdout.write(JSON.stringify(regions) + '\n');
  } catch (err) {
    const code = err.name || err.Code || '';
    if (code === 'AccessDeniedException' || code === 'AccessDenied') {
      process.stderr.write('[WARN] account:ListRegions denied — using 17-region default fallback. Opt-in regions will not be scanned.\n');
    } else {
      process.stderr.write(`[WARN] discover-regions failed (${err.message}) — using 17-region default fallback.\n`);
    }
    process.stdout.write(JSON.stringify(FALLBACK_REGIONS) + '\n');
  }
}

if (require.main === module) { main(); }

module.exports = { discoverEnabledRegions, FALLBACK_REGIONS };
