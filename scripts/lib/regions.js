'use strict';

const { DescribeRegionsCommand } = require('@aws-sdk/client-ec2');

/**
 * Discovers all enabled AWS regions via EC2 DescribeRegions.
 *
 * @param {Object} ec2Client - An initialized EC2Client instance
 * @returns {Promise<string[]>} Array of region name strings (e.g., ['us-east-1', 'eu-west-1'])
 */
async function getEnabledRegions(ec2Client) {
  const response = await ec2Client.send(
    new DescribeRegionsCommand({ AllRegions: false })
  );
  return (response.Regions || []).map((r) => r.RegionName).sort();
}

/**
 * Runs a callback for each region, collecting results. Per-region errors are
 * caught and recorded without stopping the iteration.
 *
 * @param {string[]} regionList - Array of region names to iterate
 * @param {Function} callback - Async function: (region) => result
 * @returns {Promise<Array<{region: string, result?: *, error?: string}>>}
 */
async function forEachRegion(regionList, callback) {
  if (!Array.isArray(regionList) || regionList.length === 0) {
    return [];
  }

  const results = [];
  for (const region of regionList) {
    try {
      const result = await callback(region);
      results.push({ region, result });
    } catch (err) {
      results.push({ region, error: err.message || String(err) });
    }
  }
  return results;
}

module.exports = { getEnabledRegions, forEachRegion };
