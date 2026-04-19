#!/usr/bin/env node
// SCOPE Graph Extraction — Phase A Deterministic Graph Construction
// Reads enumeration module JSONs from a run directory and outputs a
// deterministic {nodes, edges} graph to stdout.
//
// Usage:
//   node bin/extract-graph.js <run-dir>
//
// Exit codes:
//   0 — success (including empty graph from missing/empty files)
//   1 — error (missing run dir, bad args)

'use strict';

const fs = require('fs');
const path = require('path');

function main() {
  const runDir = process.argv[2];

  if (!runDir) {
    console.error('Usage: node bin/extract-graph.js <run-dir>');
    process.exit(1);
  }

  const resolved = path.resolve(runDir);

  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
    console.error(`[ERROR] Not a directory: ${resolved}`);
    process.exit(1);
  }

  // Read module files (missing = empty findings)
  const iam = readModule(resolved, 'iam.json');
  const s3 = readModule(resolved, 's3.json');
  const kms = readModule(resolved, 'kms.json');
  const secrets = readModule(resolved, 'secrets.json');
  const rds = readModule(resolved, 'rds.json');

  // Extract nodes
  const nodes = extractNodes(iam, s3, kms, secrets, rds);

  // Extract edges
  const edges = extractEdges(iam);

  // Output
  console.log(JSON.stringify({ nodes, edges }));
}

/**
 * Read and parse a module JSON file from the run directory.
 * Returns parsed object. If file doesn't exist, returns {findings: []}.
 * If JSON.parse fails, lets it throw (hooks guarantee valid JSON upstream).
 */
function readModule(runDir, filename) {
  const filePath = path.join(runDir, filename);
  if (!fs.existsSync(filePath)) {
    return { findings: [] };
  }
  const raw = fs.readFileSync(filePath, 'utf-8');
  return JSON.parse(raw);
}

/**
 * Extract all graph nodes from module data.
 * - IAM identity nodes: user, role (excluding service-linked), group
 * - Service nodes: from IAM role trust_relationships where trust_type === "service"
 * - Data store nodes: S3, KMS, Secrets, RDS
 * All nodes: {id, label, type, _source: "api"}
 * Deduplicated by .id, sorted by .id
 */
function extractNodes(iam, s3, kms, secrets, rds) {
  const allNodes = [];

  // Identity nodes from iam.json
  for (const finding of iam.findings || []) {
    if (finding.resource_type === 'iam_user') {
      allNodes.push({ id: 'user:' + finding.resource_id, label: finding.resource_id, type: 'user', _source: 'api' });
    } else if (finding.resource_type === 'iam_role' && !finding.is_service_linked) {
      allNodes.push({ id: 'role:' + finding.resource_id, label: finding.resource_id, type: 'role', _source: 'api' });
    } else if (finding.resource_type === 'iam_group') {
      allNodes.push({ id: 'group:' + finding.resource_id, label: finding.resource_id, type: 'group', _source: 'api' });
    }
  }

  // Service nodes from IAM role trust_relationships where trust_type === "service"
  for (const finding of iam.findings || []) {
    if (finding.resource_type !== 'iam_role') continue;
    const trusts = finding.trust_relationships || [];
    for (const tr of trusts) {
      if (tr.trust_type === 'service') {
        allNodes.push({ id: 'svc:' + tr.principal, label: tr.principal, type: 'external', _source: 'api' });
      }
    }
  }

  // Data store nodes
  for (const finding of s3.findings || []) {
    allNodes.push({ id: 'data:s3:' + finding.resource_id, label: finding.resource_id, type: 'data', _source: 'api' });
  }
  for (const finding of kms.findings || []) {
    allNodes.push({ id: 'data:kms:' + finding.resource_id, label: finding.resource_id, type: 'data', _source: 'api' });
  }
  for (const finding of secrets.findings || []) {
    allNodes.push({ id: 'data:secrets:' + finding.resource_id, label: finding.resource_id, type: 'data', _source: 'api' });
  }
  for (const finding of rds.findings || []) {
    allNodes.push({ id: 'data:rds:' + finding.resource_id, label: finding.resource_id, type: 'data', _source: 'api' });
  }

  // Deduplicate by .id, sort by .id
  return deduplicateAndSort(allNodes, n => n.id);
}

/**
 * Extract all graph edges from IAM data.
 * - Trust edges from IAM roles (not service-linked), for each trust_relationship
 * - Membership edges from IAM users, for each group
 * Deduplicated by [source, target, edge_type], sorted by same composite key.
 */
function extractEdges(iam) {
  const allEdges = [];

  for (const finding of iam.findings || []) {
    // Trust edges: from IAM roles (not service-linked)
    if (finding.resource_type === 'iam_role' && !finding.is_service_linked) {
      const trusts = finding.trust_relationships || [];
      for (const tr of trusts) {
        let source;
        if (tr.trust_type === 'service') {
          source = 'svc:' + tr.principal;
        } else if (tr.trust_type === 'wildcard') {
          source = 'external:anonymous';
        } else if (tr.trust_type === 'cross-account') {
          source = 'external:' + tr.principal;
        } else if (tr.trust_type === 'same-account') {
          if (tr.principal.indexOf(':user/') !== -1) {
            source = 'user:' + tr.principal.split('/').pop();
          } else if (tr.principal.indexOf(':role/') !== -1) {
            source = 'role:' + tr.principal.split('/').pop();
          } else {
            source = 'external:' + tr.principal;
          }
        } else if (tr.trust_type === 'federated') {
          source = 'external:' + tr.principal;
        } else {
          source = 'external:' + tr.principal;
        }

        allEdges.push({
          source: source,
          target: 'role:' + finding.resource_id,
          edge_type: tr.trust_type === 'service' ? 'service' : 'trust',
          trust_type: tr.trust_type,
          severity: tr.risk,
          label: 'can_assume',
          _source: 'api'
        });
      }
    }

    // Membership edges: from IAM users
    if (finding.resource_type === 'iam_user') {
      const groups = finding.groups || [];
      for (const group of groups) {
        allEdges.push({
          source: 'user:' + finding.resource_id,
          target: 'group:' + group,
          edge_type: 'membership',
          label: 'member_of',
          _source: 'api'
        });
      }
    }
  }

  // Deduplicate by [source, target, edge_type], sort by same composite key
  return deduplicateAndSort(allEdges, e => e.source + '\0' + e.target + '\0' + e.edge_type);
}

/**
 * Deduplicate items by a key function, then sort by that key.
 * Preserves first occurrence for duplicates.
 */
function deduplicateAndSort(items, keyFn) {
  const seen = new Map();
  for (const item of items) {
    const key = keyFn(item);
    if (!seen.has(key)) {
      seen.set(key, item);
    }
  }
  const unique = Array.from(seen.values());
  unique.sort((a, b) => keyFn(a).localeCompare(keyFn(b)));
  return unique;
}

main();
