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
  const iam        = readModule(resolved, 'iam.json');
  const s3         = readModule(resolved, 's3.json');
  const kms        = readModule(resolved, 'kms.json');
  const secrets    = readModule(resolved, 'secrets.json');
  const rds        = readModule(resolved, 'rds.json');
  const lambda     = readModule(resolved, 'lambda.json');
  const ec2        = readModule(resolved, 'ec2.json');
  const codebuild  = readModule(resolved, 'codebuild.json');
  const apigateway = readModule(resolved, 'apigateway.json');
  const sns        = readModule(resolved, 'sns.json');
  const sqs        = readModule(resolved, 'sqs.json');
  const bedrock    = readModule(resolved, 'bedrock.json');
  const cognito    = readModule(resolved, 'cognito.json');
  const dynamodb   = readModule(resolved, 'dynamodb.json');
  const ssm        = readModule(resolved, 'ssm.json');

  // Extract nodes
  const nodes = extractNodes(iam, s3, kms, secrets, rds, lambda, ec2, codebuild, apigateway, sns, sqs, bedrock, cognito, dynamodb, ssm);

  // Extract edges
  const edges = extractEdges(iam, lambda, ec2, codebuild, bedrock, apigateway, cognito);

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
 * Node types (D-12):
 * - IAM identity: user:, role: (excl service-linked), group:
 * - Service nodes: svc: (from IAM role trust_relationships where trust_type === "service")
 * - OIDC providers: oidc: (from iam.json oidc_provider findings)
 * - Data stores: data:s3:, data:kms:, data:secrets:, data:rds:, data:dynamodb:, data:ssm:
 * - Compute: compute:lambda:, compute:ec2:, compute:codebuild:
 * - Gateway: gateway:apigw:
 * - Messaging: messaging:sns:, messaging:sqs:
 * - AI: ai:bedrock:
 * - Identity Provider: idp:cognito:
 * All nodes: {id, label, type, _source: "api"}
 * Deduplicated by .id, sorted by .id
 */
function extractNodes(iam, s3, kms, secrets, rds, lambda, ec2, codebuild, apigateway, sns, sqs, bedrock, cognito, dynamodb, ssm) {
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

  // Data tier — new services
  for (const finding of dynamodb.findings || []) {
    if (finding.resource_type === 'dynamodb_table') {
      allNodes.push({ id: 'data:dynamodb:' + finding.resource_id, label: finding.resource_id, type: 'data', _source: 'api' });
    }
  }
  for (const finding of ssm.findings || []) {
    if (finding.resource_type === 'ssm_parameter') {
      allNodes.push({ id: 'data:ssm:' + finding.resource_id, label: finding.resource_id, type: 'data', _source: 'api' });
    }
  }

  // Compute tier
  for (const finding of lambda.findings || []) {
    if (finding.resource_type === 'lambda_function') {
      allNodes.push({ id: 'compute:lambda:' + finding.resource_id, label: finding.resource_id, type: 'compute', _source: 'api' });
    }
  }
  for (const finding of ec2.findings || []) {
    if (finding.resource_type === 'ec2_instance') {
      allNodes.push({ id: 'compute:ec2:' + finding.resource_id, label: finding.resource_id, type: 'compute', _source: 'api' });
    }
  }
  for (const finding of codebuild.findings || []) {
    if (finding.resource_type === 'codebuild_project') {
      allNodes.push({ id: 'compute:codebuild:' + finding.resource_id, label: finding.resource_id, type: 'compute', _source: 'api' });
    }
  }

  // Gateway tier
  for (const finding of apigateway.findings || []) {
    if (['apigateway_rest_api', 'apigateway_http_api', 'apigateway_websocket_api'].includes(finding.resource_type)) {
      allNodes.push({ id: 'gateway:apigw:' + finding.resource_id, label: finding.resource_id, type: 'gateway', _source: 'api' });
    }
  }

  // Messaging tier
  for (const finding of sns.findings || []) {
    if (finding.resource_type === 'sns_topic') {
      allNodes.push({ id: 'messaging:sns:' + finding.resource_id, label: finding.resource_id, type: 'messaging', _source: 'api' });
    }
  }
  for (const finding of sqs.findings || []) {
    if (finding.resource_type === 'sqs_queue') {
      allNodes.push({ id: 'messaging:sqs:' + finding.resource_id, label: finding.resource_id, type: 'messaging', _source: 'api' });
    }
  }

  // AI tier
  for (const finding of bedrock.findings || []) {
    if (finding.resource_type === 'bedrock_agent') {
      allNodes.push({ id: 'ai:bedrock:' + finding.resource_id, label: finding.resource_id, type: 'ai', _source: 'api' });
    }
  }

  // Identity Provider tier
  for (const finding of cognito.findings || []) {
    if (finding.resource_type === 'cognito_identity_pool' || finding.resource_type === 'cognito_user_pool') {
      allNodes.push({ id: 'idp:cognito:' + finding.resource_id, label: finding.resource_id, type: 'idp', _source: 'api' });
    }
  }

  // OIDC provider nodes (from iam.json oidc_provider findings)
  for (const finding of iam.findings || []) {
    if (finding.resource_type === 'oidc_provider') {
      allNodes.push({ id: 'oidc:' + finding.url, label: finding.url, type: 'oidc', _source: 'api' });
    }
  }

  // Deduplicate by .id, sort by .id
  return deduplicateAndSort(allNodes, n => n.id);
}

/**
 * Extract all graph edges from module data.
 * Edge types (D-13):
 * - Trust edges from IAM roles (not service-linked), for each trust_relationship
 * - Membership edges from IAM users, for each group
 * - executes_as: lambda/ec2/codebuild/bedrock -> IAM role
 * - invokes: apigateway -> lambda function
 * - authenticates_to: cognito identity pool -> IAM role, oidc provider -> IAM role
 * Deduplicated by [source, target, edge_type], sorted by same composite key.
 */
function extractEdges(iam, lambda, ec2, codebuild, bedrock, apigateway, cognito) {
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

  // Compute -> IAM: executes_as edges
  for (const finding of lambda.findings || []) {
    if (finding.resource_type === 'lambda_function' && finding.role) {
      const roleName = finding.role.split('/').pop();
      allEdges.push({
        source: 'compute:lambda:' + finding.resource_id,
        target: 'role:' + roleName,
        edge_type: 'executes_as',
        label: 'executes_as',
        _source: 'api'
      });
    }
  }
  for (const finding of ec2.findings || []) {
    if (finding.resource_type === 'ec2_instance' && finding.iam_instance_profile?.arn) {
      // NOTE: Uses instance profile name as role name proxy — may mismatch if profile and role names differ. Full fix requires ec2.js to include role name.
      const roleName = finding.iam_instance_profile.arn.split('/').pop();
      allEdges.push({
        source: 'compute:ec2:' + finding.resource_id,
        target: 'role:' + roleName,
        edge_type: 'executes_as',
        label: 'executes_as',
        _source: 'api'
      });
    }
  }
  for (const finding of codebuild.findings || []) {
    if (finding.resource_type === 'codebuild_project' && finding.service_role) {
      const roleName = finding.service_role.split('/').pop();
      allEdges.push({
        source: 'compute:codebuild:' + finding.resource_id,
        target: 'role:' + roleName,
        edge_type: 'executes_as',
        label: 'executes_as',
        _source: 'api'
      });
    }
  }
  for (const finding of bedrock.findings || []) {
    if (finding.resource_type === 'bedrock_agent' && finding.execution_role_arn) {
      const roleName = finding.execution_role_arn.split('/').pop();
      allEdges.push({
        source: 'ai:bedrock:' + finding.resource_id,
        target: 'role:' + roleName,
        edge_type: 'executes_as',
        label: 'executes_as',
        _source: 'api'
      });
    }
  }

  // Gateway -> Compute: API Gateway invokes Lambda
  for (const finding of apigateway.findings || []) {
    for (const lambdaArn of finding.lambda_integrations || []) {
      const fnName = lambdaArn.split(':function:').pop()?.split(':')[0] || lambdaArn;
      allEdges.push({
        source: 'gateway:apigw:' + finding.resource_id,
        target: 'compute:lambda:' + fnName,
        edge_type: 'invokes',
        label: 'invokes',
        _source: 'api'
      });
    }
  }

  // Identity Provider -> IAM: Cognito authenticates_to roles
  for (const finding of cognito.findings || []) {
    if (finding.resource_type === 'cognito_identity_pool') {
      if (finding.authenticated_role_arn) {
        const roleName = finding.authenticated_role_arn.split('/').pop();
        allEdges.push({
          source: 'idp:cognito:' + finding.resource_id,
          target: 'role:' + roleName,
          edge_type: 'authenticates_to',
          label: 'authenticates_to',
          _source: 'api'
        });
      }
      if (finding.unauthenticated_role_arn) {
        const roleName = finding.unauthenticated_role_arn.split('/').pop();
        allEdges.push({
          source: 'idp:cognito:' + finding.resource_id,
          target: 'role:' + roleName,
          edge_type: 'authenticates_to',
          label: 'authenticates_to',
          _source: 'api'
        });
      }
    }
  }

  // OIDC provider -> IAM: authenticates_to roles (from iam.json oidc_provider findings)
  for (const finding of iam.findings || []) {
    if (finding.resource_type === 'oidc_provider') {
      for (const roleArn of finding.assumed_role_arns || []) {
        const roleName = roleArn.split('/').pop();
        const trustCond = (finding.trust_conditions || []).find(
          c => c && (c.principal === finding.arn || c.principal === finding.url)
        ) || null;
        allEdges.push({
          source: 'oidc:' + finding.url,
          target: 'role:' + roleName,
          edge_type: 'authenticates_to',
          label: 'authenticates_to',
          conditions: trustCond,
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
