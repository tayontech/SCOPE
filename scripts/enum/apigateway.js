'use strict';

const {
  APIGatewayClient,
  GetRestApisCommand,
  GetAuthorizersCommand: GetRestAuthorizersCommand,
  GetStagesCommand: GetRestStagesCommand,
  GetResourcesCommand,
} = require('@aws-sdk/client-api-gateway');

const {
  ApiGatewayV2Client,
  GetApisCommand,
  GetAuthorizersCommand: GetV2AuthorizersCommand,
  GetStagesCommand: GetV2StagesCommand,
  GetIntegrationsCommand,
} = require('@aws-sdk/client-apigatewayv2');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');

// --- Helpers ---

/**
 * Extracts Lambda integration ARNs from REST API resources or V2 integrations.
 */
function extractLambdaIntegrations(integrations) {
  const lambdaArns = new Set();
  for (const integration of integrations) {
    const uri = integration.IntegrationUri || integration.uri || '';
    // Lambda ARN pattern in integration URI
    const match = uri.match(/arn:aws:lambda:[^:]+:\d+:function:[^/]+/);
    if (match) {
      lambdaArns.add(match[0]);
    }
  }
  return [...lambdaArns];
}

/**
 * Extracts Lambda integrations from REST API resources (methods → integrations).
 */
function extractRestLambdaIntegrations(resources) {
  const lambdaArns = new Set();
  for (const resource of resources) {
    const methods = resource.resourceMethods || {};
    for (const method of Object.values(methods)) {
      const integration = method.methodIntegration;
      if (!integration) continue;
      const uri = integration.uri || '';
      const match = uri.match(/arn:aws:lambda:[^:]+:\d+:function:[^/]+/);
      if (match) {
        lambdaArns.add(match[0]);
      }
    }
  }
  return [...lambdaArns];
}

/**
 * Parses resource policy from REST API (URL-encoded JSON).
 */
function parseResourcePolicy(policyStr) {
  if (!policyStr) return null;
  try {
    const decoded = decodeURIComponent(policyStr);
    JSON.parse(decoded); // validate it parses
    return decoded;
  } catch {
    try {
      JSON.parse(policyStr);
      return policyStr;
    } catch {
      return null;
    }
  }
}

// --- REST API Enumeration ---

async function enumerateRestApis(client, region, logger) {
  const findings = [];
  const errors = [];

  // GetRestApis — paginated via position
  let restApis;
  try {
    logger.log('api_call', 'GetRestApis', { region });
    restApis = await paginate(client, GetRestApisCommand, 'items', {
      tokenKey: 'position',
      responseTokenKey: 'position',
    });
  } catch (err) {
    logger.log('error', 'GetRestApis', { error: err.message });
    return { findings, errors: [{ resource: 'rest-apis', error: err.message }] };
  }

  for (const api of restApis) {
    const apiId = api.id;
    const apiName = api.name;

    try {
      // GetAuthorizers
      let authorizers = [];
      try {
        logger.log('api_call', 'GetAuthorizers', { apiId });
        const authResp = await withRetry(() =>
          client.send(new GetRestAuthorizersCommand({ restApiId: apiId }))
        );
        authorizers = (authResp.items || []).map((a) => ({
          type: a.type || null,
          name: a.name || null,
        }));
      } catch (err) {
        errors.push({ resource: `${apiId}/authorizers`, error: err.message });
        logger.log('warning', 'GetAuthorizers', { apiId, error: err.message });
      }

      // GetStages
      let stages = [];
      try {
        logger.log('api_call', 'GetStages', { apiId });
        const stageResp = await withRetry(() =>
          client.send(new GetRestStagesCommand({ restApiId: apiId }))
        );
        stages = (stageResp.item || []).map((s) => s.stageName);
      } catch (err) {
        errors.push({ resource: `${apiId}/stages`, error: err.message });
        logger.log('warning', 'GetStages', { apiId, error: err.message });
      }

      // GetResources (paginated via position)
      let resources = [];
      try {
        logger.log('api_call', 'GetResources', { apiId });
        resources = await paginate(client, GetResourcesCommand, 'items', {
          params: { restApiId: apiId, embed: ['methods'] },
          tokenKey: 'position',
          responseTokenKey: 'position',
        });
      } catch (err) {
        errors.push({ resource: `${apiId}/resources`, error: err.message });
        logger.log('warning', 'GetResources', { apiId, error: err.message });
      }

      const lambdaIntegrations = extractRestLambdaIntegrations(resources);
      const resourcePolicy = parseResourcePolicy(api.policy);

      findings.push({
        resource_type: 'apigateway_rest_api',
        resource_id: apiId,
        arn: `arn:aws:apigateway:${region}::/restapis/${apiId}`,
        region,
        name: apiName,
        api_type: 'REST',
        authorizers,
        stages,
        lambda_integrations: lambdaIntegrations,
        resource_policy: resourcePolicy,
        findings: [],
      });
    } catch (err) {
      errors.push({ resource: apiId, error: err.message });
      logger.log('warning', 'RestApiDetail', { apiId, error: err.message });
    }
  }

  return { findings, errors };
}

// --- HTTP/WebSocket API Enumeration ---

async function enumerateV2Apis(client, region, logger) {
  const findings = [];
  const errors = [];

  // GetApis — paginated via NextToken
  let apis;
  try {
    logger.log('api_call', 'GetApis', { region });
    apis = await paginate(client, GetApisCommand, 'Items', {});
  } catch (err) {
    logger.log('error', 'GetApis', { error: err.message });
    return { findings, errors: [{ resource: 'v2-apis', error: err.message }] };
  }

  for (const api of apis) {
    const apiId = api.ApiId;
    const apiName = api.Name;
    const protocolType = api.ProtocolType; // HTTP or WEBSOCKET

    const resourceType = protocolType === 'WEBSOCKET'
      ? 'apigateway_websocket_api'
      : 'apigateway_http_api';

    try {
      // GetAuthorizers (v2)
      let authorizers = [];
      try {
        logger.log('api_call', 'GetAuthorizersV2', { apiId });
        const authResp = await withRetry(() =>
          client.send(new GetV2AuthorizersCommand({ ApiId: apiId }))
        );
        authorizers = (authResp.Items || []).map((a) => ({
          type: a.AuthorizerType || null,
          name: a.Name || null,
        }));
      } catch (err) {
        errors.push({ resource: `${apiId}/authorizers`, error: err.message });
        logger.log('warning', 'GetAuthorizersV2', { apiId, error: err.message });
      }

      // GetStages (v2)
      let stages = [];
      try {
        logger.log('api_call', 'GetStagesV2', { apiId });
        const stageResp = await withRetry(() =>
          client.send(new GetV2StagesCommand({ ApiId: apiId }))
        );
        stages = (stageResp.Items || []).map((s) => s.StageName);
      } catch (err) {
        errors.push({ resource: `${apiId}/stages`, error: err.message });
        logger.log('warning', 'GetStagesV2', { apiId, error: err.message });
      }

      // GetIntegrations (v2)
      let lambdaIntegrations = [];
      try {
        logger.log('api_call', 'GetIntegrations', { apiId });
        const intResp = await withRetry(() =>
          client.send(new GetIntegrationsCommand({ ApiId: apiId }))
        );
        lambdaIntegrations = extractLambdaIntegrations(intResp.Items || []);
      } catch (err) {
        errors.push({ resource: `${apiId}/integrations`, error: err.message });
        logger.log('warning', 'GetIntegrations', { apiId, error: err.message });
      }

      findings.push({
        resource_type: resourceType,
        resource_id: apiId,
        arn: `arn:aws:apigateway:${region}::/apis/${apiId}`,
        region,
        name: apiName,
        api_type: protocolType,
        authorizers,
        stages,
        lambda_integrations: lambdaIntegrations,
        resource_policy: null, // HTTP/WebSocket APIs do not have resource policies
        findings: [],
      });
    } catch (err) {
      errors.push({ resource: apiId, error: err.message });
      logger.log('warning', 'V2ApiDetail', { apiId, error: err.message });
    }
  }

  return { findings, errors };
}

// --- Run (exported for testing) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const logger = opts.logger || createLogger(runDir, 'apigateway');
  logger.log('info', 'APIGateway_Enumeration_Start', { region });

  // Enumerate REST APIs (APIGatewayClient)
  const restClient = opts.clients?.apigateway ?? new APIGatewayClient({ region });
  const restResult = await enumerateRestApis(restClient, region, logger);

  // Enumerate HTTP/WebSocket APIs (ApiGatewayV2Client)
  const v2Client = opts.clients?.apigatewayV2 ?? new ApiGatewayV2Client({ region });
  const v2Result = await enumerateV2Apis(v2Client, region, logger);

  // Combine results
  const findings = [...restResult.findings, ...v2Result.findings];
  const allErrors = [...restResult.errors, ...v2Result.errors];
  const status = allErrors.length > 0 ? 'partial' : 'complete';

  await logger.flush();
  return { findings, status };
}

if (require.main === module) {
  baseEnum({ module: 'apigateway', run });
}

module.exports = { run };
