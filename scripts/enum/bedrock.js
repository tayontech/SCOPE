'use strict';

const {
  BedrockClient,
  ListFoundationModelsCommand,
  ListCustomModelsCommand,
  ListGuardrailsCommand,
  GetModelInvocationLoggingConfigurationCommand,
  ListProvisionedModelThroughputsCommand,
} = require('@aws-sdk/client-bedrock');

const {
  BedrockAgentClient,
  ListAgentsCommand,
  GetAgentCommand,
  ListKnowledgeBasesCommand,
  GetKnowledgeBaseCommand,
} = require('@aws-sdk/client-bedrock-agent');

const { withRetry, paginate, createLogger } = require('../lib');
const { baseEnum } = require('../lib/base-enum');

// --- Region availability check ---

function isRegionNotAvailableError(err) {
  const code = err.name || err.Code || '';
  const message = (err.message || '').toLowerCase();
  return (
    code === 'UnrecognizedClientException' ||
    code === 'InvalidClientTokenId' ||
    code === 'EndpointNotFound' ||
    code === 'UnknownEndpoint' ||
    message.includes('not available in this region') ||
    message.includes('service is not available') ||
    message.includes('could not resolve endpoint') ||
    message.includes('is not supported in region')
  );
}

// --- Enumeration functions ---

async function enumerateFoundationModels(client, region, logger) {
  logger.log('api_call', 'ListFoundationModels', {});
  const resp = await withRetry(() => client.send(new ListFoundationModelsCommand({})));
  const models = resp.modelSummaries || [];
  return models.map((m) => ({
    resource_type: 'bedrock_model',
    resource_id: m.modelId,
    arn: m.modelArn || `arn:aws:bedrock:${region}::foundation-model/${m.modelId}`,
    region,
    model_name: m.modelName || null,
    provider: m.providerName || null,
    model_arn: m.modelArn || null,
    input_modalities: m.inputModalities || [],
    output_modalities: m.outputModalities || [],
    customizations_supported: m.customizationsSupported || [],
    inference_types: m.inferenceTypesSupported || [],
    findings: [],
  }));
}

async function enumerateCustomModels(client, region, logger) {
  logger.log('api_call', 'ListCustomModels', {});
  const models = await paginate(client, ListCustomModelsCommand, 'modelSummaries', {});
  return models.map((m) => ({
    resource_type: 'bedrock_custom_model',
    resource_id: m.modelName || m.modelArn,
    arn: m.modelArn || `arn:aws:bedrock:${region}:unknown:custom-model/${m.modelName}`,
    region,
    model_name: m.modelName || null,
    model_arn: m.modelArn || null,
    base_model_arn: m.baseModelArn || null,
    creation_time: m.creationTime || null,
    findings: [{ type: 'training_data_exposure', severity: 'medium', detail: 'Custom model — training data exposure risk' }],
  }));
}

async function enumerateAgents(agentClient, region, logger) {
  logger.log('api_call', 'ListAgents', {});
  const agents = await paginate(agentClient, ListAgentsCommand, 'agentSummaries', {});
  const findings = [];

  for (const agent of agents) {
    try {
      logger.log('api_call', 'GetAgent', { agentId: agent.agentId });
      const resp = await withRetry(() =>
        agentClient.send(new GetAgentCommand({ agentId: agent.agentId }))
      );
      const detail = resp.agent || {};
      findings.push({
        resource_type: 'bedrock_agent',
        resource_id: detail.agentName || agent.agentId,
        arn: detail.agentArn || `arn:aws:bedrock:${region}:unknown:agent/${agent.agentId}`,
        region,
        agent_id: agent.agentId,
        agent_arn: detail.agentArn || null,
        status: detail.agentStatus || agent.agentStatus || null,
        execution_role_arn: detail.agentResourceRoleArn || null,
        foundation_model: detail.foundationModel || null,
        description: detail.description || null,
        created_at: detail.createdAt || null,
        updated_at: detail.updatedAt || null,
        findings: detail.agentResourceRoleArn
          ? [{ type: 'overpermissive_role', severity: 'high', detail: 'Agent execution role — IAM attack surface (often overpermissive)' }]
          : [],
      });
    } catch (err) {
      logger.log('warning', 'GetAgent', { agentId: agent.agentId, error: err.message });
      findings.push({
        resource_type: 'bedrock_agent',
        resource_id: agent.agentId,
        arn: `arn:aws:bedrock:${region}:unknown:agent/${agent.agentId}`,
        region,
        agent_id: agent.agentId,
        status: agent.agentStatus || null,
        execution_role_arn: null,
        findings: [],
      });
    }
  }

  return findings;
}

async function enumerateKnowledgeBases(agentClient, region, logger) {
  logger.log('api_call', 'ListKnowledgeBases', {});
  const kbs = await paginate(agentClient, ListKnowledgeBasesCommand, 'knowledgeBaseSummaries', {});
  const findings = [];

  for (const kb of kbs) {
    try {
      logger.log('api_call', 'GetKnowledgeBase', { knowledgeBaseId: kb.knowledgeBaseId });
      const resp = await withRetry(() =>
        agentClient.send(new GetKnowledgeBaseCommand({ knowledgeBaseId: kb.knowledgeBaseId }))
      );
      const detail = resp.knowledgeBase || {};
      const storageConfig = detail.storageConfiguration || {};
      findings.push({
        resource_type: 'bedrock_knowledge_base',
        resource_id: detail.name || kb.knowledgeBaseId,
        arn: detail.knowledgeBaseArn || `arn:aws:bedrock:${region}:unknown:knowledge-base/${kb.knowledgeBaseId}`,
        region,
        knowledge_base_id: kb.knowledgeBaseId,
        knowledge_base_arn: detail.knowledgeBaseArn || null,
        status: detail.status || kb.status || null,
        role_arn: detail.roleArn || null,
        storage_type: storageConfig.type || null,
        storage_configuration: storageConfig,
        description: detail.description || null,
        created_at: detail.createdAt || null,
        updated_at: detail.updatedAt || null,
        findings: [{ type: 'data_access_mapping', severity: 'medium', detail: 'Knowledge base data source — data access mapping' }],
      });
    } catch (err) {
      logger.log('warning', 'GetKnowledgeBase', { knowledgeBaseId: kb.knowledgeBaseId, error: err.message });
      findings.push({
        resource_type: 'bedrock_knowledge_base',
        resource_id: kb.knowledgeBaseId,
        arn: `arn:aws:bedrock:${region}:unknown:knowledge-base/${kb.knowledgeBaseId}`,
        region,
        knowledge_base_id: kb.knowledgeBaseId,
        status: kb.status || null,
        findings: [],
      });
    }
  }

  return findings;
}

async function enumerateGuardrails(client, region, logger) {
  logger.log('api_call', 'ListGuardrails', {});
  const guardrails = await paginate(client, ListGuardrailsCommand, 'guardrails', {});
  return guardrails.map((g) => ({
    resource_type: 'bedrock_guardrail',
    resource_id: g.name || g.id,
    arn: g.arn || `arn:aws:bedrock:${region}:unknown:guardrail/${g.id}`,
    region,
    guardrail_id: g.id || null,
    guardrail_arn: g.arn || null,
    name: g.name || null,
    status: g.status || null,
    version: g.version || null,
    created_at: g.createdAt || null,
    updated_at: g.updatedAt || null,
    findings: [],
  }));
}

async function checkLoggingConfiguration(client, logger) {
  logger.log('api_call', 'GetModelInvocationLoggingConfiguration', {});
  const resp = await withRetry(() =>
    client.send(new GetModelInvocationLoggingConfigurationCommand({}))
  );
  const config = resp.loggingConfig || null;
  const loggingEnabled = !!(
    config &&
    (config.textDataDeliveryEnabled ||
      config.imageDataDeliveryEnabled ||
      config.embeddingDataDeliveryEnabled ||
      config.cloudWatchConfig?.logGroupName ||
      config.s3Config?.bucketName)
  );

  return {
    logging_enabled: loggingEnabled,
    logging_config: config,
    finding: loggingEnabled
      ? null
      : 'Bedrock model invocation logging DISABLED — defense evasion vector (no evidence of queries)',
  };
}

async function enumerateProvisionedThroughput(client, logger) {
  logger.log('api_call', 'ListProvisionedModelThroughputs', {});
  const throughputs = await paginate(
    client,
    ListProvisionedModelThroughputsCommand,
    'provisionedModelSummaries',
    {}
  );
  return throughputs.map((t) => ({
    resource_id: t.provisionedModelName || t.provisionedModelArn,
    provisioned_model_arn: t.provisionedModelArn || null,
    model_arn: t.modelArn || null,
    status: t.status || null,
    commitment_duration: t.commitmentDuration || null,
    commitment_expiration: t.commitmentExpirationTime || null,
    created_at: t.creationTime || null,
  }));
}

// --- Run (exported for testing) ---

async function run(opts = {}) {
  const runDir = opts.runDir;
  const region = opts.region;
  const accountId = opts.accountId;

  const logger = opts.logger || createLogger(runDir, 'bedrock');
  logger.log('info', 'Bedrock_Enumeration_Start', { region });

  const bedrockClient = opts.clients?.bedrock ?? new BedrockClient({ region });
  const agentClient = opts.clients?.bedrockAgent ?? new BedrockAgentClient({ region });

  let findings = [];
  let status = 'complete';
  const partialErrors = [];

  try {
    // Foundation models
    try {
      const models = await enumerateFoundationModels(bedrockClient, region, logger);
      findings.push(...models);
    } catch (err) {
      if (isRegionNotAvailableError(err)) {
        logger.log('info', 'Bedrock_NotAvailable', { region, error: err.message });
        await logger.flush();
        return { findings: [], status: 'complete' };
      }
      throw err;
    }

    // Custom models
    try {
      const customModels = await enumerateCustomModels(bedrockClient, region, logger);
      findings.push(...customModels);
    } catch (err) {
      partialErrors.push({ resource: 'custom_models', error: err.message });
      logger.log('warning', 'ListCustomModels', { error: err.message });
    }

    // Agents
    try {
      const agents = await enumerateAgents(agentClient, region, logger);
      findings.push(...agents);
    } catch (err) {
      partialErrors.push({ resource: 'agents', error: err.message });
      logger.log('warning', 'ListAgents', { error: err.message });
    }

    // Knowledge bases
    try {
      const kbs = await enumerateKnowledgeBases(agentClient, region, logger);
      findings.push(...kbs);
    } catch (err) {
      partialErrors.push({ resource: 'knowledge_bases', error: err.message });
      logger.log('warning', 'ListKnowledgeBases', { error: err.message });
    }

    // Guardrails
    try {
      const guardrails = await enumerateGuardrails(bedrockClient, region, logger);
      findings.push(...guardrails);
    } catch (err) {
      partialErrors.push({ resource: 'guardrails', error: err.message });
      logger.log('warning', 'ListGuardrails', { error: err.message });
    }

    // Logging configuration
    try {
      const loggingResult = await checkLoggingConfiguration(bedrockClient, logger);
      if (loggingResult.finding) {
        findings.push({
          resource_type: 'bedrock_logging',
          resource_id: 'invocation_logging',
          arn: `arn:aws:bedrock:${region}:unknown:logging/invocation_logging`,
          region,
          logging_enabled: loggingResult.logging_enabled,
          logging_config: loggingResult.logging_config,
          findings: [{ type: 'logging_disabled', severity: 'high', detail: loggingResult.finding }],
        });
      }
    } catch (err) {
      partialErrors.push({ resource: 'logging_config', error: err.message });
      logger.log('warning', 'GetModelInvocationLoggingConfiguration', { error: err.message });
    }

    // Provisioned throughput
    try {
      const throughputs = await enumerateProvisionedThroughput(bedrockClient, logger);
      if (throughputs.length > 0) {
        findings.push({
          resource_type: 'bedrock_provisioned_throughput',
          resource_id: 'provisioned_throughputs',
          arn: `arn:aws:bedrock:${region}:${accountId || 'unknown'}:provisioned-throughput/summary`,
          region,
          provisioned_model_arn: null,
          throughputs,
          findings: [],
        });
      }
    } catch (err) {
      partialErrors.push({ resource: 'provisioned_throughput', error: err.message });
      logger.log('warning', 'ListProvisionedModelThroughputs', { error: err.message });
    }

  } catch (err) {
    if (isRegionNotAvailableError(err)) {
      logger.log('info', 'Bedrock_NotAvailable', { region, error: err.message });
      await logger.flush();
      return { findings: [], status: 'complete' };
    }
    logger.log('error', 'Bedrock_Fatal', { error: err.message });
    status = 'error';
  }

  if (partialErrors.length > 0 && status === 'complete') {
    status = 'partial';
  }

  await logger.flush();
  return { findings, status };
}

if (require.main === module) {
  baseEnum({ module: 'bedrock', run });
}

module.exports = { run };
