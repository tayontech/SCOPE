from __future__ import annotations

from typing import Any

from scope.core.models import ErrorRecord, ModuleEnvelope


def run(factory: Any, region: str) -> ModuleEnvelope:
    bedrock = factory.client("bedrock")
    agent = factory.client("bedrock_agent")
    findings: list[dict[str, Any]] = []
    errors: list[ErrorRecord] = []
    status = "complete"

    try:
        findings.extend(_foundation_models(bedrock, region))
    except Exception as err:
        if _is_region_not_available(err):
            return _envelope(factory.account_id, region, [], "complete", [])
        return _envelope(
            factory.account_id,
            region,
            [],
            "error",
            [_error("bedrock.ListFoundationModels", "foundation_models", err)],
        )

    for operation, resource, collector in (
        ("bedrock.ListCustomModels", "custom_models", lambda: _custom_models(factory, bedrock, region)),
        ("bedrock-agent.ListAgents", "agents", lambda: _agents(factory, agent, region)),
        ("bedrock-agent.ListKnowledgeBases", "knowledge_bases", lambda: _knowledge_bases(factory, agent, region)),
        ("bedrock.ListGuardrails", "guardrails", lambda: _guardrails(factory, bedrock, region)),
        ("bedrock.GetModelInvocationLoggingConfiguration", "logging_config", lambda: _logging(bedrock, region)),
        ("bedrock.ListProvisionedModelThroughputs", "provisioned_throughput", lambda: _throughput(factory, bedrock, region, factory.account_id)),
    ):
        try:
            findings.extend(collector())
        except Exception as err:
            if _is_operation_unsupported(err):
                continue
            status = "partial"
            errors.append(_error(operation, resource, err))

    return _envelope(factory.account_id, region, findings, status, errors)


def _envelope(
    account_id: str,
    region: str,
    findings: list[dict[str, Any]],
    status: str,
    errors: list[ErrorRecord],
) -> ModuleEnvelope:
    return ModuleEnvelope(
        module="bedrock",
        account_id=account_id,
        region=region,
        status=status,
        resources=findings,
        coverage=[],
        errors=errors,
    )


def _foundation_models(client: Any, region: str) -> list[dict[str, Any]]:
    response = client.list_foundation_models()
    return [
        {
            "resource_type": "bedrock_model",
            "resource_id": model.get("modelId"),
            "arn": model.get("modelArn") or f"arn:aws:bedrock:{region}::foundation-model/{model.get('modelId')}",
            "region": region,
            "model_name": model.get("modelName"),
            "provider": model.get("providerName"),
            "model_arn": model.get("modelArn"),
            "input_modalities": model.get("inputModalities") or [],
            "output_modalities": model.get("outputModalities") or [],
            "customizations_supported": model.get("customizationsSupported") or [],
            "inference_types": model.get("inferenceTypesSupported") or [],
            "findings": [],
        }
        for model in response.get("modelSummaries") or []
    ]


def _custom_models(factory: Any, client: Any, region: str) -> list[dict[str, Any]]:
    models = factory.paginate(client, "list_custom_models", "modelSummaries")
    return [
        {
            "resource_type": "bedrock_custom_model",
            "resource_id": model.get("modelName") or model.get("modelArn"),
            "arn": model.get("modelArn") or f"arn:aws:bedrock:{region}:unknown:custom-model/{model.get('modelName')}",
            "region": region,
            "model_name": model.get("modelName"),
            "model_arn": model.get("modelArn"),
            "base_model_arn": model.get("baseModelArn"),
            "creation_time": model.get("creationTime"),
            "findings": [
                {
                    "type": "training_data_exposure",
                    "severity": "medium",
                    "detail": "Custom model — training data exposure risk",
                }
            ],
        }
        for model in models
    ]


def _agents(factory: Any, client: Any, region: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for summary in factory.paginate(client, "list_agents", "agentSummaries"):
        agent_id = summary.get("agentId")
        try:
            detail = client.get_agent(agentId=agent_id).get("agent") or {}
            execution_role = detail.get("agentResourceRoleArn")
            findings.append(
                {
                    "resource_type": "bedrock_agent",
                    "resource_id": detail.get("agentName") or agent_id,
                    "arn": detail.get("agentArn") or f"arn:aws:bedrock:{region}:unknown:agent/{agent_id}",
                    "region": region,
                    "agent_id": agent_id,
                    "agent_arn": detail.get("agentArn"),
                    "status": detail.get("agentStatus") or summary.get("agentStatus"),
                    "execution_role_arn": execution_role,
                    "foundation_model": detail.get("foundationModel"),
                    "description": detail.get("description"),
                    "created_at": detail.get("createdAt"),
                    "updated_at": detail.get("updatedAt"),
                    "findings": [
                        {
                            "type": "overpermissive_role",
                            "severity": "high",
                            "detail": "Agent execution role — IAM attack surface (often overpermissive)",
                        }
                    ]
                    if execution_role
                    else [],
                }
            )
        except Exception:
            findings.append(
                {
                    "resource_type": "bedrock_agent",
                    "resource_id": agent_id,
                    "arn": f"arn:aws:bedrock:{region}:unknown:agent/{agent_id}",
                    "region": region,
                    "agent_id": agent_id,
                    "status": summary.get("agentStatus"),
                    "execution_role_arn": None,
                    "findings": [],
                }
            )
    return findings


def _knowledge_bases(factory: Any, client: Any, region: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for summary in factory.paginate(client, "list_knowledge_bases", "knowledgeBaseSummaries"):
        kb_id = summary.get("knowledgeBaseId")
        try:
            detail = client.get_knowledge_base(knowledgeBaseId=kb_id).get("knowledgeBase") or {}
            storage = detail.get("storageConfiguration") or {}
            findings.append(
                {
                    "resource_type": "bedrock_knowledge_base",
                    "resource_id": detail.get("name") or kb_id,
                    "arn": detail.get("knowledgeBaseArn") or f"arn:aws:bedrock:{region}:unknown:knowledge-base/{kb_id}",
                    "region": region,
                    "knowledge_base_id": kb_id,
                    "knowledge_base_arn": detail.get("knowledgeBaseArn"),
                    "status": detail.get("status") or summary.get("status"),
                    "role_arn": detail.get("roleArn"),
                    "storage_type": storage.get("type"),
                    "storage_configuration": storage,
                    "description": detail.get("description"),
                    "created_at": detail.get("createdAt"),
                    "updated_at": detail.get("updatedAt"),
                    "findings": [
                        {
                            "type": "data_access_mapping",
                            "severity": "medium",
                            "detail": "Knowledge base data source — data access mapping",
                        }
                    ],
                }
            )
        except Exception:
            findings.append(
                {
                    "resource_type": "bedrock_knowledge_base",
                    "resource_id": kb_id,
                    "arn": f"arn:aws:bedrock:{region}:unknown:knowledge-base/{kb_id}",
                    "region": region,
                    "knowledge_base_id": kb_id,
                    "status": summary.get("status"),
                    "findings": [],
                }
            )
    return findings


def _guardrails(factory: Any, client: Any, region: str) -> list[dict[str, Any]]:
    return [
        {
            "resource_type": "bedrock_guardrail",
            "resource_id": guardrail.get("name") or guardrail.get("id"),
            "arn": guardrail.get("arn") or f"arn:aws:bedrock:{region}:unknown:guardrail/{guardrail.get('id')}",
            "region": region,
            "guardrail_id": guardrail.get("id"),
            "guardrail_arn": guardrail.get("arn"),
            "name": guardrail.get("name"),
            "status": guardrail.get("status"),
            "version": guardrail.get("version"),
            "created_at": guardrail.get("createdAt"),
            "updated_at": guardrail.get("updatedAt"),
            "findings": [],
        }
        for guardrail in factory.paginate(client, "list_guardrails", "guardrails")
    ]


def _logging(client: Any, region: str) -> list[dict[str, Any]]:
    config = client.get_model_invocation_logging_configuration().get("loggingConfig")
    enabled = bool(
        config
        and (
            config.get("textDataDeliveryEnabled")
            or config.get("imageDataDeliveryEnabled")
            or config.get("embeddingDataDeliveryEnabled")
            or (config.get("cloudWatchConfig") or {}).get("logGroupName")
            or (config.get("s3Config") or {}).get("bucketName")
        )
    )
    if enabled:
        return []
    return [
        {
            "resource_type": "bedrock_logging",
            "resource_id": "invocation_logging",
            "arn": f"arn:aws:bedrock:{region}:unknown:logging/invocation_logging",
            "region": region,
            "logging_enabled": False,
            "logging_config": config,
            "findings": [
                {
                    "type": "logging_disabled",
                    "severity": "high",
                    "detail": "Bedrock model invocation logging DISABLED — defense evasion vector (no evidence of queries)",
                }
            ],
        }
    ]


def _throughput(factory: Any, client: Any, region: str, account_id: str) -> list[dict[str, Any]]:
    throughputs = [
        {
            "resource_id": item.get("provisionedModelName") or item.get("provisionedModelArn"),
            "provisioned_model_arn": item.get("provisionedModelArn"),
            "model_arn": item.get("modelArn"),
            "status": item.get("status"),
            "commitment_duration": item.get("commitmentDuration"),
            "commitment_expiration": item.get("commitmentExpirationTime"),
            "created_at": item.get("creationTime"),
        }
        for item in factory.paginate(client, "list_provisioned_model_throughputs", "provisionedModelSummaries")
    ]
    if not throughputs:
        return []
    return [
        {
            "resource_type": "bedrock_provisioned_throughput",
            "resource_id": "provisioned_throughputs",
            "arn": f"arn:aws:bedrock:{region}:{account_id}:provisioned-throughput/summary",
            "region": region,
            "provisioned_model_arn": None,
            "throughputs": throughputs,
            "findings": [],
        }
    ]


def _is_region_not_available(err: Exception) -> bool:
    code = _error_code(err)
    message = str(err).lower()
    return code in {"UnrecognizedClientException", "InvalidClientTokenId", "EndpointNotFound", "UnknownEndpoint"} or any(
        phrase in message
        for phrase in (
            "not available in this region",
            "service is not available",
            "could not resolve endpoint",
            "is not supported in region",
        )
    )


def _is_operation_unsupported(err: Exception) -> bool:
    code = _error_code(err)
    message = str(err).lower()
    return code == "UnknownOperationException" or "unknown operation" in message


def _error(operation: str, resource: str, err: Exception) -> ErrorRecord:
    return ErrorRecord(operation=operation, resource=resource, code=_error_code(err), message=str(err))


def _error_code(err: Exception) -> str:
    response = getattr(err, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict) and error.get("Code"):
            return str(error["Code"])
    code = getattr(err, "Code", None)
    if code:
        return str(code)
    return err.__class__.__name__ or "Error"
