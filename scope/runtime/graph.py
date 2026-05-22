from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from pydantic import ValidationError

from scope.core.models import ModuleEnvelope

Graph = dict[str, Any]
Resource = dict[str, Any]
LoadedModule = tuple[str, ModuleEnvelope]


def build_graph_from_run(run_dir: Path) -> Graph:
    modules = _load_modules(run_dir)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    omissions: list[dict[str, Any]] = []

    by_service = _group_by_service(modules)

    _extract_iam(by_service.get("iam", []), nodes, edges)
    _extract_lambda(by_service.get("lambda", []), nodes, edges)
    _extract_ec2(by_service.get("ec2", []), nodes, edges, omissions)
    _extract_codebuild(by_service.get("codebuild", []), nodes, edges)
    _extract_bedrock(by_service.get("bedrock", []), nodes, edges)
    _extract_apigateway(by_service.get("apigateway", []), nodes, edges)
    _extract_cognito(by_service.get("cognito", []), nodes, edges)
    _extract_data_and_policy_services(by_service, nodes, edges)
    _ensure_edge_endpoint_nodes(nodes, edges)

    return {
        "schema_version": "2.0",
        "metadata": {
            "source": "scope-runtime",
            "relationship_extractors": [
                "iam",
                "lambda",
                "ec2",
                "codebuild",
                "apigateway",
                "cognito",
                "bedrock",
                "resource_policy",
                "kms_dependency",
            ],
            "omissions": omissions,
        },
        "nodes": _dedupe_sort(nodes, lambda node: node["id"]),
        "edges": _dedupe_edges(edges),
    }


def write_graph(run_dir: Path, graph: Graph) -> Path:
    path = run_dir / "graph.json"
    path.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _load_modules(run_dir: Path) -> list[LoadedModule]:
    modules_dir = run_dir / "modules"
    if not modules_dir.exists():
        return []

    loaded: list[LoadedModule] = []
    for path in sorted(modules_dir.glob("*/*.json")):
        rel_path = path.relative_to(run_dir).as_posix()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            loaded.append((rel_path, ModuleEnvelope.model_validate(payload)))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError):
            continue
    return loaded


def _group_by_service(modules: list[LoadedModule]) -> dict[str, list[LoadedModule]]:
    grouped: dict[str, list[LoadedModule]] = {}
    for rel_path, envelope in modules:
        grouped.setdefault(envelope.module, []).append((rel_path, envelope))
    return grouped


def _extract_iam(
    modules: list[LoadedModule],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> None:
    for source_path, envelope in modules:
        for resource in envelope.resources:
            resource_type = resource.get("resource_type")
            resource_id = resource.get("resource_id")
            if resource_type == "iam_role" and not resource.get("is_service_linked"):
                nodes.append(_node(f"role:{resource_id}", resource_id, "role", resource, envelope, source_path))
                for trust in resource.get("trust_relationships") or []:
                    principal = str(trust.get("principal") or "")
                    trust_type = trust.get("trust_type")
                    if trust_type == "service":
                        source = f"svc:{principal}"
                        edge_type = "service"
                    elif trust_type == "same-account" and ":user/" in principal:
                        source = f"user:{principal.split('/')[-1]}"
                        edge_type = "trust"
                    elif trust_type == "same-account" and ":role/" in principal:
                        source = f"role:{principal.split('/')[-1]}"
                        edge_type = "trust"
                    else:
                        source = f"external:{principal or 'unknown'}"
                        edge_type = "trust"
                    edges.append(
                        _edge(
                            source,
                            f"role:{resource_id}",
                            edge_type,
                            "can_assume",
                            "iam_role_trusts_principal",
                            envelope,
                            source_path,
                            resource,
                            "trust_relationships",
                            trust_type=trust_type,
                            severity=trust.get("risk"),
                        )
                    )
            elif resource_type == "iam_user":
                nodes.append(_node(f"user:{resource_id}", resource_id, "user", resource, envelope, source_path))
                for group in resource.get("groups") or []:
                    edges.append(
                        _edge(
                            f"user:{resource_id}",
                            f"group:{group}",
                            "membership",
                            "member_of",
                            "iam_user_member_of_group",
                            envelope,
                            source_path,
                            resource,
                            "groups",
                        )
                    )
            elif resource_type == "iam_group":
                nodes.append(_node(f"group:{resource_id}", resource_id, "group", resource, envelope, source_path))
            elif resource_type == "oidc_provider":
                url = resource.get("url") or resource_id
                nodes.append(_node(f"oidc:{url}", url, "oidc", resource, envelope, source_path))
                for role_arn in resource.get("assumed_role_arns") or []:
                    edges.append(
                        _edge(
                            f"oidc:{url}",
                            f"role:{str(role_arn).split('/')[-1]}",
                            "authenticates_to",
                            "authenticates_to",
                            "oidc_provider_authenticates_to_role",
                            envelope,
                            source_path,
                            resource,
                            "assumed_role_arns",
                        )
                    )


def _extract_lambda(
    modules: list[LoadedModule],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> None:
    for source_path, envelope in modules:
        for resource in envelope.resources:
            if resource.get("resource_type") != "lambda_function":
                continue
            resource_id = resource.get("resource_id")
            nodes.append(_node(f"compute:lambda:{resource_id}", resource_id, "compute", resource, envelope, source_path))
            role = resource.get("role")
            if role:
                edges.append(
                    _edge(
                        f"compute:lambda:{resource_id}",
                        f"role:{str(role).split('/')[-1]}",
                        "executes_as",
                        "executes_as",
                        "lambda_function_executes_as_iam_role",
                        envelope,
                        source_path,
                        resource,
                        "role",
                    )
                )


def _extract_ec2(
    modules: list[LoadedModule],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    omissions: list[dict[str, Any]],
) -> None:
    for source_path, envelope in modules:
        for resource in envelope.resources:
            if resource.get("resource_type") != "ec2_instance":
                continue
            resource_id = resource.get("resource_id")
            nodes.append(_node(f"compute:ec2:{resource_id}", resource_id, "compute", resource, envelope, source_path))
            role_name = _ec2_role_name(resource.get("iam_instance_profile"))
            if role_name:
                edges.append(
                    _edge(
                        f"compute:ec2:{resource_id}",
                        f"role:{role_name}",
                        "executes_as",
                        "executes_as",
                        "ec2_instance_executes_as_iam_role",
                        envelope,
                        source_path,
                        resource,
                        "iam_instance_profile",
                    )
                )
            elif resource.get("iam_instance_profile"):
                omissions.append(
                    {
                        "service": "ec2",
                        "resource_id": resource_id,
                        "relationship": "ec2_instance_executes_as_iam_role",
                        "reason": "iam_instance_profile_role_unresolved",
                        "source_path": source_path,
                    }
                )


def _extract_codebuild(
    modules: list[LoadedModule],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> None:
    for source_path, envelope in modules:
        for resource in envelope.resources:
            if resource.get("resource_type") != "codebuild_project":
                continue
            resource_id = resource.get("resource_id")
            nodes.append(_node(f"compute:codebuild:{resource_id}", resource_id, "compute", resource, envelope, source_path))
            role = resource.get("service_role")
            if role:
                edges.append(
                    _edge(
                        f"compute:codebuild:{resource_id}",
                        f"role:{str(role).split('/')[-1]}",
                        "executes_as",
                        "executes_as",
                        "codebuild_project_executes_as_iam_role",
                        envelope,
                        source_path,
                        resource,
                        "service_role",
                    )
                )
            _add_kms_edge(
                edges,
                f"compute:codebuild:{resource_id}",
                resource.get("encryption_key"),
                "codebuild_project_encrypted_by_kms_key",
                envelope,
                source_path,
                resource,
                "encryption_key",
            )


def _extract_bedrock(
    modules: list[LoadedModule],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> None:
    for source_path, envelope in modules:
        for resource in envelope.resources:
            resource_type = resource.get("resource_type")
            resource_id = resource.get("resource_id")
            if resource_type == "bedrock_agent":
                node_id = f"ai:bedrock:{resource_id}"
                nodes.append(_node(node_id, resource_id, "ai", resource, envelope, source_path))
                role = resource.get("execution_role_arn")
                if role:
                    edges.append(
                        _edge(
                            node_id,
                            f"role:{str(role).split('/')[-1]}",
                            "executes_as",
                            "executes_as",
                            "bedrock_agent_executes_as_iam_role",
                            envelope,
                            source_path,
                            resource,
                            "execution_role_arn",
                        )
                    )
            elif resource_type == "bedrock_knowledge_base":
                node_id = f"ai:bedrock:{resource_id}"
                nodes.append(_node(node_id, resource_id, "ai", resource, envelope, source_path))
                role = resource.get("role_arn")
                if role:
                    edges.append(
                        _edge(
                            node_id,
                            f"role:{str(role).split('/')[-1]}",
                            "executes_as",
                            "executes_as",
                            "bedrock_knowledge_base_executes_as_iam_role",
                            envelope,
                            source_path,
                            resource,
                            "role_arn",
                        )
                    )


def _extract_apigateway(
    modules: list[LoadedModule],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> None:
    api_types = {"apigateway_rest_api", "apigateway_http_api", "apigateway_websocket_api"}
    for source_path, envelope in modules:
        for resource in envelope.resources:
            if resource.get("resource_type") not in api_types:
                continue
            resource_id = resource.get("resource_id")
            node_id = f"gateway:apigw:{resource_id}"
            nodes.append(_node(node_id, resource_id, "gateway", resource, envelope, source_path))
            for lambda_arn in resource.get("lambda_integrations") or []:
                function_name = _lambda_name_from_arn(str(lambda_arn))
                edges.append(
                    _edge(
                        node_id,
                        f"compute:lambda:{function_name}",
                        "invokes",
                        "invokes",
                        "apigateway_invokes_lambda_function",
                        envelope,
                        source_path,
                        resource,
                        "lambda_integrations",
                    )
                )


def _extract_cognito(
    modules: list[LoadedModule],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> None:
    for source_path, envelope in modules:
        for resource in envelope.resources:
            resource_type = resource.get("resource_type")
            if resource_type not in {"cognito_identity_pool", "cognito_user_pool"}:
                continue
            resource_id = resource.get("resource_id")
            node_id = f"idp:cognito:{resource_id}"
            nodes.append(_node(node_id, resource_id, "idp", resource, envelope, source_path))
            for field in ("authenticated_role_arn", "unauthenticated_role_arn"):
                role = resource.get(field)
                if role:
                    edges.append(
                        _edge(
                            node_id,
                            f"role:{str(role).split('/')[-1]}",
                            "authenticates_to",
                            "authenticates_to",
                            f"cognito_identity_pool_{field.removesuffix('_arn')}_role",
                            envelope,
                            source_path,
                            resource,
                            field,
                        )
                    )


def _extract_data_and_policy_services(
    by_service: dict[str, list[LoadedModule]],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> None:
    for service, modules in by_service.items():
        for source_path, envelope in modules:
            for resource in envelope.resources:
                node = _resource_node_for(resource, envelope, source_path)
                if node is None:
                    continue
                nodes.append(node)
                node_id = node["id"]
                for principal in _resource_policy_principals(resource):
                    edges.append(
                        _edge(
                            _principal_node_id(str(principal)),
                            node_id,
                            "resource_policy_allows",
                            "resource_policy_allows",
                            f"{resource.get('resource_type')}_policy_allows_principal",
                            envelope,
                            source_path,
                            resource,
                            _resource_policy_field(resource),
                        )
                    )
                for field, key_id in _kms_references(resource):
                    _add_kms_edge(
                        edges,
                        node_id,
                        key_id,
                        f"{resource.get('resource_type')}_encrypted_by_kms_key",
                        envelope,
                        source_path,
                        resource,
                        field,
                    )


def _resource_node_for(
    resource: Resource,
    envelope: ModuleEnvelope,
    source_path: str,
) -> dict[str, Any] | None:
    resource_type = resource.get("resource_type")
    resource_id = resource.get("resource_id")
    if resource_type == "s3_bucket":
        return _node(f"data:s3:{resource_id}", resource_id, "data", resource, envelope, source_path)
    if resource_type == "kms_key":
        return _node(f"data:kms:{resource_id}", resource_id, "data", resource, envelope, source_path)
    if resource_type == "secrets_secret":
        return _node(f"data:secrets:{resource_id}", resource_id, "data", resource, envelope, source_path)
    if resource_type in {"rds_instance", "rds_snapshot"}:
        return _node(f"data:rds:{resource_id}", resource_id, "data", resource, envelope, source_path)
    if resource_type == "dynamodb_table":
        return _node(f"data:dynamodb:{resource_id}", resource_id, "data", resource, envelope, source_path)
    if resource_type == "ssm_parameter":
        return _node(f"data:ssm:{resource_id}", resource_id, "data", resource, envelope, source_path)
    if resource_type == "sns_topic":
        return _node(f"messaging:sns:{resource.get('arn') or resource_id}", resource_id, "messaging", resource, envelope, source_path)
    if resource_type == "sqs_queue":
        return _node(f"messaging:sqs:{resource.get('queue_url') or resource_id}", resource_id, "messaging", resource, envelope, source_path)
    return None


def _resource_policy_principals(resource: Resource) -> list[str]:
    principals: set[str] = set()
    for key in ("resource_policy_principals", "policy_principals"):
        value = resource.get(key)
        if isinstance(value, list):
            principals.update(str(item) for item in value)

    resource_policy = resource.get("resource_policy")
    if isinstance(resource_policy, dict):
        raw_principals = resource_policy.get("principals")
        if isinstance(raw_principals, list):
            principals.update(str(item) for item in raw_principals)
        else:
            principals.update(_principals_from_policy(resource_policy))
    elif isinstance(resource_policy, str):
        principals.update(_principals_from_policy(resource_policy))

    policy = resource.get("policy")
    if isinstance(policy, (str, dict)):
        principals.update(_principals_from_policy(policy))

    return sorted(principal for principal in principals if principal)


def _resource_policy_field(resource: Resource) -> str:
    for field in ("resource_policy_principals", "policy_principals", "resource_policy", "policy"):
        if resource.get(field):
            return field
    return "resource_policy"


def _principals_from_policy(policy: Any) -> set[str]:
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return set()
    if not isinstance(policy, dict):
        return set()

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    principals: set[str] = set()
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principals.update(_normalize_principal_values(statement.get("Principal")))
    return principals


def _normalize_principal_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        principals: set[str] = set()
        for key in ("AWS", "Service", "Federated"):
            item = value.get(key)
            if isinstance(item, str):
                principals.add(item)
            elif isinstance(item, list):
                principals.update(str(part) for part in item)
        return principals
    if isinstance(value, list):
        return {str(item) for item in value}
    return set()


def _kms_references(resource: Resource) -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []
    for field in ("kms_key_id", "encryption_key"):
        value = resource.get(field)
        if value:
            refs.append((field, str(value)))

    encryption = resource.get("encryption")
    if isinstance(encryption, dict):
        for rule in encryption.get("Rules") or []:
            default = (rule or {}).get("ApplyServerSideEncryptionByDefault") or {}
            key_id = default.get("KMSMasterKeyID") or default.get("KMSMasterKeyId")
            if key_id:
                refs.append(("encryption", str(key_id)))

    return refs


def _add_kms_edge(
    edges: list[dict[str, Any]],
    source_node: str,
    key_id: Any,
    relationship: str,
    envelope: ModuleEnvelope,
    source_path: str,
    resource: Resource,
    field: str,
) -> None:
    normalized = _kms_node_id(key_id)
    if not normalized:
        return
    edges.append(
        _edge(
            source_node,
            normalized,
            "encrypted_by",
            "encrypted_by",
            relationship,
            envelope,
            source_path,
            resource,
            field,
        )
    )


def _kms_node_id(key_id: Any) -> str | None:
    if not key_id:
        return None
    value = str(key_id)
    if ":key/" in value:
        value = value.split(":key/", 1)[1]
    elif "/" in value:
        value = value.split("/")[-1]
    return f"data:kms:{value}"


def _principal_node_id(principal: str) -> str:
    if principal == "*":
        return "external:anonymous"
    if principal.endswith(".amazonaws.com"):
        return f"svc:{principal}"
    if ":user/" in principal:
        return f"user:{principal.split('/')[-1]}"
    if ":role/" in principal:
        return f"role:{principal.split('/')[-1]}"
    return f"external:{principal}"


def _lambda_name_from_arn(lambda_arn: str) -> str:
    if ":function:" in lambda_arn:
        return lambda_arn.split(":function:", 1)[1].split(":")[0]
    return lambda_arn.split("/")[-1]


def _ec2_role_name(profile: Any) -> str | None:
    if not isinstance(profile, dict):
        return None
    for key in ("role_arn", "role"):
        value = profile.get(key)
        if value:
            return str(value).split("/")[-1]
    return None


def _node(
    node_id: str,
    label: Any,
    node_type: str,
    resource: Resource,
    envelope: ModuleEnvelope,
    source_path: str,
) -> dict[str, Any]:
    return {
        "id": node_id,
        "label": str(label or node_id),
        "type": node_type,
        "resource_type": resource.get("resource_type"),
        "arn": resource.get("arn"),
        "service": envelope.module,
        "region": envelope.region,
        "account_id": envelope.account_id,
        "source_path": source_path,
        "_source": "api",
    }


def _edge(
    source: str,
    target: str,
    edge_type: str,
    label: str,
    relationship: str,
    envelope: ModuleEnvelope,
    source_path: str,
    resource: Resource,
    field: str,
    **extra: Any,
) -> dict[str, Any]:
    edge = {
        "id": f"edge:{edge_type}:{source}->{target}",
        "source": source,
        "target": target,
        "edge_type": edge_type,
        "label": label,
        "relationship": relationship,
        "service": envelope.module,
        "region": envelope.region,
        "account_id": envelope.account_id,
        "evidence": [
            {
                "source_path": source_path,
                "resource_type": resource.get("resource_type"),
                "resource_id": resource.get("resource_id"),
                "arn": resource.get("arn"),
                "field": field,
            }
        ],
        "_source": "api",
    }
    edge.update({key: value for key, value in extra.items() if value is not None})
    return edge


def _ensure_edge_endpoint_nodes(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> None:
    existing = {node["id"] for node in nodes}
    for edge in edges:
        for endpoint in (edge["source"], edge["target"]):
            if endpoint in existing:
                continue
            nodes.append(
                {
                    "id": endpoint,
                    "label": _label_from_endpoint(endpoint),
                    "type": _type_from_endpoint(endpoint),
                    "_source": "api",
                }
            )
            existing.add(endpoint)


def _label_from_endpoint(node_id: str) -> str:
    for prefix in (
        "compute:lambda:",
        "compute:ec2:",
        "compute:codebuild:",
        "gateway:apigw:",
        "messaging:sns:",
        "messaging:sqs:",
        "ai:bedrock:",
        "idp:cognito:",
        "data:s3:",
        "data:kms:",
        "data:secrets:",
        "data:rds:",
        "data:dynamodb:",
        "data:ssm:",
        "external:",
        "oidc:",
        "svc:",
        "user:",
        "role:",
        "group:",
    ):
        if node_id.startswith(prefix):
            return node_id[len(prefix):]
    return node_id


def _type_from_endpoint(node_id: str) -> str:
    if node_id.startswith("user:"):
        return "user"
    if node_id.startswith("role:"):
        return "role"
    if node_id.startswith("group:"):
        return "group"
    if node_id.startswith("data:"):
        return "data"
    if node_id.startswith("compute:"):
        return "compute"
    if node_id.startswith("gateway:"):
        return "gateway"
    if node_id.startswith("messaging:"):
        return "messaging"
    if node_id.startswith("ai:"):
        return "ai"
    if node_id.startswith("idp:"):
        return "idp"
    if node_id.startswith("oidc:"):
        return "oidc"
    return "external"


def _dedupe_sort(items: list[dict[str, Any]], key_fn: Callable[[dict[str, Any]], str]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for item in items:
        seen.setdefault(key_fn(item), item)
    return [seen[key] for key in sorted(seen)]


def _dedupe_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for edge in edges:
        existing = merged.get(edge["id"])
        if existing is None:
            merged[edge["id"]] = edge
            continue
        existing_evidence = existing.setdefault("evidence", [])
        for evidence in edge.get("evidence", []):
            if evidence not in existing_evidence:
                existing_evidence.append(evidence)
    return [merged[key] for key in sorted(merged)]
