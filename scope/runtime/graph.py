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
    dns_index = _dns_target_index(modules)

    _extract_iam(by_service.get("iam", []), nodes, edges)
    _extract_lambda(by_service.get("lambda", []), nodes, edges)
    _extract_ec2(by_service.get("ec2", []), nodes, edges, omissions)
    _extract_ecs(by_service.get("ecs", []), nodes, edges)
    _extract_codebuild(by_service.get("codebuild", []), nodes, edges)
    _extract_bedrock(by_service.get("bedrock", []), nodes, edges)
    _extract_apigateway(by_service.get("apigateway", []), nodes, edges)
    _extract_cloudfront(by_service.get("cloudfront", []), nodes, edges, dns_index)
    _extract_route53(by_service.get("route53", []), nodes, edges, dns_index)
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
                "ecs",
                "codebuild",
                "apigateway",
                "cloudfront",
                "route53",
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


def _dns_target_index(modules: list[LoadedModule]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for _, envelope in modules:
        for resource in envelope.resources:
            resource_type = resource.get("resource_type")
            resource_id = resource.get("resource_id")
            if resource_type == "cloudfront_distribution" and resource_id:
                node_id = f"gateway:cloudfront:{resource_id}"
                for name in [resource.get("domain_name"), *(resource.get("aliases") or [])]:
                    normalized = _normalize_dns_name(name)
                    if normalized:
                        index[normalized] = {
                            "node_id": node_id,
                            "resource_type": "cloudfront_distribution",
                        }
            elif resource_type == "ec2_load_balancer" and resource_id:
                normalized = _normalize_dns_name(resource.get("dns_name"))
                if normalized:
                    index[normalized] = {
                        "node_id": f"gateway:alb:{resource_id}",
                        "resource_type": "ec2_load_balancer",
                    }
    return index


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
                            trust_actions=trust.get("actions"),
                            conditions=trust.get("conditions"),
                            has_external_id=trust.get("has_external_id"),
                            has_mfa_condition=trust.get("has_mfa_condition"),
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
            node_id = f"compute:lambda:{resource_id}"
            nodes.append(_node(node_id, resource_id, "compute", resource, envelope, source_path))
            role = resource.get("role")
            if role:
                edges.append(
                    _edge(
                        node_id,
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
            _add_resource_policy_statement_edges(edges, node_id, resource, envelope, source_path)
            _add_lambda_event_source_mapping_edges(edges, node_id, resource, envelope, source_path)


def _extract_ec2(
    modules: list[LoadedModule],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    omissions: list[dict[str, Any]],
) -> None:
    for source_path, envelope in modules:
        for resource in envelope.resources:
            resource_type = resource.get("resource_type")
            resource_id = resource.get("resource_id")
            if resource_type == "ec2_instance":
                nodes.append(_node(f"compute:ec2:{resource_id}", resource_id, "compute", resource, envelope, source_path))
                for security_group_id in resource.get("security_groups") or []:
                    if not security_group_id:
                        continue
                    edges.append(
                        _edge(
                            f"network:sg:{security_group_id}",
                            f"compute:ec2:{resource_id}",
                            "network",
                            "attached_to",
                            "security_group_attached_to_ec2_instance",
                            envelope,
                            source_path,
                            resource,
                            "security_groups",
                        )
                    )
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
            elif resource_type == "ec2_security_group":
                node_id = f"network:sg:{resource_id}"
                nodes.append(_node(node_id, resource_id, "network", resource, envelope, source_path))
                for rule in resource.get("inbound_rules") or []:
                    if not isinstance(rule, dict) or not _security_group_rule_is_public(rule):
                        continue
                    edges.append(
                        _edge(
                            _external_node_for_security_group_rule(rule),
                            node_id,
                            "public_access",
                            "public_access",
                            "security_group_allows_public_ingress",
                            envelope,
                            source_path,
                            resource,
                            "inbound_rules",
                            protocol=rule.get("protocol"),
                            from_port=rule.get("from_port"),
                            to_port=rule.get("to_port"),
                            sources=rule.get("sources"),
                        )
                    )
            elif resource_type == "ec2_load_balancer":
                node_id = f"gateway:alb:{resource_id}"
                nodes.append(_node(node_id, resource_id, "gateway", resource, envelope, source_path))
                if resource.get("scheme") == "internet-facing":
                    for listener in resource.get("listeners") or []:
                        if not isinstance(listener, dict):
                            continue
                        protocol = str(listener.get("protocol") or "").lower()
                        port = listener.get("port")
                        external_node = "external:https" if protocol == "https" or port == 443 else "external:http"
                        edges.append(
                            _edge(
                                external_node,
                                node_id,
                                "public_access",
                                "public_access",
                                "public_http_reaches_load_balancer",
                                envelope,
                                source_path,
                                resource,
                                "listeners",
                                port=port,
                                protocol=listener.get("protocol"),
                            )
                        )
                for listener in resource.get("listeners") or []:
                    if not isinstance(listener, dict):
                        continue
                    for target_group_arn in listener.get("target_group_arns") or []:
                        target_group_id = _target_group_id_from_arn(str(target_group_arn))
                        if not target_group_id:
                            continue
                        edges.append(
                            _edge(
                                node_id,
                                f"gateway:target-group:{target_group_id}",
                                "network",
                                "routes_to",
                                "load_balancer_listener_routes_to_target_group",
                                envelope,
                                source_path,
                                resource,
                                "listeners",
                            )
                        )
            elif resource_type == "ec2_target_group":
                node_id = f"gateway:target-group:{resource_id}"
                nodes.append(_node(node_id, resource_id, "gateway", resource, envelope, source_path))


def _extract_ecs(
    modules: list[LoadedModule],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> None:
    for source_path, envelope in modules:
        for resource in envelope.resources:
            resource_type = resource.get("resource_type")
            resource_id = resource.get("resource_id")
            if resource_type == "ecs_service":
                service_node = f"compute:ecs-service:{resource_id}"
                nodes.append(_node(service_node, resource_id, "compute", resource, envelope, source_path))
                for load_balancer in resource.get("load_balancers") or []:
                    if not isinstance(load_balancer, dict):
                        continue
                    target_group_id = _target_group_id_from_arn(str(load_balancer.get("target_group_arn") or ""))
                    if not target_group_id:
                        continue
                    edges.append(
                        _edge(
                            f"gateway:target-group:{target_group_id}",
                            service_node,
                            "network",
                            "routes_to",
                            "target_group_routes_to_ecs_service",
                            envelope,
                            source_path,
                            resource,
                            "load_balancers",
                        )
                    )
                task_definition_id = _task_definition_id_from_arn(str(resource.get("task_definition_arn") or ""))
                if task_definition_id:
                    edges.append(
                        _edge(
                            service_node,
                            f"compute:ecs-task-definition:{task_definition_id}",
                            "service",
                            "uses",
                            "ecs_service_uses_task_definition",
                            envelope,
                            source_path,
                            resource,
                            "task_definition_arn",
                        )
                    )
            elif resource_type == "ecs_task_definition":
                task_definition_id = resource_id or _task_definition_id_from_arn(str(resource.get("arn") or ""))
                task_node = f"compute:ecs-task-definition:{task_definition_id}"
                nodes.append(_node(task_node, task_definition_id, "compute", resource, envelope, source_path))
                task_role = resource.get("task_role_arn")
                if task_role:
                    edges.append(
                        _edge(
                            task_node,
                            f"role:{str(task_role).split('/')[-1]}",
                            "executes_as",
                            "executes_as",
                            "ecs_task_definition_uses_task_role",
                            envelope,
                            source_path,
                            resource,
                            "task_role_arn",
                        )
                    )
                execution_role = resource.get("execution_role_arn")
                if execution_role:
                    edges.append(
                        _edge(
                            task_node,
                            f"role:{str(execution_role).split('/')[-1]}",
                            "executes_as",
                            "executes_as",
                            "ecs_task_definition_uses_execution_role",
                            envelope,
                            source_path,
                            resource,
                            "execution_role_arn",
                        )
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
            if resource.get("public_endpoint") is True:
                edges.append(
                    _edge(
                        "external:https",
                        node_id,
                        "public_access",
                        "public_access",
                        "public_https_reaches_apigateway_api",
                        envelope,
                        source_path,
                        resource,
                        "public_endpoint",
                    )
                )
            _add_resource_policy_statement_edges(
                edges,
                node_id,
                resource,
                envelope,
                source_path,
            )
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


def _extract_cloudfront(
    modules: list[LoadedModule],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    dns_index: dict[str, dict[str, str]],
) -> None:
    for source_path, envelope in modules:
        for resource in envelope.resources:
            if resource.get("resource_type") != "cloudfront_distribution":
                continue
            resource_id = resource.get("resource_id")
            node_id = f"gateway:cloudfront:{resource_id}"
            nodes.append(_node(node_id, resource_id, "gateway", resource, envelope, source_path))
            if resource.get("public_endpoint"):
                edges.append(
                    _edge(
                        "external:public",
                        node_id,
                        "public_access",
                        "public_access",
                        "cloudfront_distribution_public_endpoint",
                        envelope,
                        source_path,
                        resource,
                        "public_endpoint",
                    )
                )
            for origin in resource.get("origins") or []:
                if not isinstance(origin, dict) or not origin.get("domain_name"):
                    continue
                edges.append(
                    _edge(
                        node_id,
                        _dns_node_id(origin["domain_name"]),
                        "network",
                        "routes_to",
                        "cloudfront_distribution_routes_to_origin",
                        envelope,
                        source_path,
                        resource,
                        "origins",
                        origin_id=origin.get("id"),
                        origin_type=origin.get("origin_type"),
                    )
                )
                target = dns_index.get(_normalize_dns_name(origin["domain_name"]))
                if target and target["node_id"] != node_id:
                    edges.append(
                        _edge(
                            node_id,
                            target["node_id"],
                            "network",
                            "routes_to",
                            _cloudfront_origin_relationship(target["resource_type"]),
                            envelope,
                            source_path,
                            resource,
                            "origins",
                            origin_id=origin.get("id"),
                            origin_type=origin.get("origin_type"),
                        )
                    )


def _extract_route53(
    modules: list[LoadedModule],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    dns_index: dict[str, dict[str, str]],
) -> None:
    for source_path, envelope in modules:
        for resource in envelope.resources:
            if resource.get("resource_type") != "route53_hosted_zone":
                continue
            for record in resource.get("records") or []:
                if not isinstance(record, dict) or not record.get("public_dns"):
                    continue
                record_name = str(record.get("name") or "")
                node_id = f"gateway:route53:{record_name}"
                record_resource = {**resource, "resource_id": record_name, "record_type": record.get("type")}
                nodes.append(_node(node_id, record_name, "gateway", record_resource, envelope, source_path))
                edges.append(
                    _edge(
                        "external:public",
                        node_id,
                        "public_access",
                        "public_access",
                        "route53_record_public_dns",
                        envelope,
                        source_path,
                        record_resource,
                        "records",
                    )
                )
                for target in _route53_record_targets(record):
                    edges.append(
                        _edge(
                            node_id,
                            _dns_node_id(target),
                            "network",
                            "resolves_to",
                            "route53_record_resolves_to_target",
                            envelope,
                            source_path,
                            record_resource,
                            "records",
                            aws_target_type=record.get("aws_target_type"),
                            dangling_dns_candidate=record.get("dangling_dns_candidate"),
                        )
                    )
                    target_resource = dns_index.get(_normalize_dns_name(target))
                    if target_resource:
                        edges.append(
                            _edge(
                                node_id,
                                target_resource["node_id"],
                                "network",
                                "resolves_to",
                                _route53_resolves_relationship(target_resource["resource_type"]),
                                envelope,
                                source_path,
                                record_resource,
                                "records",
                                record_type=record.get("type"),
                                aws_target_type=record.get("aws_target_type"),
                                dangling_dns_candidate=False,
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
            node_id = _cognito_node_id(resource)
            nodes.append(_node(node_id, resource_id, "idp", resource, envelope, source_path))
            if resource_type == "cognito_identity_pool" and resource.get("allow_unauthenticated") is True:
                edges.append(
                    _edge(
                        "external:anonymous",
                        node_id,
                        "public_access",
                        "public_access",
                        "cognito_identity_pool_allows_unauthenticated_identity",
                        envelope,
                        source_path,
                        resource,
                        "allow_unauthenticated",
                    )
                )
            for field in ("authenticated_role_arn", "unauthenticated_role_arn"):
                role = resource.get(field)
                if role:
                    edges.append(
                        _edge(
                            node_id,
                            f"role:{str(role).split('/')[-1]}",
                            "authenticates_to",
                            "authenticates_to",
                            f"cognito_identity_pool_{field.removesuffix('_role_arn')}_role",
                            envelope,
                            source_path,
                            resource,
                            field,
                            )
                    )


def _cognito_node_id(resource: Resource) -> str:
    return f"idp:cognito:{resource.get('pool_id') or resource.get('resource_id')}"


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
                _add_resource_policy_statement_edges(
                    edges,
                    node_id,
                    resource,
                    envelope,
                    source_path,
                )
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
                if resource.get("resource_type") == "s3_bucket":
                    _add_s3_notification_edges(edges, node_id, resource, envelope, source_path)
                elif resource.get("resource_type") == "sns_topic":
                    _add_sns_subscription_edges(edges, node_id, resource, envelope, source_path)
                elif resource.get("resource_type") == "rds_instance":
                    _add_rds_instance_edges(edges, node_id, resource, envelope, source_path)


def _add_resource_policy_statement_edges(
    edges: list[dict[str, Any]],
    node_id: str,
    resource: Resource,
    envelope: ModuleEnvelope,
    source_path: str,
) -> None:
    statements = resource.get("resource_policy_statements")
    if not isinstance(statements, list):
        return

    for index, statement in enumerate(statements):
        if not isinstance(statement, dict) or statement.get("effect") != "Allow":
            continue
        principals = statement.get("normalized_principals")
        if not isinstance(principals, list):
            continue
        for principal in principals:
            statement_id = statement.get("sid") or f"statement-{index + 1}"
            edge = _edge(
                _resource_policy_statement_principal_node_id(str(principal), statement, envelope),
                node_id,
                "resource_policy_statement",
                "resource_policy_statement",
                f"{resource.get('resource_type')}_policy_statement_allows_action",
                envelope,
                source_path,
                resource,
                "resource_policy_statements",
                statement_id=statement_id,
                actions=statement.get("normalized_actions"),
                resources=statement.get("normalized_resources"),
                conditions=statement.get("condition"),
                source_arns=statement.get("source_arns"),
                source_accounts=statement.get("source_accounts"),
                source_org_ids=statement.get("source_org_ids"),
                is_public=statement.get("is_public"),
                is_cross_account=statement.get("is_cross_account"),
            )
            edge["id"] = f"{edge['id']}:{statement_id}"
            edges.append(edge)


def _add_lambda_event_source_mapping_edges(
    edges: list[dict[str, Any]],
    node_id: str,
    resource: Resource,
    envelope: ModuleEnvelope,
    source_path: str,
) -> None:
    mappings = resource.get("event_source_mappings")
    if not isinstance(mappings, list):
        return
    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue
        source_arn = mapping.get("event_source_arn")
        if not isinstance(source_arn, str) or not source_arn:
            continue
        source_node = _event_source_node_id(source_arn)
        if source_node is None:
            continue
        edges.append(
            _edge(
                source_node,
                node_id,
                "event_source",
                "triggers",
                _lambda_event_source_relationship(source_arn),
                envelope,
                source_path,
                resource,
                "event_source_mappings",
                mapping_uuid=mapping.get("uuid"),
                state=mapping.get("state"),
                batch_size=mapping.get("batch_size"),
            )
        )


def _add_sns_subscription_edges(
    edges: list[dict[str, Any]],
    node_id: str,
    resource: Resource,
    envelope: ModuleEnvelope,
    source_path: str,
) -> None:
    subscriptions = resource.get("subscriptions")
    if not isinstance(subscriptions, list):
        return
    for subscription in subscriptions:
        if not isinstance(subscription, dict):
            continue
        protocol = str(subscription.get("protocol") or "").lower()
        endpoint = subscription.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint:
            continue
        if protocol == "sqs":
            target = f"messaging:sqs:{endpoint}"
            relationship = "sns_topic_delivers_to_sqs_queue"
        elif protocol == "lambda":
            target = f"compute:lambda:{_lambda_name_from_arn(endpoint)}"
            relationship = "sns_topic_invokes_lambda_function"
        else:
            continue
        edges.append(
            _edge(
                node_id,
                target,
                "event_source",
                "notifies",
                relationship,
                envelope,
                source_path,
                resource,
                "subscriptions",
                subscription_arn=subscription.get("subscription_arn"),
                protocol=subscription.get("protocol"),
            )
        )


def _add_s3_notification_edges(
    edges: list[dict[str, Any]],
    node_id: str,
    resource: Resource,
    envelope: ModuleEnvelope,
    source_path: str,
) -> None:
    notification = resource.get("notification_configuration")
    if not isinstance(notification, dict):
        return

    for config in notification.get("LambdaFunctionConfigurations") or []:
        if not isinstance(config, dict) or not config.get("LambdaFunctionArn"):
            continue
        function_name = str(config["LambdaFunctionArn"]).rsplit(":", 1)[-1]
        edges.append(
            _edge(
                node_id,
                f"compute:lambda:{function_name}",
                "event_source",
                "notifies",
                "s3_bucket_notifies_lambda_function",
                envelope,
                source_path,
                resource,
                "notification_configuration",
                notification_id=config.get("Id"),
                events=config.get("Events") or [],
            )
        )

    for config in notification.get("TopicConfigurations") or []:
        if not isinstance(config, dict) or not config.get("TopicArn"):
            continue
        topic_arn = str(config["TopicArn"])
        edges.append(
            _edge(
                node_id,
                f"messaging:sns:{topic_arn}",
                "event_source",
                "notifies",
                "s3_bucket_notifies_sns_topic",
                envelope,
                source_path,
                resource,
                "notification_configuration",
                notification_id=config.get("Id"),
                events=config.get("Events") or [],
            )
        )

    for config in notification.get("QueueConfigurations") or []:
        if not isinstance(config, dict) or not config.get("QueueArn"):
            continue
        queue_arn = str(config["QueueArn"])
        edges.append(
            _edge(
                node_id,
                f"messaging:sqs:{queue_arn}",
                "event_source",
                "notifies",
                "s3_bucket_notifies_sqs_queue",
                envelope,
                source_path,
                resource,
                "notification_configuration",
                notification_id=config.get("Id"),
                events=config.get("Events") or [],
            )
        )


def _add_rds_instance_edges(
    edges: list[dict[str, Any]],
    node_id: str,
    resource: Resource,
    envelope: ModuleEnvelope,
    source_path: str,
) -> None:
    if resource.get("publicly_accessible") is True:
        edges.append(
            _edge(
                "external:public",
                node_id,
                "public_access",
                "public_access",
                "rds_instance_public_endpoint",
                envelope,
                source_path,
                resource,
                "publicly_accessible",
                endpoint=resource.get("endpoint"),
                port=resource.get("port"),
            )
        )

    for security_group in resource.get("security_groups") or []:
        if isinstance(security_group, dict):
            security_group_id = security_group.get("id")
            status = security_group.get("status")
        else:
            security_group_id = security_group
            status = None
        if not security_group_id:
            continue
        edges.append(
            _edge(
                f"network:sg:{security_group_id}",
                node_id,
                "network",
                "attached_to",
                "security_group_attached_to_rds_instance",
                envelope,
                source_path,
                resource,
                "security_groups",
                status=status,
            )
        )


def _resource_policy_statement_principal_node_id(
    principal: str,
    statement: dict[str, Any],
    envelope: ModuleEnvelope,
) -> str:
    if statement.get("is_cross_account") and _principal_account_id(principal) != envelope.account_id:
        return f"external:{principal}"
    return _principal_node_id(principal)


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


def _principal_account_id(principal: str) -> str | None:
    parts = principal.split(":", 5)
    if len(parts) == 6 and parts[0] == "arn" and parts[2] == "iam":
        return parts[4] or None
    return None


def _dns_node_id(value: Any) -> str:
    return f"external:dns:{str(value).rstrip('.')}"


def _normalize_dns_name(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _cloudfront_origin_relationship(resource_type: str) -> str:
    if resource_type == "ec2_load_balancer":
        return "cloudfront_distribution_routes_to_load_balancer"
    return "cloudfront_distribution_routes_to_collected_dns_target"


def _route53_resolves_relationship(resource_type: str) -> str:
    if resource_type == "cloudfront_distribution":
        return "route53_record_resolves_to_cloudfront_distribution"
    if resource_type == "ec2_load_balancer":
        return "route53_record_resolves_to_load_balancer"
    return "route53_record_resolves_to_collected_dns_target"


def _event_source_node_id(source_arn: str) -> str | None:
    if ":sqs:" in source_arn:
        return f"messaging:sqs:{source_arn}"
    if ":sns:" in source_arn:
        return f"messaging:sns:{source_arn}"
    if ":dynamodb:" in source_arn and ":table/" in source_arn:
        table_name = source_arn.split(":table/", 1)[1].split("/", 1)[0]
        return f"data:dynamodb:{table_name}"
    return None


def _lambda_event_source_relationship(source_arn: str) -> str:
    if ":sqs:" in source_arn:
        return "sqs_queue_triggers_lambda_function"
    if ":sns:" in source_arn:
        return "sns_topic_triggers_lambda_function"
    if ":dynamodb:" in source_arn:
        return "dynamodb_stream_triggers_lambda_function"
    return "event_source_triggers_lambda_function"


def _route53_record_targets(record: dict[str, Any]) -> list[str]:
    targets: list[str] = []
    alias_target = record.get("alias_target")
    if alias_target:
        targets.append(str(alias_target))
    for target in record.get("target_values") or []:
        if target:
            targets.append(str(target))
    return sorted(set(targets))


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


def _target_group_id_from_arn(target_group_arn: str) -> str | None:
    if ":targetgroup/" not in target_group_arn:
        return None
    tail = target_group_arn.split(":targetgroup/", 1)[1]
    return tail.split("/", 1)[0]


def _security_group_rule_is_public(rule: dict[str, Any]) -> bool:
    return any(source in {"0.0.0.0/0", "::/0"} for source in rule.get("sources") or [])


def _external_node_for_security_group_rule(rule: dict[str, Any]) -> str:
    protocol = str(rule.get("protocol") or "").lower()
    from_port = rule.get("from_port")
    to_port = rule.get("to_port")
    if protocol in {"-1", "all"}:
        return "external:public"
    if from_port == 443 or to_port == 443:
        return "external:https"
    if from_port == 80 or to_port == 80:
        return "external:http"
    return "external:public"


def _task_definition_id_from_arn(task_definition_arn: str) -> str | None:
    if ":task-definition/" not in task_definition_arn:
        return None
    return task_definition_arn.split(":task-definition/", 1)[1]


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
        "compute:ecs-service:",
        "compute:ecs-task-definition:",
        "compute:codebuild:",
        "gateway:apigw:",
        "gateway:cloudfront:",
        "gateway:route53:",
        "gateway:alb:",
        "gateway:target-group:",
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
