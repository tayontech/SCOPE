from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scope.attack.policy_eval import PolicyDecision, evaluate_policy_documents
from scope.attack.schema import AttackCandidate


SERVICE_PASSROLE_ACTIONS = {
    "codebuild.amazonaws.com": "iam:PassRole + codebuild:CreateProject + codebuild:StartBuild",
    "ec2.amazonaws.com": "iam:PassRole + ec2:RunInstances + ec2:AssociateIamInstanceProfile",
}

IAM_ADMIN_MUTATION_ACTIONS = [
    "iam:CreateUser",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:UpdateAssumeRolePolicy",
]


@dataclass(frozen=True)
class Principal:
    resource_type: str
    resource_id: str
    arn: str
    context: str
    policies: list[dict[str, Any]]
    policy_names: set[str]


@dataclass(frozen=True)
class Role:
    resource_id: str
    arn: str
    context: str
    policies: list[dict[str, Any]]
    policy_names: set[str]


@dataclass(frozen=True)
class Impact:
    type: str
    category: str
    severity: str
    action: str
    resource: str
    capability: str
    detection: str
    remediation: str
    validation_type: str = "iam"
    assumption: str | None = None


def generate_iam_candidates_from_run(run_dir: Path) -> list[dict[str, Any]]:
    results = _load_json(run_dir / "results.json")
    iam_path = run_dir / "modules" / "iam" / "global.json"
    if not iam_path.exists():
        return []
    iam = _load_json(iam_path)
    graph = results.get("graph") or _load_optional_json(run_dir / "graph.json")
    module_resources = _load_module_resources(run_dir)
    return [
        *generate_iam_candidates(
            iam_payload=iam,
            graph=graph,
            module_resources=module_resources,
        ),
        *generate_public_service_candidates(
            results=results,
            iam_payload=iam,
            graph=graph,
            module_resources=module_resources,
        ),
    ]


def generate_public_service_candidates(
    *,
    results: dict[str, Any],
    iam_payload: dict[str, Any],
    graph: dict[str, Any],
    module_resources: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    roles = _roles_by_arn(iam_payload)
    edges = _graph_edges_by_id(graph)
    resources = module_resources or []
    candidates: list[dict[str, Any]] = []
    next_id = 1

    for entrypoint in results.get("public_entrypoints") or []:
        if not isinstance(entrypoint, dict) or entrypoint.get("attack_path_seed") is not True:
            continue
        role_arn = _first_string(entrypoint.get("execution_roles"))
        if role_arn is None:
            continue
        role = roles.get(role_arn)
        if role is None:
            continue
        graph_hops = _public_entrypoint_graph_hops(entrypoint, edges)
        if not graph_hops or not _public_graph_reaches_role(graph_hops, role):
            continue
        impacts = _role_impacts(role, resources)
        if not impacts:
            continue
        for impact in impacts:
            candidates.append(
                _public_service_candidate(
                    next_id,
                    entrypoint,
                    role,
                    impact,
                    graph_hops,
                    resources,
                )
            )
            next_id += 1

    return [_validated_candidate(candidate) for candidate in candidates]


def generate_iam_candidates(
    *,
    iam_payload: dict[str, Any],
    graph: dict[str, Any],
    module_resources: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    principals, roles = _principals_and_roles(iam_payload)
    roles_by_arn = {role.arn: role for role in roles}
    trust_edges = _trust_edges(graph)
    codebuild_edges = _codebuild_project_exec_edges(graph)
    resources = module_resources or []
    codebuild_projects = _codebuild_projects(resources)
    candidates: list[dict[str, Any]] = []
    next_id = 1

    for source in principals:
        for target in roles:
            if source.context == target.context:
                continue
            impacts = _role_impacts(target, resources)
            if not impacts:
                continue
            edge = trust_edges.get((source.context, target.context))
            for impact in impacts:
                if edge and _can_call(source.policies, "sts:AssumeRole", target.arn):
                    candidates.append(_assume_role_candidate(next_id, source, target, edge, impact))
                    next_id += 1

                for service, action in SERVICE_PASSROLE_ACTIONS.items():
                    service_edge = trust_edges.get((f"svc:{service}", target.context))
                    if service_edge and _can_call(source.policies, action, target.arn):
                        candidates.append(
                            _passrole_service_candidate(
                                next_id,
                                source,
                                target,
                                service,
                                action,
                                service_edge,
                                impact,
                            )
                        )
                        next_id += 1

        for project in codebuild_projects:
            project_arn = _resource_arn(project)
            role_arn = project.get("service_role")
            if project_arn is None or not isinstance(role_arn, str):
                continue
            target = roles_by_arn.get(role_arn)
            if target is None or source.context == target.context:
                continue
            edge = codebuild_edges.get((_codebuild_project_context(project), target.context))
            if edge is None or not _can_call(source.policies, "codebuild:StartBuild", project_arn):
                continue
            for impact in _role_impacts(target, resources):
                candidates.append(_codebuild_start_build_candidate(next_id, source, project, target, edge, impact))
                next_id += 1

    return [_validated_candidate(candidate) for candidate in candidates]


def generate_iam_candidates_only_from_run(run_dir: Path) -> list[dict[str, Any]]:
    iam_path = run_dir / "modules" / "iam" / "global.json"
    if not iam_path.exists():
        return []
    iam = _load_json(iam_path)
    return generate_iam_candidates(
        iam_payload=iam,
        graph=_load_optional_json(run_dir / "graph.json"),
        module_resources=_load_module_resources(run_dir),
    )


def merge_generated_candidates(payload: dict[str, Any], generated: list[dict[str, Any]]) -> dict[str, Any]:
    existing = payload.get("candidate_attack_paths")
    if not isinstance(existing, list):
        existing = []
    seen_names = {candidate.get("name") for candidate in existing if isinstance(candidate, dict)}
    seen_ids = {candidate.get("id") for candidate in existing if isinstance(candidate, dict)}
    merged = [*existing]
    for candidate in generated:
        if candidate.get("name") not in seen_names and candidate.get("id") not in seen_ids:
            merged.append(candidate)
            seen_names.add(candidate.get("name"))
            seen_ids.add(candidate.get("id"))
    result = dict(payload)
    result["candidate_attack_paths"] = merged
    return result


def enrich_results_with_generated_candidates(run_dir: Path) -> dict[str, Any]:
    results_path = run_dir / "results.json"
    payload = _load_json(results_path)
    generated = generate_iam_candidates_from_run(run_dir)
    merged = merge_generated_candidates(payload, generated)
    results_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"generated": generated, "candidate_count": len(merged.get("candidate_attack_paths", []))}


def _principals_and_roles(iam_payload: dict[str, Any]) -> tuple[list[Principal], list[Role]]:
    resources = [resource for resource in iam_payload.get("resources", []) if isinstance(resource, dict)]
    group_policies = {
        resource.get("resource_id"): _policy_documents(resource)
        for resource in resources
        if resource.get("resource_type") == "iam_group"
    }

    principals: list[Principal] = []
    roles: list[Role] = []
    for resource in resources:
        resource_type = resource.get("resource_type")
        resource_id = resource.get("resource_id")
        arn = resource.get("arn")
        if not isinstance(resource_id, str) or not isinstance(arn, str):
            continue
        if resource_type == "iam_user":
            policies = [
                *_policy_documents(resource),
                *[
                    document
                    for group in resource.get("groups") or []
                    for document in group_policies.get(group, [])
                ],
            ]
            principals.append(
                Principal(
                    resource_type,
                    resource_id,
                    arn,
                    f"user:{resource_id}",
                    policies,
                    _policy_names(resource),
                )
            )
        elif resource_type == "iam_role" and not resource.get("is_service_linked"):
            policies = _policy_documents(resource)
            role = Role(resource_id, arn, f"role:{resource_id}", policies, _policy_names(resource))
            roles.append(role)
            principals.append(
                Principal(resource_type, resource_id, arn, role.context, policies, role.policy_names)
            )

    return principals, roles


def _roles_by_arn(iam_payload: dict[str, Any]) -> dict[str, Role]:
    _, roles = _principals_and_roles(iam_payload)
    return {role.arn: role for role in roles}


def _policy_documents(resource: dict[str, Any]) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    for policy in [*resource.get("inline_policies", []), *resource.get("attached_policies", [])]:
        if isinstance(policy, dict) and isinstance(policy.get("document"), dict):
            documents.append(policy["document"])
    return documents


def _policy_names(resource: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for policy in [*resource.get("inline_policies", []), *resource.get("attached_policies", [])]:
        if not isinstance(policy, dict):
            continue
        name = policy.get("name") or policy.get("policy_name") or policy.get("PolicyName")
        if isinstance(name, str):
            names.add(name)
    return names


def _graph_edges_by_id(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    edges: dict[str, dict[str, Any]] = {}
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        edge_id = edge.get("id")
        if isinstance(edge_id, str):
            edges[edge_id] = edge
    return edges


def _trust_edges(graph: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        if edge.get("relationship") != "iam_role_trusts_principal":
            continue
        source = edge.get("source")
        target = edge.get("target")
        if isinstance(source, str) and isinstance(target, str):
            edges[(source, target)] = edge
    return edges


def _codebuild_project_exec_edges(graph: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        if edge.get("relationship") != "codebuild_project_executes_as_iam_role":
            continue
        source = edge.get("source")
        target = edge.get("target")
        if isinstance(source, str) and isinstance(target, str):
            edges[(source, target)] = edge
    return edges


def _codebuild_projects(resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        resource
        for resource in resources
        if resource.get("resource_type") == "codebuild_project"
        and isinstance(resource.get("service_role"), str)
    ]


def _codebuild_project_context(project: dict[str, Any]) -> str:
    return f"compute:codebuild:{project.get('resource_id') or project.get('arn')}"


def _aws_managed_policy_name_impact(role: Role) -> Impact | None:
    names = role.policy_names
    if "AdministratorAccess" in names:
        return Impact(
            type="admin_access",
            category="privilege_escalation",
            severity="critical",
            action="iam:CreateUser",
            resource="*",
            capability=(
                "Attached AWS-managed AdministratorAccess policy name indicates "
                "administrator IAM mutation capability."
            ),
            detection="Public endpoint invocation followed by IAM mutation events",
            remediation="Remove public reachability or constrain the execution role policy.",
            validation_type="runtime_assumption",
            assumption="AWS-managed AdministratorAccess policy is a known permission profile.",
        )
    if "SecretsManagerReadWrite" in names:
        return Impact(
            type="data_access",
            category="data_exposure",
            severity="high",
            action="secretsmanager:GetSecretValue",
            resource="*",
            capability=(
                "Attached AWS-managed SecretsManagerReadWrite policy name indicates "
                "Secrets Manager read capability."
            ),
            detection="Public endpoint invocation followed by GetSecretValue events",
            remediation="Remove public reachability or constrain secret access on the execution role.",
            validation_type="runtime_assumption",
            assumption="AWS-managed SecretsManagerReadWrite policy is a known permission profile.",
        )
    if names.intersection({"AmazonS3ReadOnlyAccess", "AmazonS3FullAccess"}):
        return Impact(
            type="data_access",
            category="data_exposure",
            severity="high",
            action="s3:GetObject",
            resource="*",
            capability=(
                "Attached AWS-managed S3 policy name indicates object read capability."
            ),
            detection="Public endpoint invocation followed by S3 data access events where available",
            remediation="Remove public reachability or constrain S3 access on the execution role.",
            validation_type="runtime_assumption",
            assumption="Attached AWS-managed S3 policy is a known permission profile.",
        )
    return None


def _role_impacts(role: Role, module_resources: list[dict[str, Any]]) -> list[Impact]:
    documented = _documented_role_impacts(role, module_resources)
    if documented:
        return documented
    return _aws_managed_policy_name_impacts(role, module_resources)


def _documented_role_impacts(role: Role, module_resources: list[dict[str, Any]]) -> list[Impact]:
    for action in IAM_ADMIN_MUTATION_ACTIONS:
        if _decision_allows_or_conditions(_evaluate(role.policies, action, "*")):
            return [
                Impact(
                    type="admin_access",
                    category="privilege_escalation",
                    severity="critical",
                    action=action,
                    resource="*",
                    capability="Administrator-level IAM mutation through the target role.",
                    detection="CloudTrail AssumeRole and IAM mutation events",
                    remediation="Remove unneeded assume-role or PassRole access and constrain the target role policy.",
                )
            ]
    secret_impacts = _secrets_documented_impacts(role, module_resources)
    if secret_impacts:
        return secret_impacts
    if _decision_allows_or_conditions(_evaluate(role.policies, "secretsmanager:GetSecretValue", "*")):
        impact = Impact(
            type="data_access",
            category="data_exposure",
            severity="high",
            action="secretsmanager:GetSecretValue",
            resource="*",
            capability="Secrets Manager read access through the target role.",
            detection="CloudTrail AssumeRole and GetSecretValue events",
            remediation="Constrain secret access on the target role and review who can reach it.",
        )
        bound = _bind_impact_to_concrete_resource(impact, module_resources)
        return [bound or impact]

    s3_impacts = _s3_documented_impacts(role, module_resources)
    if s3_impacts:
        return s3_impacts
    dynamodb_impacts = _dynamodb_documented_impacts(role, module_resources)
    if dynamodb_impacts:
        return dynamodb_impacts
    ssm_impacts = _ssm_documented_impacts(role, module_resources)
    if ssm_impacts:
        return ssm_impacts
    return []


def _secrets_documented_impacts(role: Role, module_resources: list[dict[str, Any]]) -> list[Impact]:
    impacts: list[Impact] = []
    for resource in _concrete_resources_for_action("secretsmanager:GetSecretValue", module_resources):
        resource_arn = _resource_arn(resource)
        if resource_arn is None:
            continue
        decision = _evaluate(role.policies, "secretsmanager:GetSecretValue", resource_arn)
        if not _decision_allows_or_conditions(decision):
            continue
        resource_id = str(resource.get("resource_id") or resource_arn)
        impacts.append(
            Impact(
                type="data_access",
                category="data_exposure",
                severity="high",
                action="secretsmanager:GetSecretValue",
                resource=resource_arn,
                capability=f"Secrets Manager read access through the target role. The account contains {resource_id}.",
                detection="CloudTrail AssumeRole and GetSecretValue events",
                remediation="Constrain secret access on the target role and review who can reach it.",
            )
        )
    return impacts


def _s3_documented_impacts(role: Role, module_resources: list[dict[str, Any]]) -> list[Impact]:
    impacts: list[Impact] = []
    for resource in _concrete_resources_for_action("s3:GetObject", module_resources):
        resource_arn = _resource_arn(resource)
        if resource_arn is None:
            continue
        decision = _evaluate(role.policies, "s3:GetObject", resource_arn)
        if not _decision_allows_or_conditions(decision):
            continue
        resource_id = str(resource.get("resource_id") or resource_arn)
        impacts.append(
            Impact(
                type="data_access",
                category="data_exposure",
                severity="high",
                action="s3:GetObject",
                resource=resource_arn,
                capability=f"S3 object read access through the target role. The account contains {resource_id}.",
                detection="CloudTrail AssumeRole and S3 data access events where available",
                remediation="Constrain S3 object access on the target role and review who can reach it.",
            )
        )
    return impacts


def _dynamodb_documented_impacts(role: Role, module_resources: list[dict[str, Any]]) -> list[Impact]:
    impacts: list[Impact] = []
    for resource in _concrete_resources_for_action("dynamodb:GetItem", module_resources):
        resource_arn = _resource_arn(resource)
        if resource_arn is None:
            continue
        action = _first_allowed_action(role, ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"], resource_arn)
        if action is None:
            continue
        resource_id = str(resource.get("resource_id") or resource_arn)
        impacts.append(
            Impact(
                type="data_access",
                category="data_exposure",
                severity="high",
                action=action,
                resource=resource_arn,
                capability=f"DynamoDB table read access through the target role. The account contains {resource_id}.",
                detection="CloudTrail DynamoDB data access events where available",
                remediation="Constrain DynamoDB table read access on the target role and review who can reach it.",
            )
        )
    return impacts


def _ssm_documented_impacts(role: Role, module_resources: list[dict[str, Any]]) -> list[Impact]:
    impacts: list[Impact] = []
    for resource in _concrete_resources_for_action("ssm:GetParameter", module_resources):
        resource_arn = _resource_arn(resource)
        if resource_arn is None:
            continue
        action = _first_allowed_action(role, ["ssm:GetParameter", "ssm:GetParameters"], resource_arn)
        if action is None:
            continue
        resource_id = str(resource.get("resource_id") or resource_arn)
        impacts.append(
            Impact(
                type="data_access",
                category="data_exposure",
                severity="high",
                action=action,
                resource=resource_arn,
                capability=f"SSM Parameter Store read access through the target role. The account contains {resource_id}.",
                detection="CloudTrail GetParameter or GetParameters events",
                remediation="Constrain SSM parameter read access on the target role and review who can reach it.",
            )
        )
    return impacts


def _first_allowed_action(role: Role, actions: list[str], resource_arn: str) -> str | None:
    for action in actions:
        if _decision_allows_or_conditions(_evaluate(role.policies, action, resource_arn)):
            return action
    return None


def _aws_managed_policy_name_impacts(
    role: Role,
    module_resources: list[dict[str, Any]],
) -> list[Impact]:
    base = _aws_managed_policy_name_impact(role)
    if base is None:
        return []
    bound = _bind_impact_to_concrete_resource(base, module_resources)
    return [bound] if bound is not None else []


def _bind_impact_to_concrete_resource(
    impact: Impact,
    module_resources: list[dict[str, Any]],
) -> Impact | None:
    resource = _concrete_resource_for_action(impact.action, module_resources)
    if resource is None:
        if impact.type == "data_access":
            return None
        return impact
    resource_arn = _resource_arn(resource)
    if resource_arn is None:
        if impact.type == "data_access":
            return None
        return impact
    resource_id = str(resource.get("resource_id") or resource_arn)
    return Impact(
        type=impact.type,
        category=impact.category,
        severity=impact.severity,
        action=impact.action,
        resource=resource_arn,
        capability=f"{impact.capability} The account contains {resource_id}.",
        detection=impact.detection,
        remediation=impact.remediation,
        validation_type=impact.validation_type,
        assumption=impact.assumption,
    )


def _concrete_resource_for_action(
    action: str,
    module_resources: list[dict[str, Any]],
) -> dict[str, Any] | None:
    resource_type = {
        "secretsmanager:GetSecretValue": "secrets_secret",
        "s3:GetObject": "s3_bucket",
        "dynamodb:GetItem": "dynamodb_table",
        "ssm:GetParameter": "ssm_parameter",
    }.get(action)
    if resource_type is None:
        return None
    matches = [
        resource
        for resource in module_resources
        if resource.get("resource_type") == resource_type
    ]
    if not matches:
        return None
    return sorted(matches, key=lambda resource: str(resource.get("resource_id") or resource.get("arn") or ""))[0]


def _concrete_resources_for_action(
    action: str,
    module_resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    resource_type = {
        "secretsmanager:GetSecretValue": "secrets_secret",
        "s3:GetObject": "s3_bucket",
        "dynamodb:GetItem": "dynamodb_table",
        "ssm:GetParameter": "ssm_parameter",
    }.get(action)
    if resource_type is None:
        return []
    return sorted(
        [
            resource
            for resource in module_resources
            if resource.get("resource_type") == resource_type
        ],
        key=lambda resource: str(resource.get("resource_id") or resource.get("arn") or ""),
    )


def _resource_arn(resource: dict[str, Any]) -> str | None:
    arn = resource.get("arn")
    if isinstance(arn, str) and arn:
        if resource.get("resource_type") == "s3_bucket" and not arn.endswith("/*"):
            return f"{arn}/*"
        return arn
    if resource.get("resource_type") == "s3_bucket":
        resource_id = resource.get("resource_id")
        if isinstance(resource_id, str) and resource_id:
            return f"arn:aws:s3:::{resource_id}/*"
    return None


def _role_impact(role: Role) -> Impact | None:
    impacts = _documented_role_impacts(role, [])
    return impacts[0] if impacts else None


def _can_call(policies: list[dict[str, Any]], action: str, resource: str) -> bool:
    actions = [part.strip() for part in action.split("+") if part.strip()]
    return all(_decision_allows_or_conditions(_evaluate(policies, required, resource)) for required in actions)


def _evaluate(policies: list[dict[str, Any]], action: str, resource: str) -> PolicyDecision:
    return evaluate_policy_documents(policies, action=action, resource=resource)


def _decision_allows_or_conditions(decision: PolicyDecision) -> bool:
    return decision.decision in {"allowed", "conditional"}


def _assume_role_candidate(
    number: int,
    source: Principal,
    target: Role,
    edge: dict[str, Any],
    impact: Impact,
) -> dict[str, Any]:
    candidate_id = f"det-iam-{number:03d}"
    return {
        "id": candidate_id,
        "name": f"{source.resource_id} can assume {target.resource_id} and reach {impact.action}",
        "category": impact.category,
        "severity": impact.severity,
        "starting_position": {"type": "principal", "id": source.context, "arn": source.arn},
        "initial_context": {"principal": source.context, "capabilities": []},
        "hops": [
            {
                "id": f"{candidate_id}-hop-001",
                "transition": "assume_role",
                "from_context": source.context,
                "action": "sts:AssumeRole",
                "target": target.arn,
                "resulting_context": source.context,
                "capability_gained": f"{source.resource_id} can request credentials for {target.resource_id}.",
                "required": True,
                "validation_type": "iam",
                "evidence": [{"type": "policy_document", "id": source.arn}],
                "assumptions": [],
            },
            {
                "id": f"{candidate_id}-hop-002",
                "transition": "assume_role",
                "from_context": source.context,
                "action": "sts:AssumeRole",
                "target": target.context,
                "resulting_context": f"principal:{target.arn}",
                "capability_gained": f"{target.resource_id} trust allows the source principal to assume it.",
                "required": True,
                "validation_type": "graph",
                "evidence": [{"type": "graph_edge", "id": edge["id"]}],
                "assumptions": [],
            },
            _impact_hop(candidate_id, 3, target, impact),
        ],
        "impact": {"type": impact.type, "resource": impact.resource, "action": impact.action},
        "affected_resources": [source.arn, target.arn],
        "detection_opportunities": ["CloudTrail AssumeRole", impact.detection],
        "mitre_techniques": ["T1078.004"],
        "remediation": [impact.remediation],
    }


def _passrole_service_candidate(
    number: int,
    source: Principal,
    target: Role,
    service: str,
    action: str,
    edge: dict[str, Any],
    impact: Impact,
) -> dict[str, Any]:
    service_name = service.split(".", 1)[0]
    candidate_id = f"det-iam-{number:03d}"
    return {
        "id": candidate_id,
        "name": f"{source.resource_id} can pass {target.resource_id} to {service_name} and reach {impact.action}",
        "category": impact.category,
        "severity": impact.severity,
        "starting_position": {"type": "principal", "id": source.context, "arn": source.arn},
        "initial_context": {"principal": source.context, "capabilities": []},
        "hops": [
            {
                "id": f"{candidate_id}-hop-001",
                "transition": "pass_role",
                "from_context": source.context,
                "action": action,
                "target": target.arn,
                "resulting_context": f"resource:{service_name}-execution-with-{target.resource_id}",
                "capability_gained": f"{source.resource_id} can create {service_name} execution using {target.resource_id}.",
                "required": True,
                "validation_type": "iam",
                "evidence": [{"type": "policy_document", "id": source.arn}],
                "assumptions": [],
            },
            {
                "id": f"{candidate_id}-hop-002",
                "transition": "execute_as",
                "from_context": f"resource:{service_name}-execution-with-{target.resource_id}",
                "action": f"sts:AssumeRole by {service}",
                "target": target.context,
                "resulting_context": f"principal:{target.arn}",
                "capability_gained": f"{service} can assume {target.resource_id}.",
                "required": True,
                "validation_type": "graph",
                "evidence": [{"type": "graph_edge", "id": edge["id"]}],
                "assumptions": [],
            },
            _impact_hop(candidate_id, 3, target, impact),
        ],
        "impact": {"type": impact.type, "resource": impact.resource, "action": impact.action},
        "affected_resources": [source.arn, target.arn],
        "detection_opportunities": ["CloudTrail PassRole", service_name, impact.detection],
        "mitre_techniques": ["T1078.004", "T1578"],
        "remediation": [impact.remediation],
    }


def _codebuild_start_build_candidate(
    number: int,
    source: Principal,
    project: dict[str, Any],
    target: Role,
    edge: dict[str, Any],
    impact: Impact,
) -> dict[str, Any]:
    candidate_id = f"det-codebuild-{number:03d}"
    project_id = str(project.get("resource_id") or project.get("arn") or "project")
    project_context = _codebuild_project_context(project)
    project_arn = _resource_arn(project) or project_id
    return {
        "id": candidate_id,
        "name": f"{source.resource_id} can start CodeBuild project {project_id} as {target.resource_id} and reach {impact.action}",
        "category": impact.category,
        "severity": impact.severity,
        "starting_position": {
            "type": "principal",
            "id": source.context,
            "arn": source.arn,
        },
        "initial_context": {
            "principal": source.context,
            "capabilities": ["codebuild:StartBuild"],
        },
        "hops": [
            {
                "id": f"{candidate_id}-hop-001",
                "transition": "create_compute",
                "from_context": source.context,
                "action": "codebuild:StartBuild",
                "target": project_arn,
                "resulting_context": project_context,
                "capability_gained": (
                    "Can start the collected CodeBuild project. StartBuild supports per-build "
                    "buildspec and source overrides when IAM conditions do not restrict them."
                ),
                "required": True,
                "validation_type": "iam",
                "evidence": [{"type": "policy_document", "id": source.arn}],
                "assumptions": [],
            },
            {
                "id": f"{candidate_id}-hop-002",
                "transition": "execute_as",
                "from_context": project_context,
                "action": "sts:AssumeRole by codebuild.amazonaws.com",
                "target": target.context,
                "resulting_context": f"principal:{target.arn}",
                "capability_gained": f"CodeBuild receives {target.resource_id} credentials.",
                "required": True,
                "validation_type": "graph",
                "evidence": [{"type": "graph_edge", "id": edge["id"]}],
                "assumptions": [],
            },
            _impact_hop(candidate_id, 3, target, impact),
        ],
        "impact": {"type": impact.type, "resource": impact.resource, "action": impact.action},
        "affected_resources": [source.arn, project_arn, target.arn],
        "detection_opportunities": ["CloudTrail StartBuild", "CodeBuild build logs", impact.detection],
        "mitre_techniques": ["T1578", "T1078.004"],
        "remediation": ["Restrict CodeBuild StartBuild permissions and constrain build override condition keys.", impact.remediation],
    }


def _public_service_candidate(
    number: int,
    entrypoint: dict[str, Any],
    role: Role,
    impact: Impact,
    graph_hops: list[dict[str, Any]],
    module_resources: list[dict[str, Any]],
) -> dict[str, Any]:
    candidate_id = f"det-svc-{number:03d}"
    entry_id = str(entrypoint["id"])
    entry_resource = str(entrypoint.get("arn") or entrypoint.get("resource") or entry_id)
    hops: list[dict[str, Any]] = []
    previous_context = None

    for index, edge in enumerate(graph_hops, start=1):
        source = str(edge.get("source"))
        target = str(edge.get("target"))
        transition = _transition_for_graph_edge(edge)
        action = _action_for_graph_edge(edge)
        hops.append(
            {
                "id": f"{candidate_id}-hop-{index:03d}",
                "transition": transition,
                "from_context": previous_context or source,
                "action": action,
                "target": target,
                "resulting_context": target,
                "capability_gained": _capability_for_graph_edge(edge, role),
                "required": True,
                "validation_type": "graph",
                "evidence": [{"type": "graph_edge", "id": str(edge["id"])}],
                "assumptions": [],
            }
        )
        previous_context = target

    if graph_hops[-1].get("edge_type") != "authenticates_to":
        runtime_index = len(hops) + 1
        runtime_assumption = (
            f"Backend code reachable from {entry_id} must execute {impact.action} "
            f"on {impact.resource} using {role.resource_id}."
        )
        hops.append(
            {
                "id": f"{candidate_id}-hop-{runtime_index:03d}",
                "transition": "invoke",
                "from_context": previous_context or f"principal:{role.arn}",
                "action": "application_request_reaches_backend_code",
                "target": entry_resource,
                "resulting_context": f"principal:{role.arn}",
                "capability_gained": "The public request reaches backend code that can use the execution role.",
                "required": True,
                "validation_type": "runtime_assumption",
                "evidence": [{"type": "module_resource", "id": entry_id, "arn": entrypoint.get("arn")}],
                "assumptions": [runtime_assumption],
            }
        )

    impact_index = len(hops) + 1
    hops.append(
        {
            "id": f"{candidate_id}-hop-{impact_index:03d}",
            "transition": _transition_for_impact(impact),
            "from_context": f"principal:{role.arn}",
            "action": impact.action,
            "target": impact.resource,
            "resulting_context": _resulting_context_for_impact(impact),
            "capability_gained": impact.capability,
            "required": True,
            "validation_type": impact.validation_type,
            "evidence": _coverage_caveat_evidence(role, impact, module_resources),
            "assumptions": [impact.assumption] if impact.assumption else [],
        }
    )

    return {
        "id": candidate_id,
        "name": f"Public {_entrypoint_display(entrypoint)} reaches {role.resource_id} and {impact.action}",
        "category": impact.category,
        "severity": impact.severity,
        "starting_position": {
            "type": "public_endpoint",
            "id": entry_id,
            "arn": entrypoint.get("arn"),
        },
        "initial_context": {
            "principal": None,
            "capabilities": [str(entrypoint.get("seed_reason") or "Public endpoint can reach backend service.")],
        },
        "hops": hops,
        "impact": {"type": impact.type, "resource": impact.resource, "action": impact.action},
        "affected_resources": sorted(
            {
                entry_resource,
                role.arn,
                *[
                    item
                    for item in entrypoint.get("invokes", [])
                    if isinstance(item, str) and item
                ],
            }
        ),
        "detection_opportunities": [
            "Load balancer or service access logs",
            "CloudTrail service role activity",
            impact.detection,
        ],
        "mitre_techniques": ["T1190", "T1611"],
        "remediation": [impact.remediation],
    }


def _coverage_caveat_evidence(
    role: Role,
    impact: Impact,
    module_resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    evidence = [
        {
            "type": "module_resource",
            "id": role.resource_id,
            "arn": role.arn,
            "source_path": "modules/iam/global.json",
            "field": "resources[].attached_policies",
        }
    ]
    resource = _resource_by_arn(impact.resource, module_resources)
    if resource is not None:
        evidence.append(
            {
                "type": "module_resource",
                "id": str(resource.get("resource_id") or impact.resource),
                "arn": _resource_arn(resource),
                "source_path": _source_path_for_resource(resource),
                "field": "resources[]",
            }
        )
    return evidence


def _resource_by_arn(
    arn: str,
    module_resources: list[dict[str, Any]],
) -> dict[str, Any] | None:
    normalized = arn.removesuffix("/*")
    for resource in module_resources:
        resource_arn = _resource_arn(resource)
        if resource_arn in {arn, normalized} or (resource_arn or "").removesuffix("/*") == normalized:
            return resource
    return None


def _source_path_for_resource(resource: dict[str, Any]) -> str | None:
    source_path = resource.get("_source_path")
    return str(source_path) if source_path else None


def _public_entrypoint_graph_hops(
    entrypoint: dict[str, Any],
    edges_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    for evidence in entrypoint.get("evidence") or []:
        if not isinstance(evidence, dict) or evidence.get("type") != "graph_edge":
            continue
        edge_id = evidence.get("id")
        if not isinstance(edge_id, str):
            continue
        edge = edges_by_id.get(edge_id)
        if edge is None:
            continue
        if edge.get("edge_type") not in {
            "public_access",
            "network",
            "service",
            "invokes",
            "executes_as",
            "authenticates_to",
        }:
            continue
        hops.append(edge)
    return _ordered_public_service_hops(hops)


def _public_graph_reaches_role(graph_hops: list[dict[str, Any]], role: Role) -> bool:
    role_targets = {role.context, f"principal:{role.arn}", role.arn}
    return any(
        edge.get("edge_type") in {"executes_as", "authenticates_to"} and edge.get("target") in role_targets
        for edge in graph_hops
    )


def _entrypoint_display(entrypoint: dict[str, Any]) -> str:
    resource = entrypoint.get("resource")
    if isinstance(resource, str) and resource:
        return resource
    service = entrypoint.get("service")
    if isinstance(service, str) and service:
        return f"{service} entrypoint"
    return "entrypoint"


def _ordered_public_service_hops(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not edges:
        return []
    by_source: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        source = edge.get("source")
        if isinstance(source, str):
            by_source.setdefault(source, []).append(edge)

    start = next((edge for edge in edges if edge.get("edge_type") == "public_access"), None)
    if start is None:
        return []

    ordered = [start]
    used = {str(start.get("id"))}
    current = start.get("target")
    while isinstance(current, str):
        candidates = [edge for edge in by_source.get(current, []) if str(edge.get("id")) not in used]
        if not candidates:
            break
        edge = sorted(candidates, key=_public_service_edge_rank)[0]
        ordered.append(edge)
        used.add(str(edge.get("id")))
        current = edge.get("target")
        if edge.get("edge_type") in {"executes_as", "authenticates_to"}:
            break

    if ordered[-1].get("edge_type") not in {"executes_as", "authenticates_to"}:
        return []
    return ordered


def _public_service_edge_rank(edge: dict[str, Any]) -> tuple[int, str]:
    target = str(edge.get("target") or "")
    if target.startswith("external:dns:"):
        return (1, str(edge.get("id") or ""))
    return (0, str(edge.get("id") or ""))


def _transition_for_graph_edge(edge: dict[str, Any]) -> str:
    if edge.get("edge_type") == "executes_as":
        return "execute_as"
    if edge.get("edge_type") == "authenticates_to":
        return "authenticate"
    return "invoke"


def _action_for_graph_edge(edge: dict[str, Any]) -> str:
    relationship = edge.get("relationship") or edge.get("label") or edge.get("edge_type")
    return str(relationship)


def _capability_for_graph_edge(edge: dict[str, Any], role: Role) -> str:
    edge_type = edge.get("edge_type")
    if edge_type == "public_access":
        return "External traffic can reach the public entrypoint."
    if edge_type == "network":
        return "Traffic routes to the next backend resource."
    if edge_type == "invokes":
        return "The public service invokes the backend compute resource."
    if edge_type == "service":
        return "The service uses the referenced runtime configuration."
    if edge_type == "executes_as":
        return f"The backend executes with {role.resource_id} permissions."
    if edge_type == "authenticates_to":
        return f"The public identity path can obtain {role.resource_id} credentials."
    return "Graph relationship changes reachable context."


def _impact_hop(candidate_id: str, hop_number: int, target: Role, impact: Impact) -> dict[str, Any]:
    return {
        "id": f"{candidate_id}-hop-{hop_number:03d}",
        "transition": _transition_for_impact(impact),
        "from_context": f"principal:{target.arn}",
        "action": impact.action,
        "target": impact.resource,
        "resulting_context": _resulting_context_for_impact(impact),
        "capability_gained": impact.capability,
        "required": True,
        "validation_type": "iam",
        "evidence": [{"type": "policy_document", "id": target.arn}],
        "assumptions": [],
    }


def _transition_for_impact(impact: Impact) -> str:
    if impact.type == "admin_access":
        return "mutate_policy"
    return "data_access"


def _resulting_context_for_impact(impact: Impact) -> str:
    if impact.type == "admin_access":
        return "account-admin"
    return f"data:{_safe_context_token(impact.action)}"


def _safe_context_token(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]+", "-", value).strip("-") or "impact"


def _first_string(value: Any) -> str | None:
    if not isinstance(value, list):
        return None
    for item in value:
        if isinstance(item, str) and item:
            return item
    return None


def _validated_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    return AttackCandidate.model_validate(candidate).model_dump(mode="json")


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return _load_json(path)


def _load_module_resources(run_dir: Path) -> list[dict[str, Any]]:
    modules_dir = run_dir / "modules"
    if not modules_dir.exists():
        return []
    resources: list[dict[str, Any]] = []
    for module_path in sorted(modules_dir.glob("*/*.json")):
        payload = _load_optional_json(module_path)
        for resource in payload.get("resources", []) or []:
            if not isinstance(resource, dict):
                continue
            enriched = dict(resource)
            enriched["_source_path"] = str(module_path.relative_to(run_dir))
            resources.append(enriched)
    return resources


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m scope.attack.candidates",
        description="Generate deterministic SCOPE IAM and public-service attack-path candidates.",
    )
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--write", action="store_true", help="Merge generated candidates into results.json")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    if args.write:
        result = enrich_results_with_generated_candidates(args.run_dir)
        print(json.dumps({"generated": len(result["generated"]), "candidate_count": result["candidate_count"]}))
    else:
        print(json.dumps(generate_iam_candidates_from_run(args.run_dir), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
