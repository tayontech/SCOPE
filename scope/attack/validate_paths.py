from __future__ import annotations

from copy import deepcopy
from fnmatch import fnmatchcase
from typing import Any

from scope.attack.policy_eval import PolicyDecision, evaluate_policy_documents
from scope.attack.schema import AttackCandidate, AttackPathGroup, AttackValidation, FinalAttackPath
from scope.attack.validate_graph import graph_edges_by_id, graph_nodes_by_id


def validate_candidates(
    payload: dict[str, Any],
    *,
    principal_policies: dict[str, list[dict[str, Any]]] | None = None,
    resource_policies: dict[str, list[dict[str, Any]]] | None = None,
    permission_boundary_policies: dict[str, list[dict[str, Any]]] | None = None,
    permission_boundary_presence: set[str] | None = None,
    kms_grants: dict[str, list[dict[str, Any]]] | None = None,
    lambda_function_url_auth_types: dict[str, str] | None = None,
) -> dict[str, Any]:
    policies_by_principal = principal_policies or {}
    policies_by_resource = resource_policies or {}
    boundaries_by_principal = permission_boundary_policies or {}
    boundary_presence = permission_boundary_presence or set()
    grants_by_key = kms_grants or {}
    function_url_auth_types = lambda_function_url_auth_types or {}
    graph_edges = graph_edges_by_id(payload.get("graph") or {})
    graph_nodes = graph_nodes_by_id(payload.get("graph") or {})
    public_entrypoint_seeds = _public_entrypoint_seeds(payload)
    account_id = str(payload.get("account_id") or "")
    validations: list[dict[str, Any]] = []
    final_paths: list[dict[str, Any]] = []

    for raw_candidate in payload.get("candidate_attack_paths", []):
        candidate = AttackCandidate.model_validate(raw_candidate)
        validation = _validate_candidate(
            candidate,
            graph_edges=graph_edges,
            graph_nodes=graph_nodes,
            principal_policies=policies_by_principal,
            resource_policies=policies_by_resource,
            permission_boundary_policies=boundaries_by_principal,
            permission_boundary_presence=boundary_presence,
            kms_grants=grants_by_key,
            lambda_function_url_auth_types=function_url_auth_types,
            public_entrypoint_seeds=public_entrypoint_seeds,
            account_id=account_id,
        )
        validations.append(validation.model_dump(mode="json"))
        if validation.promotion_decision == "promote":
            final_paths.append(_promote_candidate(candidate, validation))

    result = deepcopy(payload)
    result["attack_validation"] = validations
    result["attack_paths"] = final_paths
    result["attack_path_groups"] = group_attack_paths(final_paths)
    _sync_attack_summary(result)
    _sync_public_exposure_promotions(result)
    return result


def _sync_attack_summary(result: dict[str, Any]) -> None:
    summary = result.setdefault("summary", {})
    if not isinstance(summary, dict):
        result["summary"] = {}
        summary = result["summary"]

    validations = result.get("attack_validation") or []
    final_paths = result.get("attack_paths") or []
    groups = result.get("attack_path_groups") or []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for path in final_paths:
        if not isinstance(path, dict):
            continue
        severity = path.get("severity")
        if severity in severity_counts:
            severity_counts[severity] += 1

    summary["attack_analysis_stage"] = "validation"
    summary["validated_attack_paths_count"] = sum(
        1
        for validation in validations
        if isinstance(validation, dict) and validation.get("status") == "validated"
    )
    summary["conditional_attack_paths_count"] = sum(
        1
        for validation in validations
        if isinstance(validation, dict) and validation.get("status") == "conditional"
    )
    summary["rejected_attack_paths_count"] = sum(
        1
        for validation in validations
        if isinstance(validation, dict) and validation.get("status") == "rejected"
    )
    summary["attack_paths_count"] = len(final_paths)
    summary["attack_path_groups_count"] = len(groups)
    summary["attack_path_severity_counts"] = severity_counts
    exposure_severities = [
        finding.get("severity")
        for finding in result.get("public_exposure_findings") or []
        if isinstance(finding, dict) and finding.get("severity") in severity_counts
    ]
    final_severities = [
        path.get("severity")
        for path in final_paths
        if isinstance(path, dict) and path.get("severity") in severity_counts
    ]
    summary["severity"] = min(
        [*final_severities, *exposure_severities] or [summary.get("severity", "low")],
        key=lambda severity: _severity_rank(str(severity)),
    )


def _sync_public_exposure_promotions(result: dict[str, Any]) -> None:
    findings = result.get("public_exposure_findings")
    if not isinstance(findings, list):
        return

    candidates_by_id = {
        candidate.get("id"): candidate
        for candidate in result.get("candidate_attack_paths") or []
        if isinstance(candidate, dict) and isinstance(candidate.get("id"), str)
    }
    path_ids_by_entrypoint: dict[str, list[str]] = {}
    for path in result.get("attack_paths") or []:
        if not isinstance(path, dict) or not isinstance(path.get("id"), str):
            continue
        candidate = candidates_by_id.get(path.get("source_candidate_id"))
        starting_position = candidate.get("starting_position") if isinstance(candidate, dict) else None
        if not isinstance(starting_position, dict):
            continue
        if starting_position.get("type") != "public_endpoint":
            continue
        entrypoint_id = starting_position.get("id")
        if not isinstance(entrypoint_id, str) or not entrypoint_id:
            continue
        path_ids_by_entrypoint.setdefault(entrypoint_id, []).append(path["id"])

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        entrypoint_id = finding.get("source_entrypoint_id")
        if not isinstance(entrypoint_id, str):
            continue
        promoted_ids = path_ids_by_entrypoint.get(entrypoint_id, [])
        if not promoted_ids:
            continue
        finding["promoted_attack_path_ids"] = promoted_ids
        finding["reason_not_attack_path"] = (
            "Promoted to final attack path(s): " + ", ".join(promoted_ids)
        )


def group_attack_paths(final_paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
    for path in final_paths:
        key = _group_key(path)
        grouped.setdefault(key, []).append(path)

    groups: list[dict[str, Any]] = []
    for index, paths in enumerate(grouped.values(), start=1):
        sorted_paths = sorted(paths, key=_path_sort_key)
        representative = sorted_paths[0]
        terminal = _terminal_hop(representative)
        primitive = _path_primitive(representative)
        source_principals = sorted(
            {
                principal
                for path in sorted_paths
                if (principal := _source_principal(path))
            }
        )
        affected_resources = sorted(
            {
                resource
                for path in sorted_paths
                for resource in path.get("affected_resources", [])
                if isinstance(resource, str) and resource
            }
        )
        statuses = sorted(
            {
                path.get("validation_status")
                for path in sorted_paths
                if path.get("validation_status") in {"validated", "conditional"}
            }
        )
        group = AttackPathGroup(
            id=f"apg-{index:03d}",
            name=_group_name(primitive, terminal, sorted_paths),
            severity=min(
                (str(path.get("severity", "low")) for path in sorted_paths),
                key=lambda severity: _severity_rank(severity),
            ),
            category=str(representative.get("category", "privilege_escalation")),
            validation_statuses=statuses or ["validated"],
            primitive=primitive,
            impact={
                "action": str(terminal.get("action", "unknown")),
                "resource": str(terminal.get("target", "unknown")),
                "resulting_context": str(terminal.get("resulting_context", "unknown")),
            },
            representative_path_id=str(representative.get("id")),
            member_path_ids=[str(path.get("id")) for path in sorted_paths],
            member_count=len(sorted_paths),
            source_principals=source_principals,
            leveraging_assets=_leveraging_assets(sorted_paths),
            affected_resources=affected_resources,
            description=_group_description(primitive, terminal, sorted_paths),
        )
        groups.append(group.model_dump(mode="json"))
    return groups


def _validate_candidate(
    candidate: AttackCandidate,
    *,
    graph_edges: dict[str, dict[str, Any]],
    graph_nodes: dict[str, dict[str, Any]],
    principal_policies: dict[str, list[dict[str, Any]]],
    resource_policies: dict[str, list[dict[str, Any]]],
    permission_boundary_policies: dict[str, list[dict[str, Any]]],
    permission_boundary_presence: set[str],
    kms_grants: dict[str, list[dict[str, Any]]],
    lambda_function_url_auth_types: dict[str, str],
    public_entrypoint_seeds: set[str],
    account_id: str,
) -> AttackValidation:
    chain_failure = _chain_quality_failure(
        candidate,
        public_entrypoint_seeds=public_entrypoint_seeds,
    )
    validated_hops: list[str] = []
    conditional_hops: list[str] = []
    failed_hops: list[str] = []
    runtime_assumptions: list[str] = []
    coverage_caveats: list[str] = []
    current_context = candidate.initial_context.principal or candidate.starting_position.id

    for hop in candidate.hops:
        if hop.validation_type == "graph":
            if _uncontrolled_external_assume_role(candidate, hop):
                failed_hops.append(hop.id)
            elif _invalid_graph_edge_evidence(hop.evidence, graph_edges, hop, current_context):
                failed_hops.append(hop.id)
            else:
                validated_hops.append(hop.id)
        elif hop.validation_type == "iam":
            policies = _policies_for_context(
                principal_policies, hop.from_context, current_context
            )
            if not policies:
                conditional_hops.append(hop.id)
                coverage_caveats.append(
                    f"No collected policy documents for {hop.from_context}"
                )
                current_context = hop.resulting_context
                continue
            decision = _evaluate_hop_policy(policies, action=hop.action, resource=hop.target)
            if decision.decision == "allowed":
                boundary_decision = _evaluate_permission_boundary(
                    permission_boundary_policies,
                    permission_boundary_presence,
                    hop.from_context,
                    current_context,
                    action=hop.action,
                    resource=hop.target,
                )
                kms_decision = _evaluate_kms_dependency(
                    graph_edges,
                    graph_nodes,
                    resource_policies,
                    kms_grants,
                    policies,
                    action=hop.action,
                    resource=hop.target,
                    principal_context=hop.from_context,
                    account_id=account_id,
                )
                if boundary_decision and boundary_decision.decision in {"explicit_deny", "implicit_deny"}:
                    failed_hops.append(hop.id)
                    coverage_caveats.extend(
                        boundary_decision.caveats
                        or [f"Permission boundary denies {hop.action} on {hop.target}"]
                    )
                elif kms_decision and kms_decision.decision in {"explicit_deny", "implicit_deny"}:
                    failed_hops.append(hop.id)
                elif (
                    boundary_decision
                    and boundary_decision.decision in {"conditional", "unknown"}
                ):
                    conditional_hops.append(hop.id)
                    coverage_caveats.extend(
                        boundary_decision.caveats
                        or [f"Permission boundary evaluation returned {boundary_decision.decision} for {hop.id}"]
                    )
                elif kms_decision is None or kms_decision.decision == "allowed":
                    validated_hops.append(hop.id)
                elif kms_decision.decision in {"conditional", "unknown"}:
                    conditional_hops.append(hop.id)
                    coverage_caveats.extend(
                        kms_decision.caveats
                        or [f"KMS policy evaluation returned {kms_decision.decision} for {hop.id}"]
                    )
                else:
                    failed_hops.append(hop.id)
            elif decision.decision in {"conditional", "unknown"}:
                conditional_hops.append(hop.id)
                coverage_caveats.extend(
                    decision.caveats
                    or [f"IAM policy evaluation returned {decision.decision} for {hop.id}"]
                )
            else:
                failed_hops.append(hop.id)
        elif hop.validation_type == "resource_policy":
            statements = _resource_policies_for_target(resource_policies, hop.target)
            if not statements:
                conditional_hops.append(hop.id)
                coverage_caveats.append(f"No collected resource policy statements for {hop.target}")
                current_context = hop.resulting_context
                continue
            decision = _evaluate_resource_policy_hop(
                statements,
                principal=hop.from_context,
                action=hop.action,
                resource=hop.target,
                source_arns=_source_arns_for_hop(candidate, hop, current_context),
                source_accounts=_source_accounts_for_hop(candidate, hop, current_context, account_id),
                kms_via_services=set(),
                lambda_function_url_auth_type=_lambda_function_url_auth_type_for_target(
                    lambda_function_url_auth_types,
                    hop.target,
                ),
                lambda_invoked_via_function_url=_lambda_invoked_via_function_url(hop.action),
            )
            if decision.decision == "allowed":
                kms_decision = _evaluate_kms_dependency(
                    graph_edges,
                    graph_nodes,
                    resource_policies,
                    kms_grants,
                    [],
                    action=hop.action,
                    resource=hop.target,
                    principal_context=hop.from_context,
                    account_id=account_id,
                )
                if kms_decision is None or kms_decision.decision == "allowed":
                    validated_hops.append(hop.id)
                elif kms_decision.decision in {"conditional", "unknown"}:
                    conditional_hops.append(hop.id)
                    coverage_caveats.extend(
                        kms_decision.caveats
                        or [f"KMS policy evaluation returned {kms_decision.decision} for {hop.id}"]
                    )
                else:
                    failed_hops.append(hop.id)
            elif decision.decision in {"conditional", "unknown"}:
                conditional_hops.append(hop.id)
                coverage_caveats.extend(
                    decision.caveats
                    or [f"Resource policy evaluation returned {decision.decision} for {hop.id}"]
                )
            else:
                failed_hops.append(hop.id)
        elif hop.validation_type == "runtime_assumption":
            conditional_hops.append(hop.id)
            runtime_assumptions.extend(hop.assumptions)
        elif hop.validation_type == "coverage_caveat":
            conditional_hops.append(hop.id)
            coverage_caveats.extend(
                hop.assumptions or [f"Coverage caveat remains for {hop.id}"]
            )
        else:
            conditional_hops.append(hop.id)
            coverage_caveats.append(
                f"{hop.validation_type} validation is not implemented for {hop.id}"
            )

        current_context = hop.resulting_context

    if chain_failure is not None:
        failed_hops.extend(
            hop.id for hop in candidate.hops if hop.id not in failed_hops
        )
        return AttackValidation(
            candidate_id=candidate.id,
            status="rejected",
            promotion_decision="drop",
            reason=f"Candidate failed chain quality gate: {chain_failure}",
            validated_hops=validated_hops,
            conditional_hops=conditional_hops,
            failed_hops=failed_hops,
            runtime_assumptions=runtime_assumptions,
            coverage_caveats=coverage_caveats,
            final_context=current_context,
            validated_impact=None,
        )

    if failed_hops:
        return AttackValidation(
            candidate_id=candidate.id,
            status="rejected",
            promotion_decision="drop",
            reason="One or more required hops failed validation.",
            validated_hops=validated_hops,
            conditional_hops=conditional_hops,
            failed_hops=failed_hops,
            runtime_assumptions=runtime_assumptions,
            coverage_caveats=coverage_caveats,
            final_context=current_context,
            validated_impact=None,
        )

    if conditional_hops or runtime_assumptions or coverage_caveats:
        return AttackValidation(
            candidate_id=candidate.id,
            status="conditional",
            promotion_decision="promote",
            reason="The path validates with runtime assumptions or coverage caveats.",
            validated_hops=validated_hops,
            conditional_hops=conditional_hops,
            failed_hops=[],
            runtime_assumptions=runtime_assumptions,
            coverage_caveats=coverage_caveats,
            final_context=current_context,
            validated_impact=candidate.impact,
        )

    return AttackValidation(
        candidate_id=candidate.id,
        status="validated",
        promotion_decision="promote",
        reason="Collected evidence validates each required hop.",
        validated_hops=validated_hops,
        conditional_hops=[],
        failed_hops=[],
        runtime_assumptions=[],
        coverage_caveats=[],
        final_context=current_context,
        validated_impact=candidate.impact,
    )


def _chain_quality_failure(
    candidate: AttackCandidate,
    *,
    public_entrypoint_seeds: set[str],
) -> str | None:
    hops = candidate.hops
    if (
        candidate.starting_position.type == "public_endpoint"
        and candidate.starting_position.id not in public_entrypoint_seeds
    ):
        return (
            "public endpoint candidate does not reference a public_entrypoints[] "
            "seed with attack_path_seed true"
        )

    if _public_endpoint_only_reachability(candidate):
        return "public endpoint candidate only proves reachability or invocation"

    if len(hops) == 1 and not _single_hop_reaches_complete_impact(candidate):
        return "single-hop candidate does not prove complete attacker progression"

    if not _has_attacker_progression(candidate):
        return "candidate hops do not change attacker context or capability"

    if not _has_terminal_impact_hop(candidate):
        return "candidate does not end in a concrete impact transition"

    return None


def _public_entrypoint_seeds(payload: dict[str, Any]) -> set[str]:
    entrypoints = payload.get("public_entrypoints", [])
    if not isinstance(entrypoints, list):
        return set()
    return {
        entrypoint["id"]
        for entrypoint in entrypoints
        if isinstance(entrypoint, dict)
        and isinstance(entrypoint.get("id"), str)
        and entrypoint.get("attack_path_seed") is True
    }


def _public_endpoint_only_reachability(candidate: AttackCandidate) -> bool:
    if candidate.starting_position.type != "public_endpoint":
        return False

    weak_actions = {
        "execute-api:Invoke",
        "lambda:InvokeFunctionUrl",
        "tcp:Connect",
        "dns:Resolve",
    }
    return all(
        hop.transition == "invoke" or hop.action in weak_actions
        for hop in candidate.hops
    )


def _single_hop_reaches_complete_impact(candidate: AttackCandidate) -> bool:
    hop = candidate.hops[0]
    starts_from_external_control = (
        candidate.starting_position.type in {"external", "public_endpoint"}
        or hop.from_context.startswith("external:")
    )
    return (
        starts_from_external_control
        and hop.transition in {"resource_policy_access", "data_access", "decrypt", "invoke"}
        and hop.action == candidate.impact.action
        and hop.target == candidate.impact.resource
        and hop.resulting_context != hop.from_context
    )


def _has_attacker_progression(candidate: AttackCandidate) -> bool:
    return any(
        hop.resulting_context != hop.from_context
        or hop.target not in {hop.from_context, hop.resulting_context}
        or hop.transition
        in {
            "invoke",
            "execute_as",
            "assume_role",
            "pass_role",
            "create_compute",
            "mutate_policy",
            "resource_policy_access",
            "event_injection",
            "authenticate",
        }
        for hop in candidate.hops
    )


def _has_terminal_impact_hop(candidate: AttackCandidate) -> bool:
    if not candidate.hops:
        return False
    hop = candidate.hops[-1]
    impact_transitions = {
        "data_access",
        "decrypt",
        "mutate_policy",
        "create_compute",
        "pass_role",
        "resource_policy_access",
        "event_injection",
    }
    return (
        hop.transition in impact_transitions
        or (
            hop.action == candidate.impact.action
            and hop.target == candidate.impact.resource
        )
    )


def _invalid_graph_edge_evidence(
    evidence: list[Any],
    graph_edges: dict[str, dict[str, Any]],
    hop: Any,
    current_context: str,
) -> bool:
    graph_edge_refs = [item for item in evidence if item.type == "graph_edge"]
    if not graph_edge_refs:
        return True

    for evidence_ref in graph_edge_refs:
        if evidence_ref.id is None:
            return True
        edge = graph_edges.get(evidence_ref.id)
        if edge is None:
            return True
        if not _edge_matches_hop(edge, hop, current_context):
            return True
    return False


def _uncontrolled_external_assume_role(candidate: AttackCandidate, hop: Any) -> bool:
    if hop.transition != "assume_role":
        return False
    if not str(hop.from_context).startswith("external:"):
        return False
    control_text = " ".join(
        [
            *[str(item) for item in hop.assumptions],
            *[str(item) for item in candidate.initial_context.capabilities],
        ]
    ).lower()
    controlled_markers = {
        "operator-controlled external principal",
        "controlled external principal",
        "controlled by the operator",
        "operator controls",
    }
    return not any(marker in control_text for marker in controlled_markers)


def _policies_for_context(
    principal_policies: dict[str, list[dict[str, Any]]],
    *contexts: str,
) -> list[dict[str, Any]]:
    for context in contexts:
        for key in _principal_policy_keys(context):
            if key in principal_policies:
                return principal_policies[key]
    return []


def _evaluate_permission_boundary(
    permission_boundary_policies: dict[str, list[dict[str, Any]]],
    permission_boundary_presence: set[str],
    *contexts: str,
    action: str,
    resource: str,
) -> PolicyDecision | None:
    boundary_policies = _policies_for_context(permission_boundary_policies, *contexts)
    if boundary_policies:
        return _evaluate_hop_policy(boundary_policies, action=action, resource=resource)
    if _context_has_permission_boundary(permission_boundary_presence, *contexts):
        return PolicyDecision(
            "unknown",
            caveats=[f"permission boundary document missing for {_first_context_key(*contexts)}"],
        )
    return None


def _context_has_permission_boundary(
    permission_boundary_presence: set[str],
    *contexts: str,
) -> bool:
    return any(
        key in permission_boundary_presence
        for context in contexts
        for key in _principal_policy_keys(context)
    )


def _first_context_key(*contexts: str) -> str:
    for context in contexts:
        keys = _principal_policy_keys(context)
        if keys:
            return keys[0]
    return "unknown"


def _principal_policy_keys(context: str) -> list[str]:
    keys = [context]
    if context.startswith("principal:"):
        stripped = context.removeprefix("principal:")
        keys.append(stripped)
        if ":user/" in stripped:
            keys.append(f"user:{stripped.rsplit('/', 1)[-1]}")
        elif ":role/" in stripped:
            keys.append(f"role:{stripped.rsplit('/', 1)[-1]}")
        elif ":group/" in stripped:
            keys.append(f"group:{stripped.rsplit('/', 1)[-1]}")
    return keys


def _evaluate_hop_policy(
    policies: list[dict[str, Any]], *, action: str, resource: str
) -> PolicyDecision:
    actions = _required_actions(action)
    decisions = [
        evaluate_policy_documents(policies, action=required_action, resource=resource)
        for required_action in actions
    ]
    if all(decision.decision == "allowed" for decision in decisions):
        return decisions[0]
    for decision in decisions:
        if decision.decision in {"explicit_deny", "implicit_deny"}:
            return decision
    caveats = [
        caveat
        for decision in decisions
        for caveat in (
            decision.caveats
            or [f"IAM policy evaluation returned {decision.decision} for {action}"]
        )
    ]
    return PolicyDecision("conditional", caveats=caveats)


def _evaluate_kms_dependency(
    graph_edges: dict[str, dict[str, Any]],
    graph_nodes: dict[str, dict[str, Any]],
    resource_policies: dict[str, list[dict[str, Any]]],
    kms_grants: dict[str, list[dict[str, Any]]],
    policies: list[dict[str, Any]],
    *,
    action: str,
    resource: str,
    principal_context: str,
    account_id: str,
) -> PolicyDecision | None:
    source_nodes = _kms_dependency_source_nodes(action, resource, graph_nodes)
    if not source_nodes:
        return None

    kms_edges = [
        edge
        for edge in graph_edges.values()
        if edge.get("edge_type") == "encrypted_by"
        and str(edge.get("relationship") or "").endswith("_encrypted_by_kms_key")
        and edge.get("source") in source_nodes
    ]
    if not kms_edges:
        return None

    via_service = _kms_via_service_name(action)
    decisions: list[PolicyDecision] = []
    for edge in kms_edges:
        key_resource = _kms_resource_for_edge(edge, graph_nodes)
        if key_resource is None:
            return PolicyDecision(
                "unknown",
                caveats=[f"KMS key target is missing or unresolved for {edge.get('source')}"],
            )
        identity_decision = _evaluate_hop_policy(policies, action="kms:Decrypt", resource=key_resource)
        key_policy_decision = _evaluate_kms_key_policy_dependency(
            resource_policies,
            graph_nodes,
            key_resource=key_resource,
            key_node_id=str(edge.get("target") or ""),
            principal_context=principal_context,
            source_resource=resource,
            account_id=account_id,
            identity_decision=identity_decision,
            via_service=via_service,
        )
        grant_decision = _evaluate_kms_grant_dependency(
            kms_grants,
            graph_nodes,
            key_resource=key_resource,
            key_node_id=str(edge.get("target") or ""),
            principal_context=principal_context,
            account_id=account_id,
        )
        decisions.append(
            _combine_kms_authorization_decisions(
                identity_decision,
                key_policy_decision,
                grant_decision,
            )
        )

    if all(decision.decision == "allowed" for decision in decisions):
        return PolicyDecision("allowed")
    for decision in decisions:
        if decision.decision in {"explicit_deny", "implicit_deny"}:
            return decision
    caveats = [
        caveat
        for decision in decisions
        for caveat in (
            decision.caveats
            or [f"KMS policy evaluation returned {decision.decision} for kms:Decrypt"]
        )
    ]
    return PolicyDecision("conditional", caveats=caveats)


def _evaluate_kms_key_policy_dependency(
    resource_policies: dict[str, list[dict[str, Any]]],
    graph_nodes: dict[str, dict[str, Any]],
    *,
    key_resource: str,
    key_node_id: str,
    principal_context: str,
    source_resource: str,
    account_id: str,
    identity_decision: PolicyDecision,
    via_service: str | None,
) -> PolicyDecision:
    statements = _resource_policies_for_target(resource_policies, key_resource)
    if not statements and key_node_id:
        statements = _resource_policies_for_target(resource_policies, key_node_id)
    if not statements:
        return PolicyDecision(
            "unknown",
            caveats=[f"KMS key policy unavailable for {key_resource}"],
        )

    candidates = _kms_policy_principal_candidates(
        principal_context,
        graph_nodes,
        account_id,
    )
    direct_candidates = [candidate for candidate in candidates if not candidate.endswith(":root")]
    root_candidates = [candidate for candidate in candidates if candidate.endswith(":root")]
    via_services = _kms_via_services_for_key(key_resource, via_service) if via_service else set()

    direct_decisions = [
        _evaluate_resource_policy_hop(
            statements,
            principal=principal,
            action="kms:Decrypt",
            resource=key_resource,
            source_arns=_kms_source_arns(source_resource),
            source_accounts=_kms_source_accounts(source_resource, account_id),
            kms_via_services=via_services,
            lambda_function_url_auth_type=None,
            lambda_invoked_via_function_url=None,
        )
        for principal in direct_candidates
    ]
    root_decisions = [
        _evaluate_resource_policy_hop(
            statements,
            principal=principal,
            action="kms:Decrypt",
            resource=key_resource,
            source_arns=_kms_source_arns(source_resource),
            source_accounts=_kms_source_accounts(source_resource, account_id),
            kms_via_services=via_services,
            lambda_function_url_auth_type=None,
            lambda_invoked_via_function_url=None,
        )
        for principal in root_candidates
    ]
    decisions = [*direct_decisions, *root_decisions]

    for decision in decisions:
        if decision.decision == "explicit_deny":
            return decision
    if any(decision.decision == "allowed" for decision in direct_decisions):
        return PolicyDecision("allowed")
    for decision in direct_decisions:
        if decision.decision in {"conditional", "unknown"}:
            return decision
    if any(decision.decision == "allowed" for decision in root_decisions):
        if identity_decision.decision == "allowed":
            return PolicyDecision("allowed")
        if identity_decision.decision in {"conditional", "unknown"}:
            return PolicyDecision(
                "conditional",
                caveats=identity_decision.caveats
                or ["KMS account-root delegation depends on conditional identity kms:Decrypt authorization"],
            )
        return PolicyDecision(
            "implicit_deny",
            caveats=["KMS account-root delegation requires identity kms:Decrypt authorization"],
        )
    for decision in root_decisions:
        if decision.decision in {"conditional", "unknown"}:
            return decision
    return PolicyDecision(
        "implicit_deny",
        caveats=[f"KMS key policy does not allow {principal_context} to decrypt {key_resource}"],
    )


def _evaluate_kms_grant_dependency(
    kms_grants: dict[str, list[dict[str, Any]]],
    graph_nodes: dict[str, dict[str, Any]],
    *,
    key_resource: str,
    key_node_id: str,
    principal_context: str,
    account_id: str,
) -> PolicyDecision:
    grants = _kms_grants_for_key(kms_grants, key_resource, key_node_id)
    if not grants:
        return PolicyDecision("implicit_deny")
    principal_candidates = set(
        _kms_policy_principal_candidates(principal_context, graph_nodes, account_id)
    )
    conditional_caveats: list[str] = []
    for grant in grants:
        grantee = grant.get("grantee_principal")
        if not isinstance(grantee, str) or grantee not in principal_candidates:
            continue
        operations = {str(operation).lower() for operation in grant.get("operations") or []}
        if "decrypt" not in operations and "kms:decrypt" not in operations and "*" not in operations:
            continue
        constraints = grant.get("constraints")
        if isinstance(constraints, dict) and constraints:
            conditional_caveats.append(
                f"KMS grant {grant.get('grant_id') or grantee} has encryption context constraints"
            )
            continue
        return PolicyDecision("allowed")
    if conditional_caveats:
        return PolicyDecision("conditional", caveats=conditional_caveats)
    return PolicyDecision("implicit_deny")


def _kms_grants_for_key(
    kms_grants: dict[str, list[dict[str, Any]]],
    key_resource: str,
    key_node_id: str,
) -> list[dict[str, Any]]:
    for key in [key_resource, key_node_id, key_node_id.removeprefix("data:kms:")]:
        if key and key in kms_grants:
            return kms_grants[key]
    return []


def _combine_kms_authorization_decisions(
    identity_decision: PolicyDecision,
    key_policy_decision: PolicyDecision,
    grant_decision: PolicyDecision,
) -> PolicyDecision:
    if identity_decision.decision == "explicit_deny":
        return identity_decision
    if key_policy_decision.decision == "explicit_deny":
        return key_policy_decision
    if grant_decision.decision == "allowed" or key_policy_decision.decision == "allowed":
        return PolicyDecision("allowed")
    if grant_decision.decision in {"conditional", "unknown"}:
        return grant_decision
    if key_policy_decision.decision in {"conditional", "unknown"}:
        return key_policy_decision
    return key_policy_decision


def _kms_dependency_source_nodes(
    action: str,
    resource: str,
    graph_nodes: dict[str, dict[str, Any]],
) -> set[str]:
    normalized_action = action.lower()
    if normalized_action == "s3:getobject":
        bucket_node = _s3_bucket_node_id(resource)
        return {bucket_node} if bucket_node else set()
    if normalized_action == "secretsmanager:getsecretvalue":
        if resource.startswith("data:secrets:"):
            return {resource}
        return {
            node_id
            for node_id, node in graph_nodes.items()
            if node_id.startswith("data:secrets:")
            and isinstance(node, dict)
            and node.get("arn") == resource
        }
    if normalized_action in {"ssm:getparameter", "ssm:getparameters"}:
        if resource.startswith("data:ssm:"):
            return {resource}
        return {
            node_id
            for node_id, node in graph_nodes.items()
            if node_id.startswith("data:ssm:")
            and isinstance(node, dict)
            and node.get("arn") == resource
        }
    return set()


def _kms_policy_principal_candidates(
    principal_context: str,
    graph_nodes: dict[str, dict[str, Any]],
    account_id: str,
) -> list[str]:
    candidates = [principal_context]
    node = graph_nodes.get(principal_context)
    arn = node.get("arn") if isinstance(node, dict) else None
    if isinstance(arn, str) and arn:
        candidates.append(arn)
        account = _account_id_from_arn(arn)
        if account:
            candidates.append(f"arn:aws:iam::{account}:root")
    if principal_context.startswith("principal:"):
        stripped = principal_context.removeprefix("principal:")
        candidates.append(stripped)
        account = _account_id_from_arn(stripped)
        if account:
            candidates.append(f"arn:aws:iam::{account}:root")
    elif account_id:
        candidates.append(f"arn:aws:iam::{account_id}:root")
    return list(dict.fromkeys(candidate for candidate in candidates if candidate))


def _kms_source_arns(source_resource: str) -> set[str]:
    values = {source_resource}
    if source_resource.startswith("arn:aws:s3:::"):
        bucket = source_resource.removeprefix("arn:aws:s3:::").split("/", 1)[0]
        if bucket:
            values.add(f"arn:aws:s3:::{bucket}")
    return values


def _kms_source_accounts(source_resource: str, account_id: str) -> set[str]:
    accounts = {account_id} if account_id else set()
    account = _account_id_from_arn(source_resource)
    if account:
        accounts.add(account)
    return accounts


def _kms_via_service_name(action: str) -> str | None:
    normalized_action = action.lower()
    if normalized_action == "s3:getobject":
        return "s3"
    elif normalized_action == "secretsmanager:getsecretvalue":
        return "secretsmanager"
    elif normalized_action in {"ssm:getparameter", "ssm:getparameters"}:
        return "ssm"
    return None


def _kms_via_services_for_key(key_resource: str, service: str | None) -> set[str]:
    if not service:
        return set()
    parts = key_resource.split(":")
    if len(parts) > 3 and parts[0] == "arn" and parts[2] == "kms":
        region = parts[3]
        if region:
            return {f"{service}.{region}.amazonaws.com"}
    return set()


def _s3_bucket_node_id(resource: str) -> str | None:
    if resource.startswith("data:s3:"):
        return resource
    prefix = "arn:aws:s3:::"
    if not resource.startswith(prefix):
        return None
    bucket = resource.removeprefix(prefix).split("/", 1)[0]
    if not bucket:
        return None
    return f"data:s3:{bucket}"


def _kms_resource_for_edge(edge: dict[str, Any], graph_nodes: dict[str, dict[str, Any]]) -> str | None:
    target = edge.get("target")
    if not isinstance(target, str) or not target:
        return None
    node = graph_nodes.get(target)
    arn = node.get("arn") if isinstance(node, dict) else None
    if isinstance(arn, str) and arn:
        return arn
    if target.startswith("data:kms:"):
        return target.removeprefix("data:kms:")
    return target


def _resource_policies_for_target(
    resource_policies: dict[str, list[dict[str, Any]]],
    target: str,
) -> list[dict[str, Any]]:
    keys = [target]
    if target.startswith("resource:"):
        keys.append(target.removeprefix("resource:"))
    if target.startswith("messaging:sns:"):
        keys.append(target.removeprefix("messaging:sns:"))
    elif target.startswith("messaging:sqs:"):
        keys.append(target.removeprefix("messaging:sqs:"))
    elif target.startswith("data:secrets:"):
        keys.append(target.removeprefix("data:secrets:"))
    elif target.startswith("data:kms:"):
        keys.append(target.removeprefix("data:kms:"))
    elif target.startswith("data:dynamodb:"):
        keys.append(target.removeprefix("data:dynamodb:"))
    elif target.startswith("data:ssm:"):
        keys.append(target.removeprefix("data:ssm:"))
    elif target.startswith("data:s3:"):
        keys.append(target.removeprefix("data:s3:"))

    for key in keys:
        if key in resource_policies:
            return resource_policies[key]
    return []


def _evaluate_resource_policy_hop(
    statements: list[dict[str, Any]],
    *,
    principal: str,
    action: str,
    resource: str,
    source_arns: set[str],
    source_accounts: set[str],
    kms_via_services: set[str],
    lambda_function_url_auth_type: str | None,
    lambda_invoked_via_function_url: bool | None,
) -> PolicyDecision:
    matched_allow: list[dict[str, Any]] = []
    conditional_allow: list[dict[str, Any]] = []
    matched_deny: list[dict[str, Any]] = []
    caveats: list[str] = []

    for statement in statements:
        if not isinstance(statement, dict):
            caveats.append(f"Malformed resource policy statement: {type(statement).__name__}")
            continue
        if not _resource_policy_statement_principal_matches(statement, principal):
            continue
        if not _patterns_match(statement.get("normalized_actions"), action, case_sensitive=False):
            continue
        if not _patterns_match_any(statement.get("normalized_resources"), _resource_match_values(resource), case_sensitive=True):
            continue

        effect = str(statement.get("effect", "")).lower()
        if effect == "deny":
            condition_decision = _resource_policy_condition_decision(
                statement,
                source_arns=source_arns,
                source_accounts=source_accounts,
                kms_via_services=kms_via_services,
                lambda_function_url_auth_type=lambda_function_url_auth_type,
                lambda_invoked_via_function_url=lambda_invoked_via_function_url,
            )
            if condition_decision == "not_applicable":
                continue
            matched_deny.append(statement)
            if condition_decision == "conditional":
                caveats.append(_resource_policy_condition_caveat(statement, "Deny"))
                return PolicyDecision("conditional", matched_deny=matched_deny, caveats=caveats)
            return PolicyDecision("explicit_deny", matched_deny=matched_deny)
        if effect == "allow":
            condition_decision = _resource_policy_condition_decision(
                statement,
                source_arns=source_arns,
                source_accounts=source_accounts,
                kms_via_services=kms_via_services,
                lambda_function_url_auth_type=lambda_function_url_auth_type,
                lambda_invoked_via_function_url=lambda_invoked_via_function_url,
            )
            if condition_decision == "not_applicable":
                continue
            matched_allow.append(statement)
            if condition_decision == "conditional":
                conditional_allow.append(statement)
                caveats.append(_resource_policy_condition_caveat(statement, "Allow"))

    if matched_deny:
        return PolicyDecision("explicit_deny", matched_allow=matched_allow, matched_deny=matched_deny)
    if conditional_allow:
        return PolicyDecision("conditional", matched_allow=matched_allow, caveats=caveats)
    if matched_allow:
        return PolicyDecision("allowed", matched_allow=matched_allow)
    if caveats:
        return PolicyDecision("unknown", caveats=caveats)
    return PolicyDecision("implicit_deny")


def _resource_policy_condition_decision(
    statement: dict[str, Any],
    *,
    source_arns: set[str],
    source_accounts: set[str],
    kms_via_services: set[str],
    lambda_function_url_auth_type: str | None,
    lambda_invoked_via_function_url: bool | None,
) -> str:
    condition = statement.get("condition")
    if not condition:
        return "allowed"

    required_source_arns = _condition_values(statement, "aws:sourcearn")
    required_source_accounts = [
        *_condition_values(statement, "aws:sourceaccount"),
        *_condition_values(statement, "aws:sourceowner"),
    ]
    required_kms_via_services = _condition_values(statement, "kms:viaservice")
    required_lambda_auth_types = _condition_values(statement, "lambda:functionurlauthtype")
    required_lambda_invoked_via_url = _condition_values(statement, "lambda:invokedviafunctionurl")

    if required_source_arns and not _any_pattern_matches(required_source_arns, source_arns):
        return "not_applicable"
    if required_source_accounts and not _any_pattern_matches(required_source_accounts, source_accounts):
        return "not_applicable"
    if required_kms_via_services and not _any_pattern_matches(required_kms_via_services, kms_via_services):
        return "not_applicable"
    if required_lambda_auth_types:
        if lambda_function_url_auth_type is None:
            return "conditional"
        if not _any_pattern_matches(required_lambda_auth_types, {lambda_function_url_auth_type}):
            return "not_applicable"
    if required_lambda_invoked_via_url:
        if lambda_invoked_via_function_url is None:
            return "conditional"
        invoked_value = "true" if lambda_invoked_via_function_url else "false"
        if not _any_pattern_matches(required_lambda_invoked_via_url, {invoked_value}):
            return "not_applicable"

    if (
        required_source_arns
        or required_source_accounts
        or required_kms_via_services
        or required_lambda_auth_types
        or required_lambda_invoked_via_url
    ):
        if _only_supported_resource_conditions(condition):
            return "allowed"
        return "conditional"

    return "conditional"


def _resource_policy_condition_caveat(statement: dict[str, Any], effect: str) -> str:
    condition = statement.get("condition")
    if _condition_values(statement, "lambda:functionurlauthtype"):
        return f"Lambda Function URL auth type context missing or unsupported for matching {effect} statement: {condition}"
    return f"Condition present on matching {effect} statement: {condition}"


def _condition_values(statement: dict[str, Any], wanted_key: str) -> list[str]:
    values: list[str] = []
    explicit_values = statement.get("source_arns") if wanted_key == "aws:sourcearn" else None
    if wanted_key in {"aws:sourceaccount", "aws:sourceowner"}:
        explicit_values = statement.get("source_accounts")
    values.extend(_string_values(explicit_values))

    condition = statement.get("condition")
    if not isinstance(condition, dict):
        return values
    for operator_values in condition.values():
        if not isinstance(operator_values, dict):
            continue
        for key, raw_value in operator_values.items():
            if str(key).lower() == wanted_key:
                values.extend(_string_values(raw_value))
    return list(dict.fromkeys(values))


def _only_supported_resource_conditions(condition: Any) -> bool:
    if not isinstance(condition, dict):
        return False
    supported_keys = {
        "aws:sourcearn",
        "aws:sourceaccount",
        "aws:sourceowner",
        "kms:viaservice",
        "lambda:functionurlauthtype",
        "lambda:invokedviafunctionurl",
    }
    supported_operators = {
        "arnequals",
        "arnlike",
        "stringequals",
        "stringlike",
    }
    for operator, operator_values in condition.items():
        if str(operator).lower() not in supported_operators:
            return False
        if not isinstance(operator_values, dict):
            return False
        for key in operator_values:
            if str(key).lower() not in supported_keys:
                return False
    return True


def _string_values(raw_value: Any) -> list[str]:
    if isinstance(raw_value, str):
        return [raw_value]
    if isinstance(raw_value, list):
        return [str(item) for item in raw_value if isinstance(item, str)]
    return []


def _any_pattern_matches(patterns: list[str], values: set[str]) -> bool:
    return any(
        fnmatchcase(value, pattern)
        for pattern in patterns
        for value in values
    )


def _source_arns_for_hop(candidate: AttackCandidate, hop: Any, current_context: str) -> set[str]:
    values = {
        str(value)
        for value in [
            candidate.starting_position.arn,
            candidate.starting_position.id,
            candidate.initial_context.principal,
            hop.from_context,
            current_context,
        ]
        if isinstance(value, str) and value
    }
    arns: set[str] = set()
    for value in values:
        if value.startswith("arn:"):
            arns.add(value)
        if value.startswith("data:s3:"):
            bucket = value.removeprefix("data:s3:")
            arns.add(f"arn:aws:s3:::{bucket}")
    return arns


def _source_accounts_for_hop(
    candidate: AttackCandidate,
    hop: Any,
    current_context: str,
    account_id: str,
) -> set[str]:
    accounts = (
        {account_id}
        if account_id and candidate.starting_position.type == "resource"
        else set()
    )
    for value in [
        candidate.starting_position.arn,
        candidate.starting_position.id,
        candidate.initial_context.principal,
        hop.from_context,
        current_context,
    ]:
        if isinstance(value, str):
            account = _account_id_from_arn(value)
            if account:
                accounts.add(account)
    return accounts


def _lambda_function_url_auth_type_for_target(
    lambda_function_url_auth_types: dict[str, str],
    target: str,
) -> str | None:
    for key in _lambda_target_keys(target):
        value = lambda_function_url_auth_types.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _lambda_target_keys(target: str) -> list[str]:
    keys = [target]
    if target.startswith("compute:lambda:"):
        keys.append(target.removeprefix("compute:lambda:"))
    if ":function:" in target:
        function_name = target.split(":function:", 1)[1].split(":", 1)[0]
        keys.extend([function_name, f"compute:lambda:{function_name}"])
    return list(dict.fromkeys(keys))


def _lambda_invoked_via_function_url(action: str) -> bool | None:
    normalized = action.lower()
    if normalized == "lambda:invokefunctionurl":
        return True
    if normalized == "lambda:invokefunction":
        return False
    return None


def _account_id_from_arn(value: str) -> str | None:
    if not value.startswith("arn:"):
        return None
    parts = value.split(":", 5)
    if len(parts) < 5:
        return None
    account_id = parts[4]
    return account_id if account_id.isdigit() and len(account_id) == 12 else None


def _resource_policy_statement_principal_matches(statement: dict[str, Any], principal: str) -> bool:
    principals = statement.get("normalized_principals")
    if not isinstance(principals, list):
        return False
    principal_keys = _principal_match_keys(principal)
    return any(str(candidate) in principal_keys for candidate in principals)


def _principal_match_keys(principal: str) -> set[str]:
    keys = {principal, "*"}
    if principal.startswith("svc:"):
        keys.add(principal.removeprefix("svc:"))
    if principal.startswith("external:"):
        stripped = principal.removeprefix("external:")
        keys.add(stripped)
        if ":role/" in stripped:
            keys.add(stripped.rsplit("/", 1)[-1])
        elif ":user/" in stripped:
            keys.add(stripped.rsplit("/", 1)[-1])
    if principal.startswith("principal:"):
        stripped = principal.removeprefix("principal:")
        keys.add(stripped)
    return keys


def _required_actions(action: str) -> list[str]:
    actions = [part.strip() for part in action.split("+") if part.strip()]
    return actions or [action]


def _patterns_match(patterns: Any, value: str, *, case_sensitive: bool) -> bool:
    return _patterns_match_any(patterns, [value], case_sensitive=case_sensitive)


def _patterns_match_any(patterns: Any, values: list[str], *, case_sensitive: bool) -> bool:
    if isinstance(patterns, str):
        normalized_patterns = [patterns]
    elif isinstance(patterns, list):
        normalized_patterns = [str(pattern) for pattern in patterns]
    else:
        return False

    comparable_values = values if case_sensitive else [value.lower() for value in values]
    for pattern in normalized_patterns:
        comparable_pattern = pattern if case_sensitive else pattern.lower()
        for comparable_value in comparable_values:
            if fnmatchcase(comparable_value, comparable_pattern):
                return True
    return False


def _resource_match_values(resource: str) -> list[str]:
    values = [resource]
    if resource.startswith("data:s3:"):
        bucket = resource.removeprefix("data:s3:")
        values.extend([f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"])
    return values


def _edge_matches_hop(edge: dict[str, Any], hop: Any, current_context: str) -> bool:
    if _is_generic_resource_policy_edge(edge):
        return False

    if _is_resource_policy_statement_edge(edge) and not _resource_policy_statement_matches_hop(edge, hop):
        return False

    source = edge.get("source")
    target = edge.get("target")
    source_matches = source in {hop.from_context, current_context}
    target_matches = target in {hop.target, hop.resulting_context}
    if (
        hop.transition == "execute_as"
        and target_matches
        and isinstance(source, str)
        and source == _service_source_from_action(hop.action)
    ):
        return True
    return source_matches and target_matches


def _is_generic_resource_policy_edge(edge: dict[str, Any]) -> bool:
    return (
        edge.get("edge_type") == "resource_policy_allows"
        or edge.get("relationship") == "resource_policy_allows"
    )


def _is_resource_policy_statement_edge(edge: dict[str, Any]) -> bool:
    return edge.get("edge_type") == "resource_policy_statement"


def _resource_policy_statement_matches_hop(edge: dict[str, Any], hop: Any) -> bool:
    if edge.get("conditions"):
        return False
    actions = edge.get("actions")
    if not isinstance(actions, list):
        return False
    return any(_action_matches(str(pattern), hop.action) for pattern in actions)


def _action_matches(pattern: str, action: str) -> bool:
    return fnmatchcase(action.lower(), pattern.lower())


def _service_source_from_action(action: str) -> str | None:
    marker = " by "
    if marker not in action:
        return None
    service = action.rsplit(marker, 1)[-1].strip()
    if not service:
        return None
    return f"svc:{service}"


def _promote_candidate(
    candidate: AttackCandidate, validation: AttackValidation
) -> dict[str, Any]:
    final_path = FinalAttackPath(
        id=_final_path_id(candidate.id),
        source_candidate_id=candidate.id,
        validation_status=validation.status,
        name=candidate.name,
        severity=candidate.severity,
        category=candidate.category,
        description=(
            f"{candidate.name}: {candidate.impact.action} on "
            f"{candidate.impact.resource}."
        ),
        hops=candidate.hops,
        runtime_assumptions=validation.runtime_assumptions,
        coverage_caveats=validation.coverage_caveats,
        affected_resources=candidate.affected_resources,
        detection_opportunities=candidate.detection_opportunities,
        mitre_techniques=candidate.mitre_techniques,
        remediation=candidate.remediation,
    )
    return final_path.model_dump(mode="json")


def _final_path_id(candidate_id: str) -> str:
    if candidate_id.startswith("cap-"):
        return candidate_id.replace("cap-", "ap-", 1)
    return f"ap-{candidate_id}"


def _group_key(path: dict[str, Any]) -> tuple[str, str, str, str, str]:
    terminal = _terminal_hop(path)
    return (
        str(path.get("category", "")),
        _path_primitive(path),
        _impact_role_context(path),
        str(terminal.get("action", "")),
        str(terminal.get("target", "")),
    )


def _terminal_hop(path: dict[str, Any]) -> dict[str, Any]:
    hops = path.get("hops")
    if isinstance(hops, list) and hops and isinstance(hops[-1], dict):
        return hops[-1]
    return {}


def _path_primitive(path: dict[str, Any]) -> str:
    hops = [hop for hop in path.get("hops", []) if isinstance(hop, dict)]
    for hop in hops:
        if hop.get("transition") == "pass_role":
            service = _service_from_passrole_path(hops)
            return f"pass_role:{service}" if service else "pass_role"
    for hop in hops:
        if hop.get("transition") == "assume_role":
            return "assume_role"
    for hop in hops:
        if hop.get("transition") == "resource_policy_access":
            return "resource_policy_access"
    for hop in hops:
        if hop.get("transition") == "invoke":
            return "public_invoke"
    return str(hops[0].get("transition", "unknown")) if hops else "unknown"


def _service_from_passrole_path(hops: list[dict[str, Any]]) -> str | None:
    for hop in hops:
        action = str(hop.get("action", ""))
        service = _service_from_execute_as_action(action)
        if service:
            return service
    for hop in hops:
        context = str(hop.get("resulting_context", ""))
        marker = "resource:"
        suffix = "-execution-with-"
        if context.startswith(marker) and suffix in context:
            return context.removeprefix(marker).split(suffix, 1)[0]
    return None


def _service_from_execute_as_action(action: str) -> str | None:
    marker = " by "
    if marker not in action:
        return None
    service = action.rsplit(marker, 1)[-1].strip()
    return service.split(".", 1)[0] if service else None


def _impact_role_context(path: dict[str, Any]) -> str:
    terminal = _terminal_hop(path)
    from_context = str(terminal.get("from_context", ""))
    if from_context:
        return from_context
    return str(terminal.get("resulting_context", ""))


def _source_principal(path: dict[str, Any]) -> str | None:
    hops = [hop for hop in path.get("hops", []) if isinstance(hop, dict)]
    if hops and isinstance(hops[0].get("from_context"), str):
        return hops[0]["from_context"]
    starting = path.get("starting_position")
    if isinstance(starting, dict) and isinstance(starting.get("id"), str):
        return starting["id"]
    return None


def _leveraging_assets(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for path in paths:
        source = _source_principal(path)
        if not source:
            continue
        path_id = str(path.get("id", ""))
        if not path_id:
            continue
        asset = by_id.setdefault(
            source,
            {
                "id": source,
                "type": _asset_type(source),
                "arn": _source_arn(source, path),
                "path_ids": [],
            },
        )
        if asset.get("arn") is None:
            asset["arn"] = _source_arn(source, path)
        asset["path_ids"].append(path_id)
    return [
        {
            **asset,
            "path_ids": sorted(set(asset["path_ids"])),
        }
        for _, asset in sorted(by_id.items(), key=lambda item: item[0])
    ]


def _asset_type(source: str) -> str:
    if source.startswith("user:"):
        return "user"
    if source.startswith("role:") or ":role/" in source:
        return "role"
    if source.startswith("external:"):
        return "external"
    if source.startswith("resource:"):
        return "resource"
    return "unknown"


def _source_arn(source: str, path: dict[str, Any]) -> str | None:
    if source.startswith("principal:arn:"):
        return source.removeprefix("principal:")
    if source.startswith("arn:"):
        return source
    source_name = source.split(":", 1)[-1]
    source_type = _asset_type(source)
    for resource in path.get("affected_resources", []):
        if not isinstance(resource, str) or not resource.startswith("arn:"):
            continue
        if source_type == "user" and f":user/{source_name}" in resource:
            return resource
        if source_type == "role" and f":role/{source_name}" in resource:
            return resource
    return None


def _path_sort_key(path: dict[str, Any]) -> tuple[int, str]:
    return (_severity_rank(str(path.get("severity", "low"))), str(path.get("id", "")))


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(severity, 4)


def _group_name(primitive: str, terminal: dict[str, Any], paths: list[dict[str, Any]]) -> str:
    target = _display_target(str(terminal.get("from_context") or terminal.get("target") or "impact"))
    action = str(terminal.get("action", "impact"))
    if len(paths) == 1:
        return str(paths[0].get("name", f"{primitive} to {action}"))
    return f"{len(paths)} paths via {primitive} to {target} for {action}"


def _group_description(
    primitive: str, terminal: dict[str, Any], paths: list[dict[str, Any]]
) -> str:
    principals = {
        principal
        for path in paths
        if (principal := _source_principal(path))
    }
    action = str(terminal.get("action", "impact"))
    target = _display_target(str(terminal.get("from_context") or terminal.get("target") or "impact"))
    return (
        f"{len(paths)} validated or conditional attack paths use {primitive} "
        f"from {len(principals)} starting principals to reach {action} through {target}."
    )


def _display_target(value: str) -> str:
    if value.startswith("principal:"):
        value = value.removeprefix("principal:")
    if "/" in value:
        return value.rsplit("/", 1)[-1]
    if ":" in value:
        return value.rsplit(":", 1)[-1]
    return value
