from __future__ import annotations

from copy import deepcopy
from typing import Any

from scope.attack.policy_eval import evaluate_policy_documents
from scope.attack.schema import AttackCandidate, AttackValidation, FinalAttackPath
from scope.attack.validate_graph import graph_edges_by_id


def validate_candidates(
    payload: dict[str, Any],
    *,
    principal_policies: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    policies_by_principal = principal_policies or {}
    graph_edges = graph_edges_by_id(payload.get("graph") or {})
    public_entrypoint_seeds = _public_entrypoint_seeds(payload)
    validations: list[dict[str, Any]] = []
    final_paths: list[dict[str, Any]] = []

    for raw_candidate in payload.get("candidate_attack_paths", []):
        candidate = AttackCandidate.model_validate(raw_candidate)
        validation = _validate_candidate(
            candidate,
            graph_edges=graph_edges,
            principal_policies=policies_by_principal,
            public_entrypoint_seeds=public_entrypoint_seeds,
        )
        validations.append(validation.model_dump(mode="json"))
        if validation.promotion_decision == "promote":
            final_paths.append(_promote_candidate(candidate, validation))

    result = deepcopy(payload)
    result["attack_validation"] = validations
    result["attack_paths"] = final_paths
    return result


def _validate_candidate(
    candidate: AttackCandidate,
    *,
    graph_edges: dict[str, dict[str, Any]],
    principal_policies: dict[str, list[dict[str, Any]]],
    public_entrypoint_seeds: set[str],
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
            if _invalid_graph_edge_evidence(hop.evidence, graph_edges, hop, current_context):
                failed_hops.append(hop.id)
            else:
                validated_hops.append(hop.id)
        elif hop.validation_type == "iam":
            if hop.from_context in principal_policies:
                policies = principal_policies[hop.from_context]
            else:
                policies = principal_policies.get(current_context, [])
            if not policies:
                conditional_hops.append(hop.id)
                coverage_caveats.append(
                    f"No collected policy documents for {hop.from_context}"
                )
                current_context = hop.resulting_context
                continue
            decision = evaluate_policy_documents(
                policies, action=hop.action, resource=hop.target
            )
            if decision.decision == "allowed":
                validated_hops.append(hop.id)
            elif decision.decision in {"conditional", "unknown"}:
                conditional_hops.append(hop.id)
                coverage_caveats.extend(
                    decision.caveats
                    or [f"IAM policy evaluation returned {decision.decision} for {hop.id}"]
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

    if not _has_impact_hop(candidate):
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
        }
        for hop in candidate.hops
    )


def _has_impact_hop(candidate: AttackCandidate) -> bool:
    impact_transitions = {
        "data_access",
        "decrypt",
        "mutate_policy",
        "create_compute",
        "pass_role",
        "resource_policy_access",
        "event_injection",
    }
    return any(
        hop.transition in impact_transitions
        or hop.action == candidate.impact.action
        or hop.target == candidate.impact.resource
        for hop in candidate.hops
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


def _edge_matches_hop(edge: dict[str, Any], hop: Any, current_context: str) -> bool:
    source = edge.get("source")
    target = edge.get("target")
    source_matches = source in {hop.from_context, current_context}
    target_matches = target in {hop.target, hop.resulting_context}
    return source_matches and target_matches


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
