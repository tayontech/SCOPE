from __future__ import annotations

import pytest
from pydantic import ValidationError

from scope.attack.schema import (
    AttackCandidate,
    AttackValidation,
    EvidenceRef,
    FinalAttackPath,
    Hop,
    Impact,
)


def test_candidate_accepts_structured_stateful_hops() -> None:
    candidate = AttackCandidate.model_validate(
        {
            "id": "cap-001",
            "name": "Public API reaches Lambda role",
            "category": "data_exposure",
            "severity": "high",
            "starting_position": {
                "type": "public_endpoint",
                "id": "gateway:apigw:api",
                "arn": None,
            },
            "initial_context": {
                "principal": None,
                "capabilities": ["invoke_public_api"],
            },
            "hops": [
                {
                    "id": "cap-001-hop-001",
                    "transition": "invoke",
                    "from_context": "external:*",
                    "action": "execute-api:Invoke",
                    "target": "compute:lambda:handler",
                    "resulting_context": "compute:lambda:handler",
                    "capability_gained": "Attacker can trigger Lambda execution",
                    "required": True,
                    "validation_type": "graph",
                    "evidence": [
                        {
                            "type": "graph_edge",
                            "id": "edge:invokes:gateway:apigw:api->compute:lambda:handler",
                            "source_path": "modules/apigateway/us-east-1.json",
                        }
                    ],
                    "assumptions": [],
                }
            ],
            "impact": {
                "type": "data_access",
                "resource": "arn:aws:s3:::sensitive/*",
                "action": "s3:GetObject",
            },
            "affected_resources": ["arn:aws:s3:::sensitive"],
            "detection_opportunities": ["Invoke", "GetObject"],
            "mitre_techniques": ["T1078.004"],
            "remediation": ["Restrict the public API or remove role S3 access"],
        }
    )

    assert candidate.hops[0].transition == "invoke"
    assert candidate.impact.action == "s3:GetObject"


def test_candidate_rejects_unknown_transition() -> None:
    payload = {
        "id": "cap-001",
        "name": "Bad transition",
        "category": "data_exposure",
        "severity": "high",
        "starting_position": {
            "type": "public_endpoint",
            "id": "gateway:apigw:api",
            "arn": None,
        },
        "initial_context": {"principal": None, "capabilities": []},
        "hops": [
            {
                "id": "cap-001-hop-001",
                "transition": "guess",
                "from_context": "external:*",
                "action": "execute-api:Invoke",
                "target": "compute:lambda:handler",
                "resulting_context": "compute:lambda:handler",
                "capability_gained": "Trigger execution",
                "required": True,
                "validation_type": "graph",
                "evidence": [],
                "assumptions": [],
            }
        ],
        "impact": {
            "type": "data_access",
            "resource": "arn:aws:s3:::sensitive/*",
            "action": "s3:GetObject",
        },
    }

    with pytest.raises(ValidationError):
        AttackCandidate.model_validate(payload)


def test_conditional_final_path_requires_assumption_or_caveat() -> None:
    base = {
        "id": "ap-001",
        "source_candidate_id": "cap-001",
        "validation_status": "conditional",
        "name": "Conditional path",
        "severity": "high",
        "category": "data_exposure",
        "description": "Authorization chain validates, runtime behavior remains unproven.",
        "hops": [
            {
                "id": "cap-001-hop-001",
                "transition": "invoke",
                "from_context": "external:*",
                "action": "execute-api:Invoke",
                "target": "compute:lambda:handler",
                "resulting_context": "compute:lambda:handler",
                "capability_gained": "Trigger execution",
                "required": True,
                "validation_type": "graph",
                "evidence": [
                    {
                        "type": "graph_edge",
                        "id": "edge:invokes:gateway:apigw:api->compute:lambda:handler",
                        "source_path": "modules/apigateway/us-east-1.json",
                    }
                ],
                "assumptions": [],
            }
        ],
        "runtime_assumptions": [],
        "coverage_caveats": [],
        "affected_resources": [],
        "detection_opportunities": [],
        "mitre_techniques": [],
        "remediation": [],
    }

    with pytest.raises(ValidationError):
        FinalAttackPath.model_validate(base)

    base["runtime_assumptions"] = [
        "Lambda code must read the target bucket on the invoked path."
    ]
    assert FinalAttackPath.model_validate(base).validation_status == "conditional"


def test_unknown_extra_field_rejected_on_model() -> None:
    with pytest.raises(ValidationError):
        EvidenceRef.model_validate(
            {
                "type": "graph_edge",
                "id": "edge:invokes:api->lambda",
                "unexpected": "field",
            }
        )


def test_blank_evidence_source_or_hop_action_target_rejected() -> None:
    with pytest.raises(ValidationError):
        EvidenceRef.model_validate({"type": "graph_edge", "source_path": "   "})

    valid_evidence = [
        {
            "type": "graph_edge",
            "id": "edge:invokes:gateway:apigw:api->compute:lambda:handler",
        }
    ]
    base_hop = {
        "id": "cap-001-hop-001",
        "transition": "invoke",
        "from_context": "external:*",
        "action": "execute-api:Invoke",
        "target": "compute:lambda:handler",
        "resulting_context": "compute:lambda:handler",
        "capability_gained": "Trigger execution",
        "required": True,
        "validation_type": "graph",
        "evidence": valid_evidence,
        "assumptions": [],
    }

    with pytest.raises(ValidationError):
        Hop.model_validate({**base_hop, "action": " "})

    with pytest.raises(ValidationError):
        Hop.model_validate({**base_hop, "target": "\t"})

    with pytest.raises(ValidationError):
        Impact.model_validate(
            {"type": "data_access", "resource": " ", "action": "s3:GetObject"}
        )

    with pytest.raises(ValidationError):
        Impact.model_validate(
            {"type": "data_access", "resource": "arn:aws:s3:::sensitive/*", "action": ""}
        )


@pytest.mark.parametrize(
    ("status", "promotion_decision"),
    [
        ("validated", "drop"),
        ("validated", "observe"),
        ("conditional", "drop"),
        ("conditional", "observe"),
        ("rejected", "promote"),
        ("rejected", "observe"),
    ],
)
def test_contradictory_validation_promotion_rejected(
    status: str, promotion_decision: str
) -> None:
    payload = {
        "candidate_id": "cap-001",
        "status": status,
        "promotion_decision": promotion_decision,
        "reason": "reviewed",
        "conditional_hops": ["cap-001-hop-001"] if status == "conditional" else [],
    }

    with pytest.raises(ValidationError):
        AttackValidation.model_validate(payload)
