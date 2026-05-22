from __future__ import annotations

from copy import deepcopy

from scope.attack.validate_paths import validate_candidates


def _public_entrypoint(seed: bool = True) -> dict[str, object]:
    return {
        "id": "gateway:apigw:api",
        "service": "apigateway",
        "resource": "api-id/prod/GET/payments",
        "public_access": True,
        "auth_type": "NONE",
        "starting_position": "external_unauthenticated",
        "attack_path_seed": seed,
        "risk": "high",
        "evidence": [{"type": "module_resource", "id": "api-id"}],
    }


def _public_api_runtime_candidate() -> dict[str, object]:
    return {
        "id": "cap-002",
        "name": "Public API triggers Lambda",
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
                "id": "cap-002-hop-001",
                "transition": "invoke",
                "from_context": "external:*",
                "action": "execute-api:Invoke",
                "target": "compute:lambda:handler",
                "resulting_context": "compute:lambda:handler",
                "capability_gained": "Trigger Lambda",
                "required": True,
                "validation_type": "graph",
                "evidence": [
                    {
                        "type": "graph_edge",
                        "id": "edge:invokes:gateway:apigw:api->compute:lambda:handler",
                    }
                ],
                "assumptions": [],
            },
            {
                "id": "cap-002-hop-002",
                "transition": "data_access",
                "from_context": "compute:lambda:handler",
                "action": "s3:GetObject",
                "target": "arn:aws:s3:::sensitive/*",
                "resulting_context": "role:LambdaRole",
                "capability_gained": "Return sensitive object",
                "required": True,
                "validation_type": "runtime_assumption",
                "evidence": [],
                "assumptions": [
                    "Lambda code must read the target object and return it."
                ],
            },
        ],
        "impact": {
            "type": "data_access",
            "resource": "arn:aws:s3:::sensitive/*",
            "action": "s3:GetObject",
        },
        "affected_resources": ["arn:aws:s3:::sensitive"],
        "detection_opportunities": ["Invoke", "GetObject"],
        "mitre_techniques": [],
        "remediation": ["Restrict public invocation or remove role data access"],
    }


def test_validates_role_chain_and_promotes_final_path() -> None:
    payload = {
        "graph": {
            "nodes": [{"id": "role:RoleA"}, {"id": "role:RoleB"}],
            "edges": [
                {
                    "id": "edge:trust:role:RoleA->role:RoleB",
                    "source": "role:RoleA",
                    "target": "role:RoleB",
                }
            ],
        },
        "modules": [],
        "candidate_attack_paths": [
            {
                "id": "cap-001",
                "name": "RoleA chains into RoleB for S3 access",
                "category": "lateral_movement",
                "severity": "high",
                "starting_position": {
                    "type": "principal",
                    "id": "role:RoleA",
                    "arn": "arn:aws:iam::123456789012:role/RoleA",
                },
                "initial_context": {"principal": "role:RoleA", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-001-hop-001",
                        "transition": "assume_role",
                        "from_context": "role:RoleA",
                        "action": "sts:AssumeRole",
                        "target": "role:RoleB",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "RoleB permissions",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [
                            {
                                "type": "graph_edge",
                                "id": "edge:trust:role:RoleA->role:RoleB",
                            }
                        ],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-001-hop-002",
                        "transition": "data_access",
                        "from_context": "role:RoleB",
                        "action": "s3:GetObject",
                        "target": "arn:aws:s3:::sensitive/*",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "Read sensitive objects",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [
                            {
                                "type": "policy_document",
                                "id": "role:RoleB:inline:ReadSensitive",
                            }
                        ],
                        "assumptions": [],
                    },
                ],
                "impact": {
                    "type": "data_access",
                    "resource": "arn:aws:s3:::sensitive/*",
                    "action": "s3:GetObject",
                },
                "affected_resources": ["arn:aws:s3:::sensitive"],
                "detection_opportunities": ["AssumeRole", "GetObject"],
                "mitre_techniques": [],
                "remediation": ["Remove RoleA trust or RoleB S3 read access"],
            }
        ],
    }
    principal_policies = {
        "role:RoleB": [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::sensitive/*",
                    }
                ]
            }
        ]
    }

    result = validate_candidates(payload, principal_policies=principal_policies)

    assert result["attack_validation"][0]["status"] == "validated"
    assert result["attack_validation"][0]["validated_hops"] == [
        "cap-001-hop-001",
        "cap-001-hop-002",
    ]
    assert result["attack_paths"][0]["validation_status"] == "validated"
    assert result["attack_paths"][0]["source_candidate_id"] == "cap-001"


def test_marks_runtime_assumption_as_conditional_and_promotes_path() -> None:
    payload = {
        "graph": {
            "nodes": [],
            "edges": [
                {
                    "id": "edge:invokes:gateway:apigw:api->compute:lambda:handler",
                    "source": "gateway:apigw:api",
                    "target": "compute:lambda:handler",
                }
            ],
        },
        "public_entrypoints": [_public_entrypoint()],
        "candidate_attack_paths": [
            {
                "id": "cap-002",
                "name": "Public API triggers Lambda",
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
                        "id": "cap-002-hop-001",
                        "transition": "invoke",
                        "from_context": "external:*",
                        "action": "execute-api:Invoke",
                        "target": "compute:lambda:handler",
                        "resulting_context": "compute:lambda:handler",
                        "capability_gained": "Trigger Lambda",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [
                            {
                                "type": "graph_edge",
                                "id": "edge:invokes:gateway:apigw:api->compute:lambda:handler",
                            }
                        ],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-002-hop-002",
                        "transition": "data_access",
                        "from_context": "compute:lambda:handler",
                        "action": "s3:GetObject",
                        "target": "arn:aws:s3:::sensitive/*",
                        "resulting_context": "role:LambdaRole",
                        "capability_gained": "Return sensitive object",
                        "required": True,
                        "validation_type": "runtime_assumption",
                        "evidence": [],
                        "assumptions": [
                            "Lambda code must read the target object and return it."
                        ],
                    },
                ],
                "impact": {
                    "type": "data_access",
                    "resource": "arn:aws:s3:::sensitive/*",
                    "action": "s3:GetObject",
                },
                "affected_resources": ["arn:aws:s3:::sensitive"],
                "detection_opportunities": ["Invoke", "GetObject"],
                "mitre_techniques": [],
                "remediation": ["Restrict public invocation or remove role data access"],
            }
        ],
    }

    result = validate_candidates(payload, principal_policies={})

    assert result["attack_validation"][0]["status"] == "conditional"
    assert result["attack_validation"][0]["conditional_hops"] == ["cap-002-hop-002"]
    assert result["attack_validation"][0]["runtime_assumptions"] == [
        "Lambda code must read the target object and return it."
    ]
    assert result["attack_paths"][0]["validation_status"] == "conditional"
    assert result["attack_paths"][0]["runtime_assumptions"] == [
        "Lambda code must read the target object and return it."
    ]


def test_rejects_public_endpoint_candidate_without_seed() -> None:
    payload = {
        "graph": {
            "nodes": [],
            "edges": [
                {
                    "id": "edge:invokes:gateway:apigw:api->compute:lambda:handler",
                    "source": "gateway:apigw:api",
                    "target": "compute:lambda:handler",
                }
            ],
        },
        "public_entrypoints": [_public_entrypoint(seed=False)],
        "candidate_attack_paths": [_public_api_runtime_candidate()],
    }

    result = validate_candidates(payload, principal_policies={})

    validation = result["attack_validation"][0]
    assert validation["status"] == "rejected"
    assert "public_entrypoints[] seed" in validation["reason"]
    assert result["attack_paths"] == []


def test_rejects_public_endpoint_candidate_with_only_invocation() -> None:
    candidate = _public_api_runtime_candidate()
    candidate["hops"] = [deepcopy(candidate["hops"][0])]
    candidate["impact"] = {
        "type": "lateral_movement",
        "resource": "compute:lambda:handler",
        "action": "execute-api:Invoke",
    }
    payload = {
        "graph": {
            "nodes": [],
            "edges": [
                {
                    "id": "edge:invokes:gateway:apigw:api->compute:lambda:handler",
                    "source": "gateway:apigw:api",
                    "target": "compute:lambda:handler",
                }
            ],
        },
        "public_entrypoints": [_public_entrypoint()],
        "candidate_attack_paths": [candidate],
    }

    result = validate_candidates(payload, principal_policies={})

    validation = result["attack_validation"][0]
    assert validation["status"] == "rejected"
    assert "only proves reachability or invocation" in validation["reason"]
    assert result["attack_paths"] == []


def test_iam_explicit_empty_from_context_policies_is_conditional_without_fallback() -> None:
    payload = {
        "graph": {
            "nodes": [{"id": "role:RoleA"}, {"id": "role:RoleB"}],
            "edges": [
                {
                    "id": "edge:trust:role:RoleA->role:RoleB",
                    "source": "role:RoleA",
                    "target": "role:RoleB",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-003",
                "name": "RoleB policy gap blocks S3 access",
                "category": "data_exposure",
                "severity": "high",
                "starting_position": {
                    "type": "principal",
                    "id": "role:RoleA",
                    "arn": "arn:aws:iam::123456789012:role/RoleA",
                },
                "initial_context": {"principal": "role:RoleA", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-003-hop-001",
                        "transition": "assume_role",
                        "from_context": "role:RoleA",
                        "action": "sts:AssumeRole",
                        "target": "role:RoleB",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "RoleB permissions",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [
                            {
                                "type": "graph_edge",
                                "id": "edge:trust:role:RoleA->role:RoleB",
                            }
                        ],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-003-hop-002",
                        "transition": "data_access",
                        "from_context": "role:RoleB",
                        "action": "s3:GetObject",
                        "target": "arn:aws:s3:::sensitive/*",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "Read sensitive objects",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [
                            {
                                "type": "policy_document",
                                "id": "role:RoleB:inline:empty",
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
                "detection_opportunities": ["GetObject"],
                "mitre_techniques": [],
                "remediation": ["Attach a least-privilege policy only where needed"],
            }
        ],
    }
    principal_policies = {
        "role:RoleB": [],
        "role:RoleA": [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::sensitive/*",
                    }
                ]
            }
        ],
    }

    result = validate_candidates(payload, principal_policies=principal_policies)

    validation = result["attack_validation"][0]
    assert validation["status"] == "conditional"
    assert validation["conditional_hops"] == ["cap-003-hop-002"]
    assert validation["validated_hops"] == ["cap-003-hop-001"]
    assert validation["failed_hops"] == []
    assert any("role:RoleB" in caveat for caveat in validation["coverage_caveats"])
    assert any(
        "No collected policy documents" in caveat
        for caveat in validation["coverage_caveats"]
    )
    assert result["attack_paths"][0]["validation_status"] == "conditional"
    assert result["attack_paths"][0]["source_candidate_id"] == "cap-003"


def test_iam_non_empty_selected_policy_implicit_deny_rejects_path() -> None:
    payload = {
        "graph": {"nodes": [{"id": "role:RoleB"}], "edges": []},
        "candidate_attack_paths": [
            {
                "id": "cap-004",
                "name": "RoleB lacks sensitive object read",
                "category": "data_exposure",
                "severity": "high",
                "starting_position": {
                    "type": "principal",
                    "id": "role:RoleB",
                    "arn": "arn:aws:iam::123456789012:role/RoleB",
                },
                "initial_context": {"principal": "role:RoleB", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-004-hop-001",
                        "transition": "data_access",
                        "from_context": "role:RoleB",
                        "action": "s3:GetObject",
                        "target": "arn:aws:s3:::sensitive/*",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "Read sensitive objects",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [
                            {
                                "type": "policy_document",
                                "id": "role:RoleB:inline:ListOnly",
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
                "detection_opportunities": ["GetObject"],
                "mitre_techniques": [],
                "remediation": ["Grant only required S3 actions"],
            }
        ],
    }
    principal_policies = {
        "role:RoleB": [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:ListBucket",
                        "Resource": "arn:aws:s3:::sensitive",
                    }
                ]
            }
        ]
    }

    result = validate_candidates(payload, principal_policies=principal_policies)

    assert result["attack_validation"][0]["status"] == "rejected"
    assert result["attack_validation"][0]["failed_hops"] == ["cap-004-hop-001"]
    assert result["attack_paths"] == []


def test_rejects_single_hop_broad_permission_without_attacker_progression() -> None:
    payload = {
        "graph": {"nodes": [{"id": "role:RoleB"}], "edges": []},
        "candidate_attack_paths": [
            {
                "id": "cap-005",
                "name": "RoleB can read sensitive object",
                "category": "data_exposure",
                "severity": "high",
                "starting_position": {
                    "type": "principal",
                    "id": "role:RoleB",
                    "arn": "arn:aws:iam::123456789012:role/RoleB",
                },
                "initial_context": {"principal": "role:RoleB", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-005-hop-001",
                        "transition": "data_access",
                        "from_context": "role:RoleB",
                        "action": "s3:GetObject",
                        "target": "arn:aws:s3:::sensitive/*",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "Read sensitive objects",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [
                            {
                                "type": "policy_document",
                                "id": "role:RoleB:inline:ReadSensitive",
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
                "detection_opportunities": ["GetObject"],
                "mitre_techniques": [],
                "remediation": ["Scope S3 access to required objects"],
            }
        ],
    }
    principal_policies = {
        "role:RoleB": [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::sensitive/*",
                    }
                ]
            }
        ]
    }

    result = validate_candidates(payload, principal_policies=principal_policies)

    validation = result["attack_validation"][0]
    assert validation["status"] == "rejected"
    assert validation["failed_hops"] == ["cap-005-hop-001"]
    assert "chain quality" in validation["reason"]
    assert result["attack_paths"] == []


def test_validates_multi_role_chain_with_data_access_impact() -> None:
    payload = {
        "graph": {
            "nodes": [
                {"id": "role:RoleA"},
                {"id": "role:RoleB"},
                {"id": "role:RoleC"},
            ],
            "edges": [
                {
                    "id": "edge:trust:role:RoleA->role:RoleB",
                    "source": "role:RoleA",
                    "target": "role:RoleB",
                },
                {
                    "id": "edge:trust:role:RoleB->role:RoleC",
                    "source": "role:RoleB",
                    "target": "role:RoleC",
                },
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-007",
                "name": "RoleA chains through RoleB into RoleC for data access",
                "category": "lateral_movement",
                "severity": "high",
                "starting_position": {
                    "type": "principal",
                    "id": "role:RoleA",
                    "arn": "arn:aws:iam::123456789012:role/RoleA",
                },
                "initial_context": {"principal": "role:RoleA", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-007-hop-001",
                        "transition": "assume_role",
                        "from_context": "role:RoleA",
                        "action": "sts:AssumeRole",
                        "target": "role:RoleB",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "RoleB permissions",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [
                            {
                                "type": "graph_edge",
                                "id": "edge:trust:role:RoleA->role:RoleB",
                            }
                        ],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-007-hop-002",
                        "transition": "assume_role",
                        "from_context": "role:RoleB",
                        "action": "sts:AssumeRole",
                        "target": "role:RoleC",
                        "resulting_context": "role:RoleC",
                        "capability_gained": "RoleC permissions",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [
                            {
                                "type": "graph_edge",
                                "id": "edge:trust:role:RoleB->role:RoleC",
                            }
                        ],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-007-hop-003",
                        "transition": "data_access",
                        "from_context": "role:RoleC",
                        "action": "s3:GetObject",
                        "target": "arn:aws:s3:::sensitive/*",
                        "resulting_context": "role:RoleC",
                        "capability_gained": "Read sensitive objects",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [
                            {
                                "type": "policy_document",
                                "id": "role:RoleC:inline:ReadSensitive",
                            }
                        ],
                        "assumptions": [],
                    },
                ],
                "impact": {
                    "type": "data_access",
                    "resource": "arn:aws:s3:::sensitive/*",
                    "action": "s3:GetObject",
                },
                "affected_resources": ["arn:aws:s3:::sensitive"],
                "detection_opportunities": ["AssumeRole", "GetObject"],
                "mitre_techniques": [],
                "remediation": ["Remove chained trust or RoleC S3 read access"],
            }
        ],
    }
    principal_policies = {
        "role:RoleC": [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::sensitive/*",
                    }
                ]
            }
        ]
    }

    result = validate_candidates(payload, principal_policies=principal_policies)

    validation = result["attack_validation"][0]
    assert validation["status"] == "validated"
    assert validation["validated_hops"] == [
        "cap-007-hop-001",
        "cap-007-hop-002",
        "cap-007-hop-003",
    ]
    assert result["attack_paths"][0]["source_candidate_id"] == "cap-007"


def test_graph_hop_without_graph_edge_evidence_rejects_path() -> None:
    payload = {
        "graph": {
            "nodes": [{"id": "role:RoleA"}, {"id": "role:RoleB"}],
            "edges": [
                {
                    "id": "edge:trust:role:RoleA->role:RoleB",
                    "source": "role:RoleA",
                    "target": "role:RoleB",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-005",
                "name": "RoleA graph evidence missing",
                "category": "lateral_movement",
                "severity": "high",
                "starting_position": {
                    "type": "principal",
                    "id": "role:RoleA",
                    "arn": "arn:aws:iam::123456789012:role/RoleA",
                },
                "initial_context": {"principal": "role:RoleA", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-005-hop-001",
                        "transition": "assume_role",
                        "from_context": "role:RoleA",
                        "action": "sts:AssumeRole",
                        "target": "role:RoleB",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "RoleB permissions",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [
                            {
                                "type": "policy_document",
                                "id": "role:RoleA:inline:AssumeRole",
                            }
                        ],
                        "assumptions": [],
                    }
                ],
                "impact": {
                    "type": "lateral_movement",
                    "resource": "role:RoleB",
                    "action": "sts:AssumeRole",
                },
                "affected_resources": ["role:RoleB"],
                "detection_opportunities": ["AssumeRole"],
                "mitre_techniques": [],
                "remediation": ["Remove unnecessary trust"],
            }
        ],
    }

    result = validate_candidates(payload, principal_policies={})

    assert result["attack_validation"][0]["status"] == "rejected"
    assert result["attack_validation"][0]["failed_hops"] == ["cap-005-hop-001"]
    assert result["attack_paths"] == []


def test_graph_hop_with_unrelated_existing_edge_rejects_path() -> None:
    payload = {
        "graph": {
            "nodes": [
                {"id": "role:RoleA"},
                {"id": "role:RoleB"},
                {"id": "role:Other"},
            ],
            "edges": [
                {
                    "id": "edge:trust:role:Other->role:RoleB",
                    "source": "role:Other",
                    "target": "role:RoleB",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-006",
                "name": "Unrelated trust edge cannot validate RoleA",
                "category": "lateral_movement",
                "severity": "high",
                "starting_position": {
                    "type": "principal",
                    "id": "role:RoleA",
                    "arn": "arn:aws:iam::123456789012:role/RoleA",
                },
                "initial_context": {"principal": "role:RoleA", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-006-hop-001",
                        "transition": "assume_role",
                        "from_context": "role:RoleA",
                        "action": "sts:AssumeRole",
                        "target": "role:RoleB",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "RoleB permissions",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [
                            {
                                "type": "graph_edge",
                                "id": "edge:trust:role:Other->role:RoleB",
                            }
                        ],
                        "assumptions": [],
                    }
                ],
                "impact": {
                    "type": "lateral_movement",
                    "resource": "role:RoleB",
                    "action": "sts:AssumeRole",
                },
                "affected_resources": ["role:RoleB"],
                "detection_opportunities": ["AssumeRole"],
                "mitre_techniques": [],
                "remediation": ["Remove unnecessary trust"],
            }
        ],
    }

    result = validate_candidates(payload, principal_policies={})

    assert result["attack_validation"][0]["status"] == "rejected"
    assert result["attack_validation"][0]["failed_hops"] == ["cap-006-hop-001"]
    assert result["attack_paths"] == []
