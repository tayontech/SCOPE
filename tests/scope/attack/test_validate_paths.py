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


def _s3_kms_candidate_payload() -> dict[str, object]:
    return {
        "account_id": "123456789012",
        "graph": {
            "nodes": [
                {"id": "role:RoleA", "arn": "arn:aws:iam::123456789012:role/RoleA"},
                {"id": "role:RoleB", "arn": "arn:aws:iam::123456789012:role/RoleB"},
                {
                    "id": "data:kms:key-1",
                    "arn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
                },
            ],
            "edges": [
                {
                    "id": "edge:trust:role:RoleA->role:RoleB",
                    "source": "role:RoleA",
                    "target": "role:RoleB",
                },
                {
                    "id": "edge:encrypted_by:data:s3:sensitive->data:kms:key-1",
                    "source": "data:s3:sensitive",
                    "target": "data:kms:key-1",
                    "edge_type": "encrypted_by",
                    "relationship": "s3_bucket_encrypted_by_kms_key",
                },
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-kms-001",
                "name": "RoleB reads SSE-KMS bucket",
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
                        "id": "cap-kms-001-hop-001",
                        "transition": "assume_role",
                        "from_context": "role:RoleA",
                        "action": "sts:AssumeRole",
                        "target": "role:RoleB",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "RoleB permissions",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [{"type": "graph_edge", "id": "edge:trust:role:RoleA->role:RoleB"}],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-kms-001-hop-002",
                        "transition": "data_access",
                        "from_context": "role:RoleB",
                        "action": "s3:GetObject",
                        "target": "arn:aws:s3:::sensitive/*",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "Read sensitive objects",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [{"type": "policy_document", "id": "role:RoleB:inline:ReadSensitive"}],
                        "assumptions": [],
                    },
                ],
                "impact": {
                    "type": "data_access",
                    "resource": "arn:aws:s3:::sensitive/*",
                    "action": "s3:GetObject",
                },
                "affected_resources": ["arn:aws:s3:::sensitive"],
                "detection_opportunities": ["GetObject", "Decrypt"],
                "mitre_techniques": [],
                "remediation": ["Grant only required S3 and KMS actions"],
            }
        ],
    }


def _s3_kms_identity_policies(*, include_kms: bool = True) -> dict[str, list[dict[str, object]]]:
    actions = ["s3:GetObject", "kms:Decrypt"] if include_kms else ["s3:GetObject"]
    resources = [
        "arn:aws:s3:::sensitive/*",
    ]
    if include_kms:
        resources.append("arn:aws:kms:us-east-1:123456789012:key/key-1")
    return {
        "role:RoleB": [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": actions,
                        "Resource": resources,
                    }
                ]
            }
        ]
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
    assert result["attack_path_groups"][0]["representative_path_id"] == "ap-001"


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
        "public_exposure_findings": [
            {
                "id": "pe-001",
                "source_entrypoint_id": "gateway:apigw:api",
                "reason_not_attack_path": "Downstream validation has not run.",
            }
        ],
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
    assert result["summary"]["attack_analysis_stage"] == "validation"
    assert result["summary"]["conditional_attack_paths_count"] == 1
    assert result["summary"]["attack_paths_count"] == 1
    assert result["public_exposure_findings"][0]["promoted_attack_path_ids"] == ["ap-002"]
    assert result["public_exposure_findings"][0]["reason_not_attack_path"] == (
        "Promoted to final attack path(s): ap-002"
    )


def test_groups_equivalent_promoted_paths_without_removing_raw_paths() -> None:
    candidate_one = {
        "id": "cap-001",
        "name": "Alice can pass AdminRole to CodeBuild",
        "category": "privilege_escalation",
        "severity": "critical",
        "starting_position": {
            "type": "principal",
            "id": "user:Alice",
            "arn": "arn:aws:iam::123456789012:user/Alice",
        },
        "initial_context": {"principal": "user:Alice", "capabilities": []},
        "hops": [
            {
                "id": "cap-001-hop-001",
                "transition": "pass_role",
                "from_context": "user:Alice",
                "action": "iam:PassRole + codebuild:CreateProject + codebuild:StartBuild",
                "target": "arn:aws:iam::123456789012:role/AdminRole",
                "resulting_context": "resource:codebuild-execution-with-AdminRole",
                "capability_gained": "Create CodeBuild with AdminRole.",
                "required": True,
                "validation_type": "iam",
                "evidence": [{"type": "policy_document", "id": "alice-policy"}],
                "assumptions": [],
            },
            {
                "id": "cap-001-hop-002",
                "transition": "execute_as",
                "from_context": "resource:codebuild-execution-with-AdminRole",
                "action": "sts:AssumeRole by codebuild.amazonaws.com",
                "target": "role:AdminRole",
                "resulting_context": "principal:arn:aws:iam::123456789012:role/AdminRole",
                "capability_gained": "CodeBuild can assume AdminRole.",
                "required": True,
                "validation_type": "graph",
                "evidence": [
                    {
                        "type": "graph_edge",
                        "id": "edge:service:svc:codebuild.amazonaws.com->role:AdminRole",
                    }
                ],
                "assumptions": [],
            },
            {
                "id": "cap-001-hop-003",
                "transition": "mutate_policy",
                "from_context": "principal:arn:aws:iam::123456789012:role/AdminRole",
                "action": "iam:CreateUser",
                "target": "*",
                "resulting_context": "account-admin",
                "capability_gained": "AdminRole can mutate IAM.",
                "required": True,
                "validation_type": "iam",
                "evidence": [{"type": "policy_document", "id": "admin-policy"}],
                "assumptions": [],
            },
        ],
        "impact": {"type": "admin_access", "resource": "*", "action": "iam:CreateUser"},
        "affected_resources": [
            "arn:aws:iam::123456789012:user/Alice",
            "arn:aws:iam::123456789012:role/AdminRole",
        ],
        "detection_opportunities": ["CloudTrail PassRole", "CloudTrail CreateUser"],
        "mitre_techniques": ["T1078.004"],
        "remediation": ["Constrain PassRole to AdminRole."],
    }
    candidate_two = deepcopy(candidate_one)
    candidate_two["id"] = "cap-002"
    candidate_two["name"] = "Bob can pass AdminRole to CodeBuild"
    candidate_two["starting_position"] = {
        "type": "principal",
        "id": "user:Bob",
        "arn": "arn:aws:iam::123456789012:user/Bob",
    }
    candidate_two["initial_context"] = {"principal": "user:Bob", "capabilities": []}
    candidate_two["affected_resources"] = [
        "arn:aws:iam::123456789012:user/Bob",
        "arn:aws:iam::123456789012:role/AdminRole",
    ]
    for hop in candidate_two["hops"]:
        hop["id"] = hop["id"].replace("cap-001", "cap-002")
        if hop["from_context"] == "user:Alice":
            hop["from_context"] = "user:Bob"
        if hop["evidence"][0]["id"] == "alice-policy":
            hop["evidence"][0]["id"] = "bob-policy"

    payload = {
        "graph": {
            "nodes": [],
            "edges": [
                {
                    "id": "edge:service:svc:codebuild.amazonaws.com->role:AdminRole",
                    "source": "svc:codebuild.amazonaws.com",
                    "target": "role:AdminRole",
                }
            ],
        },
        "candidate_attack_paths": [candidate_one, candidate_two],
    }
    principal_policies = {
        "user:Alice": [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"],
                        "Resource": "*",
                    }
                ]
            }
        ],
        "user:Bob": [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"],
                        "Resource": "*",
                    }
                ]
            }
        ],
        "arn:aws:iam::123456789012:role/AdminRole": [
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*"}
                ]
            }
        ],
    }

    result = validate_candidates(payload, principal_policies=principal_policies)

    assert len(result["attack_paths"]) == 2
    assert len(result["attack_path_groups"]) == 1
    group = result["attack_path_groups"][0]
    assert group["member_path_ids"] == ["ap-001", "ap-002"]
    assert group["member_count"] == 2
    assert group["primitive"] == "pass_role:codebuild"
    assert group["impact"]["action"] == "iam:CreateUser"
    assert group["source_principals"] == ["user:Alice", "user:Bob"]
    assert group["leveraging_assets"] == [
        {
            "id": "user:Alice",
            "type": "user",
            "arn": "arn:aws:iam::123456789012:user/Alice",
            "path_ids": ["ap-001"],
        },
        {
            "id": "user:Bob",
            "type": "user",
            "arn": "arn:aws:iam::123456789012:user/Bob",
            "path_ids": ["ap-002"],
        },
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


def test_permission_boundary_rejects_otherwise_allowed_iam_hop() -> None:
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
                "id": "cap-boundary-001",
                "name": "RoleB boundary blocks S3 read",
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
                        "id": "cap-boundary-001-hop-001",
                        "transition": "assume_role",
                        "from_context": "role:RoleA",
                        "action": "sts:AssumeRole",
                        "target": "role:RoleB",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "RoleB permissions",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [{"type": "graph_edge", "id": "edge:trust:role:RoleA->role:RoleB"}],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-boundary-001-hop-002",
                        "transition": "data_access",
                        "from_context": "role:RoleB",
                        "action": "s3:GetObject",
                        "target": "arn:aws:s3:::sensitive/*",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "Read sensitive objects",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [{"type": "policy_document", "id": "role:RoleB:inline:ReadSensitive"}],
                        "assumptions": [],
                    }
                ],
                "impact": {"type": "data_access", "resource": "arn:aws:s3:::sensitive/*", "action": "s3:GetObject"},
                "affected_resources": ["arn:aws:s3:::sensitive"],
                "detection_opportunities": ["GetObject"],
                "mitre_techniques": [],
                "remediation": ["Update the permission boundary only if the access is required"],
            }
        ],
    }
    principal_policies = {
        "role:RoleB": [
            {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::sensitive/*"}]}
        ]
    }
    permission_boundaries = {
        "role:RoleB": [
            {"Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::sensitive"}]}
        ]
    }

    result = validate_candidates(
        payload,
        principal_policies=principal_policies,
        permission_boundary_policies=permission_boundaries,
    )

    assert result["attack_validation"][0]["status"] == "rejected"
    assert result["attack_validation"][0]["validated_hops"] == ["cap-boundary-001-hop-001"]
    assert result["attack_validation"][0]["failed_hops"] == ["cap-boundary-001-hop-002"]
    assert result["attack_paths"] == []


def test_missing_permission_boundary_document_makes_iam_hop_conditional() -> None:
    candidate = {
        "id": "cap-boundary-002",
        "name": "RoleB boundary document missing",
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
                "id": "cap-boundary-002-hop-001",
                "transition": "assume_role",
                "from_context": "role:RoleA",
                "action": "sts:AssumeRole",
                "target": "role:RoleB",
                "resulting_context": "role:RoleB",
                "capability_gained": "RoleB permissions",
                "required": True,
                "validation_type": "graph",
                "evidence": [{"type": "graph_edge", "id": "edge:trust:role:RoleA->role:RoleB"}],
                "assumptions": [],
            },
            {
                "id": "cap-boundary-002-hop-002",
                "transition": "data_access",
                "from_context": "role:RoleB",
                "action": "s3:GetObject",
                "target": "arn:aws:s3:::sensitive/*",
                "resulting_context": "role:RoleB",
                "capability_gained": "Read sensitive objects",
                "required": True,
                "validation_type": "iam",
                "evidence": [{"type": "policy_document", "id": "role:RoleB:inline:ReadSensitive"}],
                "assumptions": [],
            }
        ],
        "impact": {"type": "data_access", "resource": "arn:aws:s3:::sensitive/*", "action": "s3:GetObject"},
        "affected_resources": ["arn:aws:s3:::sensitive"],
        "detection_opportunities": ["GetObject"],
        "mitre_techniques": [],
        "remediation": ["Collect and inspect the permission boundary"],
    }
    principal_policies = {
        "role:RoleB": [
            {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::sensitive/*"}]}
        ]
    }

    result = validate_candidates(
        {
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
            "candidate_attack_paths": [candidate],
        },
        principal_policies=principal_policies,
        permission_boundary_presence={"role:RoleB"},
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "conditional"
    assert validation["validated_hops"] == ["cap-boundary-002-hop-001"]
    assert validation["conditional_hops"] == ["cap-boundary-002-hop-002"]
    assert any("permission boundary" in caveat for caveat in validation["coverage_caveats"])


def test_s3_kms_encrypted_bucket_requires_kms_decrypt_for_iam_data_access() -> None:
    payload = {
        "account_id": "123456789012",
        "graph": {
            "nodes": [
                {"id": "role:RoleA"},
                {"id": "role:RoleB"},
                {
                    "id": "data:kms:key-1",
                    "arn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
                }
            ],
            "edges": [
                {
                    "id": "edge:trust:role:RoleA->role:RoleB",
                    "source": "role:RoleA",
                    "target": "role:RoleB",
                },
                {
                    "id": "edge:encrypted_by:data:s3:sensitive->data:kms:key-1",
                    "source": "data:s3:sensitive",
                    "target": "data:kms:key-1",
                    "edge_type": "encrypted_by",
                    "relationship": "s3_bucket_encrypted_by_kms_key",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-004a",
                "name": "RoleB lacks KMS decrypt for SSE-KMS bucket",
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
                        "id": "cap-004a-hop-001",
                        "transition": "assume_role",
                        "from_context": "role:RoleA",
                        "action": "sts:AssumeRole",
                        "target": "role:RoleB",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "RoleB permissions",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [{"type": "graph_edge", "id": "edge:trust:role:RoleA->role:RoleB"}],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-004a-hop-002",
                        "transition": "data_access",
                        "from_context": "role:RoleB",
                        "action": "s3:GetObject",
                        "target": "arn:aws:s3:::sensitive/*",
                        "resulting_context": "role:RoleB",
                        "capability_gained": "Read sensitive objects",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [{"type": "policy_document", "id": "role:RoleB:inline:ReadSensitive"}],
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
                "remediation": ["Grant only required S3 and KMS actions"],
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
    resource_policies = {
        "arn:aws:kms:us-east-1:123456789012:key/key-1": [
            {
                "sid": "EnableAccountIam",
                "effect": "Allow",
                "normalized_principals": ["arn:aws:iam::123456789012:root"],
                "normalized_actions": ["kms:*"],
                "normalized_resources": ["*"],
                "condition": None,
            }
        ]
    }

    result = validate_candidates(
        payload,
        principal_policies=principal_policies,
        resource_policies=resource_policies,
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "rejected"
    assert validation["failed_hops"] == ["cap-004a-hop-002"]
    assert result["attack_paths"] == []


def test_ssm_secure_string_requires_kms_decrypt_for_iam_data_access() -> None:
    parameter_arn = "arn:aws:ssm:us-east-1:123456789012:parameter/app/secret-key"
    key_arn = "arn:aws:kms:us-east-1:123456789012:key/key-1"
    payload = {
        "account_id": "123456789012",
        "graph": {
            "nodes": [
                {"id": "data:ssm:/app/secret-key", "arn": parameter_arn},
                {"id": "data:kms:key-1", "arn": key_arn},
            ],
            "edges": [
                {
                    "id": "edge:encrypted_by:data:ssm:/app/secret-key->data:kms:key-1",
                    "source": "data:ssm:/app/secret-key",
                    "target": "data:kms:key-1",
                    "edge_type": "encrypted_by",
                    "relationship": "ssm_parameter_encrypted_by_kms_key",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-ssm-kms-001",
                "name": "Role reads encrypted parameter",
                "category": "data_exposure",
                "severity": "high",
                "starting_position": {
                    "type": "principal",
                    "id": "principal:arn:aws:iam::123456789012:role/ParameterReader",
                    "arn": "arn:aws:iam::123456789012:role/ParameterReader",
                },
                "initial_context": {
                    "principal": "principal:arn:aws:iam::123456789012:role/ParameterReader",
                    "capabilities": ["ssm:GetParameter"],
                },
                "hops": [
                    {
                        "id": "cap-ssm-kms-001-hop-001",
                        "transition": "data_access",
                        "from_context": "principal:arn:aws:iam::123456789012:role/ParameterReader",
                        "action": "ssm:GetParameter",
                        "target": parameter_arn,
                        "resulting_context": "data:ssm:GetParameter",
                        "capability_gained": "Can read SecureString parameter.",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [{"type": "policy_document", "id": "ParameterReader"}],
                        "assumptions": [],
                    }
                ],
                "impact": {
                    "type": "data_access",
                    "resource": parameter_arn,
                    "action": "ssm:GetParameter",
                },
                "affected_resources": [parameter_arn],
                "detection_opportunities": ["CloudTrail GetParameter"],
                "mitre_techniques": ["T1552"],
                "remediation": ["Restrict parameter access."],
            }
        ],
    }

    result = validate_candidates(
        payload,
        principal_policies={
            "principal:arn:aws:iam::123456789012:role/ParameterReader": [
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "ssm:GetParameter",
                            "Resource": parameter_arn,
                        }
                    ]
                }
            ]
        },
        resource_policies={
            key_arn: [
                {
                    "effect": "Allow",
                    "normalized_principals": ["arn:aws:iam::123456789012:root"],
                    "normalized_actions": ["kms:*"],
                    "normalized_resources": ["*"],
                }
            ]
        },
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "rejected"
    assert validation["failed_hops"] == ["cap-ssm-kms-001-hop-001"]
    assert result["attack_paths"] == []


def test_s3_kms_encrypted_bucket_requires_key_policy_allow() -> None:
    resource_policies = {
        "arn:aws:kms:us-east-1:123456789012:key/key-1": [
            {
                "sid": "AllowDifferentRole",
                "effect": "Allow",
                "normalized_principals": ["arn:aws:iam::123456789012:role/OtherRole"],
                "normalized_actions": ["kms:Decrypt"],
                "normalized_resources": ["*"],
                "condition": None,
            }
        ]
    }

    result = validate_candidates(
        _s3_kms_candidate_payload(),
        principal_policies=_s3_kms_identity_policies(),
        resource_policies=resource_policies,
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "rejected"
    assert validation["failed_hops"] == ["cap-kms-001-hop-002"]
    assert result["attack_paths"] == []


def test_s3_kms_encrypted_bucket_validates_with_key_policy_account_root_delegation() -> None:
    resource_policies = {
        "arn:aws:kms:us-east-1:123456789012:key/key-1": [
            {
                "sid": "EnableAccountIam",
                "effect": "Allow",
                "normalized_principals": ["arn:aws:iam::123456789012:root"],
                "normalized_actions": ["kms:*"],
                "normalized_resources": ["*"],
                "condition": {
                    "StringEquals": {
                        "kms:ViaService": "s3.us-east-1.amazonaws.com",
                    }
                },
            }
        ]
    }

    result = validate_candidates(
        _s3_kms_candidate_payload(),
        principal_policies=_s3_kms_identity_policies(),
        resource_policies=resource_policies,
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "validated"
    assert validation["validated_hops"] == ["cap-kms-001-hop-001", "cap-kms-001-hop-002"]
    assert result["attack_paths"][0]["validation_status"] == "validated"


def test_s3_kms_encrypted_bucket_direct_key_policy_allow_does_not_require_identity_kms() -> None:
    resource_policies = {
        "arn:aws:kms:us-east-1:123456789012:key/key-1": [
            {
                "sid": "AllowRoleDirectDecrypt",
                "effect": "Allow",
                "normalized_principals": ["arn:aws:iam::123456789012:role/RoleB"],
                "normalized_actions": ["kms:Decrypt"],
                "normalized_resources": ["*"],
                "condition": None,
            }
        ]
    }

    result = validate_candidates(
        _s3_kms_candidate_payload(),
        principal_policies=_s3_kms_identity_policies(include_kms=False),
        resource_policies=resource_policies,
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "validated"
    assert validation["validated_hops"] == ["cap-kms-001-hop-001", "cap-kms-001-hop-002"]


def test_s3_kms_encrypted_bucket_grant_allows_decrypt_without_identity_kms() -> None:
    kms_grants = {
        "arn:aws:kms:us-east-1:123456789012:key/key-1": [
            {
                "grant_id": "grant-1",
                "grantee_principal": "arn:aws:iam::123456789012:role/RoleB",
                "operations": ["Decrypt"],
                "constraints": {},
            }
        ]
    }

    result = validate_candidates(
        _s3_kms_candidate_payload(),
        principal_policies=_s3_kms_identity_policies(include_kms=False),
        resource_policies={},
        kms_grants=kms_grants,
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "validated"
    assert validation["validated_hops"] == ["cap-kms-001-hop-001", "cap-kms-001-hop-002"]


def test_s3_kms_encrypted_bucket_missing_key_policy_is_conditional() -> None:
    result = validate_candidates(
        _s3_kms_candidate_payload(),
        principal_policies=_s3_kms_identity_policies(),
        resource_policies={},
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "conditional"
    assert validation["conditional_hops"] == ["cap-kms-001-hop-002"]
    assert any("KMS key policy" in caveat for caveat in validation["coverage_caveats"])


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


def test_graph_only_resource_policy_edge_does_not_promote_path() -> None:
    payload = {
        "graph": {
            "nodes": [
                {"id": "external:anonymous"},
                {"id": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic"},
            ],
            "edges": [
                {
                    "id": (
                        "edge:resource_policy_allows:external:anonymous->"
                        "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic"
                    ),
                    "source": "external:anonymous",
                    "target": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic",
                    "edge_type": "resource_policy_allows",
                    "relationship": "resource_policy_allows",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-008",
                "name": "Anonymous SNS publish from principal-only graph edge",
                "category": "data_exposure",
                "severity": "high",
                "starting_position": {
                    "type": "external",
                    "id": "external:anonymous",
                    "arn": None,
                },
                "initial_context": {"principal": "external:anonymous", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-008-hop-001",
                        "transition": "resource_policy_access",
                        "from_context": "external:anonymous",
                        "action": "sns:Publish",
                        "target": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic",
                        "resulting_context": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic",
                        "capability_gained": "Publish to the SNS topic",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [
                            {
                                "type": "graph_edge",
                                "id": (
                                    "edge:resource_policy_allows:external:anonymous->"
                                    "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic"
                                ),
                            }
                        ],
                        "assumptions": [],
                    }
                ],
                "impact": {
                    "type": "data_access",
                    "resource": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic",
                    "action": "sns:Publish",
                },
                "affected_resources": ["arn:aws:sns:us-east-1:123456789012:topic"],
                "detection_opportunities": ["Publish"],
                "mitre_techniques": [],
                "remediation": ["Review the SNS topic resource policy"],
            }
        ],
    }

    result = validate_candidates(payload, principal_policies={})

    validation = result["attack_validation"][0]
    assert validation["status"] == "rejected"
    assert validation["failed_hops"] == ["cap-008-hop-001"]
    assert result["attack_paths"] == []


def test_resource_policy_statement_graph_edge_requires_matching_action() -> None:
    payload = {
        "graph": {
            "nodes": [
                {"id": "external:anonymous"},
                {"id": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic"},
            ],
            "edges": [
                {
                    "id": "edge:resource_policy_statement:external:anonymous->topic:SnsReadOnly",
                    "source": "external:anonymous",
                    "target": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic",
                    "edge_type": "resource_policy_statement",
                    "relationship": "sns_topic_policy_statement_allows_action",
                    "actions": ["sns:GetTopicAttributes"],
                    "resources": ["arn:aws:sns:us-east-1:123456789012:topic"],
                    "statement_id": "SnsReadOnly",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-009",
                "name": "Anonymous SNS publish from read-only statement",
                "category": "data_exposure",
                "severity": "high",
                "starting_position": {
                    "type": "external",
                    "id": "external:anonymous",
                    "arn": None,
                },
                "initial_context": {"principal": "external:anonymous", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-009-hop-001",
                        "transition": "resource_policy_access",
                        "from_context": "external:anonymous",
                        "action": "sns:Publish",
                        "target": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic",
                        "resulting_context": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic",
                        "capability_gained": "Publish to the SNS topic",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [
                            {
                                "type": "graph_edge",
                                "id": "edge:resource_policy_statement:external:anonymous->topic:SnsReadOnly",
                            }
                        ],
                        "assumptions": [],
                    }
                ],
                "impact": {
                    "type": "data_access",
                    "resource": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic",
                    "action": "sns:Publish",
                },
                "affected_resources": ["arn:aws:sns:us-east-1:123456789012:topic"],
                "detection_opportunities": ["Publish"],
                "mitre_techniques": [],
                "remediation": ["Review the SNS topic resource policy"],
            }
        ],
    }

    result = validate_candidates(payload, principal_policies={})

    assert result["attack_validation"][0]["status"] == "rejected"
    assert result["attack_validation"][0]["failed_hops"] == ["cap-009-hop-001"]
    assert result["attack_paths"] == []


def test_conditioned_resource_policy_statement_graph_edge_does_not_promote_path() -> None:
    payload = {
        "graph": {
            "nodes": [
                {"id": "external:anonymous"},
                {"id": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic"},
            ],
            "edges": [
                {
                    "id": "edge:resource_policy_statement:external:anonymous->topic:S3PublishOnly",
                    "source": "external:anonymous",
                    "target": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic",
                    "edge_type": "resource_policy_statement",
                    "relationship": "sns_topic_policy_statement_allows_action",
                    "actions": ["sns:Publish"],
                    "resources": ["arn:aws:sns:us-east-1:123456789012:topic"],
                    "conditions": {
                        "StringEquals": {
                            "AWS:SourceArn": "arn:aws:s3:::tot-vpc-logs",
                        }
                    },
                    "statement_id": "S3PublishOnly",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-010",
                "name": "Anonymous SNS publish from source-constrained statement",
                "category": "data_exposure",
                "severity": "high",
                "starting_position": {
                    "type": "external",
                    "id": "external:anonymous",
                    "arn": None,
                },
                "initial_context": {"principal": "external:anonymous", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-010-hop-001",
                        "transition": "resource_policy_access",
                        "from_context": "external:anonymous",
                        "action": "sns:Publish",
                        "target": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic",
                        "resulting_context": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic",
                        "capability_gained": "Publish to the SNS topic",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [
                            {
                                "type": "graph_edge",
                                "id": "edge:resource_policy_statement:external:anonymous->topic:S3PublishOnly",
                            }
                        ],
                        "assumptions": [],
                    }
                ],
                "impact": {
                    "type": "data_access",
                    "resource": "messaging:sns:arn:aws:sns:us-east-1:123456789012:topic",
                    "action": "sns:Publish",
                },
                "affected_resources": ["arn:aws:sns:us-east-1:123456789012:topic"],
                "detection_opportunities": ["Publish"],
                "mitre_techniques": [],
                "remediation": ["Review the SNS topic resource policy"],
            }
        ],
    }

    result = validate_candidates(payload, principal_policies={})

    assert result["attack_validation"][0]["status"] == "rejected"
    assert result["attack_validation"][0]["failed_hops"] == ["cap-010-hop-001"]
    assert result["attack_paths"] == []


def test_uncontrolled_external_trust_assume_role_candidate_is_rejected() -> None:
    payload = {
        "graph": {
            "nodes": [{"id": "external:arn:aws:iam::999999999999:role/Partner"}, {"id": "role:TargetRole"}],
            "edges": [
                {
                    "id": "edge:trust:external:partner->role:TargetRole",
                    "source": "external:arn:aws:iam::999999999999:role/Partner",
                    "target": "role:TargetRole",
                    "relationship": "iam_role_trusts_principal",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-external-001",
                "name": "External partner can assume target role",
                "category": "lateral_movement",
                "severity": "high",
                "starting_position": {
                    "type": "external",
                    "id": "external:arn:aws:iam::999999999999:role/Partner",
                    "arn": "arn:aws:iam::999999999999:role/Partner",
                },
                "initial_context": {
                    "principal": "external:arn:aws:iam::999999999999:role/Partner",
                    "capabilities": [],
                },
                "hops": [
                    {
                        "id": "cap-external-001-hop-001",
                        "transition": "assume_role",
                        "from_context": "external:arn:aws:iam::999999999999:role/Partner",
                        "action": "sts:AssumeRole",
                        "target": "role:TargetRole",
                        "resulting_context": "role:TargetRole",
                        "capability_gained": "External role can request TargetRole credentials",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [{"type": "graph_edge", "id": "edge:trust:external:partner->role:TargetRole"}],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-external-001-hop-002",
                        "transition": "mutate_policy",
                        "from_context": "role:TargetRole",
                        "action": "iam:PutRolePolicy",
                        "target": "*",
                        "resulting_context": "role:TargetRole",
                        "capability_gained": "TargetRole can mutate IAM policy",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [{"type": "policy_document", "id": "role:TargetRole:inline:Admin"}],
                        "assumptions": [],
                    },
                ],
                "impact": {"type": "admin_access", "resource": "*", "action": "iam:PutRolePolicy"},
                "affected_resources": ["arn:aws:iam::123456789012:role/TargetRole"],
                "detection_opportunities": ["AssumeRole", "PutRolePolicy"],
                "mitre_techniques": [],
                "remediation": ["Validate external trust ownership before promoting the path"],
            }
        ],
    }

    result = validate_candidates(
        payload,
        principal_policies={
            "role:TargetRole": [
                {"Statement": [{"Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": "*"}]}
            ]
        },
    )

    assert result["attack_validation"][0]["status"] == "rejected"
    assert result["attack_paths"] == []


def test_resource_policy_validation_promotes_unconditioned_matching_statement() -> None:
    payload = {
        "graph": {"nodes": [], "edges": []},
        "candidate_attack_paths": [
            {
                "id": "cap-011",
                "name": "External principal reads shared secret",
                "category": "data_exposure",
                "severity": "high",
                "starting_position": {
                    "type": "external",
                    "id": "external:arn:aws:iam::999999999999:role/Reader",
                    "arn": "arn:aws:iam::999999999999:role/Reader",
                },
                "initial_context": {
                    "principal": "external:arn:aws:iam::999999999999:role/Reader",
                    "capabilities": [],
                },
                "hops": [
                    {
                        "id": "cap-011-hop-001",
                        "transition": "resource_policy_access",
                        "from_context": "external:arn:aws:iam::999999999999:role/Reader",
                        "action": "secretsmanager:GetSecretValue",
                        "target": "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf",
                        "resulting_context": "data:secret:shared-AbCdEf",
                        "capability_gained": "Read the shared secret value",
                        "required": True,
                        "validation_type": "resource_policy",
                        "evidence": [{"type": "policy_document", "id": "secret-policy"}],
                        "assumptions": [],
                    }
                ],
                "impact": {
                    "type": "data_access",
                    "resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf",
                    "action": "secretsmanager:GetSecretValue",
                },
                "affected_resources": [
                    "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf"
                ],
                "detection_opportunities": ["GetSecretValue"],
                "mitre_techniques": [],
                "remediation": ["Remove cross-account secret read access"],
            }
        ],
    }
    resource_policies = {
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf": [
            {
                "sid": "CrossAccountRead",
                "effect": "Allow",
                "normalized_principals": ["arn:aws:iam::999999999999:role/Reader"],
                "normalized_actions": ["secretsmanager:GetSecretValue"],
                "normalized_resources": [
                    "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf"
                ],
                "condition": None,
            }
        ]
    }

    result = validate_candidates(payload, principal_policies={}, resource_policies=resource_policies)

    validation = result["attack_validation"][0]
    assert validation["status"] == "validated"
    assert validation["validated_hops"] == ["cap-011-hop-001"]
    assert result["attack_paths"][0]["validation_status"] == "validated"


def _encrypted_secret_resource_policy_payload() -> dict[str, object]:
    secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf"
    key_arn = "arn:aws:kms:us-east-1:123456789012:key/key-1"
    return {
        "account_id": "123456789012",
        "graph": {
            "nodes": [
                {"id": "data:secrets:shared", "arn": secret_arn},
                {"id": "data:kms:key-1", "arn": key_arn},
            ],
            "edges": [
                {
                    "id": "edge:encrypted_by:data:secrets:shared->data:kms:key-1",
                    "source": "data:secrets:shared",
                    "target": "data:kms:key-1",
                    "edge_type": "encrypted_by",
                    "relationship": "secrets_secret_encrypted_by_kms_key",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-secret-kms-001",
                "name": "External principal reads CMK-encrypted secret",
                "category": "data_exposure",
                "severity": "high",
                "starting_position": {
                    "type": "external",
                    "id": "external:arn:aws:iam::999999999999:role/Reader",
                    "arn": "arn:aws:iam::999999999999:role/Reader",
                },
                "initial_context": {
                    "principal": "external:arn:aws:iam::999999999999:role/Reader",
                    "capabilities": [],
                },
                "hops": [
                    {
                        "id": "cap-secret-kms-001-hop-001",
                        "transition": "resource_policy_access",
                        "from_context": "external:arn:aws:iam::999999999999:role/Reader",
                        "action": "secretsmanager:GetSecretValue",
                        "target": secret_arn,
                        "resulting_context": "data:secrets:shared",
                        "capability_gained": "Read the shared secret value",
                        "required": True,
                        "validation_type": "resource_policy",
                        "evidence": [{"type": "policy_document", "id": "secret-policy"}],
                        "assumptions": [],
                    }
                ],
                "impact": {
                    "type": "data_access",
                    "resource": secret_arn,
                    "action": "secretsmanager:GetSecretValue",
                },
                "affected_resources": [secret_arn],
                "detection_opportunities": ["GetSecretValue", "Decrypt"],
                "mitre_techniques": [],
                "remediation": ["Remove cross-account secret and key policy access"],
            }
        ],
    }


def _secret_resource_policy_statements() -> list[dict[str, object]]:
    secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf"
    return [
        {
            "sid": "CrossAccountRead",
            "effect": "Allow",
            "normalized_principals": ["arn:aws:iam::999999999999:role/Reader"],
            "normalized_actions": ["secretsmanager:GetSecretValue"],
            "normalized_resources": [secret_arn],
            "condition": None,
        }
    ]


def _lambda_function_url_payload() -> dict[str, object]:
    function_arn = "arn:aws:lambda:us-east-1:123456789012:function:public-handler"
    return {
        "graph": {"nodes": [{"id": "compute:lambda:public-handler", "arn": function_arn}], "edges": []},
        "candidate_attack_paths": [
            {
                "id": "cap-lambda-url-001",
                "name": "Anonymous caller invokes public Lambda Function URL",
                "category": "lateral_movement",
                "severity": "medium",
                "starting_position": {"type": "external", "id": "external:anonymous", "arn": None},
                "initial_context": {"principal": "external:anonymous", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-lambda-url-001-hop-001",
                        "transition": "resource_policy_access",
                        "from_context": "external:anonymous",
                        "action": "lambda:InvokeFunctionUrl",
                        "target": function_arn,
                        "resulting_context": "compute:lambda:public-handler",
                        "capability_gained": "Invoke the Lambda Function URL",
                        "required": True,
                        "validation_type": "resource_policy",
                        "evidence": [{"type": "policy_document", "id": "lambda-policy"}],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-lambda-url-001-hop-002",
                        "transition": "data_access",
                        "from_context": "compute:lambda:public-handler",
                        "action": "lambda runtime behavior",
                        "target": "role:LambdaExecutionRole",
                        "resulting_context": "role:LambdaExecutionRole",
                        "capability_gained": "Function code must expose an AWS-level effect to the caller",
                        "required": True,
                        "validation_type": "runtime_assumption",
                        "evidence": [],
                        "assumptions": ["Function runtime behavior must expose an AWS-level effect to the caller."],
                    },
                ],
                "impact": {
                    "type": "lateral_movement",
                    "resource": "role:LambdaExecutionRole",
                    "action": "lambda runtime behavior",
                },
                "affected_resources": [function_arn],
                "detection_opportunities": ["InvokeFunctionUrl"],
                "mitre_techniques": [],
                "remediation": ["Require IAM auth or remove public Function URL access"],
            }
        ],
    }


def _lambda_function_url_policy() -> dict[str, list[dict[str, object]]]:
    function_arn = "arn:aws:lambda:us-east-1:123456789012:function:public-handler"
    return {
        function_arn: [
            {
                "sid": "PublicFunctionUrl",
                "effect": "Allow",
                "normalized_principals": ["*"],
                "normalized_actions": ["lambda:InvokeFunctionUrl"],
                "normalized_resources": [function_arn],
                "condition": {
                    "StringEquals": {
                        "lambda:FunctionUrlAuthType": "NONE",
                        "lambda:InvokedViaFunctionUrl": "true",
                    }
                },
            }
        ]
    }


def test_lambda_function_url_policy_condition_validates_matching_auth_type() -> None:
    function_arn = "arn:aws:lambda:us-east-1:123456789012:function:public-handler"

    result = validate_candidates(
        _lambda_function_url_payload(),
        principal_policies={},
        resource_policies=_lambda_function_url_policy(),
        lambda_function_url_auth_types={function_arn: "NONE"},
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "conditional"
    assert validation["validated_hops"] == ["cap-lambda-url-001-hop-001"]
    assert validation["conditional_hops"] == ["cap-lambda-url-001-hop-002"]


def test_lambda_function_url_policy_condition_rejects_mismatched_auth_type() -> None:
    function_arn = "arn:aws:lambda:us-east-1:123456789012:function:public-handler"

    result = validate_candidates(
        _lambda_function_url_payload(),
        principal_policies={},
        resource_policies=_lambda_function_url_policy(),
        lambda_function_url_auth_types={function_arn: "AWS_IAM"},
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "rejected"
    assert validation["failed_hops"] == ["cap-lambda-url-001-hop-001"]
    assert result["attack_paths"] == []


def test_lambda_function_url_policy_condition_is_conditional_when_auth_type_missing() -> None:
    result = validate_candidates(
        _lambda_function_url_payload(),
        principal_policies={},
        resource_policies=_lambda_function_url_policy(),
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "conditional"
    assert validation["conditional_hops"] == [
        "cap-lambda-url-001-hop-001",
        "cap-lambda-url-001-hop-002",
    ]
    assert any("Lambda Function URL auth type" in caveat for caveat in validation["coverage_caveats"])


def test_encrypted_secret_resource_policy_requires_kms_authorization() -> None:
    secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf"
    key_arn = "arn:aws:kms:us-east-1:123456789012:key/key-1"
    resource_policies = {
        secret_arn: _secret_resource_policy_statements(),
        key_arn: [
            {
                "sid": "AllowDifferentRole",
                "effect": "Allow",
                "normalized_principals": ["arn:aws:iam::999999999999:role/OtherRole"],
                "normalized_actions": ["kms:Decrypt"],
                "normalized_resources": ["*"],
                "condition": None,
            }
        ],
    }

    result = validate_candidates(
        _encrypted_secret_resource_policy_payload(),
        principal_policies={},
        resource_policies=resource_policies,
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "rejected"
    assert validation["failed_hops"] == ["cap-secret-kms-001-hop-001"]
    assert result["attack_paths"] == []


def test_encrypted_secret_resource_policy_validates_with_direct_kms_key_policy() -> None:
    secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf"
    key_arn = "arn:aws:kms:us-east-1:123456789012:key/key-1"
    resource_policies = {
        secret_arn: _secret_resource_policy_statements(),
        key_arn: [
            {
                "sid": "AllowReaderDecrypt",
                "effect": "Allow",
                "normalized_principals": ["arn:aws:iam::999999999999:role/Reader"],
                "normalized_actions": ["kms:Decrypt"],
                "normalized_resources": ["*"],
                "condition": None,
            }
        ],
    }

    result = validate_candidates(
        _encrypted_secret_resource_policy_payload(),
        principal_policies={},
        resource_policies=resource_policies,
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "validated"
    assert validation["validated_hops"] == ["cap-secret-kms-001-hop-001"]


def test_encrypted_secret_resource_policy_missing_kms_policy_is_conditional() -> None:
    secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:shared-AbCdEf"
    resource_policies = {secret_arn: _secret_resource_policy_statements()}

    result = validate_candidates(
        _encrypted_secret_resource_policy_payload(),
        principal_policies={},
        resource_policies=resource_policies,
    )

    validation = result["attack_validation"][0]
    assert validation["status"] == "conditional"
    assert validation["conditional_hops"] == ["cap-secret-kms-001-hop-001"]
    assert any("KMS key policy" in caveat for caveat in validation["coverage_caveats"])


def test_resource_policy_validation_matches_s3_graph_node_target_to_bucket_arn() -> None:
    payload = {
        "graph": {"nodes": [], "edges": []},
        "candidate_attack_paths": [
            {
                "id": "cap-011a",
                "name": "Anonymous principal reads public bucket through bucket policy",
                "category": "data_exposure",
                "severity": "high",
                "starting_position": {"type": "external", "id": "external:anonymous", "arn": None},
                "initial_context": {"principal": "external:anonymous", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-011a-hop-001",
                        "transition": "resource_policy_access",
                        "from_context": "external:anonymous",
                        "action": "s3:GetObject",
                        "target": "data:s3:public-bucket",
                        "resulting_context": "data:s3:public-bucket",
                        "capability_gained": "Read public bucket objects",
                        "required": True,
                        "validation_type": "resource_policy",
                        "evidence": [{"type": "policy_document", "id": "bucket-policy"}],
                        "assumptions": [],
                    }
                ],
                "impact": {"type": "data_access", "resource": "data:s3:public-bucket", "action": "s3:GetObject"},
                "affected_resources": ["arn:aws:s3:::public-bucket"],
                "detection_opportunities": ["GetObject"],
                "mitre_techniques": [],
                "remediation": ["Remove anonymous bucket policy access"],
            }
        ],
    }
    resource_policies = {
        "public-bucket": [
            {
                "sid": "PublicRead",
                "effect": "Allow",
                "normalized_principals": ["*"],
                "normalized_actions": ["s3:GetObject"],
                "normalized_resources": ["arn:aws:s3:::public-bucket/*"],
                "condition": None,
            }
        ]
    }

    result = validate_candidates(payload, principal_policies={}, resource_policies=resource_policies)

    assert result["attack_validation"][0]["status"] == "validated"
    assert result["attack_paths"][0]["validation_status"] == "validated"


def test_resource_policy_validation_matches_service_principal_context() -> None:
    payload = {
        "graph": {
            "nodes": [],
            "edges": [
                {
                    "id": "edge:event_source:data:s3:uploads->svc:s3.amazonaws.com",
                    "source": "data:s3:uploads",
                    "target": "svc:s3.amazonaws.com",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-011b",
                "name": "S3 bucket notification publishes to SNS topic",
                "category": "data_exposure",
                "severity": "medium",
                "starting_position": {"type": "resource", "id": "data:s3:uploads", "arn": "arn:aws:s3:::uploads"},
                "initial_context": {"principal": "data:s3:uploads", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-011b-hop-001",
                        "transition": "event_injection",
                        "from_context": "data:s3:uploads",
                        "action": "s3:ObjectCreated:Put",
                        "target": "svc:s3.amazonaws.com",
                        "resulting_context": "svc:s3.amazonaws.com",
                        "capability_gained": "S3 emits an object-created event as the S3 service principal",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [{"type": "graph_edge", "id": "edge:event_source:data:s3:uploads->svc:s3.amazonaws.com"}],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-011b-hop-002",
                        "transition": "resource_policy_access",
                        "from_context": "svc:s3.amazonaws.com",
                        "action": "sns:Publish",
                        "target": "arn:aws:sns:us-east-1:123456789012:uploads",
                        "resulting_context": "messaging:sns:arn:aws:sns:us-east-1:123456789012:uploads",
                        "capability_gained": "S3 can publish object events to the topic",
                        "required": True,
                        "validation_type": "resource_policy",
                        "evidence": [{"type": "policy_document", "id": "topic-policy"}],
                        "assumptions": [],
                    }
                ],
                "impact": {
                    "type": "data_access",
                    "resource": "arn:aws:sns:us-east-1:123456789012:uploads",
                    "action": "sns:Publish",
                },
                "affected_resources": ["arn:aws:sns:us-east-1:123456789012:uploads"],
                "detection_opportunities": ["Publish"],
                "mitre_techniques": [],
                "remediation": ["Constrain the SNS topic policy source"],
            }
        ],
    }
    resource_policies = {
        "arn:aws:sns:us-east-1:123456789012:uploads": [
            {
                "sid": "S3Publish",
                "effect": "Allow",
                "normalized_principals": ["s3.amazonaws.com"],
                "normalized_actions": ["sns:Publish"],
                "normalized_resources": ["arn:aws:sns:us-east-1:123456789012:uploads"],
                "condition": None,
            }
        ]
    }

    result = validate_candidates(payload, principal_policies={}, resource_policies=resource_policies)

    assert result["attack_validation"][0]["status"] == "validated"
    assert result["attack_paths"][0]["validation_status"] == "validated"


def test_resource_policy_source_arn_condition_validates_against_starting_resource() -> None:
    payload = {
        "account_id": "123456789012",
        "graph": {
            "nodes": [],
            "edges": [
                {
                    "id": "edge:event_source:data:s3:uploads->svc:s3.amazonaws.com",
                    "source": "data:s3:uploads",
                    "target": "svc:s3.amazonaws.com",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-011c",
                "name": "S3 bucket notification publishes to source-constrained SNS topic",
                "category": "data_exposure",
                "severity": "medium",
                "starting_position": {"type": "resource", "id": "data:s3:uploads", "arn": "arn:aws:s3:::uploads"},
                "initial_context": {"principal": "data:s3:uploads", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-011c-hop-001",
                        "transition": "event_injection",
                        "from_context": "data:s3:uploads",
                        "action": "s3:ObjectCreated:Put",
                        "target": "svc:s3.amazonaws.com",
                        "resulting_context": "svc:s3.amazonaws.com",
                        "capability_gained": "S3 emits an object-created event as the S3 service principal",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [{"type": "graph_edge", "id": "edge:event_source:data:s3:uploads->svc:s3.amazonaws.com"}],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-011c-hop-002",
                        "transition": "resource_policy_access",
                        "from_context": "svc:s3.amazonaws.com",
                        "action": "sns:Publish",
                        "target": "arn:aws:sns:us-east-1:123456789012:uploads",
                        "resulting_context": "messaging:sns:arn:aws:sns:us-east-1:123456789012:uploads",
                        "capability_gained": "S3 can publish object events to the topic",
                        "required": True,
                        "validation_type": "resource_policy",
                        "evidence": [{"type": "policy_document", "id": "topic-policy"}],
                        "assumptions": [],
                    },
                ],
                "impact": {"type": "data_access", "resource": "arn:aws:sns:us-east-1:123456789012:uploads", "action": "sns:Publish"},
                "affected_resources": ["arn:aws:sns:us-east-1:123456789012:uploads"],
                "detection_opportunities": ["Publish"],
                "mitre_techniques": [],
                "remediation": ["Constrain the SNS topic policy source"],
            }
        ],
    }
    resource_policies = {
        "arn:aws:sns:us-east-1:123456789012:uploads": [
            {
                "sid": "S3Publish",
                "effect": "Allow",
                "normalized_principals": ["s3.amazonaws.com"],
                "normalized_actions": ["sns:Publish"],
                "normalized_resources": ["arn:aws:sns:us-east-1:123456789012:uploads"],
                "condition": {
                    "StringEquals": {
                        "AWS:SourceArn": "arn:aws:s3:::uploads",
                        "AWS:SourceAccount": "123456789012",
                    }
                },
                "source_arns": ["arn:aws:s3:::uploads"],
                "source_accounts": ["123456789012"],
            }
        ]
    }

    result = validate_candidates(payload, principal_policies={}, resource_policies=resource_policies)

    assert result["attack_validation"][0]["status"] == "validated"
    assert result["attack_paths"][0]["validation_status"] == "validated"


def test_resource_policy_wildcard_principal_validates_service_source_context() -> None:
    payload = {
        "account_id": "123456789012",
        "graph": {
            "nodes": [],
            "edges": [
                {
                    "id": "edge:event_source:data:s3:tot-vpc-logs->svc:s3.amazonaws.com",
                    "source": "data:s3:tot-vpc-logs",
                    "target": "svc:s3.amazonaws.com",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-011d",
                "name": "S3 bucket notification publishes to SNS topic with wildcard policy principal",
                "category": "data_exposure",
                "severity": "medium",
                "starting_position": {
                    "type": "resource",
                    "id": "data:s3:tot-vpc-logs",
                    "arn": "arn:aws:s3:::tot-vpc-logs",
                },
                "initial_context": {"principal": "data:s3:tot-vpc-logs", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-011d-hop-001",
                        "transition": "event_injection",
                        "from_context": "data:s3:tot-vpc-logs",
                        "action": "s3:ObjectCreated:Put",
                        "target": "svc:s3.amazonaws.com",
                        "resulting_context": "svc:s3.amazonaws.com",
                        "capability_gained": "S3 emits an object-created event as the S3 service principal",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [
                            {
                                "type": "graph_edge",
                                "id": "edge:event_source:data:s3:tot-vpc-logs->svc:s3.amazonaws.com",
                            }
                        ],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-011d-hop-002",
                        "transition": "resource_policy_access",
                        "from_context": "svc:s3.amazonaws.com",
                        "action": "sns:Publish",
                        "target": "arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns",
                        "resulting_context": "messaging:sns:arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns",
                        "capability_gained": "S3 can publish object events to the SNS topic",
                        "required": True,
                        "validation_type": "resource_policy",
                        "evidence": [{"type": "policy_document", "id": "topic-policy"}],
                        "assumptions": [],
                    },
                ],
                "impact": {
                    "type": "data_access",
                    "resource": "arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns",
                    "action": "sns:Publish",
                },
                "affected_resources": ["arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns"],
                "detection_opportunities": ["Publish"],
                "mitre_techniques": [],
                "remediation": ["Constrain the SNS topic policy source"],
            }
        ],
    }
    resource_policies = {
        "arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns": [
            {
                "sid": "__default_statement_ID",
                "effect": "Allow",
                "normalized_principals": ["*"],
                "normalized_actions": [
                    "SNS:GetTopicAttributes",
                    "SNS:SetTopicAttributes",
                    "SNS:AddPermission",
                    "SNS:RemovePermission",
                    "SNS:DeleteTopic",
                    "SNS:Subscribe",
                    "SNS:ListSubscriptionsByTopic",
                    "SNS:Publish",
                ],
                "normalized_resources": ["arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns"],
                "condition": {"StringEquals": {"AWS:SourceOwner": "123456789012"}},
                "source_accounts": ["123456789012"],
            },
            {
                "sid": "S3-policy",
                "effect": "Allow",
                "normalized_principals": ["*"],
                "normalized_actions": ["SNS:Publish"],
                "normalized_resources": ["arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns"],
                "condition": {"StringEquals": {"AWS:SourceArn": "arn:aws:s3:::tot-vpc-logs"}},
                "source_arns": ["arn:aws:s3:::tot-vpc-logs"],
            },
        ]
    }

    result = validate_candidates(payload, principal_policies={}, resource_policies=resource_policies)

    assert result["attack_validation"][0]["status"] == "validated"
    assert result["attack_paths"][0]["validation_status"] == "validated"


def test_resource_policy_validation_rejects_non_matching_action() -> None:
    payload = {
        "graph": {"nodes": [], "edges": []},
        "candidate_attack_paths": [
            {
                "id": "cap-012",
                "name": "External principal publishes through read-only topic policy",
                "category": "data_exposure",
                "severity": "high",
                "starting_position": {
                    "type": "external",
                    "id": "external:anonymous",
                    "arn": None,
                },
                "initial_context": {"principal": "external:anonymous", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-012-hop-001",
                        "transition": "resource_policy_access",
                        "from_context": "external:anonymous",
                        "action": "sns:Publish",
                        "target": "arn:aws:sns:us-east-1:123456789012:topic",
                        "resulting_context": "arn:aws:sns:us-east-1:123456789012:topic",
                        "capability_gained": "Publish to the topic",
                        "required": True,
                        "validation_type": "resource_policy",
                        "evidence": [{"type": "policy_document", "id": "topic-policy"}],
                        "assumptions": [],
                    }
                ],
                "impact": {
                    "type": "data_access",
                    "resource": "arn:aws:sns:us-east-1:123456789012:topic",
                    "action": "sns:Publish",
                },
                "affected_resources": ["arn:aws:sns:us-east-1:123456789012:topic"],
                "detection_opportunities": ["Publish"],
                "mitre_techniques": [],
                "remediation": ["Review topic policy actions"],
            }
        ],
    }
    resource_policies = {
        "arn:aws:sns:us-east-1:123456789012:topic": [
            {
                "sid": "ReadOnly",
                "effect": "Allow",
                "normalized_principals": ["*"],
                "normalized_actions": ["sns:GetTopicAttributes"],
                "normalized_resources": ["arn:aws:sns:us-east-1:123456789012:topic"],
                "condition": None,
            }
        ]
    }

    result = validate_candidates(payload, principal_policies={}, resource_policies=resource_policies)

    assert result["attack_validation"][0]["status"] == "rejected"
    assert result["attack_validation"][0]["failed_hops"] == ["cap-012-hop-001"]
    assert result["attack_paths"] == []


def test_resource_policy_validation_rejects_source_condition_without_matching_source() -> None:
    payload = {
        "graph": {"nodes": [], "edges": []},
        "candidate_attack_paths": [
            {
                "id": "cap-013",
                "name": "Anonymous SNS publish through source-constrained policy",
                "category": "data_exposure",
                "severity": "high",
                "starting_position": {
                    "type": "external",
                    "id": "external:anonymous",
                    "arn": None,
                },
                "initial_context": {"principal": "external:anonymous", "capabilities": []},
                "hops": [
                    {
                        "id": "cap-013-hop-001",
                        "transition": "resource_policy_access",
                        "from_context": "external:anonymous",
                        "action": "sns:Publish",
                        "target": "arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns",
                        "resulting_context": "arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns",
                        "capability_gained": "Publish to the topic",
                        "required": True,
                        "validation_type": "resource_policy",
                        "evidence": [{"type": "policy_document", "id": "topic-policy"}],
                        "assumptions": [],
                    }
                ],
                "impact": {
                    "type": "data_access",
                    "resource": "arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns",
                    "action": "sns:Publish",
                },
                "affected_resources": ["arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns"],
                "detection_opportunities": ["Publish"],
                "mitre_techniques": [],
                "remediation": ["Review topic policy conditions"],
            }
        ],
    }
    resource_policies = {
        "arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns": [
            {
                "sid": "S3PublishOnly",
                "effect": "Allow",
                "normalized_principals": ["*"],
                "normalized_actions": ["sns:Publish"],
                "normalized_resources": ["arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns"],
                "condition": {
                    "StringEquals": {
                        "AWS:SourceArn": "arn:aws:s3:::tot-vpc-logs",
                    }
                },
            }
        ]
    }

    result = validate_candidates(payload, principal_policies={}, resource_policies=resource_policies)

    validation = result["attack_validation"][0]
    assert validation["status"] == "rejected"
    assert validation["failed_hops"] == ["cap-013-hop-001"]
    assert result["attack_paths"] == []


def test_validates_service_passrole_chain_with_compound_actions_and_principal_arn_context() -> None:
    payload = {
        "graph": {
            "nodes": [
                {"id": "user:Builder"},
                {"id": "role:HighPrivServiceRole"},
                {"id": "svc:codebuild.amazonaws.com"},
            ],
            "edges": [
                {
                    "id": "edge:service:svc:codebuild.amazonaws.com->role:HighPrivServiceRole",
                    "source": "svc:codebuild.amazonaws.com",
                    "target": "role:HighPrivServiceRole",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-007",
                "name": "CodeBuild can execute as high privilege role",
                "category": "privilege_escalation",
                "severity": "critical",
                "starting_position": {
                    "type": "principal",
                    "id": "user:Builder",
                    "arn": "arn:aws:iam::123456789012:user/Builder",
                },
                "initial_context": {
                    "principal": "principal:arn:aws:iam::123456789012:user/Builder",
                    "capabilities": [],
                },
                "hops": [
                    {
                        "id": "cap-007-hop-001",
                        "transition": "pass_role",
                        "from_context": "principal:arn:aws:iam::123456789012:user/Builder",
                        "action": "iam:PassRole + codebuild:CreateProject + codebuild:StartBuild",
                        "target": "arn:aws:iam::123456789012:role/HighPrivServiceRole",
                        "resulting_context": "resource:codebuild-project-created-by-attacker",
                        "capability_gained": "Create and start a build using the high privilege role",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [{"type": "policy_document", "id": "builder-policy"}],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-007-hop-002",
                        "transition": "execute_as",
                        "from_context": "resource:codebuild-project-created-by-attacker",
                        "action": "sts:AssumeRole by codebuild.amazonaws.com",
                        "target": "role:HighPrivServiceRole",
                        "resulting_context": "principal:arn:aws:iam::123456789012:role/HighPrivServiceRole",
                        "capability_gained": "CodeBuild receives role credentials",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [
                            {
                                "type": "graph_edge",
                                "id": "edge:service:svc:codebuild.amazonaws.com->role:HighPrivServiceRole",
                            }
                        ],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-007-hop-003",
                        "transition": "mutate_policy",
                        "from_context": "principal:arn:aws:iam::123456789012:role/HighPrivServiceRole",
                        "action": "iam:*",
                        "target": "arn:aws:iam::123456789012:root",
                        "resulting_context": "account administrator",
                        "capability_gained": "Administrator IAM permissions",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [{"type": "policy_document", "id": "admin-policy"}],
                        "assumptions": [],
                    },
                ],
                "impact": {
                    "type": "admin_access",
                    "resource": "arn:aws:iam::123456789012:root",
                    "action": "iam:*",
                },
                "affected_resources": ["arn:aws:iam::123456789012:role/HighPrivServiceRole"],
                "detection_opportunities": ["CreateProject", "StartBuild"],
                "mitre_techniques": [],
                "remediation": ["Scope PassRole and CodeBuild creation permissions"],
            }
        ],
    }
    principal_policies = {
        "arn:aws:iam::123456789012:user/Builder": [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:PassRole",
                            "codebuild:CreateProject",
                            "codebuild:StartBuild",
                        ],
                        "Resource": "*",
                    }
                ]
            }
        ],
        "arn:aws:iam::123456789012:role/HighPrivServiceRole": [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ]
            }
        ],
    }

    result = validate_candidates(payload, principal_policies=principal_policies)

    validation = result["attack_validation"][0]
    assert validation["status"] == "validated"
    assert validation["validated_hops"] == [
        "cap-007-hop-001",
        "cap-007-hop-002",
        "cap-007-hop-003",
    ]
    assert validation["failed_hops"] == []
    assert result["attack_paths"][0]["validation_status"] == "validated"


def test_rejects_candidate_when_impact_is_not_terminal_hop() -> None:
    payload = {
        "graph": {
            "nodes": [
                {"id": "user:Builder"},
                {"id": "role:HighPrivServiceRole"},
                {"id": "svc:codebuild.amazonaws.com"},
            ],
            "edges": [
                {
                    "id": "edge:service:svc:codebuild.amazonaws.com->role:HighPrivServiceRole",
                    "source": "svc:codebuild.amazonaws.com",
                    "target": "role:HighPrivServiceRole",
                }
            ],
        },
        "candidate_attack_paths": [
            {
                "id": "cap-014",
                "name": "Impact appears before a non-impact terminal hop",
                "category": "privilege_escalation",
                "severity": "critical",
                "starting_position": {
                    "type": "principal",
                    "id": "user:Builder",
                    "arn": "arn:aws:iam::123456789012:user/Builder",
                },
                "initial_context": {
                    "principal": "principal:arn:aws:iam::123456789012:user/Builder",
                    "capabilities": [],
                },
                "hops": [
                    {
                        "id": "cap-014-hop-001",
                        "transition": "mutate_policy",
                        "from_context": "principal:arn:aws:iam::123456789012:user/Builder",
                        "action": "iam:*",
                        "target": "arn:aws:iam::123456789012:root",
                        "resulting_context": "account administrator",
                        "capability_gained": "Administrator IAM permissions",
                        "required": True,
                        "validation_type": "iam",
                        "evidence": [{"type": "policy_document", "id": "builder-policy"}],
                        "assumptions": [],
                    },
                    {
                        "id": "cap-014-hop-002",
                        "transition": "execute_as",
                        "from_context": "resource:codebuild-project-created-by-attacker",
                        "action": "sts:AssumeRole by codebuild.amazonaws.com",
                        "target": "role:HighPrivServiceRole",
                        "resulting_context": "principal:arn:aws:iam::123456789012:role/HighPrivServiceRole",
                        "capability_gained": "CodeBuild receives role credentials",
                        "required": True,
                        "validation_type": "graph",
                        "evidence": [
                            {
                                "type": "graph_edge",
                                "id": "edge:service:svc:codebuild.amazonaws.com->role:HighPrivServiceRole",
                            }
                        ],
                        "assumptions": [],
                    },
                ],
                "impact": {
                    "type": "admin_access",
                    "resource": "arn:aws:iam::123456789012:root",
                    "action": "iam:*",
                },
                "affected_resources": ["arn:aws:iam::123456789012:role/HighPrivServiceRole"],
                "detection_opportunities": ["CreateProject", "StartBuild"],
                "mitre_techniques": [],
                "remediation": ["Scope PassRole and CodeBuild creation permissions"],
            }
        ],
    }
    principal_policies = {
        "arn:aws:iam::123456789012:user/Builder": [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ]
            }
        ]
    }

    result = validate_candidates(payload, principal_policies=principal_policies)

    validation = result["attack_validation"][0]
    assert validation["status"] == "rejected"
    assert "does not end in a concrete impact transition" in validation["reason"]
    assert result["attack_paths"] == []
