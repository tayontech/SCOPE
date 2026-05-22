from __future__ import annotations

import json
from pathlib import Path

from scope.runtime.graph import build_graph_from_run


def write_module(
    run_dir: Path,
    service: str,
    region: str,
    resources: list[dict],
    *,
    account_id: str = "123456789012",
    status: str = "complete",
) -> None:
    module_dir = run_dir / "modules" / service
    module_dir.mkdir(parents=True, exist_ok=True)
    (module_dir / f"{region}.json").write_text(
        json.dumps(
            {
                "module": service,
                "account_id": account_id,
                "region": region,
                "status": status,
                "resources": resources,
                "coverage": [],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )


def test_graph_v2_extracts_iam_and_lambda_relationship_with_evidence(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "iam",
        "global",
        [
            {
                "resource_type": "iam_role",
                "resource_id": "LambdaExecRole",
                "arn": "arn:aws:iam::123456789012:role/LambdaExecRole",
                "is_service_linked": False,
                "trust_relationships": [
                    {
                        "principal": "lambda.amazonaws.com",
                        "trust_type": "service",
                        "is_wildcard": False,
                        "has_external_id": False,
                        "has_mfa_condition": False,
                    }
                ],
            }
        ],
    )
    write_module(
        tmp_path,
        "lambda",
        "us-east-1",
        [
            {
                "resource_type": "lambda_function",
                "resource_id": "api",
                "arn": "arn:aws:lambda:us-east-1:123456789012:function:api",
                "role": "arn:aws:iam::123456789012:role/LambdaExecRole",
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    assert graph["schema_version"] == "2.0"
    assert graph["metadata"]["source"] == "scope-runtime"

    role = next(node for node in graph["nodes"] if node["id"] == "role:LambdaExecRole")
    assert role["resource_type"] == "iam_role"
    assert role["arn"] == "arn:aws:iam::123456789012:role/LambdaExecRole"
    assert role["service"] == "iam"
    assert role["region"] == "global"
    assert role["account_id"] == "123456789012"
    assert role["source_path"] == "modules/iam/global.json"

    edge = next(
        edge
        for edge in graph["edges"]
        if edge["source"] == "compute:lambda:api"
        and edge["target"] == "role:LambdaExecRole"
        and edge["edge_type"] == "executes_as"
    )
    assert edge["id"] == "edge:executes_as:compute:lambda:api->role:LambdaExecRole"
    assert edge["relationship"] == "lambda_function_executes_as_iam_role"
    assert edge["service"] == "lambda"
    assert edge["region"] == "us-east-1"
    assert edge["account_id"] == "123456789012"
    assert edge["evidence"] == [
        {
            "source_path": "modules/lambda/us-east-1.json",
            "resource_type": "lambda_function",
            "resource_id": "api",
            "arn": "arn:aws:lambda:us-east-1:123456789012:function:api",
            "field": "role",
        }
    ]


def test_graph_v2_extracts_resource_policy_and_kms_dependency_edges(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "s3",
        "global",
        [
            {
                "resource_type": "s3_bucket",
                "resource_id": "data-bucket",
                "arn": "arn:aws:s3:::data-bucket",
                "policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::data-bucket/*",
                            }
                        ],
                    }
                ),
                "policy_status": "present",
                "encryption": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/key-1"
                            }
                        }
                    ]
                },
            }
        ],
    )
    write_module(
        tmp_path,
        "kms",
        "us-east-1",
        [
            {
                "resource_type": "kms_key",
                "resource_id": "key-1",
                "arn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
                "policy_principals": ["arn:aws:iam::999999999999:root"],
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    assert any(node["id"] == "data:s3:data-bucket" for node in graph["nodes"])
    assert any(node["id"] == "data:kms:key-1" for node in graph["nodes"])
    assert any(
        edge["source"] == "external:arn:aws:iam::999999999999:root"
        and edge["target"] == "data:s3:data-bucket"
        and edge["edge_type"] == "resource_policy_allows"
        and edge["relationship"] == "s3_bucket_policy_allows_principal"
        for edge in graph["edges"]
    )
    assert any(
        edge["source"] == "data:s3:data-bucket"
        and edge["target"] == "data:kms:key-1"
        and edge["edge_type"] == "encrypted_by"
        and edge["relationship"] == "s3_bucket_encrypted_by_kms_key"
        for edge in graph["edges"]
    )
