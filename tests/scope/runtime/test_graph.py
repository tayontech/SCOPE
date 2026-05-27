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
                        "has_external_id": True,
                        "has_mfa_condition": False,
                        "actions": ["sts:AssumeRole"],
                        "conditions": {"StringEquals": {"sts:ExternalId": "app-123"}},
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

    trust_edge = next(
        edge
        for edge in graph["edges"]
        if edge["source"] == "svc:lambda.amazonaws.com"
        and edge["target"] == "role:LambdaExecRole"
        and edge["relationship"] == "iam_role_trusts_principal"
    )
    assert trust_edge["trust_actions"] == ["sts:AssumeRole"]
    assert trust_edge["conditions"] == {"StringEquals": {"sts:ExternalId": "app-123"}}
    assert trust_edge["has_external_id"] is True


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


def test_graph_v2_extracts_statement_aware_resource_policy_edges(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "sns",
        "us-east-1",
        [
            {
                "resource_type": "sns_topic",
                "resource_id": "vpc-flow-logs-sns",
                "arn": "arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns",
                "resource_policy_statements": [
                    {
                        "sid": "S3PublishOnly",
                        "effect": "Allow",
                        "principal": "*",
                        "action": ["sns:Publish"],
                        "resource": ["arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns"],
                        "condition": {
                            "StringEquals": {
                                "AWS:SourceArn": "arn:aws:s3:::tot-vpc-logs",
                            }
                        },
                        "normalized_principals": ["*"],
                        "normalized_actions": ["sns:Publish"],
                        "normalized_resources": ["arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns"],
                        "source_arns": ["arn:aws:s3:::tot-vpc-logs"],
                        "source_accounts": [],
                        "source_org_ids": [],
                        "service_principals": [],
                        "is_public": True,
                        "is_cross_account": False,
                    }
                ],
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    edge = next(
        edge
        for edge in graph["edges"]
        if edge["source"] == "external:anonymous"
        and edge["target"] == "messaging:sns:arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns"
        and edge["relationship"] == "sns_topic_policy_statement_allows_action"
    )
    assert edge["edge_type"] == "resource_policy_statement"
    assert edge["actions"] == ["sns:Publish"]
    assert edge["resources"] == ["arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns"]
    assert edge["conditions"] == {"StringEquals": {"AWS:SourceArn": "arn:aws:s3:::tot-vpc-logs"}}
    assert edge["statement_id"] == "S3PublishOnly"


def test_graph_v2_extracts_s3_notification_edges(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "s3",
        "global",
        [
            {
                "resource_type": "s3_bucket",
                "resource_id": "uploads",
                "arn": "arn:aws:s3:::uploads",
                "notification_configuration": {
                    "LambdaFunctionConfigurations": [
                        {
                            "Id": "ProcessUploads",
                            "LambdaFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:processor",
                            "Events": ["s3:ObjectCreated:*"],
                        }
                    ],
                    "TopicConfigurations": [
                        {
                            "Id": "PublishUploads",
                            "TopicArn": "arn:aws:sns:us-east-1:123456789012:uploads",
                            "Events": ["s3:ObjectCreated:Put"],
                        }
                    ],
                    "QueueConfigurations": [
                        {
                            "Id": "QueueUploads",
                            "QueueArn": "arn:aws:sqs:us-east-1:123456789012:uploads",
                            "Events": ["s3:ObjectCreated:Put"],
                        }
                    ],
                },
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    assert any(
        edge["source"] == "data:s3:uploads"
        and edge["target"] == "compute:lambda:processor"
        and edge["edge_type"] == "event_source"
        and edge["relationship"] == "s3_bucket_notifies_lambda_function"
        and edge["events"] == ["s3:ObjectCreated:*"]
        for edge in graph["edges"]
    )
    assert any(
        edge["source"] == "data:s3:uploads"
        and edge["target"] == "messaging:sns:arn:aws:sns:us-east-1:123456789012:uploads"
        and edge["edge_type"] == "event_source"
        and edge["relationship"] == "s3_bucket_notifies_sns_topic"
        and edge["events"] == ["s3:ObjectCreated:Put"]
        for edge in graph["edges"]
    )
    assert any(
        edge["source"] == "data:s3:uploads"
        and edge["target"] == "messaging:sqs:arn:aws:sqs:us-east-1:123456789012:uploads"
        and edge["edge_type"] == "event_source"
        and edge["relationship"] == "s3_bucket_notifies_sqs_queue"
        and edge["events"] == ["s3:ObjectCreated:Put"]
        for edge in graph["edges"]
    )


def test_graph_v2_extracts_sns_subscription_edges(tmp_path: Path) -> None:
    topic_arn = "arn:aws:sns:us-east-1:123456789012:uploads"
    queue_arn = "arn:aws:sqs:us-east-1:123456789012:uploads-queue"
    function_arn = "arn:aws:lambda:us-east-1:123456789012:function:processor"
    write_module(
        tmp_path,
        "sns",
        "us-east-1",
        [
            {
                "resource_type": "sns_topic",
                "resource_id": "uploads",
                "arn": topic_arn,
                "subscriptions": [
                    {
                        "subscription_arn": f"{topic_arn}:sub-1",
                        "protocol": "sqs",
                        "endpoint": queue_arn,
                    },
                    {
                        "subscription_arn": f"{topic_arn}:sub-2",
                        "protocol": "lambda",
                        "endpoint": function_arn,
                    },
                ],
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    assert any(
        edge["source"] == f"messaging:sns:{topic_arn}"
        and edge["target"] == f"messaging:sqs:{queue_arn}"
        and edge["edge_type"] == "event_source"
        and edge["relationship"] == "sns_topic_delivers_to_sqs_queue"
        for edge in graph["edges"]
    )
    assert any(
        edge["source"] == f"messaging:sns:{topic_arn}"
        and edge["target"] == "compute:lambda:processor"
        and edge["edge_type"] == "event_source"
        and edge["relationship"] == "sns_topic_invokes_lambda_function"
        for edge in graph["edges"]
    )


def test_graph_v2_extracts_lambda_event_source_mapping_edges(tmp_path: Path) -> None:
    queue_arn = "arn:aws:sqs:us-east-1:123456789012:uploads-queue"
    write_module(
        tmp_path,
        "lambda",
        "us-east-1",
        [
            {
                "resource_type": "lambda_function",
                "resource_id": "processor",
                "arn": "arn:aws:lambda:us-east-1:123456789012:function:processor",
                "role": "arn:aws:iam::123456789012:role/processor-role",
                "event_source_mappings": [
                    {
                        "uuid": "mapping-1",
                        "event_source_arn": queue_arn,
                        "function_arn": "arn:aws:lambda:us-east-1:123456789012:function:processor",
                        "state": "Enabled",
                        "batch_size": 10,
                    }
                ],
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    assert any(
        edge["source"] == f"messaging:sqs:{queue_arn}"
        and edge["target"] == "compute:lambda:processor"
        and edge["edge_type"] == "event_source"
        and edge["relationship"] == "sqs_queue_triggers_lambda_function"
        and edge["mapping_uuid"] == "mapping-1"
        for edge in graph["edges"]
    )


def test_graph_v2_extracts_apigateway_statement_aware_resource_policy_edges(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "apigateway",
        "us-east-1",
        [
            {
                "resource_type": "apigateway_rest_api",
                "resource_id": "abc123def4",
                "arn": "arn:aws:apigateway:us-east-1::/restapis/abc123def4",
                "lambda_integrations": [],
                "resource_policy_statements": [
                    {
                        "sid": "ExternalInvoke",
                        "effect": "Allow",
                        "normalized_principals": ["arn:aws:iam::999999999999:role/Caller"],
                        "normalized_actions": ["execute-api:Invoke"],
                        "normalized_resources": [
                            "arn:aws:execute-api:us-east-1:123456789012:abc123def4/*/*/*"
                        ],
                        "condition": None,
                        "source_arns": [],
                        "source_accounts": [],
                        "source_org_ids": [],
                        "is_public": False,
                        "is_cross_account": True,
                    }
                ],
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    edge = next(
        edge
        for edge in graph["edges"]
        if edge["source"] == "external:arn:aws:iam::999999999999:role/Caller"
        and edge["target"] == "gateway:apigw:abc123def4"
        and edge["relationship"] == "apigateway_rest_api_policy_statement_allows_action"
    )
    assert edge["edge_type"] == "resource_policy_statement"
    assert edge["actions"] == ["execute-api:Invoke"]
    assert edge["is_cross_account"] is True


def test_graph_v2_extracts_public_apigateway_lambda_role_path(tmp_path: Path) -> None:
    function_arn = "arn:aws:lambda:us-east-1:123456789012:function:payments"
    role_arn = "arn:aws:iam::123456789012:role/payments-role"
    write_module(
        tmp_path,
        "apigateway",
        "us-east-1",
        [
            {
                "resource_type": "apigateway_http_api",
                "resource_id": "api123",
                "arn": "arn:aws:apigateway:us-east-1::/apis/api123",
                "public_endpoint": True,
                "lambda_integrations": [function_arn],
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
                "resource_id": "payments",
                "arn": function_arn,
                "role": role_arn,
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    expected_edges = {
        ("external:https", "gateway:apigw:api123", "public_access", "public_https_reaches_apigateway_api"),
        ("gateway:apigw:api123", "compute:lambda:payments", "invokes", "apigateway_invokes_lambda_function"),
        ("compute:lambda:payments", "role:payments-role", "executes_as", "lambda_function_executes_as_iam_role"),
    }
    actual_edges = {
        (edge["source"], edge["target"], edge["edge_type"], edge["relationship"])
        for edge in graph["edges"]
    }
    assert expected_edges <= actual_edges


def test_graph_v2_extracts_lambda_statement_aware_resource_policy_edges(tmp_path: Path) -> None:
    function_arn = "arn:aws:lambda:us-east-1:123456789012:function:public-handler"
    write_module(
        tmp_path,
        "lambda",
        "us-east-1",
        [
            {
                "resource_type": "lambda_function",
                "resource_id": "public-handler",
                "arn": function_arn,
                "resource_policy_statements": [
                    {
                        "sid": "PublicFunctionUrl",
                        "effect": "Allow",
                        "normalized_principals": ["*"],
                        "normalized_actions": ["lambda:InvokeFunctionUrl"],
                        "normalized_resources": [function_arn],
                        "condition": {
                            "StringEquals": {
                                "lambda:FunctionUrlAuthType": "NONE",
                            }
                        },
                        "source_arns": [],
                        "source_accounts": [],
                        "source_org_ids": [],
                        "is_public": True,
                        "is_cross_account": False,
                    }
                ],
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    edge = next(
        edge
        for edge in graph["edges"]
        if edge["source"] == "external:anonymous"
        and edge["target"] == "compute:lambda:public-handler"
        and edge["relationship"] == "lambda_function_policy_statement_allows_action"
    )
    assert edge["edge_type"] == "resource_policy_statement"
    assert edge["actions"] == ["lambda:InvokeFunctionUrl"]
    assert edge["conditions"] == {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}


def test_graph_v2_extracts_cloudfront_public_endpoint_and_origin_edges(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "cloudfront",
        "global",
        [
            {
                "resource_type": "cloudfront_distribution",
                "resource_id": "E123ABC",
                "arn": "arn:aws:cloudfront::123456789012:distribution/E123ABC",
                "domain_name": "d111111abcdef8.cloudfront.net",
                "enabled": True,
                "public_endpoint": True,
                "origins": [
                    {
                        "id": "alb-origin",
                        "domain_name": "app-alb-123.us-east-1.elb.amazonaws.com",
                        "origin_type": "custom",
                    }
                ],
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    assert any(node["id"] == "gateway:cloudfront:E123ABC" for node in graph["nodes"])
    assert any(
        edge["source"] == "external:public"
        and edge["target"] == "gateway:cloudfront:E123ABC"
        and edge["edge_type"] == "public_access"
        and edge["relationship"] == "cloudfront_distribution_public_endpoint"
        for edge in graph["edges"]
    )
    assert any(
        edge["source"] == "gateway:cloudfront:E123ABC"
        and edge["target"] == "external:dns:app-alb-123.us-east-1.elb.amazonaws.com"
        and edge["edge_type"] == "network"
        and edge["relationship"] == "cloudfront_distribution_routes_to_origin"
        for edge in graph["edges"]
    )


def test_graph_v2_extracts_route53_public_dns_edges(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "route53",
        "global",
        [
            {
                "resource_type": "route53_hosted_zone",
                "resource_id": "Z123",
                "arn": "arn:aws:route53:::hostedzone/Z123",
                "name": "example.com.",
                "public_zone": True,
                "records": [
                    {
                        "name": "app.example.com.",
                        "type": "CNAME",
                        "public_dns": True,
                        "target_values": ["d111111abcdef8.cloudfront.net"],
                        "aws_target_type": "cloudfront",
                        "dangling_dns_candidate": True,
                    }
                ],
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    assert any(node["id"] == "gateway:route53:app.example.com." for node in graph["nodes"])
    assert any(
        edge["source"] == "external:public"
        and edge["target"] == "gateway:route53:app.example.com."
        and edge["edge_type"] == "public_access"
        and edge["relationship"] == "route53_record_public_dns"
        for edge in graph["edges"]
    )
    assert any(
        edge["source"] == "gateway:route53:app.example.com."
        and edge["target"] == "external:dns:d111111abcdef8.cloudfront.net"
        and edge["edge_type"] == "network"
        and edge["relationship"] == "route53_record_resolves_to_target"
        and edge["dangling_dns_candidate"] is True
        for edge in graph["edges"]
    )


def test_graph_v2_correlates_route53_record_to_collected_cloudfront_distribution(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "route53",
        "global",
        [
            {
                "resource_type": "route53_hosted_zone",
                "resource_id": "Z123",
                "arn": "arn:aws:route53:::hostedzone/Z123",
                "name": "example.com.",
                "public_zone": True,
                "records": [
                    {
                        "name": "app.example.com.",
                        "type": "CNAME",
                        "public_dns": True,
                        "target_values": ["d111111abcdef8.cloudfront.net"],
                        "aws_target_type": "cloudfront",
                        "dangling_dns_candidate": True,
                    }
                ],
            }
        ],
    )
    write_module(
        tmp_path,
        "cloudfront",
        "global",
        [
            {
                "resource_type": "cloudfront_distribution",
                "resource_id": "E123ABC",
                "arn": "arn:aws:cloudfront::123456789012:distribution/E123ABC",
                "domain_name": "d111111abcdef8.cloudfront.net",
                "enabled": True,
                "public_endpoint": True,
                "aliases": ["app.example.com"],
                "origins": [],
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    assert any(
        edge["source"] == "gateway:route53:app.example.com."
        and edge["target"] == "gateway:cloudfront:E123ABC"
        and edge["edge_type"] == "network"
        and edge["relationship"] == "route53_record_resolves_to_cloudfront_distribution"
        and edge["dangling_dns_candidate"] is False
        for edge in graph["edges"]
    )


def test_graph_v2_correlates_cloudfront_origin_to_collected_alb(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "cloudfront",
        "global",
        [
            {
                "resource_type": "cloudfront_distribution",
                "resource_id": "E123ABC",
                "arn": "arn:aws:cloudfront::123456789012:distribution/E123ABC",
                "domain_name": "d111111abcdef8.cloudfront.net",
                "enabled": True,
                "public_endpoint": True,
                "origins": [
                    {
                        "id": "alb-origin",
                        "domain_name": "app-alb-123.us-east-1.elb.amazonaws.com",
                        "origin_type": "custom",
                    }
                ],
            }
        ],
    )
    write_module(
        tmp_path,
        "ec2",
        "us-east-1",
        [
            {
                "resource_type": "ec2_load_balancer",
                "resource_id": "app-alb",
                "arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-alb/abc",
                "type": "application",
                "scheme": "internet-facing",
                "dns_name": "app-alb-123.us-east-1.elb.amazonaws.com",
                "listeners": [],
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    assert any(
        edge["source"] == "gateway:cloudfront:E123ABC"
        and edge["target"] == "gateway:alb:app-alb"
        and edge["edge_type"] == "network"
        and edge["relationship"] == "cloudfront_distribution_routes_to_load_balancer"
        for edge in graph["edges"]
    )


def test_graph_v2_extracts_alb_target_group_ecs_task_role_path(tmp_path: Path) -> None:
    lb_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/aws-goat-m2-alb/abc"
    tg_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/aws-goat-m2-tg/def"
    service_arn = "arn:aws:ecs:us-east-1:123456789012:service/aws-goat/ecs_service_worker"
    task_definition_arn = "arn:aws:ecs:us-east-1:123456789012:task-definition/aws-goat-m2:3"
    task_role_arn = "arn:aws:iam::123456789012:role/ecs-task-role"
    write_module(
        tmp_path,
        "ec2",
        "us-east-1",
        [
            {
                "resource_type": "ec2_load_balancer",
                "resource_id": "aws-goat-m2-alb",
                "arn": lb_arn,
                "type": "application",
                "scheme": "internet-facing",
                "listeners": [
                    {
                        "arn": f"{lb_arn}/listener/app/123",
                        "port": 80,
                        "protocol": "HTTP",
                        "target_group_arns": [tg_arn],
                    }
                ],
            },
            {
                "resource_type": "ec2_target_group",
                "resource_id": "aws-goat-m2-tg",
                "arn": tg_arn,
                "load_balancer_arns": [lb_arn],
            },
        ],
    )
    write_module(
        tmp_path,
        "ecs",
        "us-east-1",
        [
            {
                "resource_type": "ecs_service",
                "resource_id": "ecs_service_worker",
                "arn": service_arn,
                "task_definition_arn": task_definition_arn,
                "load_balancers": [
                    {
                        "target_group_arn": tg_arn,
                        "container_name": "worker",
                        "container_port": 80,
                    }
                ],
            },
            {
                "resource_type": "ecs_task_definition",
                "resource_id": "aws-goat-m2:3",
                "arn": task_definition_arn,
                "task_role_arn": task_role_arn,
                "execution_role_arn": "arn:aws:iam::123456789012:role/ecs-execution-role",
            },
        ],
    )

    graph = build_graph_from_run(tmp_path)

    expected_edges = {
        ("external:http", "gateway:alb:aws-goat-m2-alb", "public_access", "public_http_reaches_load_balancer"),
        ("gateway:alb:aws-goat-m2-alb", "gateway:target-group:aws-goat-m2-tg", "network", "load_balancer_listener_routes_to_target_group"),
        ("gateway:target-group:aws-goat-m2-tg", "compute:ecs-service:ecs_service_worker", "network", "target_group_routes_to_ecs_service"),
        ("compute:ecs-service:ecs_service_worker", "compute:ecs-task-definition:aws-goat-m2:3", "service", "ecs_service_uses_task_definition"),
        ("compute:ecs-task-definition:aws-goat-m2:3", "role:ecs-task-role", "executes_as", "ecs_task_definition_uses_task_role"),
    }
    actual_edges = {
        (edge["source"], edge["target"], edge["edge_type"], edge["relationship"])
        for edge in graph["edges"]
    }
    assert expected_edges <= actual_edges
    assert any(node["id"] == "external:http" and node["type"] == "external" for node in graph["nodes"])


def test_graph_v2_extracts_public_security_group_to_ec2_role_path(tmp_path: Path) -> None:
    instance_profile = "arn:aws:iam::123456789012:instance-profile/web-profile"
    role_arn = "arn:aws:iam::123456789012:role/web-role"
    write_module(
        tmp_path,
        "ec2",
        "us-east-1",
        [
            {
                "resource_type": "ec2_security_group",
                "resource_id": "sg-public",
                "arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-public",
                "inbound_rules": [
                    {
                        "protocol": "tcp",
                        "from_port": 80,
                        "to_port": 80,
                        "sources": ["0.0.0.0/0"],
                    }
                ],
            },
            {
                "resource_type": "ec2_instance",
                "resource_id": "i-123",
                "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-123",
                "public_ip": "198.51.100.10",
                "security_groups": ["sg-public"],
                "iam_instance_profile": {
                    "arn": instance_profile,
                    "role_arn": role_arn,
                },
            },
        ],
    )

    graph = build_graph_from_run(tmp_path)

    expected_edges = {
        ("external:http", "network:sg:sg-public", "public_access", "security_group_allows_public_ingress"),
        ("network:sg:sg-public", "compute:ec2:i-123", "network", "security_group_attached_to_ec2_instance"),
        ("compute:ec2:i-123", "role:web-role", "executes_as", "ec2_instance_executes_as_iam_role"),
    }
    actual_edges = {
        (edge["source"], edge["target"], edge["edge_type"], edge["relationship"])
        for edge in graph["edges"]
    }
    assert expected_edges <= actual_edges


def test_graph_v2_extracts_public_rds_network_exposure_edges(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "ec2",
        "us-east-1",
        [
            {
                "resource_type": "ec2_security_group",
                "resource_id": "sg-db",
                "arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-db",
                "inbound_rules": [
                    {
                        "protocol": "tcp",
                        "from_port": 5432,
                        "to_port": 5432,
                        "sources": ["0.0.0.0/0"],
                    }
                ],
            }
        ],
    )
    write_module(
        tmp_path,
        "rds",
        "us-east-1",
        [
            {
                "resource_type": "rds_instance",
                "resource_id": "prod-db",
                "arn": "arn:aws:rds:us-east-1:123456789012:db:prod-db",
                "endpoint": "prod-db.abc.us-east-1.rds.amazonaws.com",
                "port": 5432,
                "publicly_accessible": True,
                "security_groups": [{"id": "sg-db", "status": "active"}],
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    expected_edges = {
        ("external:public", "network:sg:sg-db", "public_access", "security_group_allows_public_ingress"),
        ("external:public", "data:rds:prod-db", "public_access", "rds_instance_public_endpoint"),
        ("network:sg:sg-db", "data:rds:prod-db", "network", "security_group_attached_to_rds_instance"),
    }
    actual_edges = {
        (edge["source"], edge["target"], edge["edge_type"], edge["relationship"])
        for edge in graph["edges"]
    }
    assert expected_edges <= actual_edges


def test_graph_v2_extracts_cognito_unauthenticated_identity_role_path(tmp_path: Path) -> None:
    write_module(
        tmp_path,
        "cognito",
        "us-east-1",
        [
            {
                "resource_type": "cognito_identity_pool",
                "resource_id": "CustomerIdentityPool",
                "arn": "arn:aws:cognito-identity:us-east-1:123456789012:identitypool/us-east-1:pool-abc123",
                "pool_id": "us-east-1:pool-abc123",
                "allow_unauthenticated": True,
                "unauthenticated_role_arn": "arn:aws:iam::123456789012:role/CognitoUnauthRole",
                "authenticated_role_arn": "arn:aws:iam::123456789012:role/CognitoAuthRole",
            }
        ],
    )

    graph = build_graph_from_run(tmp_path)

    assert any(node["id"] == "idp:cognito:us-east-1:pool-abc123" for node in graph["nodes"])
    expected_edges = {
        (
            "external:anonymous",
            "idp:cognito:us-east-1:pool-abc123",
            "public_access",
            "cognito_identity_pool_allows_unauthenticated_identity",
        ),
        (
            "idp:cognito:us-east-1:pool-abc123",
            "role:CognitoUnauthRole",
            "authenticates_to",
            "cognito_identity_pool_unauthenticated_role",
        ),
        (
            "idp:cognito:us-east-1:pool-abc123",
            "role:CognitoAuthRole",
            "authenticates_to",
            "cognito_identity_pool_authenticated_role",
        ),
    }
    actual_edges = {
        (edge["source"], edge["target"], edge["edge_type"], edge["relationship"])
        for edge in graph["edges"]
    }
    assert expected_edges <= actual_edges
