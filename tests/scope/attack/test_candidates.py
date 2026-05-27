from __future__ import annotations

import json
from pathlib import Path

from scope.attack.candidates import (
    generate_iam_candidates,
    generate_iam_candidates_only_from_run,
    generate_public_service_candidates,
)
from scope.attack.validate_paths import validate_candidates


ACCOUNT_ID = "123456789012"
USER_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/Alice"
TARGET_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/AdminRole"


def _policy(action: str | list[str], resource: str | list[str]) -> dict[str, object]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": action,
                "Resource": resource,
            }
        ],
    }


def _user(name: str, arn: str, policies: list[dict[str, object]]) -> dict[str, object]:
    return {
        "resource_type": "iam_user",
        "resource_id": name,
        "arn": arn,
        "groups": [],
        "attached_policies": [
            {"policy_name": f"{name}Policy", "document": document}
            for document in policies
        ],
        "inline_policies": [],
    }


def _role(name: str, arn: str, policies: list[dict[str, object]]) -> dict[str, object]:
    return {
        "resource_type": "iam_role",
        "resource_id": name,
        "arn": arn,
        "is_service_linked": False,
        "attached_policies": [
            {"policy_name": f"{name}Policy", "document": document}
            for document in policies
        ],
        "inline_policies": [],
    }


def _write_run_module(run_dir: Path, service: str, region: str, resources: list[dict[str, object]]) -> None:
    module_dir = run_dir / "modules" / service
    module_dir.mkdir(parents=True, exist_ok=True)
    (module_dir / f"{region}.json").write_text(
        json.dumps(
            {
                "module": service,
                "account_id": ACCOUNT_ID,
                "region": region,
                "status": "complete",
                "resources": resources,
                "coverage": [],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )


def test_generates_and_validates_assume_role_candidate_with_terminal_impact() -> None:
    source_policy = _policy("sts:AssumeRole", TARGET_ROLE_ARN)
    target_policy = _policy("iam:CreateUser", "*")
    graph = {
        "edges": [
            {
                "id": "edge:trust:user:Alice->role:AdminRole",
                "relationship": "iam_role_trusts_principal",
                "source": "user:Alice",
                "target": "role:AdminRole",
            }
        ]
    }

    candidates = generate_iam_candidates(
        iam_payload={
            "resources": [
                _user("Alice", USER_ARN, [source_policy]),
                _role("AdminRole", TARGET_ROLE_ARN, [target_policy]),
            ]
        },
        graph=graph,
    )

    assert [candidate["name"] for candidate in candidates] == [
        "Alice can assume AdminRole and reach iam:CreateUser"
    ]
    assert [hop["transition"] for hop in candidates[0]["hops"]] == [
        "assume_role",
        "assume_role",
        "mutate_policy",
    ]
    assert candidates[0]["hops"][-1]["action"] == "iam:CreateUser"

    result = validate_candidates(
        {"graph": graph, "candidate_attack_paths": candidates},
        principal_policies={
            "user:Alice": [source_policy],
            TARGET_ROLE_ARN: [target_policy],
        },
    )

    assert result["attack_validation"][0]["status"] == "validated"
    assert result["attack_paths"][0]["source_candidate_id"] == candidates[0]["id"]


def test_generates_and_validates_passrole_service_candidate() -> None:
    source_policy = _policy(
        ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"],
        "*",
    )
    target_policy = _policy("secretsmanager:GetSecretValue", "*")
    graph = {
        "edges": [
            {
                "id": "edge:trust:svc:codebuild.amazonaws.com->role:AdminRole",
                "relationship": "iam_role_trusts_principal",
                "source": "svc:codebuild.amazonaws.com",
                "target": "role:AdminRole",
            }
        ]
    }

    candidates = generate_iam_candidates(
        iam_payload={
            "resources": [
                _user("Alice", USER_ARN, [source_policy]),
                _role("AdminRole", TARGET_ROLE_ARN, [target_policy]),
            ]
        },
        graph=graph,
    )

    assert [candidate["name"] for candidate in candidates] == [
        "Alice can pass AdminRole to codebuild and reach secretsmanager:GetSecretValue"
    ]
    assert [hop["transition"] for hop in candidates[0]["hops"]] == [
        "pass_role",
        "execute_as",
        "data_access",
    ]

    result = validate_candidates(
        {"graph": graph, "candidate_attack_paths": candidates},
        principal_policies={
            "user:Alice": [source_policy],
            TARGET_ROLE_ARN: [target_policy],
        },
    )

    assert result["attack_validation"][0]["status"] == "validated"
    assert result["attack_paths"][0]["source_candidate_id"] == candidates[0]["id"]


def test_does_not_generate_cloudformation_passrole_candidate() -> None:
    source_policy = _policy(
        ["iam:PassRole", "cloudformation:CreateStack"],
        "*",
    )
    target_policy = _policy("secretsmanager:GetSecretValue", "*")
    graph = {
        "edges": [
            {
                "id": "edge:trust:svc:cloudformation.amazonaws.com->role:AdminRole",
                "relationship": "iam_role_trusts_principal",
                "source": "svc:cloudformation.amazonaws.com",
                "target": "role:AdminRole",
            }
        ]
    }

    candidates = generate_iam_candidates(
        iam_payload={
            "resources": [
                _user("Alice", USER_ARN, [source_policy]),
                _role("AdminRole", TARGET_ROLE_ARN, [target_policy]),
            ]
        },
        graph=graph,
    )

    assert candidates == []


def test_does_not_generate_candidate_when_target_role_has_no_collected_impact() -> None:
    source_policy = _policy("sts:AssumeRole", TARGET_ROLE_ARN)
    target_policy = _policy("logs:CreateLogStream", "*")
    graph = {
        "edges": [
            {
                "id": "edge:trust:user:Alice->role:AdminRole",
                "relationship": "iam_role_trusts_principal",
                "source": "user:Alice",
                "target": "role:AdminRole",
            }
        ]
    }

    candidates = generate_iam_candidates(
        iam_payload={
            "resources": [
                _user("Alice", USER_ARN, [source_policy]),
                _role("AdminRole", TARGET_ROLE_ARN, [target_policy]),
            ]
        },
        graph=graph,
    )

    assert candidates == []


def test_generates_admin_impact_for_iam_policy_mutation_family() -> None:
    target_role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/PolicyAdmin"
    source_policy = _policy("sts:AssumeRole", target_role_arn)
    target_policy = _policy("iam:PutRolePolicy", "*")
    graph = {
        "edges": [
            {
                "id": "edge:trust:user:Alice->role:PolicyAdmin",
                "relationship": "iam_role_trusts_principal",
                "source": "user:Alice",
                "target": "role:PolicyAdmin",
            }
        ]
    }

    candidates = generate_iam_candidates(
        iam_payload={
            "resources": [
                _user("Alice", USER_ARN, [source_policy]),
                _role("PolicyAdmin", target_role_arn, [target_policy]),
            ]
        },
        graph=graph,
    )

    assert [candidate["name"] for candidate in candidates] == [
        "Alice can assume PolicyAdmin and reach iam:PutRolePolicy"
    ]
    assert candidates[0]["impact"] == {
        "type": "admin_access",
        "resource": "*",
        "action": "iam:PutRolePolicy",
    }


def test_generates_conditional_public_service_candidate_from_graph_backed_role_path() -> None:
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/EcsTaskRole"
    graph = {
        "edges": [
            {
                "id": "edge:public_access:external:http->gateway:alb:app",
                "edge_type": "public_access",
                "relationship": "public_http_reaches_load_balancer",
                "source": "external:http",
                "target": "gateway:alb:app",
                "protocol": "HTTP",
            },
            {
                "id": "edge:network:gateway:alb:app->gateway:target-group:tg",
                "edge_type": "network",
                "relationship": "load_balancer_listener_routes_to_target_group",
                "source": "gateway:alb:app",
                "target": "gateway:target-group:tg",
            },
            {
                "id": "edge:network:gateway:target-group:tg->compute:ecs-service:svc",
                "edge_type": "network",
                "relationship": "target_group_routes_to_ecs_service",
                "source": "gateway:target-group:tg",
                "target": "compute:ecs-service:svc",
            },
            {
                "id": "edge:service:compute:ecs-service:svc->compute:ecs-task-definition:task:1",
                "edge_type": "service",
                "relationship": "ecs_service_uses_task_definition",
                "source": "compute:ecs-service:svc",
                "target": "compute:ecs-task-definition:task:1",
            },
            {
                "id": "edge:executes_as:compute:ecs-task-definition:task:1->role:EcsTaskRole",
                "edge_type": "executes_as",
                "relationship": "ecs_task_definition_uses_task_role",
                "source": "compute:ecs-task-definition:task:1",
                "target": "role:EcsTaskRole",
            },
        ]
    }
    results = {
        "public_entrypoints": [
            {
                "id": "entry-elb-app-http",
                "service": "ec2",
                "arn": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT_ID}:loadbalancer/app/app/123",
                "attack_path_seed": True,
                "execution_roles": [role_arn],
                "invokes": [
                    f"arn:aws:ecs:us-east-1:{ACCOUNT_ID}:service/cluster/svc",
                    f"arn:aws:ecs:us-east-1:{ACCOUNT_ID}:task-definition/task:1",
                ],
                "evidence": [{"type": "graph_edge", "id": edge["id"]} for edge in graph["edges"]],
            }
        ]
    }
    iam_payload = {
        "resources": [
            {
                "resource_type": "iam_role",
                "resource_id": "EcsTaskRole",
                "arn": role_arn,
                "is_service_linked": False,
                "attached_policies": [
                    {
                        "name": "SecretsManagerReadWrite",
                        "arn": "arn:aws:iam::aws:policy/SecretsManagerReadWrite",
                        "document": None,
                    }
                ],
                "inline_policies": [],
            }
        ]
    }

    candidates = generate_public_service_candidates(
        results=results,
        iam_payload=iam_payload,
        graph=graph,
        module_resources=[
            {
                "resource_type": "secrets_secret",
                "resource_id": "RDS_CREDS",
                "arn": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:RDS_CREDS-AbCdEf",
                "_source_path": "modules/secrets/us-east-1.json",
            }
        ],
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["starting_position"] == {
        "type": "public_endpoint",
        "id": "entry-elb-app-http",
        "arn": f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT_ID}:loadbalancer/app/app/123",
    }
    assert [hop["validation_type"] for hop in candidate["hops"]] == [
        "graph",
        "graph",
        "graph",
        "graph",
        "graph",
        "runtime_assumption",
        "runtime_assumption",
    ]
    assert candidate["hops"][-2]["transition"] == "invoke"
    assert "Backend code reachable from entry-elb-app-http" in candidate["hops"][-2]["assumptions"][0]
    assert candidate["impact"] == {
        "type": "data_access",
        "resource": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:RDS_CREDS-AbCdEf",
        "action": "secretsmanager:GetSecretValue",
    }


def test_generates_s3_impact_for_resource_scoped_policy_on_matching_bucket() -> None:
    target_role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/S3Reader"
    source_policy = _policy("sts:AssumeRole", target_role_arn)
    target_policy = _policy("s3:GetObject", "arn:aws:s3:::bucket-b/*")
    graph = {
        "edges": [
            {
                "id": "edge:trust:user:Alice->role:S3Reader",
                "relationship": "iam_role_trusts_principal",
                "source": "user:Alice",
                "target": "role:S3Reader",
            }
        ]
    }

    candidates = generate_iam_candidates(
        iam_payload={
            "resources": [
                _user("Alice", USER_ARN, [source_policy]),
                _role("S3Reader", target_role_arn, [target_policy]),
            ]
        },
        graph=graph,
        module_resources=[
            {
                "resource_type": "s3_bucket",
                "resource_id": "bucket-a",
                "arn": "arn:aws:s3:::bucket-a",
            },
            {
                "resource_type": "s3_bucket",
                "resource_id": "bucket-b",
                "arn": "arn:aws:s3:::bucket-b",
            },
        ],
    )

    assert [candidate["name"] for candidate in candidates] == [
        "Alice can assume S3Reader and reach s3:GetObject"
    ]
    assert candidates[0]["impact"] == {
        "type": "data_access",
        "resource": "arn:aws:s3:::bucket-b/*",
        "action": "s3:GetObject",
    }


def test_does_not_generate_public_service_data_path_without_concrete_data_resource() -> None:
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/EcsTaskRole"
    graph = {
        "edges": [
            {
                "id": "edge:public_access:external:http->gateway:alb:app",
                "edge_type": "public_access",
                "relationship": "public_http_reaches_load_balancer",
                "source": "external:http",
                "target": "gateway:alb:app",
            },
            {
                "id": "edge:network:gateway:alb:app->compute:ecs-service:svc",
                "edge_type": "network",
                "relationship": "load_balancer_listener_routes_to_ecs_service",
                "source": "gateway:alb:app",
                "target": "compute:ecs-service:svc",
            },
            {
                "id": "edge:executes_as:compute:ecs-service:svc->role:EcsTaskRole",
                "edge_type": "executes_as",
                "relationship": "ecs_service_uses_task_role",
                "source": "compute:ecs-service:svc",
                "target": "role:EcsTaskRole",
            },
        ]
    }
    results = {
        "public_entrypoints": [
            {
                "id": "entry-elb-app-http",
                "service": "ec2",
                "attack_path_seed": True,
                "execution_roles": [role_arn],
                "evidence": [{"type": "graph_edge", "id": edge["id"]} for edge in graph["edges"]],
            }
        ]
    }
    iam_payload = {
        "resources": [
            {
                "resource_type": "iam_role",
                "resource_id": "EcsTaskRole",
                "arn": role_arn,
                "is_service_linked": False,
                "attached_policies": [
                    {
                        "name": "SecretsManagerReadWrite",
                        "arn": "arn:aws:iam::aws:policy/SecretsManagerReadWrite",
                        "document": None,
                    }
                ],
                "inline_policies": [],
            }
        ]
    }

    candidates = generate_public_service_candidates(
        results=results,
        iam_payload=iam_payload,
        graph=graph,
        module_resources=[],
    )

    assert candidates == []


def test_generates_public_apigateway_lambda_role_candidate_from_invoke_graph() -> None:
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/PaymentsRole"
    secret_arn = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:PAYMENTS-AbCdEf"
    graph = {
        "edges": [
            {
                "id": "edge:public_access:external:https->gateway:apigw:api123",
                "edge_type": "public_access",
                "relationship": "public_https_reaches_apigateway_api",
                "source": "external:https",
                "target": "gateway:apigw:api123",
            },
            {
                "id": "edge:invokes:gateway:apigw:api123->compute:lambda:payments",
                "edge_type": "invokes",
                "relationship": "apigateway_invokes_lambda_function",
                "source": "gateway:apigw:api123",
                "target": "compute:lambda:payments",
            },
            {
                "id": "edge:executes_as:compute:lambda:payments->role:PaymentsRole",
                "edge_type": "executes_as",
                "relationship": "lambda_function_executes_as_iam_role",
                "source": "compute:lambda:payments",
                "target": "role:PaymentsRole",
            },
        ]
    }
    results = {
        "public_entrypoints": [
            {
                "id": "entry-api-payments",
                "service": "apigateway",
                "arn": f"arn:aws:execute-api:us-east-1:{ACCOUNT_ID}:api123/prod/GET/payments",
                "attack_path_seed": True,
                "execution_roles": [role_arn],
                "invokes": [f"arn:aws:lambda:us-east-1:{ACCOUNT_ID}:function:payments"],
                "evidence": [{"type": "graph_edge", "id": edge["id"]} for edge in graph["edges"]],
            }
        ]
    }
    iam_payload = {
        "resources": [
            {
                "resource_type": "iam_role",
                "resource_id": "PaymentsRole",
                "arn": role_arn,
                "is_service_linked": False,
                "attached_policies": [],
                "inline_policies": [
                    {"name": "ReadPayments", "document": _policy("secretsmanager:GetSecretValue", secret_arn)}
                ],
            }
        ]
    }

    candidates = generate_public_service_candidates(
        results=results,
        iam_payload=iam_payload,
        graph=graph,
        module_resources=[
            {
                "resource_type": "secrets_secret",
                "resource_id": "PAYMENTS",
                "arn": secret_arn,
                "_source_path": "modules/secrets/us-east-1.json",
            }
        ],
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert [hop["validation_type"] for hop in candidate["hops"]] == [
        "graph",
        "graph",
        "graph",
        "runtime_assumption",
        "iam",
    ]
    assert candidate["hops"][1]["transition"] == "invoke"
    assert candidate["hops"][-1]["target"] == secret_arn


def test_public_service_candidate_prefers_correlated_dns_edges_over_placeholders() -> None:
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/EcsTaskRole"
    secret_arn = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:RDS_CREDS-AbCdEf"
    graph = {
        "edges": [
            {
                "id": "edge:public_access:external:public->gateway:route53:app.example.com.",
                "edge_type": "public_access",
                "relationship": "route53_record_public_dns",
                "source": "external:public",
                "target": "gateway:route53:app.example.com.",
            },
            {
                "id": "edge:network:gateway:route53:app.example.com.->external:dns:d111111abcdef8.cloudfront.net",
                "edge_type": "network",
                "relationship": "route53_record_resolves_to_target",
                "source": "gateway:route53:app.example.com.",
                "target": "external:dns:d111111abcdef8.cloudfront.net",
            },
            {
                "id": "edge:network:gateway:route53:app.example.com.->gateway:cloudfront:E123ABC",
                "edge_type": "network",
                "relationship": "route53_record_resolves_to_cloudfront_distribution",
                "source": "gateway:route53:app.example.com.",
                "target": "gateway:cloudfront:E123ABC",
            },
            {
                "id": "edge:network:gateway:cloudfront:E123ABC->external:dns:app-alb-123.us-east-1.elb.amazonaws.com",
                "edge_type": "network",
                "relationship": "cloudfront_distribution_routes_to_origin",
                "source": "gateway:cloudfront:E123ABC",
                "target": "external:dns:app-alb-123.us-east-1.elb.amazonaws.com",
            },
            {
                "id": "edge:network:gateway:cloudfront:E123ABC->gateway:alb:app-alb",
                "edge_type": "network",
                "relationship": "cloudfront_distribution_routes_to_load_balancer",
                "source": "gateway:cloudfront:E123ABC",
                "target": "gateway:alb:app-alb",
            },
            {
                "id": "edge:network:gateway:alb:app-alb->gateway:target-group:tg",
                "edge_type": "network",
                "relationship": "load_balancer_listener_routes_to_target_group",
                "source": "gateway:alb:app-alb",
                "target": "gateway:target-group:tg",
            },
            {
                "id": "edge:network:gateway:target-group:tg->compute:ecs-service:svc",
                "edge_type": "network",
                "relationship": "target_group_routes_to_ecs_service",
                "source": "gateway:target-group:tg",
                "target": "compute:ecs-service:svc",
            },
            {
                "id": "edge:service:compute:ecs-service:svc->compute:ecs-task-definition:task:1",
                "edge_type": "service",
                "relationship": "ecs_service_uses_task_definition",
                "source": "compute:ecs-service:svc",
                "target": "compute:ecs-task-definition:task:1",
            },
            {
                "id": "edge:executes_as:compute:ecs-task-definition:task:1->role:EcsTaskRole",
                "edge_type": "executes_as",
                "relationship": "ecs_task_definition_uses_task_role",
                "source": "compute:ecs-task-definition:task:1",
                "target": "role:EcsTaskRole",
            },
        ]
    }
    results = {
        "public_entrypoints": [
            {
                "id": "entry-dns-app",
                "service": "route53",
                "arn": "arn:aws:route53:::hostedzone/Z123",
                "attack_path_seed": True,
                "execution_roles": [role_arn],
                "evidence": [{"type": "graph_edge", "id": edge["id"]} for edge in graph["edges"]],
            }
        ]
    }
    iam_payload = {
        "resources": [
            {
                "resource_type": "iam_role",
                "resource_id": "EcsTaskRole",
                "arn": role_arn,
                "is_service_linked": False,
                "attached_policies": [],
                "inline_policies": [{"name": "ReadSecret", "document": _policy("secretsmanager:GetSecretValue", secret_arn)}],
            }
        ]
    }

    candidates = generate_public_service_candidates(
        results=results,
        iam_payload=iam_payload,
        graph=graph,
        module_resources=[
            {
                "resource_type": "secrets_secret",
                "resource_id": "RDS_CREDS",
                "arn": secret_arn,
                "_source_path": "modules/secrets/us-east-1.json",
            }
        ],
    )

    assert len(candidates) == 1
    targets = [hop["target"] for hop in candidates[0]["hops"]]
    assert "gateway:cloudfront:E123ABC" in targets
    assert "gateway:alb:app-alb" in targets
    assert "external:dns:d111111abcdef8.cloudfront.net" not in targets
    assert "external:dns:app-alb-123.us-east-1.elb.amazonaws.com" not in targets


def test_generates_conditional_public_security_group_ec2_role_candidate() -> None:
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/WebRole"
    secret_arn = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:WEB-AbCdEf"
    graph = {
        "edges": [
            {
                "id": "edge:public_access:external:http->network:sg:sg-public",
                "edge_type": "public_access",
                "relationship": "security_group_allows_public_ingress",
                "source": "external:http",
                "target": "network:sg:sg-public",
            },
            {
                "id": "edge:network:network:sg:sg-public->compute:ec2:i-123",
                "edge_type": "network",
                "relationship": "security_group_attached_to_ec2_instance",
                "source": "network:sg:sg-public",
                "target": "compute:ec2:i-123",
            },
            {
                "id": "edge:executes_as:compute:ec2:i-123->role:WebRole",
                "edge_type": "executes_as",
                "relationship": "ec2_instance_executes_as_iam_role",
                "source": "compute:ec2:i-123",
                "target": "role:WebRole",
            },
        ]
    }
    results = {
        "public_entrypoints": [
            {
                "id": "entry-ec2-public-http",
                "service": "ec2",
                "arn": f"arn:aws:ec2:us-east-1:{ACCOUNT_ID}:security-group/sg-public",
                "attack_path_seed": True,
                "execution_roles": [role_arn],
                "evidence": [{"type": "graph_edge", "id": edge["id"]} for edge in graph["edges"]],
            }
        ]
    }
    iam_payload = {
        "resources": [
            {
                "resource_type": "iam_role",
                "resource_id": "WebRole",
                "arn": role_arn,
                "is_service_linked": False,
                "attached_policies": [],
                "inline_policies": [{"name": "ReadSecret", "document": _policy("secretsmanager:GetSecretValue", secret_arn)}],
            }
        ]
    }

    candidates = generate_public_service_candidates(
        results=results,
        iam_payload=iam_payload,
        graph=graph,
        module_resources=[
            {
                "resource_type": "secrets_secret",
                "resource_id": "WEB",
                "arn": secret_arn,
                "_source_path": "modules/secrets/us-east-1.json",
            }
        ],
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert [hop["target"] for hop in candidate["hops"][:3]] == [
        "network:sg:sg-public",
        "compute:ec2:i-123",
        "role:WebRole",
    ]
    assert candidate["hops"][-2]["validation_type"] == "runtime_assumption"
    assert candidate["impact"] == {
        "type": "data_access",
        "resource": secret_arn,
        "action": "secretsmanager:GetSecretValue",
    }


def test_does_not_generate_public_service_candidate_for_public_rds_without_execution_role() -> None:
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/DbAdmin"
    secret_arn = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:RDS_CREDS-AbCdEf"
    graph = {
        "edges": [
            {
                "id": "edge:public_access:external:public->network:sg:sg-db",
                "edge_type": "public_access",
                "relationship": "security_group_allows_public_ingress",
                "source": "external:public",
                "target": "network:sg:sg-db",
            },
            {
                "id": "edge:public_access:external:public->data:rds:prod-db",
                "edge_type": "public_access",
                "relationship": "rds_instance_public_endpoint",
                "source": "external:public",
                "target": "data:rds:prod-db",
            },
            {
                "id": "edge:network:network:sg:sg-db->data:rds:prod-db",
                "edge_type": "network",
                "relationship": "security_group_attached_to_rds_instance",
                "source": "network:sg:sg-db",
                "target": "data:rds:prod-db",
            },
        ]
    }
    results = {
        "public_entrypoints": [
            {
                "id": "entry-rds-public",
                "service": "rds",
                "arn": f"arn:aws:rds:us-east-1:{ACCOUNT_ID}:db:prod-db",
                "attack_path_seed": True,
                "execution_roles": [],
                "evidence": [{"type": "graph_edge", "id": edge["id"]} for edge in graph["edges"]],
            }
        ]
    }
    iam_payload = {
        "resources": [
            {
                "resource_type": "iam_role",
                "resource_id": "DbAdmin",
                "arn": role_arn,
                "is_service_linked": False,
                "attached_policies": [],
                "inline_policies": [{"name": "ReadSecret", "document": _policy("secretsmanager:GetSecretValue", secret_arn)}],
            }
        ]
    }

    candidates = generate_public_service_candidates(
        results=results,
        iam_payload=iam_payload,
        graph=graph,
        module_resources=[
            {
                "resource_type": "secrets_secret",
                "resource_id": "RDS_CREDS",
                "arn": secret_arn,
                "_source_path": "modules/secrets/us-east-1.json",
            }
        ],
    )

    assert candidates == []


def test_generates_cognito_unauthenticated_identity_role_candidate_without_backend_assumption() -> None:
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/CognitoUnauthRole"
    secret_arn = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:CUSTOMER_DATA-AbCdEf"
    graph = {
        "edges": [
            {
                "id": "edge:public_access:external:anonymous->idp:cognito:us-east-1:pool-abc123",
                "edge_type": "public_access",
                "relationship": "cognito_identity_pool_allows_unauthenticated_identity",
                "source": "external:anonymous",
                "target": "idp:cognito:us-east-1:pool-abc123",
            },
            {
                "id": "edge:authenticates_to:idp:cognito:us-east-1:pool-abc123->role:CognitoUnauthRole",
                "edge_type": "authenticates_to",
                "relationship": "cognito_identity_pool_unauthenticated_role",
                "source": "idp:cognito:us-east-1:pool-abc123",
                "target": "role:CognitoUnauthRole",
            },
        ]
    }
    results = {
        "public_entrypoints": [
            {
                "id": "entry-cognito-unauth-pool",
                "service": "cognito",
                "resource": "us-east-1:pool-abc123",
                "arn": f"arn:aws:cognito-identity:us-east-1:{ACCOUNT_ID}:identitypool/us-east-1:pool-abc123",
                "attack_path_seed": True,
                "execution_roles": [role_arn],
                "seed_reason": "Identity pool allows unauthenticated identities to obtain AWS credentials.",
                "evidence": [{"type": "graph_edge", "id": edge["id"]} for edge in graph["edges"]],
            }
        ]
    }
    iam_payload = {
        "resources": [
            {
                "resource_type": "iam_role",
                "resource_id": "CognitoUnauthRole",
                "arn": role_arn,
                "is_service_linked": False,
                "attached_policies": [],
                "inline_policies": [
                    {"name": "ReadSecret", "document": _policy("secretsmanager:GetSecretValue", secret_arn)}
                ],
            }
        ]
    }

    candidates = generate_public_service_candidates(
        results=results,
        iam_payload=iam_payload,
        graph=graph,
        module_resources=[
            {
                "resource_type": "secrets_secret",
                "resource_id": "CUSTOMER_DATA",
                "arn": secret_arn,
                "_source_path": "modules/secrets/us-east-1.json",
            }
        ],
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert [hop["transition"] for hop in candidate["hops"]] == [
        "invoke",
        "authenticate",
        "data_access",
    ]
    assert all(hop["validation_type"] != "runtime_assumption" for hop in candidate["hops"])
    assert candidate["impact"] == {
        "type": "data_access",
        "resource": secret_arn,
        "action": "secretsmanager:GetSecretValue",
    }


def test_generates_dynamodb_table_read_impact_for_assumable_role() -> None:
    table_arn = f"arn:aws:dynamodb:us-east-1:{ACCOUNT_ID}:table/CustomerOrders"
    target_role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/DataReader"
    source_policy = _policy("sts:AssumeRole", target_role_arn)
    target_policy = _policy("dynamodb:GetItem", table_arn)
    graph = {
        "edges": [
            {
                "id": "edge:trust:user:Alice->role:DataReader",
                "relationship": "iam_role_trusts_principal",
                "source": "user:Alice",
                "target": "role:DataReader",
            }
        ]
    }

    candidates = generate_iam_candidates(
        iam_payload={
            "resources": [
                _user("Alice", USER_ARN, [source_policy]),
                _role("DataReader", target_role_arn, [target_policy]),
            ]
        },
        graph=graph,
        module_resources=[
            {
                "resource_type": "dynamodb_table",
                "resource_id": "CustomerOrders",
                "arn": table_arn,
            }
        ],
    )

    assert [candidate["impact"] for candidate in candidates] == [
        {"type": "data_access", "resource": table_arn, "action": "dynamodb:GetItem"}
    ]


def test_generates_ssm_parameter_read_impact_for_assumable_role() -> None:
    parameter_arn = f"arn:aws:ssm:us-east-1:{ACCOUNT_ID}:parameter/app/secret-key"
    target_role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/ParameterReader"
    source_policy = _policy("sts:AssumeRole", target_role_arn)
    target_policy = _policy("ssm:GetParameter", parameter_arn)
    graph = {
        "edges": [
            {
                "id": "edge:trust:user:Alice->role:ParameterReader",
                "relationship": "iam_role_trusts_principal",
                "source": "user:Alice",
                "target": "role:ParameterReader",
            }
        ]
    }

    candidates = generate_iam_candidates(
        iam_payload={
            "resources": [
                _user("Alice", USER_ARN, [source_policy]),
                _role("ParameterReader", target_role_arn, [target_policy]),
            ]
        },
        graph=graph,
        module_resources=[
            {
                "resource_type": "ssm_parameter",
                "resource_id": "/app/secret-key",
                "arn": parameter_arn,
                "type": "SecureString",
            }
        ],
    )

    assert [candidate["impact"] for candidate in candidates] == [
        {"type": "data_access", "resource": parameter_arn, "action": "ssm:GetParameter"}
    ]


def test_generates_codebuild_start_build_candidate_for_existing_project_service_role() -> None:
    project_arn = f"arn:aws:codebuild:us-east-1:{ACCOUNT_ID}:project/deploy"
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/BuildRole"
    secret_arn = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:DEPLOY-AbCdEf"
    source_policy = _policy("codebuild:StartBuild", project_arn)
    target_policy = _policy("secretsmanager:GetSecretValue", secret_arn)
    graph = {
        "edges": [
            {
                "id": "edge:executes_as:compute:codebuild:deploy->role:BuildRole",
                "edge_type": "executes_as",
                "relationship": "codebuild_project_executes_as_iam_role",
                "source": "compute:codebuild:deploy",
                "target": "role:BuildRole",
            }
        ]
    }

    candidates = generate_iam_candidates(
        iam_payload={
            "resources": [
                _user("Alice", USER_ARN, [source_policy]),
                _role("BuildRole", role_arn, [target_policy]),
            ]
        },
        graph=graph,
        module_resources=[
            {
                "resource_type": "codebuild_project",
                "resource_id": "deploy",
                "arn": project_arn,
                "service_role": role_arn,
            },
            {
                "resource_type": "secrets_secret",
                "resource_id": "DEPLOY",
                "arn": secret_arn,
            },
        ],
    )

    assert [candidate["name"] for candidate in candidates] == [
        "Alice can start CodeBuild project deploy as BuildRole and reach secretsmanager:GetSecretValue"
    ]
    assert [hop["transition"] for hop in candidates[0]["hops"]] == [
        "create_compute",
        "execute_as",
        "data_access",
    ]
    assert candidates[0]["impact"] == {
        "type": "data_access",
        "resource": secret_arn,
        "action": "secretsmanager:GetSecretValue",
    }


def test_generate_iam_candidates_only_from_run_loads_module_resources(tmp_path: Path) -> None:
    table_arn = f"arn:aws:dynamodb:us-east-1:{ACCOUNT_ID}:table/CustomerOrders"
    target_role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/DataReader"
    _write_run_module(
        tmp_path,
        "iam",
        "global",
        [
            _user("Alice", USER_ARN, [_policy("sts:AssumeRole", target_role_arn)]),
            _role("DataReader", target_role_arn, [_policy("dynamodb:GetItem", table_arn)]),
        ],
    )
    _write_run_module(
        tmp_path,
        "dynamodb",
        "us-east-1",
        [
            {
                "resource_type": "dynamodb_table",
                "resource_id": "CustomerOrders",
                "arn": table_arn,
            }
        ],
    )
    (tmp_path / "graph.json").write_text(
        json.dumps(
            {
                "edges": [
                    {
                        "id": "edge:trust:user:Alice->role:DataReader",
                        "relationship": "iam_role_trusts_principal",
                        "source": "user:Alice",
                        "target": "role:DataReader",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    candidates = generate_iam_candidates_only_from_run(tmp_path)

    assert [candidate["impact"] for candidate in candidates] == [
        {"type": "data_access", "resource": table_arn, "action": "dynamodb:GetItem"}
    ]
