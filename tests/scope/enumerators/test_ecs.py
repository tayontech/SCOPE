from __future__ import annotations

from botocore.exceptions import ClientError

from scope.enumerators.ecs import run
from tests.scope.enumerators.fakes import FakeClient, FakeFactory


def _factory(ecs_ops=None):
    defaults = {
        "list_clusters": {
            "clusterArns": [
                "arn:aws:ecs:us-east-1:123456789012:cluster/aws-goat",
            ]
        },
        "describe_clusters": {
            "clusters": [
                {
                    "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/aws-goat",
                    "clusterName": "aws-goat",
                    "status": "ACTIVE",
                    "runningTasksCount": 1,
                    "pendingTasksCount": 0,
                    "activeServicesCount": 1,
                }
            ]
        },
        "list_services": {
            "serviceArns": [
                "arn:aws:ecs:us-east-1:123456789012:service/aws-goat/ecs_service_worker",
            ]
        },
        "describe_services": {
            "services": [
                {
                    "serviceArn": "arn:aws:ecs:us-east-1:123456789012:service/aws-goat/ecs_service_worker",
                    "serviceName": "ecs_service_worker",
                    "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/aws-goat",
                    "status": "ACTIVE",
                    "desiredCount": 1,
                    "runningCount": 1,
                    "launchType": "FARGATE",
                    "taskDefinition": "arn:aws:ecs:us-east-1:123456789012:task-definition/aws-goat-m2:3",
                    "loadBalancers": [
                        {
                            "targetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/aws-goat-m2-tg/def",
                            "containerName": "worker",
                            "containerPort": 80,
                        }
                    ],
                    "networkConfiguration": {
                        "awsvpcConfiguration": {
                            "subnets": ["subnet-1"],
                            "securityGroups": ["sg-task"],
                            "assignPublicIp": "DISABLED",
                        }
                    },
                }
            ]
        },
        "describe_task_definition": {
            "taskDefinition": {
                "taskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/aws-goat-m2:3",
                "family": "aws-goat-m2",
                "revision": 3,
                "status": "ACTIVE",
                "taskRoleArn": "arn:aws:iam::123456789012:role/ecs-task-role",
                "executionRoleArn": "arn:aws:iam::123456789012:role/ecs-execution-role",
                "networkMode": "awsvpc",
                "requiresCompatibilities": ["FARGATE"],
                "cpu": "256",
                "memory": "512",
                "containerDefinitions": [
                    {
                        "name": "worker",
                        "image": "public.ecr.aws/example/worker:latest",
                        "portMappings": [{"containerPort": 80, "hostPort": 80, "protocol": "tcp"}],
                        "environment": [{"name": "SECRET_TOKEN", "value": "do-not-store"}],
                        "secrets": [{"name": "DB_PASSWORD", "valueFrom": "arn:aws:ssm:us-east-1:123456789012:parameter/db"}],
                    }
                ],
            }
        },
    }
    if ecs_ops:
        defaults.update(ecs_ops)
    return FakeFactory(ecs=FakeClient(defaults))


def test_ecs_collects_clusters_services_task_definitions_and_roles():
    envelope = run(_factory(), "us-east-1")

    assert envelope.module == "ecs"
    assert envelope.status == "complete"

    cluster = next(resource for resource in envelope.resources if resource["resource_type"] == "ecs_cluster")
    service = next(resource for resource in envelope.resources if resource["resource_type"] == "ecs_service")
    task_definition = next(resource for resource in envelope.resources if resource["resource_type"] == "ecs_task_definition")

    assert cluster["resource_id"] == "aws-goat"
    assert service["resource_id"] == "ecs_service_worker"
    assert service["task_definition_arn"] == "arn:aws:ecs:us-east-1:123456789012:task-definition/aws-goat-m2:3"
    assert service["load_balancers"] == [
        {
            "target_group_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/aws-goat-m2-tg/def",
            "container_name": "worker",
            "container_port": 80,
        }
    ]
    assert service["network_configuration"] == {
        "subnets": ["subnet-1"],
        "security_groups": ["sg-task"],
        "assign_public_ip": "DISABLED",
    }
    assert task_definition["task_role_arn"] == "arn:aws:iam::123456789012:role/ecs-task-role"
    assert task_definition["execution_role_arn"] == "arn:aws:iam::123456789012:role/ecs-execution-role"
    assert task_definition["container_definitions"] == [
        {
            "name": "worker",
            "image": "public.ecr.aws/example/worker:latest",
            "port_mappings": [{"container_port": 80, "host_port": 80, "protocol": "tcp"}],
            "environment_variable_names": ["SECRET_TOKEN"],
            "secret_names": ["DB_PASSWORD"],
        }
    ]
    assert "do-not-store" not in str(task_definition)


def test_ecs_list_clusters_failure_marks_module_error():
    factory = _factory(
        {
            "list_clusters": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListClusters",
            )
        }
    )

    envelope = run(factory, "us-east-1")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "ecs.ListClusters"


def test_ecs_task_definition_failure_keeps_service_partial():
    factory = _factory(
        {
            "describe_task_definition": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "DescribeTaskDefinition",
            )
        }
    )

    envelope = run(factory, "us-east-1")

    assert envelope.status == "partial"
    assert any(resource["resource_type"] == "ecs_service" for resource in envelope.resources)
    assert not any(resource["resource_type"] == "ecs_task_definition" for resource in envelope.resources)
    assert envelope.errors[0].operation == "ecs.DescribeTaskDefinition"


def test_ecs_task_definition_id_falls_back_to_full_family_revision_from_arn():
    factory = _factory(
        {
            "describe_task_definition": {
                "taskDefinition": {
                    "taskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/aws-goat-m2:3",
                    "status": "ACTIVE",
                }
            }
        }
    )

    envelope = run(factory, "us-east-1")

    task_definition = next(resource for resource in envelope.resources if resource["resource_type"] == "ecs_task_definition")
    assert task_definition["resource_id"] == "aws-goat-m2:3"
