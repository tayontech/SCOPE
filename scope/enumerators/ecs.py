from __future__ import annotations

from typing import Any

from scope.core.coverage import CoverageTracker
from scope.core.models import ModuleEnvelope


PRIMARY_CHECKS = ["list_clusters"]
REQUIRED_CHECKS = ["describe_clusters", "list_services", "describe_services", "describe_task_definition"]


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    ecs = factory.client("ecs")
    findings: list[dict[str, Any]] = []

    try:
        cluster_arns = factory.paginate(ecs, "list_clusters", "clusterArns")
        tracker.record_ok("list_clusters", resource="clusters")
    except Exception as err:
        tracker.record_module_failure("list_clusters", operation="ecs.ListClusters", err=err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="ecs",
            account_id=factory.account_id,
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    clusters = _describe_clusters(ecs, cluster_arns, tracker)
    findings.extend(_cluster_resource(cluster, region) for cluster in clusters)

    task_definition_arns: set[str] = set()
    for cluster_arn in cluster_arns:
        service_arns = _list_services(factory, ecs, cluster_arn, tracker)
        for service in _describe_services(ecs, cluster_arn, service_arns, tracker):
            findings.append(_service_resource(service, region))
            task_definition_arn = service.get("taskDefinition")
            if isinstance(task_definition_arn, str) and task_definition_arn:
                task_definition_arns.add(task_definition_arn)

    for task_definition_arn in sorted(task_definition_arns):
        task_definition = _describe_task_definition(ecs, task_definition_arn, tracker)
        if task_definition is not None:
            findings.append(_task_definition_resource(task_definition, region))

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="ecs",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )


def _describe_clusters(ecs: Any, cluster_arns: list[str], tracker: CoverageTracker) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = []
    for batch in _chunks(cluster_arns, 100):
        if not batch:
            continue
        try:
            response = ecs.describe_clusters(clusters=batch)
            clusters.extend(response.get("clusters") or [])
            tracker.record_ok("describe_clusters", resource=f"batch({len(batch)})")
        except Exception as err:
            tracker.record_resource_failure(
                "describe_clusters",
                resource=f"batch({len(batch)})",
                operation="ecs.DescribeClusters",
                err=err,
            )
    return clusters


def _list_services(factory: Any, ecs: Any, cluster_arn: str, tracker: CoverageTracker) -> list[str]:
    try:
        service_arns = factory.paginate(ecs, "list_services", "serviceArns", cluster=cluster_arn)
        tracker.record_ok("list_services", resource=cluster_arn)
        return service_arns
    except Exception as err:
        tracker.record_resource_failure(
            "list_services",
            resource=cluster_arn,
            operation="ecs.ListServices",
            err=err,
        )
        return []


def _describe_services(
    ecs: Any,
    cluster_arn: str,
    service_arns: list[str],
    tracker: CoverageTracker,
) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    for batch in _chunks(service_arns, 10):
        if not batch:
            continue
        try:
            response = ecs.describe_services(cluster=cluster_arn, services=batch)
            services.extend(response.get("services") or [])
            tracker.record_ok("describe_services", resource=f"{cluster_arn}:batch({len(batch)})")
        except Exception as err:
            tracker.record_resource_failure(
                "describe_services",
                resource=f"{cluster_arn}:batch({len(batch)})",
                operation="ecs.DescribeServices",
                err=err,
            )
    return services


def _describe_task_definition(ecs: Any, task_definition_arn: str, tracker: CoverageTracker) -> dict[str, Any] | None:
    try:
        response = ecs.describe_task_definition(taskDefinition=task_definition_arn)
        tracker.record_ok("describe_task_definition", resource=task_definition_arn)
        return response.get("taskDefinition")
    except Exception as err:
        tracker.record_resource_failure(
            "describe_task_definition",
            resource=task_definition_arn,
            operation="ecs.DescribeTaskDefinition",
            err=err,
        )
        return None


def _cluster_resource(cluster: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "resource_type": "ecs_cluster",
        "resource_id": cluster.get("clusterName") or _arn_suffix(cluster.get("clusterArn")),
        "arn": cluster.get("clusterArn"),
        "region": region,
        "status": cluster.get("status"),
        "running_tasks_count": cluster.get("runningTasksCount"),
        "pending_tasks_count": cluster.get("pendingTasksCount"),
        "active_services_count": cluster.get("activeServicesCount"),
        "findings": [],
    }


def _service_resource(service: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "resource_type": "ecs_service",
        "resource_id": service.get("serviceName") or _arn_suffix(service.get("serviceArn")),
        "arn": service.get("serviceArn"),
        "region": region,
        "cluster_arn": service.get("clusterArn"),
        "status": service.get("status"),
        "desired_count": service.get("desiredCount"),
        "running_count": service.get("runningCount"),
        "launch_type": service.get("launchType"),
        "task_definition_arn": service.get("taskDefinition"),
        "load_balancers": [_service_load_balancer(load_balancer) for load_balancer in service.get("loadBalancers") or []],
        "network_configuration": _network_configuration(service.get("networkConfiguration")),
        "findings": [],
    }


def _task_definition_resource(task_definition: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "resource_type": "ecs_task_definition",
        "resource_id": _task_definition_id(task_definition),
        "arn": task_definition.get("taskDefinitionArn"),
        "region": region,
        "family": task_definition.get("family"),
        "revision": task_definition.get("revision"),
        "status": task_definition.get("status"),
        "task_role_arn": task_definition.get("taskRoleArn"),
        "execution_role_arn": task_definition.get("executionRoleArn"),
        "network_mode": task_definition.get("networkMode"),
        "requires_compatibilities": task_definition.get("requiresCompatibilities") or [],
        "cpu": task_definition.get("cpu"),
        "memory": task_definition.get("memory"),
        "container_definitions": [
            _container_definition(container) for container in task_definition.get("containerDefinitions") or []
        ],
        "findings": [],
    }


def _service_load_balancer(load_balancer: dict[str, Any]) -> dict[str, Any]:
    return {
        "target_group_arn": load_balancer.get("targetGroupArn"),
        "container_name": load_balancer.get("containerName"),
        "container_port": load_balancer.get("containerPort"),
    }


def _network_configuration(network_configuration: dict[str, Any] | None) -> dict[str, Any] | None:
    if not network_configuration:
        return None
    awsvpc = network_configuration.get("awsvpcConfiguration") or {}
    return {
        "subnets": awsvpc.get("subnets") or [],
        "security_groups": awsvpc.get("securityGroups") or [],
        "assign_public_ip": awsvpc.get("assignPublicIp"),
    }


def _container_definition(container: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": container.get("name"),
        "image": container.get("image"),
        "port_mappings": [
            {
                "container_port": port.get("containerPort"),
                "host_port": port.get("hostPort"),
                "protocol": port.get("protocol"),
            }
            for port in container.get("portMappings") or []
        ],
        "environment_variable_names": [
            variable.get("name") for variable in container.get("environment") or [] if variable.get("name")
        ],
        "secret_names": [secret.get("name") for secret in container.get("secrets") or [] if secret.get("name")],
    }


def _task_definition_id(task_definition: dict[str, Any]) -> str | None:
    family = task_definition.get("family")
    revision = task_definition.get("revision")
    if family and revision is not None:
        return f"{family}:{revision}"
    return _arn_suffix(task_definition.get("taskDefinitionArn"))


def _arn_suffix(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if "/" in value:
        return value.rsplit("/", 1)[-1]
    return value.rsplit(":", 1)[-1]


def _chunks(values: list[Any], size: int) -> list[list[Any]]:
    return [values[index : index + size] for index in range(0, len(values), size)]
