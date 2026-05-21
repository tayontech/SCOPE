from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from scope_core.coverage import CoverageTracker
from scope_core.models import ModuleEnvelope


PRIMARY_CHECKS = ["list_projects"]
REQUIRED_CHECKS = ["batch_get_projects"]
SECRET_PATTERNS = re.compile(r"password|secret|token|key|credential|api.?key|auth", re.IGNORECASE)


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    codebuild = factory.client("codebuild")
    findings: list[dict[str, Any]] = []

    try:
        project_names = factory.paginate(codebuild, "list_projects", "projects")
        tracker.record_ok("list_projects", resource="projects")
    except Exception as err:
        tracker.record_module_failure("list_projects", operation="codebuild.ListProjects", err=err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="codebuild",
            account_id=factory.account_id,
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    for batch in _chunks(project_names, 100):
        batch_label = f"batch({len(batch)})"
        try:
            response = codebuild.batch_get_projects(names=batch)
        except Exception as err:
            tracker.record_resource_failure(
                "batch_get_projects",
                resource=batch_label,
                operation="codebuild.BatchGetProjects",
                err=err,
            )
            continue

        for project in response.get("projects", []):
            finding = _project_finding(project, region)
            findings.append(finding)
            tracker.record_ok("batch_get_projects", resource=project.get("arn") or project.get("name"))

        for name in response.get("projectsNotFound", []):
            tracker.record_resource_failure(
                "batch_get_projects",
                resource=name,
                operation="codebuild.BatchGetProjects",
                err=_ErrorRecord("ProjectNotFound", f"Project '{name}' was listed but not returned in BatchGetProjects response"),
            )

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="codebuild",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )


def _project_finding(project: dict[str, Any], region: str) -> dict[str, Any]:
    environment = project.get("environment") or {}
    source = project.get("source") or {}
    env_var_names = [var.get("name") for var in environment.get("environmentVariables", []) if var.get("name")]
    secret_pattern_names = [name for name in env_var_names if SECRET_PATTERNS.search(name)]
    vpc_config = project.get("vpcConfig")

    finding = {
        "resource_type": "codebuild_project",
        "resource_id": project.get("name"),
        "arn": project.get("arn"),
        "region": region,
        "service_role": project.get("serviceRole"),
        "source_type": source.get("type"),
        "source_location": source.get("location"),
        "source_buildspec": bool(source.get("buildspec")),
        "environment_type": environment.get("type"),
        "environment_image": environment.get("image"),
        "environment_compute_type": environment.get("computeType"),
        "privileged_mode": environment.get("privilegedMode") or False,
        "vpc_config": _vpc_config(vpc_config),
        "env_var_names": env_var_names,
        "secret_pattern_names": secret_pattern_names,
        "encryption_key": project.get("encryptionKey"),
        "last_modified": _format_timestamp(project.get("lastModified")),
        "findings": [],
    }

    if secret_pattern_names:
        finding["findings"].append(
            {
                "type": "secret_env_vars",
                "severity": "high",
                "detail": (
                    f"Project has {len(secret_pattern_names)} env var(s) matching secret patterns: "
                    f"{', '.join(secret_pattern_names)}"
                ),
            }
        )
    if environment.get("privilegedMode"):
        finding["findings"].append(
            {
                "type": "privileged_mode",
                "severity": "medium",
                "detail": "Build environment runs in privileged mode (Docker daemon access)",
            }
        )
    if not vpc_config:
        finding["findings"].append(
            {
                "type": "no_vpc",
                "severity": "info",
                "detail": "Project builds do not run inside a VPC",
            }
        )

    return finding


def _vpc_config(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if not value:
        return None
    return {
        "vpc_id": value.get("vpcId"),
        "subnets": value.get("subnets") or [],
        "security_group_ids": value.get("securityGroupIds") or [],
    }


def _chunks(values: list[Any], size: int) -> list[list[Any]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def _format_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        normalized = value.astimezone(timezone.utc)
        return normalized.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return str(value)


class _ErrorRecord(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.response = {"Error": {"Code": code, "Message": message}}
