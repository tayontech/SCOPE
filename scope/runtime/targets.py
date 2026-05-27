from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ARN_PATTERN = re.compile(
    r"^arn:"
    r"(?P<partition>[A-Za-z0-9-]+):"
    r"(?P<service>[A-Za-z0-9-]+):"
    r"(?P<region>[A-Za-z0-9-]*):"
    r"(?P<account_id>[0-9]{12})?:"
    r"(?P<resource>.+)$"
)

SUPPORTED_SERVICES = {
    "apigateway",
    "bedrock",
    "cloudfront",
    "codebuild",
    "cognito-idp",
    "cognito-identity",
    "dynamodb",
    "ec2",
    "ecs",
    "elasticloadbalancing",
    "iam",
    "kms",
    "lambda",
    "rds",
    "route53",
    "s3",
    "secretsmanager",
    "sns",
    "sqs",
    "ssm",
    "sts",
}

SERVICE_MODULES = {
    "cognito-idp": "cognito",
    "cognito-identity": "cognito",
    "elasticloadbalancing": "ec2",
    "secretsmanager": "secrets",
}

NO_REGION_MODULES = {"cloudfront", "iam", "route53", "s3", "sts"}

RESOURCE_TYPE_ALIASES = {
    ("apigateway", "restapis"): {"apigateway_rest_api", "apigateway_restapis"},
    ("bedrock", "agent"): {"bedrock_agent"},
    ("cloudfront", "distribution"): {"cloudfront_distribution"},
    ("codebuild", "project"): {"codebuild_project"},
    ("cognito-idp", "userpool"): {"cognito_user_pool", "cognito_userpool"},
    ("cognito-identity", "identitypool"): {"cognito_identity_pool", "cognito_identitypool"},
    ("dynamodb", "table"): {"dynamodb_table"},
    ("ec2", "instance"): {"ec2_instance"},
    ("ecs", "cluster"): {"ecs_cluster"},
    ("ecs", "service"): {"ecs_service"},
    ("ecs", "task-definition"): {"ecs_task_definition"},
    ("elasticloadbalancing", "loadbalancer"): {"ec2_load_balancer", "elb_load_balancer"},
    ("iam", "role"): {"iam_role"},
    ("kms", "key"): {"kms_key"},
    ("lambda", "function"): {"lambda_function"},
    ("rds", "db"): {"rds_db", "rds_instance"},
    ("route53", "hostedzone"): {"route53_hosted_zone"},
    ("s3", "bucket"): {"s3_bucket"},
    ("secretsmanager", "secret"): {"secrets_secret", "secretsmanager_secret"},
    ("sns", "topic"): {"sns_topic"},
    ("sqs", "queue"): {"sqs_queue"},
    ("ssm", "parameter"): {"ssm_parameter"},
    ("sts", "assumed-role"): {"sts_assumed_role"},
}


class TargetParseError(ValueError):
    pass


@dataclass(frozen=True)
class TargetScope:
    raw: str
    arn: str
    partition: str
    service: str
    region: str | None
    account_id: str | None
    resource_type: str
    resource_id: str


@dataclass(frozen=True)
class ResourceSelector:
    service: str
    module: str
    region: str
    resource_type: str
    resource_id: str
    arn: str


def parse_target(raw: str) -> TargetScope:
    arn = raw.strip()
    if not arn.startswith("arn:"):
        raise TargetParseError(f"Expected ARN target, got: {raw}")

    match = ARN_PATTERN.fullmatch(arn)
    if match is None:
        raise TargetParseError(f"Invalid ARN target: {raw}")

    partition = match.group("partition")
    service = match.group("service")
    region = match.group("region") or None
    account_id = match.group("account_id") or None
    resource = match.group("resource")

    if service not in SUPPORTED_SERVICES:
        raise TargetParseError(f"Unsupported target service: {service}")

    module = module_for_service(service)
    if module in NO_REGION_MODULES and region is not None:
        raise TargetParseError(f"Target service {service} must not include a region")
    if module not in NO_REGION_MODULES and region is None:
        raise TargetParseError(f"Target service {service} requires a region")

    resource_type, resource_id = parse_resource(service, resource)
    return TargetScope(
        raw=raw,
        arn=arn,
        partition=partition,
        service=service,
        region=region,
        account_id=account_id,
        resource_type=resource_type,
        resource_id=resource_id,
    )


def parse_targets(raw_targets: list[str] | tuple[str, ...]) -> list[TargetScope]:
    return [parse_target(raw_target) for raw_target in raw_targets]


def read_target_file(path: Path) -> list[TargetScope]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as err:
        raise TargetParseError(f"Unable to read target file {path}: {err}") from err
    raw_targets = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not raw_targets:
        raise TargetParseError(f"No targets found in {path}")
    return parse_targets(raw_targets)


def module_for_target(target: TargetScope) -> str:
    return module_for_service(target.service)


def module_for_service(service: str) -> str:
    return SERVICE_MODULES.get(service, service)


def required_work_items_for_targets(targets: list[TargetScope]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for target in targets:
        module = module_for_target(target)
        region = target.region or "global"
        pair = (module, region)
        if pair not in seen:
            seen.add(pair)
            pairs.append(pair)

    for pair in (("iam", "global"), ("sts", "global")):
        if pair not in seen:
            seen.add(pair)
            pairs.append(pair)

    return pairs


def build_scope_metadata(
    *,
    mode: str,
    targets: list[TargetScope],
) -> dict[str, Any]:
    return {"mode": mode, "targets": [target.arn for target in targets]}


def filter_module_envelopes_for_targets(
    envelopes: dict[tuple[str, str], dict[str, Any]],
    targets: list[TargetScope],
) -> tuple[dict[tuple[str, str], dict[str, Any]], list[dict[str, str]]]:
    filtered = {
        key: {
            **copy.deepcopy(envelope),
            "resources": [],
            "coverage": copy.deepcopy(envelope.get("coverage", [])),
            "errors": copy.deepcopy(envelope.get("errors", [])),
        }
        for key, envelope in envelopes.items()
    }
    target_results: list[dict[str, str]] = []
    context_arn_sources: dict[str, str] = {}

    for target in targets:
        module = module_for_target(target)
        region = target.region or "global"
        key = (module, region)
        source_envelope = envelopes.get(key)
        if source_envelope is None:
            filtered[key] = _empty_filtered_envelope(module, region, target, envelopes.values())
            target_results.append(_target_result(target, "not_found"))
            continue

        target_resources = [
            _annotated_resource(resource, scope_match="target", scope_source=target.arn)
            for resource in source_envelope.get("resources", [])
            if _resource_matches_target(resource, target, module, region, source_envelope.get("account_id"))
        ]
        if not target_resources:
            filtered[key]["status"] = "partial"
            filtered[key]["errors"].append(_not_found_error(target))
            target_results.append(_target_result(target, "not_found"))
            continue

        filtered[key]["resources"].extend(target_resources)
        target_results.append(_target_result(target, "resolved"))

        for resource in target_resources:
            for arn in _arn_references(resource):
                if arn != target.arn:
                    context_arn_sources.setdefault(arn, target.arn)

    for key, source_envelope in envelopes.items():
        module, region = key
        for resource in source_envelope.get("resources", []):
            resource_arn = resource.get("arn")
            if not isinstance(resource_arn, str):
                continue
            scope_source = context_arn_sources.get(resource_arn)
            if scope_source is None:
                continue
            if _filtered_resource_exists(filtered[key]["resources"], resource_arn):
                continue
            filtered[key]["resources"].append(
                _annotated_resource(resource, scope_match="context", scope_source=scope_source)
            )

    for envelope in filtered.values():
        envelope["coverage"].append(_target_filter_coverage(envelope))

    return filtered, target_results


def selector_to_json(selector: ResourceSelector) -> dict[str, str]:
    return {
        "service": selector.service,
        "module": selector.module,
        "region": selector.region,
        "resource_type": selector.resource_type,
        "resource_id": selector.resource_id,
        "arn": selector.arn,
    }


def selector_from_json(payload: dict[str, Any]) -> ResourceSelector:
    return ResourceSelector(
        service=_required_string(payload, "service"),
        module=_required_string(payload, "module"),
        region=_required_string(payload, "region"),
        resource_type=_required_string(payload, "resource_type"),
        resource_id=_required_string(payload, "resource_id"),
        arn=_required_string(payload, "arn"),
    )


def selector_for_target(target: TargetScope) -> ResourceSelector:
    return ResourceSelector(
        service=target.service,
        module=module_for_target(target),
        region=target.region or "global",
        resource_type=target.resource_type,
        resource_id=target.resource_id,
        arn=target.arn,
    )


def parse_resource(service: str, resource: str) -> tuple[str, str]:
    normalized = resource.lstrip("/") if service == "apigateway" else resource

    if service == "s3":
        return "bucket", normalized
    if service == "sns":
        return "topic", normalized
    if service == "sqs":
        return "queue", normalized

    for separator in ("/", ":"):
        if separator in normalized:
            resource_type, resource_id = normalized.split(separator, 1)
            if resource_type and resource_id:
                return resource_type, resource_id

    raise TargetParseError(f"Target resource must include a resource type: {resource}")


def _resource_matches_target(
    resource: dict[str, Any],
    target: TargetScope,
    module: str,
    region: str,
    source_account_id: Any,
) -> bool:
    if (module, region) != (module_for_target(target), target.region or "global"):
        return False

    resource_arn = resource.get("arn")
    if isinstance(resource_arn, str):
        return _arn_matches_target(resource_arn, target.arn, source_account_id=source_account_id)

    resource_id = resource.get("resource_id")
    return (
        isinstance(resource_id, str)
        and resource_id == target.resource_id
        and _resource_type_matches_target(resource, target)
        and _source_account_matches_target(source_account_id, target)
    )


def _arn_matches_target(resource_arn: str, target_arn: str, *, source_account_id: Any = None) -> bool:
    if resource_arn == target_arn:
        return True

    resource_parts = resource_arn.split(":", 5)
    target_parts = target_arn.split(":", 5)
    if len(resource_parts) != 6 or len(target_parts) != 6:
        return False
    if resource_parts[:4] != target_parts[:4] or resource_parts[5] != target_parts[5]:
        return False

    resource_account = resource_parts[4]
    target_account = target_parts[4]
    if resource_account == target_account:
        return True
    if resource_account == "*" and isinstance(source_account_id, str):
        return source_account_id == target_account
    return False


def _source_account_matches_target(source_account_id: Any, target: TargetScope) -> bool:
    if target.account_id is None:
        return True
    return isinstance(source_account_id, str) and source_account_id == target.account_id


def _resource_type_matches_target(resource: dict[str, Any], target: TargetScope) -> bool:
    resource_type = resource.get("resource_type")
    if not isinstance(resource_type, str):
        return False
    return _normalized_resource_type(resource_type) in _acceptable_resource_types_for_target(target)


def _acceptable_resource_types_for_target(target: TargetScope) -> set[str]:
    target_type = _normalized_resource_type(target.resource_type)
    service = _normalized_resource_type(target.service)
    module = _normalized_resource_type(module_for_target(target))
    aliases = set(RESOURCE_TYPE_ALIASES.get((target.service, target.resource_type), set()))
    return {
        target_type,
        f"{service}_{target_type}",
        f"{module}_{target_type}",
        *aliases,
    }


def _normalized_resource_type(resource_type: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", resource_type.lower()).strip("_")
    return re.sub(r"_+", "_", normalized)


def _annotated_resource(resource: dict[str, Any], *, scope_match: str, scope_source: str) -> dict[str, Any]:
    return {**copy.deepcopy(resource), "scope_match": scope_match, "scope_source": scope_source}


def _arn_references(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value} if value.startswith("arn:") else set()
    if isinstance(value, dict):
        return {arn for item in value.values() for arn in _arn_references(item)}
    if isinstance(value, list):
        return {arn for item in value for arn in _arn_references(item)}
    return set()


def _filtered_resource_exists(resources: list[dict[str, Any]], arn: str) -> bool:
    return any(resource.get("arn") == arn for resource in resources)


def _target_result(target: TargetScope, status: str) -> dict[str, str]:
    return {
        "target": target.arn,
        "status": status,
        "module": module_for_target(target),
        "region": target.region or "global",
    }


def _not_found_error(target: TargetScope) -> dict[str, str]:
    return {
        "operation": "target_filter",
        "resource": target.arn,
        "code": "not_found",
        "message": f"Target resource not found: {target.arn}",
    }


def _target_filter_coverage(envelope: dict[str, Any]) -> dict[str, Any]:
    failed_resources = [
        error.get("resource")
        for error in envelope.get("errors", [])
        if error.get("operation") == "target_filter" and error.get("code") == "not_found"
    ]
    succeeded = len(envelope.get("resources", []))
    failed = len(failed_resources)
    sample_resource = _sample_resource(envelope.get("resources", []), failed_resources)
    return {
        "check": "target_filter",
        "scope": "per_resource" if succeeded or failed else "module_wide",
        "status": "partial" if failed else "complete",
        "succeeded": succeeded,
        "failed": failed,
        "skipped": 0,
        "reasons": [
            {
                "code": "post_filter",
                "count": max(1, succeeded + failed),
                "sample_resource": sample_resource,
            }
        ],
    }


def _sample_resource(resources: list[dict[str, Any]], failed_resources: list[Any]) -> str | None:
    for resource in resources:
        resource_arn = resource.get("arn")
        if isinstance(resource_arn, str):
            return resource_arn
        resource_id = resource.get("resource_id")
        if isinstance(resource_id, str):
            return resource_id
    for resource in failed_resources:
        if isinstance(resource, str):
            return resource
    return None


def _empty_filtered_envelope(
    module: str,
    region: str,
    target: TargetScope,
    source_envelopes: Any,
) -> dict[str, Any]:
    account_id = target.account_id or _first_source_account_id(source_envelopes) or "unknown"
    status = "error" if account_id == "unknown" else "partial"
    return {
        "module": module,
        "account_id": account_id,
        "region": region,
        "status": status,
        "resources": [],
        "coverage": [],
        "errors": [_not_found_error(target)],
    }


def _first_source_account_id(source_envelopes: Any) -> str | None:
    for envelope in source_envelopes:
        account_id = envelope.get("account_id") if isinstance(envelope, dict) else None
        if isinstance(account_id, str) and account_id:
            return account_id
    return None


def _required_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise TargetParseError(f"Resource selector missing string field: {key}")
    return value
