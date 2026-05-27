from __future__ import annotations

from typing import Any

from scope.core.coverage import CoverageTracker
from scope.core.models import ModuleEnvelope


PRIMARY_CHECKS = ["list_distributions"]
REQUIRED_CHECKS: list[str] = []


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    cloudfront = factory.client("cloudfront")

    try:
        distributions = _list_distributions(cloudfront)
        tracker.record_ok("list_distributions", resource="distributions")
    except Exception as err:
        tracker.record_module_failure("list_distributions", "cloudfront.ListDistributions", err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="cloudfront",
            account_id=factory.account_id,
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    resources = [_distribution_finding(distribution, region) for distribution in distributions]
    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="cloudfront",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=resources,
        coverage=coverage,
        errors=errors,
    )


def _list_distributions(cloudfront: Any) -> list[dict[str, Any]]:
    distributions: list[dict[str, Any]] = []
    marker: str | None = None
    while True:
        kwargs = {"Marker": marker} if marker else {}
        response = cloudfront.list_distributions(**kwargs)
        listing = response.get("DistributionList") or {}
        distributions.extend(listing.get("Items") or [])
        if not listing.get("IsTruncated"):
            return distributions
        marker = listing.get("NextMarker")
        if not marker:
            return distributions


def _distribution_finding(distribution: dict[str, Any], region: str) -> dict[str, Any]:
    distribution_id = distribution.get("Id")
    aliases = _items(distribution.get("Aliases"))
    origins = [_origin(origin) for origin in _items(distribution.get("Origins"))]
    enabled = bool(distribution.get("Enabled"))
    finding = {
        "resource_type": "cloudfront_distribution",
        "resource_id": distribution_id,
        "arn": distribution.get("ARN"),
        "region": region,
        "domain_name": distribution.get("DomainName"),
        "status": distribution.get("Status"),
        "enabled": enabled,
        "public_endpoint": enabled,
        "aliases": aliases,
        "origins": origins,
        "default_behavior": _cache_behavior(distribution.get("DefaultCacheBehavior") or {}),
        "cache_behaviors": [_cache_behavior(behavior) for behavior in _items(distribution.get("CacheBehaviors"))],
        "viewer_certificate": _viewer_certificate(distribution.get("ViewerCertificate") or {}),
        "web_acl_id": distribution.get("WebACLId") or None,
        "logging_enabled": bool((distribution.get("Logging") or {}).get("Enabled")),
        "logging_bucket": (distribution.get("Logging") or {}).get("Bucket"),
        "findings": [],
    }
    finding["findings"] = _generate_findings(finding)
    return finding


def _origin(origin: dict[str, Any]) -> dict[str, Any]:
    custom_config = origin.get("CustomOriginConfig") or {}
    origin_type = "custom" if custom_config else "s3" if origin.get("S3OriginConfig") else "unknown"
    return {
        "id": origin.get("Id"),
        "domain_name": origin.get("DomainName"),
        "origin_type": origin_type,
        "origin_path": origin.get("OriginPath"),
        "origin_protocol_policy": custom_config.get("OriginProtocolPolicy"),
    }


def _cache_behavior(behavior: dict[str, Any]) -> dict[str, Any]:
    return {
        "target_origin_id": behavior.get("TargetOriginId"),
        "viewer_protocol_policy": behavior.get("ViewerProtocolPolicy"),
        "allowed_methods": _items(behavior.get("AllowedMethods")),
    }


def _viewer_certificate(certificate: dict[str, Any]) -> dict[str, Any]:
    return {
        "cloudfront_default_certificate": bool(certificate.get("CloudFrontDefaultCertificate")),
        "acm_certificate_arn": certificate.get("ACMCertificateArn"),
        "minimum_protocol_version": certificate.get("MinimumProtocolVersion"),
        "ssl_support_method": certificate.get("SSLSupportMethod"),
    }


def _items(value: Any) -> list[Any]:
    if isinstance(value, dict):
        items = value.get("Items")
        return items if isinstance(items, list) else []
    return []


def _generate_findings(distribution: dict[str, Any]) -> list[dict[str, str]]:
    if not distribution.get("public_endpoint"):
        return []
    return [
        {
            "type": "public_distribution",
            "severity": "medium",
            "detail": "Enabled CloudFront distribution is reachable from the internet; origin transition requires origin correlation.",
        }
    ]
