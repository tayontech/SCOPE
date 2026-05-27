from __future__ import annotations

from typing import Any

from scope.core.coverage import CoverageTracker
from scope.core.models import ModuleEnvelope


PRIMARY_CHECKS = ["list_hosted_zones"]
REQUIRED_CHECKS = ["record_sets"]
DNS_RECORD_TYPES = {"A", "AAAA", "CNAME"}
AWS_TARGET_SUFFIXES = {
    "cloudfront": [".cloudfront.net"],
    "elb": [".elb.amazonaws.com", ".elb.amazonaws.com.cn"],
    "s3_website": [".s3-website-", ".s3-website."],
    "execute_api": [".execute-api."],
}


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    route53 = factory.client("route53")

    try:
        zones = _list_hosted_zones(route53)
        tracker.record_ok("list_hosted_zones", resource="hosted_zones")
    except Exception as err:
        tracker.record_module_failure("list_hosted_zones", "route53.ListHostedZones", err)
        coverage, errors = tracker.to_envelope_fields()
        return ModuleEnvelope(
            module="route53",
            account_id=factory.account_id,
            region=region,
            status=tracker.derive_status(),
            resources=[],
            coverage=coverage,
            errors=errors,
        )

    resources: list[dict[str, Any]] = []
    for zone in zones:
        zone_id = _zone_id(zone.get("Id"))
        zone_finding = _base_zone(zone, zone_id, region)
        try:
            records = _list_record_sets(route53, zone_id)
            zone_finding["records"] = [_record(record, public_zone=zone_finding["public_zone"]) for record in records]
            zone_finding["records_status"] = "present"
            tracker.record_ok("record_sets", resource=zone_finding["arn"])
        except Exception as err:
            zone_finding["records_status"] = _classify_status(_error_code(err))
            tracker.record_resource_failure("record_sets", zone_finding["arn"], "route53.ListResourceRecordSets", err)

        zone_finding["findings"] = _generate_findings(zone_finding)
        resources.append(zone_finding)

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="route53",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=resources,
        coverage=coverage,
        errors=errors,
    )


def _list_hosted_zones(route53: Any) -> list[dict[str, Any]]:
    zones: list[dict[str, Any]] = []
    marker: str | None = None
    while True:
        kwargs = {"Marker": marker} if marker else {}
        response = route53.list_hosted_zones(**kwargs)
        zones.extend(response.get("HostedZones") or [])
        if not response.get("IsTruncated"):
            return zones
        marker = response.get("NextMarker")
        if not marker:
            return zones


def _list_record_sets(route53: Any, zone_id: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {"HostedZoneId": zone_id}
    while True:
        response = route53.list_resource_record_sets(**kwargs)
        records.extend(response.get("ResourceRecordSets") or [])
        if not response.get("IsTruncated"):
            return records
        next_name = response.get("NextRecordName")
        next_type = response.get("NextRecordType")
        if not next_name or not next_type:
            return records
        kwargs = {"HostedZoneId": zone_id, "StartRecordName": next_name, "StartRecordType": next_type}
        next_identifier = response.get("NextRecordIdentifier")
        if next_identifier:
            kwargs["StartRecordIdentifier"] = next_identifier


def _base_zone(zone: dict[str, Any], zone_id: str, region: str) -> dict[str, Any]:
    private_zone = bool((zone.get("Config") or {}).get("PrivateZone"))
    return {
        "resource_type": "route53_hosted_zone",
        "resource_id": zone_id,
        "arn": f"arn:aws:route53:::hostedzone/{zone_id}",
        "region": region,
        "name": zone.get("Name"),
        "public_zone": not private_zone,
        "private_zone": private_zone,
        "record_set_count": zone.get("ResourceRecordSetCount"),
        "records": [],
        "records_status": None,
        "findings": [],
    }


def _record(record: dict[str, Any], *, public_zone: bool) -> dict[str, Any]:
    alias_target = _clean_dns_name((record.get("AliasTarget") or {}).get("DNSName"))
    target_values = [_clean_dns_name(item.get("Value")) for item in record.get("ResourceRecords") or [] if item.get("Value")]
    targets = [target for target in [alias_target, *target_values] if target]
    aws_target_type = _aws_target_type(targets)
    public_dns = public_zone and record.get("Type") in DNS_RECORD_TYPES and bool(targets)
    return {
        "name": record.get("Name"),
        "type": record.get("Type"),
        "ttl": record.get("TTL"),
        "public_dns": public_dns,
        "alias_target": alias_target,
        "target_values": target_values,
        "aws_target_type": aws_target_type,
        "dangling_dns_candidate": bool(public_dns and aws_target_type),
        "dangling_reason": (
            "Public DNS points at an AWS-managed hostname; confirm the target exists before treating this as takeover exposure."
            if public_dns and aws_target_type
            else None
        ),
    }


def _zone_id(value: Any) -> str:
    text = str(value or "")
    return text.rsplit("/", 1)[-1]


def _clean_dns_name(value: Any) -> str | None:
    if not value:
        return None
    return str(value).rstrip(".")


def _aws_target_type(targets: list[str]) -> str | None:
    lowered = [target.lower() for target in targets]
    for target_type, suffixes in AWS_TARGET_SUFFIXES.items():
        if any(suffix in target or target.endswith(suffix) for target in lowered for suffix in suffixes):
            return target_type
    return None


def _generate_findings(zone: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    public_records = [record for record in zone.get("records") or [] if record.get("public_dns")]
    dangling_candidates = [record for record in public_records if record.get("dangling_dns_candidate")]
    if public_records:
        findings.append(
            {
                "type": "public_dns_records",
                "severity": "low",
                "detail": f"Public hosted zone has {len(public_records)} DNS record(s) pointing at concrete targets.",
            }
        )
    if dangling_candidates:
        findings.append(
            {
                "type": "dangling_dns_candidates",
                "severity": "medium",
                "detail": f"{len(dangling_candidates)} public DNS record(s) point at AWS-managed hostnames that require target-existence correlation.",
            }
        )
    return findings


def _classify_status(code: str) -> str:
    return "access_denied" if code in {"AccessDenied", "AccessDeniedException"} else "error"


def _error_code(err: Exception) -> str:
    response = getattr(err, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict) and error.get("Code"):
            return str(error["Code"])
    code = getattr(err, "Code", None)
    if code:
        return str(code)
    return err.__class__.__name__ or "Error"
