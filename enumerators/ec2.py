from __future__ import annotations

from typing import Any

from scope_core.coverage import CoverageTracker
from scope_core.models import ModuleEnvelope


PRIMARY_CHECKS: list[str] = []
REQUIRED_CHECKS = [
    "describe_instances",
    "describe_security_groups",
    "describe_vpcs",
    "describe_snapshots",
    "snapshot_attributes",
    "describe_load_balancers_v2",
    "describe_listeners",
    "describe_load_balancers_classic",
]


def run(factory: Any, region: str) -> ModuleEnvelope:
    tracker = CoverageTracker(primary=PRIMARY_CHECKS, required=REQUIRED_CHECKS)
    ec2 = factory.client("ec2")
    elbv2 = factory.client("elbv2")
    elb = factory.client("elb")
    findings: list[dict[str, Any]] = []

    findings.extend(_enumerate_instances(factory, ec2, region, tracker))
    findings.extend(_enumerate_security_groups(factory, ec2, region, tracker))
    findings.extend(_enumerate_vpcs(factory, ec2, region, tracker))
    findings.extend(_enumerate_snapshots(factory, ec2, factory.account_id, region, tracker))
    findings.extend(_enumerate_elbv2(factory, elbv2, region, tracker))
    findings.extend(_enumerate_classic_elb(factory, elb, region, tracker))

    coverage, errors = tracker.to_envelope_fields()
    return ModuleEnvelope(
        module="ec2",
        account_id=factory.account_id,
        region=region,
        status=tracker.derive_status(),
        resources=findings,
        coverage=coverage,
        errors=errors,
    )


def _enumerate_instances(factory: Any, ec2: Any, region: str, tracker: CoverageTracker) -> list[dict[str, Any]]:
    try:
        reservations = factory.paginate(ec2, "describe_instances", "Reservations")
        tracker.record_ok("describe_instances", resource="instances")
    except Exception as err:
        tracker.record_resource_failure("describe_instances", None, "ec2.DescribeInstances", err)
        return []

    findings: list[dict[str, Any]] = []
    for reservation in reservations:
        for instance in reservation.get("Instances") or []:
            metadata = instance.get("MetadataOptions") or {}
            imds_version = "v2" if metadata.get("HttpTokens") == "required" else "v1"
            name_tag = next((tag for tag in instance.get("Tags") or [] if tag.get("Key") == "Name"), None)
            finding = {
                "resource_type": "ec2_instance",
                "resource_id": instance.get("InstanceId"),
                "arn": f"arn:aws:ec2:{region}:*:instance/{instance.get('InstanceId')}",
                "region": region,
                "name": name_tag.get("Value") if name_tag else None,
                "state": (instance.get("State") or {}).get("Name"),
                "instance_type": instance.get("InstanceType"),
                "platform": instance.get("Platform") or "linux",
                "public_ip": instance.get("PublicIpAddress"),
                "private_ip": instance.get("PrivateIpAddress"),
                "vpc_id": instance.get("VpcId"),
                "subnet_id": instance.get("SubnetId"),
                "iam_instance_profile": _instance_profile(instance.get("IamInstanceProfile")),
                "security_groups": [sg.get("GroupId") for sg in instance.get("SecurityGroups") or []],
                "imds_version": imds_version,
                "metadata_options": {
                    "http_tokens": metadata.get("HttpTokens"),
                    "http_endpoint": metadata.get("HttpEndpoint"),
                    "http_put_response_hop_limit": metadata.get("HttpPutResponseHopLimit"),
                },
                "findings": [],
            }
            if imds_version == "v1":
                finding["findings"].append(
                    {
                        "type": "imds_v1_enabled",
                        "severity": "critical",
                        "detail": "Instance uses IMDSv1 (HttpTokens=optional) — credential theft via SSRF",
                    }
                )
            if instance.get("PublicIpAddress"):
                finding["findings"].append(
                    {
                        "type": "public_ip",
                        "severity": "info",
                        "detail": f"Instance has public IP: {instance.get('PublicIpAddress')}",
                    }
                )
            if not instance.get("IamInstanceProfile"):
                finding["findings"].append(
                    {
                        "type": "no_instance_profile",
                        "severity": "info",
                        "detail": "No IAM instance profile attached",
                    }
                )
            findings.append(finding)
    return findings


def _instance_profile(profile: dict[str, Any] | None) -> dict[str, Any] | None:
    if not profile:
        return None
    return {"arn": profile.get("Arn"), "id": profile.get("Id")}


def _enumerate_security_groups(factory: Any, ec2: Any, region: str, tracker: CoverageTracker) -> list[dict[str, Any]]:
    try:
        groups = factory.paginate(ec2, "describe_security_groups", "SecurityGroups")
        tracker.record_ok("describe_security_groups", resource="security_groups")
    except Exception as err:
        tracker.record_resource_failure("describe_security_groups", None, "ec2.DescribeSecurityGroups", err)
        return []

    findings: list[dict[str, Any]] = []
    for group in groups:
        inbound_rules = [_inbound_rule(permission) for permission in group.get("IpPermissions") or []]
        finding = {
            "resource_type": "ec2_security_group",
            "resource_id": group.get("GroupId"),
            "arn": f"arn:aws:ec2:{region}:*:security-group/{group.get('GroupId')}",
            "region": region,
            "name": group.get("GroupName"),
            "description": group.get("Description"),
            "vpc_id": group.get("VpcId"),
            "inbound_rules": inbound_rules,
            "findings": [],
        }
        if any(source in {"0.0.0.0/0", "::/0"} for rule in inbound_rules for source in rule["sources"]):
            finding["findings"].append(
                {
                    "type": "open_to_world",
                    "severity": "high",
                    "detail": "Security group has inbound rule(s) open to 0.0.0.0/0 or ::/0",
                }
            )
        findings.append(finding)
    return findings


def _inbound_rule(permission: dict[str, Any]) -> dict[str, Any]:
    sources = [
        *[item.get("CidrIp") for item in permission.get("IpRanges") or []],
        *[item.get("CidrIpv6") for item in permission.get("Ipv6Ranges") or []],
        *[item.get("PrefixListId") for item in permission.get("PrefixListIds") or []],
        *[item.get("GroupId") for item in permission.get("UserIdGroupPairs") or []],
    ]
    return {
        "protocol": permission.get("IpProtocol"),
        "from_port": permission.get("FromPort"),
        "to_port": permission.get("ToPort"),
        "sources": [source for source in sources if source is not None],
    }


def _enumerate_vpcs(factory: Any, ec2: Any, region: str, tracker: CoverageTracker) -> list[dict[str, Any]]:
    try:
        vpcs = factory.paginate(ec2, "describe_vpcs", "Vpcs")
        tracker.record_ok("describe_vpcs", resource="vpcs")
    except Exception as err:
        tracker.record_resource_failure("describe_vpcs", None, "ec2.DescribeVpcs", err)
        return []

    findings = []
    for vpc in vpcs:
        name_tag = next((tag for tag in vpc.get("Tags") or [] if tag.get("Key") == "Name"), None)
        findings.append(
            {
                "resource_type": "ec2_vpc",
                "resource_id": vpc.get("VpcId"),
                "arn": f"arn:aws:ec2:{region}:*:vpc/{vpc.get('VpcId')}",
                "region": region,
                "name": name_tag.get("Value") if name_tag else None,
                "cidr_block": vpc.get("CidrBlock"),
                "is_default": vpc.get("IsDefault") or False,
                "state": vpc.get("State"),
                "findings": [],
            }
        )
    return findings


def _enumerate_snapshots(factory: Any, ec2: Any, account_id: str, region: str, tracker: CoverageTracker) -> list[dict[str, Any]]:
    try:
        snapshots = factory.paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"])
        tracker.record_ok("describe_snapshots", resource="snapshots")
    except Exception as err:
        tracker.record_resource_failure("describe_snapshots", None, "ec2.DescribeSnapshots", err)
        return []

    findings: list[dict[str, Any]] = []
    for snapshot in snapshots:
        snapshot_arn = f"arn:aws:ec2:{region}:{account_id}:snapshot/{snapshot.get('SnapshotId')}"
        is_public = False
        snapshot_attributes_status = None
        try:
            response = ec2.describe_snapshot_attribute(
                SnapshotId=snapshot.get("SnapshotId"),
                Attribute="createVolumePermission",
            )
            permissions = response.get("CreateVolumePermissions") or []
            is_public = any(permission.get("Group") == "all" for permission in permissions)
            snapshot_attributes_status = "present"
            tracker.record_ok("snapshot_attributes", resource=snapshot_arn)
        except Exception as err:
            code = _error_code(err)
            snapshot_attributes_status = _classify_status(code)
            tracker.record_resource_failure(
                "snapshot_attributes",
                snapshot_arn,
                "ec2.DescribeSnapshotAttribute",
                err,
            )

        finding = {
            "resource_type": "ec2_snapshot",
            "resource_id": snapshot.get("SnapshotId"),
            "arn": snapshot_arn,
            "region": region,
            "volume_id": snapshot.get("VolumeId"),
            "volume_size_gb": snapshot.get("VolumeSize"),
            "encrypted": snapshot.get("Encrypted") or False,
            "state": snapshot.get("State"),
            "is_public": is_public,
            "snapshot_attributes_status": snapshot_attributes_status,
            "findings": [],
        }
        if is_public:
            finding["findings"].append(
                {
                    "type": "public_snapshot",
                    "severity": "critical",
                    "detail": 'Snapshot is publicly shared (createVolumePermission includes "all")',
                }
            )
        if not snapshot.get("Encrypted"):
            finding["findings"].append(
                {
                    "type": "unencrypted_snapshot",
                    "severity": "medium",
                    "detail": "Snapshot is not encrypted",
                }
            )
        findings.append(finding)
    return findings


def _enumerate_elbv2(factory: Any, elbv2: Any, region: str, tracker: CoverageTracker) -> list[dict[str, Any]]:
    try:
        load_balancers = factory.paginate(elbv2, "describe_load_balancers", "LoadBalancers")
        tracker.record_ok("describe_load_balancers_v2", resource="load_balancers_v2")
    except Exception as err:
        tracker.record_resource_failure("describe_load_balancers_v2", None, "elbv2.DescribeLoadBalancers", err)
        return []

    findings: list[dict[str, Any]] = []
    for load_balancer in load_balancers:
        lb_arn = load_balancer.get("LoadBalancerArn")
        listeners: list[dict[str, Any]] = []
        listeners_status = None
        try:
            raw_listeners = factory.paginate(elbv2, "describe_listeners", "Listeners", LoadBalancerArn=lb_arn)
            listeners = [
                {
                    "port": listener.get("Port"),
                    "protocol": listener.get("Protocol"),
                    "ssl_policy": listener.get("SslPolicy"),
                }
                for listener in raw_listeners
            ]
            listeners_status = "present"
            tracker.record_ok("describe_listeners", resource=lb_arn)
        except Exception as err:
            listeners_status = _classify_status(_error_code(err))
            tracker.record_resource_failure("describe_listeners", lb_arn, "elbv2.DescribeListeners", err)

        finding = {
            "resource_type": "ec2_load_balancer",
            "resource_id": load_balancer.get("LoadBalancerName"),
            "arn": lb_arn,
            "region": region,
            "type": load_balancer.get("Type"),
            "scheme": load_balancer.get("Scheme"),
            "state": (load_balancer.get("State") or {}).get("Code"),
            "dns_name": load_balancer.get("DNSName"),
            "vpc_id": load_balancer.get("VpcId"),
            "availability_zones": [az.get("ZoneName") for az in load_balancer.get("AvailabilityZones") or []],
            "listeners": listeners,
            "listeners_status": listeners_status,
            "findings": [],
        }
        if load_balancer.get("Scheme") == "internet-facing":
            finding["findings"].append(
                {
                    "type": "internet_facing",
                    "severity": "info",
                    "detail": f"Load balancer is internet-facing: {load_balancer.get('DNSName')}",
                }
            )
        findings.append(finding)
    return findings


def _enumerate_classic_elb(factory: Any, elb: Any, region: str, tracker: CoverageTracker) -> list[dict[str, Any]]:
    try:
        load_balancers = factory.paginate(elb, "describe_load_balancers", "LoadBalancerDescriptions")
        tracker.record_ok("describe_load_balancers_classic", resource="load_balancers_classic")
    except Exception as err:
        tracker.record_resource_failure("describe_load_balancers_classic", None, "elb.DescribeLoadBalancers", err)
        return []

    findings = []
    for load_balancer in load_balancers:
        finding = {
            "resource_type": "ec2_load_balancer",
            "resource_id": load_balancer.get("LoadBalancerName"),
            "arn": None,
            "region": region,
            "type": "classic",
            "scheme": load_balancer.get("Scheme"),
            "dns_name": load_balancer.get("DNSName"),
            "vpc_id": load_balancer.get("VPCId"),
            "availability_zones": load_balancer.get("AvailabilityZones") or [],
            "listeners": [
                {
                    "port": (description.get("Listener") or {}).get("LoadBalancerPort"),
                    "protocol": (description.get("Listener") or {}).get("Protocol"),
                    "instance_port": (description.get("Listener") or {}).get("InstancePort"),
                    "instance_protocol": (description.get("Listener") or {}).get("InstanceProtocol"),
                }
                for description in load_balancer.get("ListenerDescriptions") or []
            ],
            "findings": [],
        }
        if load_balancer.get("Scheme") == "internet-facing":
            finding["findings"].append(
                {
                    "type": "internet_facing",
                    "severity": "info",
                    "detail": f"Classic load balancer is internet-facing: {load_balancer.get('DNSName')}",
                }
            )
        findings.append(finding)
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
