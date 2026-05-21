from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from enumerators.ec2 import run
from tests.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "enum" / "ec2"


def _expected_contract() -> dict:
    return json.loads((FIXTURE_DIR / "expected.json").read_text(encoding="utf-8"))


def _contract(envelope, expected: dict) -> dict:
    dumped = envelope.model_dump(mode="json")
    return {key: dumped[key] for key in expected}


def test_ec2_matches_js_fixture_contract():
    ec2 = FakeClient(
        {
            "describe_instances": {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-0abc123def456789a",
                                "State": {"Name": "running"},
                                "InstanceType": "t3.micro",
                                "PublicIpAddress": None,
                                "PrivateIpAddress": "10.0.1.10",
                                "VpcId": "vpc-0abc123",
                                "SubnetId": "subnet-0abc123",
                                "IamInstanceProfile": {
                                    "Arn": "arn:aws:iam::123456789012:instance-profile/TestProfile",
                                    "Id": "AIPATEST",
                                },
                                "SecurityGroups": [{"GroupId": "sg-0abc123"}],
                                "MetadataOptions": {
                                    "HttpTokens": "optional",
                                    "HttpEndpoint": "enabled",
                                    "HttpPutResponseHopLimit": 1,
                                },
                                "Tags": [{"Key": "Name", "Value": "test-instance"}],
                            },
                        ],
                    },
                ],
            },
            "describe_security_groups": {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-0abc123",
                        "GroupName": "test-sg",
                        "Description": "Test security group",
                        "VpcId": "vpc-0abc123",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 80,
                                "ToPort": 80,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                "Ipv6Ranges": [],
                                "PrefixListIds": [],
                                "UserIdGroupPairs": [],
                            },
                        ],
                    },
                ],
            },
            "describe_vpcs": {
                "Vpcs": [
                    {
                        "VpcId": "vpc-0abc123",
                        "CidrBlock": "10.0.0.0/16",
                        "IsDefault": False,
                        "State": "available",
                        "Tags": [{"Key": "Name", "Value": "test-vpc"}],
                    },
                ],
            },
            "describe_snapshots": {
                "Snapshots": [
                    {
                        "SnapshotId": "snap-0abc123",
                        "VolumeId": "vol-0abc123",
                        "VolumeSize": 20,
                        "Encrypted": False,
                        "State": "completed",
                    },
                ],
            },
            "describe_snapshot_attribute": {"CreateVolumePermissions": []},
        }
    )
    elbv2 = FakeClient({"describe_load_balancers": {"LoadBalancers": []}, "describe_listeners": {"Listeners": []}})
    elb = FakeClient({"describe_load_balancers": {"LoadBalancerDescriptions": []}})
    expected = _expected_contract()

    envelope = run(FakeFactory(ec2=ec2, elbv2=elbv2, elb=elb), "us-east-1")

    assert normalize_envelope(_contract(envelope, expected)) == normalize_envelope(expected)


def _empty_clients(ec2_ops=None, elbv2_ops=None, elb_ops=None):
    ec2_defaults = {
        "describe_instances": {"Reservations": []},
        "describe_security_groups": {"SecurityGroups": []},
        "describe_vpcs": {"Vpcs": []},
        "describe_snapshots": {"Snapshots": []},
    }
    elbv2_defaults = {
        "describe_load_balancers": {"LoadBalancers": []},
        "describe_listeners": {"Listeners": []},
    }
    elb_defaults = {"describe_load_balancers": {"LoadBalancerDescriptions": []}}
    if ec2_ops:
        ec2_defaults.update(ec2_ops)
    if elbv2_ops:
        elbv2_defaults.update(elbv2_ops)
    if elb_ops:
        elb_defaults.update(elb_ops)
    return FakeFactory(
        ec2=FakeClient(ec2_defaults),
        elbv2=FakeClient(elbv2_defaults),
        elb=FakeClient(elb_defaults),
    )


def test_ec2_describe_instances_failure_marks_module_partial():
    factory = _empty_clients(
        {
            "describe_instances": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "DescribeInstances",
            ),
        }
    )

    envelope = run(factory, "us-east-1")

    assert envelope.status == "partial"
    assert envelope.errors[0].operation == "ec2.DescribeInstances"
    coverage = next(entry for entry in envelope.coverage if entry.check == "describe_instances")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_ec2_snapshot_attribute_failure_marks_snapshot_partial():
    snapshot_arn = "arn:aws:ec2:us-east-1:123456789012:snapshot/snap-0abc123"
    factory = _empty_clients(
        {
            "describe_snapshots": {
                "Snapshots": [
                    {
                        "SnapshotId": "snap-0abc123",
                        "VolumeId": "vol-0abc123",
                        "VolumeSize": 20,
                        "Encrypted": True,
                    }
                ]
            },
            "describe_snapshot_attribute": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "DescribeSnapshotAttribute",
            ),
        }
    )

    envelope = run(factory, "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources[0]["snapshot_attributes_status"] == "access_denied"
    assert envelope.errors[0].operation == "ec2.DescribeSnapshotAttribute"
    assert envelope.errors[0].resource == snapshot_arn
    coverage = next(entry for entry in envelope.coverage if entry.check == "snapshot_attributes")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_ec2_public_snapshot_generates_critical_finding():
    factory = _empty_clients(
        {
            "describe_snapshots": {
                "Snapshots": [
                    {
                        "SnapshotId": "snap-0abc123",
                        "VolumeId": "vol-0abc123",
                        "VolumeSize": 20,
                        "Encrypted": False,
                    }
                ]
            },
            "describe_snapshot_attribute": {"CreateVolumePermissions": [{"Group": "all"}]},
        }
    )

    envelope = run(factory, "us-east-1")

    snapshot = envelope.resources[0]
    assert snapshot["is_public"] is True
    assert {finding["type"] for finding in snapshot["findings"]} == {
        "public_snapshot",
        "unencrypted_snapshot",
    }


def test_ec2_elbv2_listener_failure_marks_load_balancer_partial():
    lb_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test/abc"
    factory = _empty_clients(
        elbv2_ops={
            "describe_load_balancers": {
                "LoadBalancers": [
                    {
                        "LoadBalancerName": "test-lb",
                        "LoadBalancerArn": lb_arn,
                        "Type": "application",
                        "Scheme": "internet-facing",
                        "DNSName": "test.example.com",
                    }
                ]
            },
            "describe_listeners": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "DescribeListeners",
            ),
        }
    )

    envelope = run(factory, "us-east-1")

    assert envelope.status == "partial"
    lb = envelope.resources[0]
    assert lb["listeners_status"] == "access_denied"
    assert lb["findings"][0]["type"] == "internet_facing"
    assert envelope.errors[0].operation == "elbv2.DescribeListeners"
    assert envelope.errors[0].resource == lb_arn
