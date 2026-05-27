from __future__ import annotations

from botocore.exceptions import ClientError

from scope.enumerators.route53 import run
from tests.scope.enumerators.fakes import FakeClient, FakeFactory


def test_route53_collects_public_records_and_dangling_dns_candidates():
    route53 = FakeClient(
        {
            "list_hosted_zones": {
                "IsTruncated": False,
                "HostedZones": [
                    {
                        "Id": "/hostedzone/Z123",
                        "Name": "example.com.",
                        "Config": {"PrivateZone": False},
                        "ResourceRecordSetCount": 2,
                    }
                ],
            },
            "list_resource_record_sets": {
                "IsTruncated": False,
                "ResourceRecordSets": [
                    {
                        "Name": "app.example.com.",
                        "Type": "CNAME",
                        "TTL": 300,
                        "ResourceRecords": [{"Value": "d111111abcdef8.cloudfront.net"}],
                    },
                    {
                        "Name": "api.example.com.",
                        "Type": "A",
                        "AliasTarget": {
                            "HostedZoneId": "Z35SXDOTRQ7X7K",
                            "DNSName": "dualstack.app-alb-123.us-east-1.elb.amazonaws.com.",
                            "EvaluateTargetHealth": False,
                        },
                    },
                ],
            },
        }
    )

    envelope = run(FakeFactory(route53=route53), "global")

    assert envelope.status == "complete"
    zone = envelope.resources[0]
    assert zone["resource_type"] == "route53_hosted_zone"
    assert zone["resource_id"] == "Z123"
    assert zone["public_zone"] is True
    assert zone["records"][0]["target_values"] == ["d111111abcdef8.cloudfront.net"]
    assert zone["records"][0]["aws_target_type"] == "cloudfront"
    assert zone["records"][0]["dangling_dns_candidate"] is True
    assert zone["records"][1]["alias_target"] == "dualstack.app-alb-123.us-east-1.elb.amazonaws.com"
    assert zone["records"][1]["aws_target_type"] == "elb"
    assert {finding["type"] for finding in zone["findings"]} == {
        "public_dns_records",
        "dangling_dns_candidates",
    }


def test_route53_private_zone_records_are_not_public_exposure():
    route53 = FakeClient(
        {
            "list_hosted_zones": {
                "IsTruncated": False,
                "HostedZones": [
                    {
                        "Id": "/hostedzone/ZPRIVATE",
                        "Name": "internal.example.com.",
                        "Config": {"PrivateZone": True},
                    }
                ],
            },
            "list_resource_record_sets": {
                "IsTruncated": False,
                "ResourceRecordSets": [
                    {
                        "Name": "app.internal.example.com.",
                        "Type": "CNAME",
                        "ResourceRecords": [{"Value": "d111111abcdef8.cloudfront.net"}],
                    }
                ],
            },
        }
    )

    envelope = run(FakeFactory(route53=route53), "global")

    zone = envelope.resources[0]
    assert zone["public_zone"] is False
    assert zone["records"][0]["public_dns"] is False
    assert zone["findings"] == []


def test_route53_list_hosted_zones_failure_returns_error_envelope():
    route53 = FakeClient(
        {
            "list_hosted_zones": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListHostedZones",
            )
        }
    )

    envelope = run(FakeFactory(route53=route53), "global")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "route53.ListHostedZones"
