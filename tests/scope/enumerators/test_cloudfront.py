from __future__ import annotations

from botocore.exceptions import ClientError

from scope.enumerators.cloudfront import run
from tests.scope.enumerators.fakes import FakeClient, FakeFactory


def test_cloudfront_collects_distribution_public_endpoint_context():
    cloudfront = FakeClient(
        {
            "list_distributions": {
                "DistributionList": {
                    "IsTruncated": False,
                    "Items": [
                        {
                            "Id": "E123ABC",
                            "ARN": "arn:aws:cloudfront::123456789012:distribution/E123ABC",
                            "DomainName": "d111111abcdef8.cloudfront.net",
                            "Status": "Deployed",
                            "Enabled": True,
                            "Aliases": {"Items": ["app.example.com"], "Quantity": 1},
                            "Origins": {
                                "Items": [
                                    {
                                        "Id": "alb-origin",
                                        "DomainName": "app-alb-123.us-east-1.elb.amazonaws.com",
                                        "CustomOriginConfig": {"OriginProtocolPolicy": "https-only"},
                                    }
                                ]
                            },
                            "DefaultCacheBehavior": {
                                "TargetOriginId": "alb-origin",
                                "ViewerProtocolPolicy": "redirect-to-https",
                                "AllowedMethods": {"Items": ["GET", "HEAD"]},
                            },
                            "CacheBehaviors": {"Items": []},
                            "ViewerCertificate": {"CloudFrontDefaultCertificate": False, "ACMCertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/cert"},
                            "WebACLId": "arn:aws:wafv2:us-east-1:123456789012:global/webacl/app/abc",
                            "Logging": {"Enabled": True, "Bucket": "logs.s3.amazonaws.com"},
                        }
                    ],
                }
            }
        }
    )

    envelope = run(FakeFactory(cloudfront=cloudfront), "global")

    assert envelope.status == "complete"
    distribution = envelope.resources[0]
    assert distribution["resource_type"] == "cloudfront_distribution"
    assert distribution["resource_id"] == "E123ABC"
    assert distribution["domain_name"] == "d111111abcdef8.cloudfront.net"
    assert distribution["aliases"] == ["app.example.com"]
    assert distribution["public_endpoint"] is True
    assert distribution["origins"] == [
        {
            "id": "alb-origin",
            "domain_name": "app-alb-123.us-east-1.elb.amazonaws.com",
            "origin_type": "custom",
            "origin_path": None,
            "origin_protocol_policy": "https-only",
        }
    ]
    assert distribution["default_behavior"]["target_origin_id"] == "alb-origin"
    assert distribution["logging_enabled"] is True
    assert {finding["type"] for finding in distribution["findings"]} == {"public_distribution"}


def test_cloudfront_list_distributions_failure_returns_error_envelope():
    cloudfront = FakeClient(
        {
            "list_distributions": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListDistributions",
            )
        }
    )

    envelope = run(FakeFactory(cloudfront=cloudfront), "global")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "cloudfront.ListDistributions"
