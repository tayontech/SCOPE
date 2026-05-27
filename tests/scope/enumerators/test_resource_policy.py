from __future__ import annotations

from scope.enumerators.resource_policy import normalize_resource_policy


def test_normalize_resource_policy_preserves_statement_scope_and_conditions() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3PublishOnly",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["sns:Publish"],
                "Resource": "arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns",
                "Condition": {
                    "StringEquals": {
                        "AWS:SourceArn": "arn:aws:s3:::tot-vpc-logs",
                        "AWS:SourceAccount": "123456789012",
                    }
                },
            }
        ],
    }

    normalized = normalize_resource_policy(policy, account_id="123456789012")

    assert normalized["document"] == policy
    assert normalized["principals"] == ["*"]
    assert normalized["statements"] == [
        {
            "sid": "S3PublishOnly",
            "effect": "Allow",
            "principal": "*",
            "not_principal": None,
            "action": ["sns:Publish"],
            "not_action": [],
            "resource": ["arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns"],
            "not_resource": [],
            "condition": {
                "StringEquals": {
                    "AWS:SourceArn": "arn:aws:s3:::tot-vpc-logs",
                    "AWS:SourceAccount": "123456789012",
                }
            },
            "normalized_principals": ["*"],
            "normalized_actions": ["sns:Publish"],
            "normalized_resources": ["arn:aws:sns:us-east-1:123456789012:vpc-flow-logs-sns"],
            "source_arns": ["arn:aws:s3:::tot-vpc-logs"],
            "source_accounts": ["123456789012"],
            "source_org_ids": [],
            "service_principals": [],
            "is_public": True,
            "is_cross_account": False,
        }
    ]


def test_normalize_resource_policy_classifies_cross_account_and_service_principals() -> None:
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::999999999999:root",
                    "Service": "s3.amazonaws.com",
                },
                "Action": "kms:Decrypt",
                "Resource": "*",
            }
        ]
    }

    normalized = normalize_resource_policy(policy, account_id="123456789012")

    statement = normalized["statements"][0]
    assert statement["normalized_principals"] == [
        "arn:aws:iam::999999999999:root",
        "s3.amazonaws.com",
    ]
    assert statement["service_principals"] == ["s3.amazonaws.com"]
    assert statement["is_public"] is False
    assert statement["is_cross_account"] is True
