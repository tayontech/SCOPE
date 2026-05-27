from __future__ import annotations

from scope.attack.policy_eval import evaluate_policy_documents


def test_allow_action_resource_match_returns_allowed() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "S3:GetObject",
                    "Resource": "arn:aws:s3:::sensitive/*",
                },
            }
        ],
        action="s3:GetObject",
        resource="arn:aws:s3:::sensitive/file.txt",
    )

    assert result.decision == "allowed"


def test_explicit_deny_overrides_allow() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                    {
                        "Effect": "Deny",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::sensitive/*",
                    },
                ]
            }
        ],
        action="s3:GetObject",
        resource="arn:aws:s3:::sensitive/file.txt",
    )

    assert result.decision == "explicit_deny"


def test_matching_statement_with_condition_returns_conditional() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "kms:ViaService": "s3.us-east-1.amazonaws.com"
                            }
                        },
                    }
                ]
            }
        ],
        action="kms:Decrypt",
        resource="arn:aws:kms:us-east-1:123456789012:key/key-1",
    )

    assert result.decision == "conditional"
    assert result.caveats
    assert "Condition" in result.caveats[0]


def test_no_matching_allow_returns_implicit_deny() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}
                ]
            }
        ],
        action="s3:GetObject",
        resource="arn:aws:s3:::sensitive/file.txt",
    )

    assert result.decision == "implicit_deny"


def test_not_action_deny_denies_requested_action_that_is_not_excluded() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
                    {"Effect": "Deny", "NotAction": "s3:ListBucket", "Resource": "*"},
                ]
            }
        ],
        action="s3:GetObject",
        resource="arn:aws:s3:::sensitive/file.txt",
    )

    assert result.decision == "explicit_deny"


def test_not_resource_deny_denies_requested_resource_that_is_not_excluded() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                    {
                        "Effect": "Deny",
                        "Action": "s3:GetObject",
                        "NotResource": "arn:aws:s3:::public/*",
                    },
                ]
            }
        ],
        action="s3:GetObject",
        resource="arn:aws:s3:::sensitive/file.txt",
    )

    assert result.decision == "explicit_deny"


def test_conditional_deny_returns_conditional_not_explicit_deny() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                    {
                        "Effect": "Deny",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                        "Condition": {
                            "Bool": {"aws:MultiFactorAuthPresent": "false"}
                        },
                    },
                ]
            }
        ],
        action="s3:GetObject",
        resource="arn:aws:s3:::sensitive/file.txt",
    )

    assert result.decision == "conditional"
    assert result.matched_deny
    assert result.caveats
    assert "Condition" in result.caveats[0]


def test_unconditional_allow_wins_over_another_conditional_allow() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "kms:ViaService": "s3.us-east-1.amazonaws.com"
                            }
                        },
                    },
                    {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"},
                ]
            }
        ],
        action="kms:Decrypt",
        resource="arn:aws:kms:us-east-1:123456789012:key/key-1",
    )

    assert result.decision == "allowed"


def test_malformed_statement_shape_with_matching_allow_returns_conditional() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                    "malformed-statement",
                ]
            }
        ],
        action="s3:GetObject",
        resource="arn:aws:s3:::sensitive/file.txt",
    )

    assert result.decision == "conditional"
    assert result.caveats
    assert "Malformed Statement" in result.caveats[0]


def test_missing_effect_with_matching_allow_returns_conditional() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                    {"Action": "s3:GetObject", "Resource": "*"},
                ]
            }
        ],
        action="s3:GetObject",
        resource="arn:aws:s3:::sensitive/file.txt",
    )

    assert result.decision == "conditional"
    assert result.caveats
    assert any("Malformed Effect" in caveat for caveat in result.caveats)


def test_missing_action_selector_with_matching_allow_returns_conditional() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                    {"Effect": "Deny", "Resource": "*"},
                ]
            }
        ],
        action="s3:GetObject",
        resource="arn:aws:s3:::sensitive/file.txt",
    )

    assert result.decision == "conditional"
    assert result.caveats
    assert any("missing action selector" in caveat for caveat in result.caveats)


def test_missing_resource_selector_with_matching_allow_returns_conditional() -> None:
    result = evaluate_policy_documents(
        [
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                    {"Effect": "Deny", "Action": "s3:GetObject"},
                ]
            }
        ],
        action="s3:GetObject",
        resource="arn:aws:s3:::sensitive/file.txt",
    )

    assert result.decision == "conditional"
    assert result.caveats
    assert any("missing resource selector" in caveat for caveat in result.caveats)
