from __future__ import annotations

import json
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from scope.enumerators.iam import run
from tests.scope.enumerators.fakes import FakeClient, FakeFactory
from tests.scope.enumerators.inventory_assertions import assert_facts_only_resources
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "enum" / "iam"


def _expected_contract() -> dict:
    expected = json.loads((FIXTURE_DIR / "expected.json").read_text(encoding="utf-8"))
    return expected


def _contract(envelope, expected: dict) -> dict:
    dumped = envelope.model_dump(mode="json")
    return {key: dumped[key] for key in expected}


def test_iam_matches_js_fixture_contract_gaad_path():
    iam = FakeClient(
        {
            "get_account_authorization_details": {
                "UserDetailList": [
                    {
                        "UserName": "TestUser",
                        "Arn": "arn:aws:iam::123456789012:user/TestUser",
                        "GroupList": [],
                        "AttachedManagedPolicies": [],
                        "UserPolicyList": [],
                        "PermissionsBoundary": None,
                    }
                ],
                "RoleDetailList": [
                    {
                        "RoleName": "TestRole",
                        "Arn": "arn:aws:iam::123456789012:role/TestRole",
                        "Path": "/",
                        "AssumeRolePolicyDocument": (
                            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                            '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
                        ),
                        "AttachedManagedPolicies": [],
                        "RolePolicyList": [],
                        "PermissionsBoundary": None,
                        "RoleLastUsed": None,
                    }
                ],
                "GroupDetailList": [
                    {
                        "GroupName": "TestGroup",
                        "Arn": "arn:aws:iam::123456789012:group/TestGroup",
                        "AttachedManagedPolicies": [],
                        "GroupPolicyList": [],
                    }
                ],
                "Policies": [],
                "IsTruncated": False,
            },
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {
                "Content": (
                    "user,password_enabled,password_last_used,password_last_changed,password_next_rotation,"
                    "mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
                    "access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,"
                    "access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,"
                    "access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n"
                    "<root_account>,not_supported,2026-01-01T00:00:00+00:00,not_supported,not_supported,true,"
                    "false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n"
                    "TestUser,true,N/A,2026-01-01T00:00:00+00:00,not_applicable,false,false,N/A,N/A,N/A,N/A,"
                    "false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"
                )
            },
            "list_access_keys": {"AccessKeyMetadata": [], "IsTruncated": False},
            "list_mfa_devices": {"MFADevices": [], "IsTruncated": False},
            "get_login_profile": _no_such_entity(),
            "get_group": {"Users": [{"UserName": "TestUser"}]},
            "list_open_id_connect_providers": {"OpenIDConnectProviderList": []},
            "generate_service_last_accessed_details": [
                {"JobId": "job-user-123"},
                {"JobId": "job-role-456"},
            ],
            "get_service_last_accessed_details": [
                {
                    "JobStatus": "COMPLETED",
                    "ServicesLastAccessed": [
                        {
                            "ServiceName": "Amazon S3",
                            "ServiceNamespace": "s3",
                            "LastAuthenticated": None,
                            "TotalAuthenticatedEntities": 0,
                        }
                    ],
                },
                {
                    "JobStatus": "COMPLETED",
                    "ServicesLastAccessed": [
                        {
                            "ServiceName": "Amazon S3",
                            "ServiceNamespace": "s3",
                            "LastAuthenticated": None,
                            "TotalAuthenticatedEntities": 0,
                        }
                    ],
                },
            ],
        }
    )
    expected = _expected_contract()

    envelope = run(FakeFactory(iam=iam), "global")

    assert_facts_only_resources(envelope.resources)
    assert normalize_envelope(_contract(envelope, expected)) == normalize_envelope(expected)


def test_iam_gaad_access_denied_falls_back_to_list_operations():
    iam = FakeClient(
        {
            "get_account_authorization_details": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetAccountAuthorizationDetails",
            ),
            "list_users": {"Users": []},
            "list_roles": {"Roles": []},
            "list_groups": {"Groups": []},
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {"Content": "user,mfa_active,password_last_used\n<root_account>,true,N/A"},
            "list_open_id_connect_providers": {"OpenIDConnectProviderList": []},
        }
    )

    envelope = run(FakeFactory(iam=iam), "global")

    assert envelope.status == "complete"
    assert envelope.resources == []
    assert envelope.errors == []


def test_facts_only_assertion_allows_factual_policy_document_values():
    resources = [
        {
            "resource_type": "iam_user",
            "resource_id": "PolicyUser",
            "inline_policies": [
                {
                    "name": "AllowRead",
                    "document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "*",
                                "Condition": {"StringEquals": {"aws:RequestTag/tier": "high"}},
                                "risk": "customer-tag-key",
                            }
                        ]
                    },
                }
            ],
        }
    ]

    assert_facts_only_resources(resources)

    with pytest.raises(AssertionError, match="forbidden judgment text"):
        assert_facts_only_resources([{"resource_type": "example", "note": "severity: high"}])
    with pytest.raises(AssertionError, match="forbidden judgment key"):
        assert_facts_only_resources([{"resource_type": "example", "risk": "high"}])


def test_iam_excludes_service_linked_roles():
    iam = FakeClient(
        {
            "get_account_authorization_details": {
                "UserDetailList": [],
                "RoleDetailList": [
                    {
                        "RoleName": "ApplicationRole",
                        "Arn": "arn:aws:iam::123456789012:role/ApplicationRole",
                        "Path": "/",
                        "AssumeRolePolicyDocument": '{"Statement":[]}',
                        "AttachedManagedPolicies": [],
                        "RolePolicyList": [],
                        "PermissionsBoundary": None,
                        "RoleLastUsed": None,
                    },
                    {
                        "RoleName": "AWSServiceRoleForSupport",
                        "Arn": "arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
                        "Path": "/aws-service-role/support.amazonaws.com/",
                        "AssumeRolePolicyDocument": '{"Statement":[]}',
                        "AttachedManagedPolicies": [],
                        "RolePolicyList": [],
                        "PermissionsBoundary": None,
                        "RoleLastUsed": None,
                    },
                ],
                "GroupDetailList": [],
                "Policies": [],
                "IsTruncated": False,
            },
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {"Content": "user,mfa_active,password_last_used\n<root_account>,true,N/A"},
            "list_open_id_connect_providers": {"OpenIDConnectProviderList": []},
            "generate_service_last_accessed_details": {"JobId": "job-role-456"},
            "get_service_last_accessed_details": {"JobStatus": "COMPLETED", "ServicesLastAccessed": []},
        }
    )

    envelope = run(FakeFactory(iam=iam), "global")

    assert [resource["resource_id"] for resource in envelope.resources] == ["ApplicationRole"]


def test_iam_fallback_excludes_service_linked_roles():
    iam = FakeClient(
        {
            "get_account_authorization_details": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetAccountAuthorizationDetails",
            ),
            "list_users": {"Users": []},
            "list_roles": {
                "Roles": [
                    {
                        "RoleName": "ApplicationRole",
                        "Arn": "arn:aws:iam::123456789012:role/ApplicationRole",
                        "Path": "/",
                        "AssumeRolePolicyDocument": '{"Statement":[]}',
                    },
                    {
                        "RoleName": "AWSServiceRoleForSupport",
                        "Arn": "arn:aws:iam::123456789012:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
                        "Path": "/aws-service-role/support.amazonaws.com/",
                        "AssumeRolePolicyDocument": '{"Statement":[]}',
                    },
                ]
            },
            "list_groups": {"Groups": []},
            "get_role": {
                "Role": {
                    "RoleName": "ApplicationRole",
                    "Arn": "arn:aws:iam::123456789012:role/ApplicationRole",
                    "Path": "/",
                    "AssumeRolePolicyDocument": '{"Statement":[]}',
                }
            },
            "list_role_policies": {"PolicyNames": []},
            "list_attached_role_policies": {"AttachedPolicies": []},
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {"Content": "user,mfa_active,password_last_used\n<root_account>,true,N/A"},
            "list_open_id_connect_providers": {"OpenIDConnectProviderList": []},
            "generate_service_last_accessed_details": {"JobId": "job-role-456"},
            "get_service_last_accessed_details": {"JobStatus": "COMPLETED", "ServicesLastAccessed": []},
        }
    )

    envelope = run(FakeFactory(iam=iam), "global")

    assert [resource["resource_id"] for resource in envelope.resources] == ["ApplicationRole"]
    assert iam.call_counts["get_role"] == 1


def test_iam_preserves_oidc_trust_conditions_without_risk():
    provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    trust_policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": provider_arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
                    "StringLike": {"token.actions.githubusercontent.com:sub": "repo:scope/demo:*"},
                },
            }
        ]
    }
    iam = FakeClient(
        {
            "get_account_authorization_details": {
                "UserDetailList": [],
                "RoleDetailList": [
                    {
                        "RoleName": "GitHubActionsRole",
                        "Arn": "arn:aws:iam::123456789012:role/GitHubActionsRole",
                        "Path": "/",
                        "AssumeRolePolicyDocument": json.dumps(trust_policy),
                        "AttachedManagedPolicies": [],
                        "RolePolicyList": [],
                        "PermissionsBoundary": None,
                        "RoleLastUsed": None,
                    }
                ],
                "GroupDetailList": [],
                "Policies": [],
                "IsTruncated": False,
            },
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {"Content": "user,mfa_active,password_last_used\n<root_account>,true,N/A"},
            "list_open_id_connect_providers": {"OpenIDConnectProviderList": [{"Arn": provider_arn}]},
            "get_open_id_connect_provider": {
                "Url": "token.actions.githubusercontent.com",
                "ClientIDList": ["sts.amazonaws.com"],
                "ThumbprintList": ["abc123"],
            },
            "generate_service_last_accessed_details": {"JobId": "job-role-456"},
            "get_service_last_accessed_details": {"JobStatus": "COMPLETED", "ServicesLastAccessed": []},
        }
    )

    envelope = run(FakeFactory(iam=iam), "global")

    role = next(resource for resource in envelope.resources if resource["resource_type"] == "iam_role")
    trust = role["trust_relationships"][0]
    assert trust == {
        "principal": provider_arn,
        "trust_type": "federated",
        "is_wildcard": False,
        "has_external_id": False,
        "has_mfa_condition": False,
        "conditions": trust_policy["Statement"][0]["Condition"],
    }
    assert "risk" not in trust

    oidc = next(resource for resource in envelope.resources if resource["resource_type"] == "oidc_provider")
    assert oidc["url"] == "token.actions.githubusercontent.com"
    assert oidc["assumed_role_arns"] == ["arn:aws:iam::123456789012:role/GitHubActionsRole"]
    assert_facts_only_resources(envelope.resources)


def test_iam_attached_policy_documents_follow_inventory_rules():
    customer_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    inline_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "logs:CreateLogGroup", "Resource": "*"}],
    }
    customer_policy_arn = "arn:aws:iam::123456789012:policy/CustomerManagedPolicy"
    aws_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    iam = FakeClient(
        {
            "get_account_authorization_details": {
                "UserDetailList": [
                    {
                        "UserName": "PolicyUser",
                        "Arn": "arn:aws:iam::123456789012:user/PolicyUser",
                        "GroupList": [],
                        "AttachedManagedPolicies": [
                            {"PolicyName": "CustomerManagedPolicy", "PolicyArn": customer_policy_arn},
                            {"PolicyName": "ReadOnlyAccess", "PolicyArn": aws_policy_arn},
                        ],
                        "UserPolicyList": [
                            {"PolicyName": "InlineUserPolicy", "PolicyDocument": json.dumps(inline_policy_doc)}
                        ],
                        "PermissionsBoundary": None,
                    }
                ],
                "RoleDetailList": [],
                "GroupDetailList": [],
                "Policies": [
                    {
                        "PolicyName": "CustomerManagedPolicy",
                        "Arn": customer_policy_arn,
                        "DefaultVersionId": "v3",
                    }
                ],
                "IsTruncated": False,
            },
            "get_policy_version": {"PolicyVersion": {"Document": customer_policy_doc}},
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {
                "Content": "user,mfa_active,password_last_used\n<root_account>,true,N/A\nPolicyUser,false,N/A"
            },
            "list_access_keys": {"AccessKeyMetadata": [], "IsTruncated": False},
            "list_mfa_devices": {"MFADevices": [], "IsTruncated": False},
            "get_login_profile": _no_such_entity(),
            "list_open_id_connect_providers": {"OpenIDConnectProviderList": []},
            "generate_service_last_accessed_details": {"JobId": "job-user-123"},
            "get_service_last_accessed_details": {"JobStatus": "COMPLETED", "ServicesLastAccessed": []},
        }
    )

    envelope = run(FakeFactory(iam=iam), "global")

    user = envelope.resources[0]
    assert user["inline_policies"] == [{"name": "InlineUserPolicy", "document": inline_policy_doc}]
    assert user["attached_policies"] == [
        {"name": "CustomerManagedPolicy", "arn": customer_policy_arn, "document": customer_policy_doc},
        {"name": "ReadOnlyAccess", "arn": aws_policy_arn, "document": None},
    ]


def test_iam_fallback_aws_managed_attached_policy_skips_document_lookup():
    aws_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    iam = FakeClient(
        {
            "get_account_authorization_details": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetAccountAuthorizationDetails",
            ),
            "list_users": {
                "Users": [
                    {
                        "UserName": "PolicyUser",
                        "Arn": "arn:aws:iam::123456789012:user/PolicyUser",
                    }
                ]
            },
            "list_roles": {"Roles": []},
            "list_groups": {"Groups": []},
            "list_user_policies": {"PolicyNames": []},
            "list_attached_user_policies": {
                "AttachedPolicies": [{"PolicyName": "ReadOnlyAccess", "PolicyArn": aws_policy_arn}]
            },
            "list_groups_for_user": {"Groups": []},
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {
                "Content": "user,mfa_active,password_last_used\n<root_account>,true,N/A\nPolicyUser,false,N/A"
            },
            "list_access_keys": {"AccessKeyMetadata": []},
            "list_mfa_devices": {"MFADevices": []},
            "get_login_profile": _no_such_entity(),
            "list_open_id_connect_providers": {"OpenIDConnectProviderList": []},
            "generate_service_last_accessed_details": {"JobId": "job-user-123"},
            "get_service_last_accessed_details": {"JobStatus": "COMPLETED", "ServicesLastAccessed": []},
        }
    )

    envelope = run(FakeFactory(iam=iam), "global")

    user = envelope.resources[0]
    assert user["attached_policies"] == [{"name": "ReadOnlyAccess", "arn": aws_policy_arn, "document": None}]
    assert iam.call_counts["get_policy"] == 0
    assert iam.call_counts["get_policy_version"] == 0


def test_iam_fallback_aws_managed_attached_policy_skips_document_lookup_all_partitions():
    iam = FakeClient(
        {
            "get_account_authorization_details": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetAccountAuthorizationDetails",
            ),
            "list_users": {
                "Users": [
                    {
                        "UserName": "GovPolicyUser",
                        "Arn": "arn:aws-us-gov:iam::123456789012:user/GovPolicyUser",
                    }
                ]
            },
            "list_roles": {"Roles": []},
            "list_groups": {"Groups": []},
            "list_user_policies": {"PolicyNames": []},
            "list_attached_user_policies": {
                "AttachedPolicies": [
                    {
                        "PolicyName": "ReadOnlyAccess",
                        "PolicyArn": "arn:aws-us-gov:iam::aws:policy/ReadOnlyAccess",
                    },
                    {
                        "PolicyName": "SecurityAudit",
                        "PolicyArn": "arn:aws-cn:iam::aws:policy/SecurityAudit",
                    },
                ]
            },
            "list_groups_for_user": {"Groups": []},
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {
                "Content": "user,mfa_active,password_last_used\n<root_account>,true,N/A\nGovPolicyUser,false,N/A"
            },
            "list_access_keys": {"AccessKeyMetadata": []},
            "list_mfa_devices": {"MFADevices": []},
            "get_login_profile": _no_such_entity(),
            "list_open_id_connect_providers": {"OpenIDConnectProviderList": []},
            "generate_service_last_accessed_details": {"JobId": "job-user-123"},
            "get_service_last_accessed_details": {"JobStatus": "COMPLETED", "ServicesLastAccessed": []},
        }
    )

    envelope = run(FakeFactory(iam=iam), "global")

    user = envelope.resources[0]
    assert user["attached_policies"] == [
        {"name": "ReadOnlyAccess", "arn": "arn:aws-us-gov:iam::aws:policy/ReadOnlyAccess", "document": None},
        {"name": "SecurityAudit", "arn": "arn:aws-cn:iam::aws:policy/SecurityAudit", "document": None},
    ]
    assert iam.call_counts["get_policy"] == 0
    assert iam.call_counts["get_policy_version"] == 0


def test_iam_gaad_aws_managed_attached_policy_skips_document_lookup_all_partitions():
    iam = FakeClient(
        {
            "get_account_authorization_details": {
                "UserDetailList": [
                    {
                        "UserName": "GovPolicyUser",
                        "Arn": "arn:aws-us-gov:iam::123456789012:user/GovPolicyUser",
                        "GroupList": [],
                        "AttachedManagedPolicies": [
                            {
                                "PolicyName": "ReadOnlyAccess",
                                "PolicyArn": "arn:aws-us-gov:iam::aws:policy/ReadOnlyAccess",
                            },
                            {
                                "PolicyName": "SecurityAudit",
                                "PolicyArn": "arn:aws-cn:iam::aws:policy/SecurityAudit",
                            },
                        ],
                        "UserPolicyList": [],
                        "PermissionsBoundary": None,
                    }
                ],
                "RoleDetailList": [],
                "GroupDetailList": [],
                "Policies": [
                    {
                        "Arn": "arn:aws-us-gov:iam::aws:policy/ReadOnlyAccess",
                        "DefaultVersionId": "v1",
                    },
                    {
                        "Arn": "arn:aws-cn:iam::aws:policy/SecurityAudit",
                        "DefaultVersionId": "v1",
                    },
                ],
                "IsTruncated": False,
            },
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {
                "Content": "user,mfa_active,password_last_used\n<root_account>,true,N/A\nGovPolicyUser,false,N/A"
            },
            "list_access_keys": {"AccessKeyMetadata": [], "IsTruncated": False},
            "list_mfa_devices": {"MFADevices": [], "IsTruncated": False},
            "get_login_profile": _no_such_entity(),
            "list_open_id_connect_providers": {"OpenIDConnectProviderList": []},
            "generate_service_last_accessed_details": {"JobId": "job-user-123"},
            "get_service_last_accessed_details": {"JobStatus": "COMPLETED", "ServicesLastAccessed": []},
        }
    )

    envelope = run(FakeFactory(iam=iam), "global")

    user = envelope.resources[0]
    assert user["attached_policies"] == [
        {"name": "ReadOnlyAccess", "arn": "arn:aws-us-gov:iam::aws:policy/ReadOnlyAccess", "document": None},
        {"name": "SecurityAudit", "arn": "arn:aws-cn:iam::aws:policy/SecurityAudit", "document": None},
    ]
    assert iam.call_counts["get_policy_version"] == 0


def test_iam_unexpected_gaad_failure_returns_error_envelope():
    iam = FakeClient(
        {
            "get_account_authorization_details": RuntimeError("boom"),
        }
    )

    envelope = run(FakeFactory(iam=iam), "global")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "iam.GetAccountAuthorizationDetails"
    assert envelope.errors[0].code == "RuntimeError"


def test_iam_cross_account_trust_preserves_factual_conditions():
    iam = FakeClient(
        {
            "get_account_authorization_details": {
                "UserDetailList": [],
                "RoleDetailList": [
                    {
                        "RoleName": "CrossAccountRole",
                        "Arn": "arn:aws:iam::123456789012:role/CrossAccountRole",
                        "Path": "/",
                        "AssumeRolePolicyDocument": (
                            '{"Statement":[{"Effect":"Allow","Principal":'
                            '{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]}'
                        ),
                        "AttachedManagedPolicies": [],
                        "RolePolicyList": [],
                        "PermissionsBoundary": None,
                        "RoleLastUsed": None,
                    }
                ],
                "GroupDetailList": [],
                "Policies": [],
                "IsTruncated": False,
            },
            "generate_credential_report": {"State": "COMPLETE"},
            "get_credential_report": {"Content": "user,mfa_active,password_last_used\n<root_account>,true,N/A"},
            "list_open_id_connect_providers": {"OpenIDConnectProviderList": []},
            "generate_service_last_accessed_details": {"JobId": "job-role-456"},
            "get_service_last_accessed_details": {"JobStatus": "COMPLETED", "ServicesLastAccessed": []},
        }
    )

    envelope = run(FakeFactory(iam=iam), "global")

    role = envelope.resources[0]
    assert role["trust_relationships"] == [
        {
            "principal": "arn:aws:iam::999999999999:root",
            "trust_type": "cross-account",
            "is_wildcard": False,
            "has_external_id": False,
            "has_mfa_condition": False,
            "conditions": {},
        }
    ]


def _no_such_entity():
    from botocore.exceptions import ClientError

    return ClientError({"Error": {"Code": "NoSuchEntityException", "Message": "missing"}}, "GetLoginProfile")
