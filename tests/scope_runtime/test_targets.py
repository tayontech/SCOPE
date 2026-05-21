from __future__ import annotations

from pathlib import Path

import pytest

from scope_core.models import ModuleEnvelope
from scope_runtime.targets import (
    TargetParseError,
    build_scope_metadata,
    filter_module_envelopes_for_targets,
    module_for_target,
    parse_target,
    parse_targets,
    read_target_file,
    required_work_items_for_targets,
)


@pytest.mark.parametrize(
    ("arn", "service", "module", "region", "resource_type", "resource_id"),
    [
        ("arn:aws:apigateway:us-east-1::/restapis/api123", "apigateway", "apigateway", "us-east-1", "restapis", "api123"),
        ("arn:aws:bedrock:us-east-1:123456789012:agent/agent123", "bedrock", "bedrock", "us-east-1", "agent", "agent123"),
        ("arn:aws:codebuild:us-east-1:123456789012:project/test-project", "codebuild", "codebuild", "us-east-1", "project", "test-project"),
        ("arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_abc", "cognito-idp", "cognito", "us-east-1", "userpool", "us-east-1_abc"),
        ("arn:aws:dynamodb:us-east-1:123456789012:table/Orders", "dynamodb", "dynamodb", "us-east-1", "table", "Orders"),
        ("arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0", "ec2", "ec2", "us-east-1", "instance", "i-0123456789abcdef0"),
        ("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/app-lb/abc", "elasticloadbalancing", "ec2", "us-east-1", "loadbalancer", "app/app-lb/abc"),
        ("arn:aws:iam::123456789012:role/Admin", "iam", "iam", None, "role", "Admin"),
        ("arn:aws:kms:us-east-1:123456789012:key/aaaa-bbbb", "kms", "kms", "us-east-1", "key", "aaaa-bbbb"),
        ("arn:aws:lambda:us-east-1:123456789012:function:my-func", "lambda", "lambda", "us-east-1", "function", "my-func"),
        ("arn:aws:rds:us-east-1:123456789012:db:prod", "rds", "rds", "us-east-1", "db", "prod"),
        ("arn:aws:s3:::my-bucket", "s3", "s3", None, "bucket", "my-bucket"),
        ("arn:aws:secretsmanager:us-east-1:123456789012:secret:db-password-AbCdEf", "secretsmanager", "secrets", "us-east-1", "secret", "db-password-AbCdEf"),
        ("arn:aws:sns:us-east-1:123456789012:alerts", "sns", "sns", "us-east-1", "topic", "alerts"),
        ("arn:aws:sqs:us-east-1:123456789012:queue-name", "sqs", "sqs", "us-east-1", "queue", "queue-name"),
        ("arn:aws:ssm:us-east-1:123456789012:parameter/app/db", "ssm", "ssm", "us-east-1", "parameter", "app/db"),
        ("arn:aws:sts::123456789012:assumed-role/Admin/session", "sts", "sts", None, "assumed-role", "Admin/session"),
    ],
)
def test_parse_target_supports_current_scope_services(
    arn: str,
    service: str,
    module: str,
    region: str | None,
    resource_type: str,
    resource_id: str,
):
    target = parse_target(arn)

    assert target.raw == arn
    assert target.arn == arn
    assert target.partition == "aws"
    assert target.service == service
    assert target.region == region
    assert target.account_id in {None, "123456789012"}
    assert target.resource_type == resource_type
    assert target.resource_id == resource_id
    assert module_for_target(target) == module


def test_parse_target_rejects_non_arn_before_aws_calls():
    with pytest.raises(TargetParseError) as exc:
        parse_target("lambda:my-func")

    assert "Expected ARN" in str(exc.value)


def test_parse_target_rejects_unsupported_service():
    with pytest.raises(TargetParseError) as exc:
        parse_target("arn:aws:cloudtrail:us-east-1:123456789012:trail/main")

    assert "Unsupported target service" in str(exc.value)


def test_parse_target_rejects_malformed_account_id():
    with pytest.raises(TargetParseError) as exc:
        parse_target("arn:aws:sns:us-east-1:123:alerts")

    assert "Invalid ARN target" in str(exc.value)


def test_parse_target_rejects_regional_service_without_region():
    with pytest.raises(TargetParseError) as exc:
        parse_target("arn:aws:lambda::123456789012:function:my-func")

    assert "requires a region" in str(exc.value)


@pytest.mark.parametrize(
    "arn",
    [
        "arn:aws:iam:us-east-1:123456789012:role/Admin",
        "arn:aws:s3:us-east-1::my-bucket",
        "arn:aws:sts:us-east-1:123456789012:assumed-role/Admin/session",
    ],
)
def test_parse_target_rejects_region_for_global_services(arn: str):
    with pytest.raises(TargetParseError) as exc:
        parse_target(arn)

    assert "must not include a region" in str(exc.value)


def test_read_target_file_ignores_blank_lines_and_comments(tmp_path: Path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        "\n"
        "# production targets\n"
        "arn:aws:iam::123456789012:role/Admin\n"
        "  \n"
        "arn:aws:s3:::my-bucket\n",
        encoding="utf-8",
    )

    targets = read_target_file(target_file)

    assert [target.arn for target in targets] == [
        "arn:aws:iam::123456789012:role/Admin",
        "arn:aws:s3:::my-bucket",
    ]


def test_read_target_file_rejects_empty_file(tmp_path: Path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text("# no targets\n\n", encoding="utf-8")

    with pytest.raises(TargetParseError) as exc:
        read_target_file(target_file)

    assert "No targets found" in str(exc.value)


def test_read_target_file_rejects_missing_file(tmp_path: Path):
    with pytest.raises(TargetParseError) as exc:
        read_target_file(tmp_path / "missing-targets.txt")

    assert "Unable to read target file" in str(exc.value)


def test_required_work_items_for_targets_uses_target_regions_and_context():
    targets = parse_targets(
        [
            "arn:aws:lambda:us-east-1:123456789012:function:my-func",
            "arn:aws:s3:::my-bucket",
            "arn:aws:iam::123456789012:role/Admin",
        ]
    )

    pairs = required_work_items_for_targets(targets)

    assert pairs == [
        ("lambda", "us-east-1"),
        ("s3", "global"),
        ("iam", "global"),
        ("sts", "global"),
    ]


def test_build_scope_metadata_serializes_target_mode():
    targets = parse_targets(["arn:aws:s3:::my-bucket"])

    assert build_scope_metadata(mode="target", targets=targets) == {
        "mode": "target",
        "targets": ["arn:aws:s3:::my-bucket"],
    }


def _envelope(module: str, region: str, resources: list[dict]) -> dict:
    return {
        "module": module,
        "account_id": "123456789012",
        "region": region,
        "status": "complete",
        "resources": resources,
        "coverage": [],
        "errors": [],
    }


def test_filter_module_envelopes_keeps_target_and_direct_context():
    targets = parse_targets(["arn:aws:lambda:us-east-1:123456789012:function:my-func"])
    envelopes = {
        ("lambda", "us-east-1"): _envelope(
            "lambda",
            "us-east-1",
            [
                {
                    "resource_type": "lambda_function",
                    "resource_id": "my-func",
                    "arn": "arn:aws:lambda:us-east-1:123456789012:function:my-func",
                    "role": "arn:aws:iam::123456789012:role/LambdaExecRole",
                    "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
                },
                {
                    "resource_type": "lambda_function",
                    "resource_id": "other-func",
                    "arn": "arn:aws:lambda:us-east-1:123456789012:function:other-func",
                },
            ],
        ),
        ("iam", "global"): _envelope(
            "iam",
            "global",
            [
                {
                    "resource_type": "iam_role",
                    "resource_id": "LambdaExecRole",
                    "arn": "arn:aws:iam::123456789012:role/LambdaExecRole",
                    "attached_policies": [{"name": "CustomerPolicy", "arn": "arn:aws:iam::123456789012:policy/CustomerPolicy"}],
                },
                {
                    "resource_type": "iam_role",
                    "resource_id": "UnrelatedRole",
                    "arn": "arn:aws:iam::123456789012:role/UnrelatedRole",
                },
            ],
        ),
        ("kms", "us-east-1"): _envelope(
            "kms",
            "us-east-1",
            [
                {
                    "resource_type": "kms_key",
                    "resource_id": "key-1",
                    "arn": "arn:aws:kms:us-east-1:123456789012:key/key-1",
                }
            ],
        ),
    }

    filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)

    lambda_resources = filtered[("lambda", "us-east-1")]["resources"]
    iam_resources = filtered[("iam", "global")]["resources"]
    kms_resources = filtered[("kms", "us-east-1")]["resources"]
    assert [resource["resource_id"] for resource in lambda_resources] == ["my-func"]
    assert lambda_resources[0]["scope_match"] == "target"
    assert lambda_resources[0]["scope_source"] == targets[0].arn
    assert [resource["resource_id"] for resource in iam_resources] == ["LambdaExecRole"]
    assert iam_resources[0]["scope_match"] == "context"
    assert [resource["resource_id"] for resource in kms_resources] == ["key-1"]
    assert target_results == [{"target": targets[0].arn, "status": "resolved", "module": "lambda", "region": "us-east-1"}]
    assert filtered[("lambda", "us-east-1")]["coverage"][0]["check"] == "target_filter"
    for envelope in filtered.values():
        ModuleEnvelope.model_validate(envelope)


def test_filter_module_envelopes_does_not_match_same_id_across_shared_module_services():
    targets = parse_targets(
        ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/shared-id/abc"]
    )
    envelopes = {
        ("ec2", "us-east-1"): _envelope(
            "ec2",
            "us-east-1",
            [
                {
                    "resource_type": "ec2_instance",
                    "resource_id": "app/shared-id/abc",
                    "arn": "arn:aws:ec2:us-east-1:123456789012:instance/app/shared-id/abc",
                },
                {
                    "resource_type": "ec2_load_balancer",
                    "resource_id": "app/shared-id/abc",
                    "arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/shared-id/abc",
                },
            ],
        )
    }

    filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)

    resources = filtered[("ec2", "us-east-1")]["resources"]
    assert [resource["resource_type"] for resource in resources] == ["ec2_load_balancer"]
    assert resources[0]["scope_match"] == "target"
    assert target_results == [
        {
            "target": targets[0].arn,
            "status": "resolved",
            "module": "ec2",
            "region": "us-east-1",
        }
    ]


def test_filter_module_envelopes_does_not_match_same_id_across_accounts():
    targets = parse_targets(["arn:aws:lambda:us-east-1:999999999999:function:shared-name"])
    envelopes = {
        ("lambda", "us-east-1"): _envelope(
            "lambda",
            "us-east-1",
            [
                {
                    "resource_type": "lambda_function",
                    "resource_id": "shared-name",
                    "arn": "arn:aws:lambda:us-east-1:123456789012:function:shared-name",
                }
            ],
        )
    }

    filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)

    assert filtered[("lambda", "us-east-1")]["resources"] == []
    assert target_results == [
        {
            "target": targets[0].arn,
            "status": "not_found",
            "module": "lambda",
            "region": "us-east-1",
        }
    ]


def test_filter_module_envelopes_does_not_match_wildcard_arn_across_accounts():
    targets = parse_targets(["arn:aws:ec2:us-east-1:999999999999:instance/i-abc123"])
    envelopes = {
        ("ec2", "us-east-1"): _envelope(
            "ec2",
            "us-east-1",
            [
                {
                    "resource_type": "ec2_instance",
                    "resource_id": "i-abc123",
                    "arn": "arn:aws:ec2:us-east-1:*:instance/i-abc123",
                }
            ],
        )
    }

    filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)

    assert filtered[("ec2", "us-east-1")]["resources"] == []
    assert target_results == [
        {
            "target": targets[0].arn,
            "status": "not_found",
            "module": "ec2",
            "region": "us-east-1",
        }
    ]


def test_filter_module_envelopes_does_not_match_no_arn_resource_across_accounts():
    targets = parse_targets(["arn:aws:lambda:us-east-1:999999999999:function:shared-name"])
    envelopes = {
        ("lambda", "us-east-1"): _envelope(
            "lambda",
            "us-east-1",
            [
                {
                    "resource_type": "lambda_function",
                    "resource_id": "shared-name",
                    "arn": None,
                }
            ],
        )
    }

    filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)

    assert filtered[("lambda", "us-east-1")]["resources"] == []
    assert target_results == [
        {
            "target": targets[0].arn,
            "status": "not_found",
            "module": "lambda",
            "region": "us-east-1",
        }
    ]


def test_filter_module_envelopes_matches_no_arn_resource_for_envelope_account():
    targets = parse_targets(["arn:aws:lambda:us-east-1:123456789012:function:shared-name"])
    envelopes = {
        ("lambda", "us-east-1"): _envelope(
            "lambda",
            "us-east-1",
            [
                {
                    "resource_type": "lambda_function",
                    "resource_id": "shared-name",
                    "arn": None,
                }
            ],
        )
    }

    filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)

    assert [resource["resource_id"] for resource in filtered[("lambda", "us-east-1")]["resources"]] == ["shared-name"]
    assert target_results == [
        {
            "target": targets[0].arn,
            "status": "resolved",
            "module": "lambda",
            "region": "us-east-1",
        }
    ]


def test_filter_module_envelopes_matches_wildcard_arn_for_envelope_account():
    targets = parse_targets(["arn:aws:ec2:us-east-1:123456789012:instance/i-abc123"])
    envelopes = {
        ("ec2", "us-east-1"): _envelope(
            "ec2",
            "us-east-1",
            [
                {
                    "resource_type": "ec2_instance",
                    "resource_id": "i-abc123",
                    "arn": "arn:aws:ec2:us-east-1:*:instance/i-abc123",
                }
            ],
        )
    }

    filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)

    assert [resource["resource_id"] for resource in filtered[("ec2", "us-east-1")]["resources"]] == ["i-abc123"]
    assert target_results == [
        {
            "target": targets[0].arn,
            "status": "resolved",
            "module": "ec2",
            "region": "us-east-1",
        }
    ]


def test_filter_module_envelopes_records_not_found_target():
    targets = parse_targets(["arn:aws:s3:::missing-bucket"])
    envelopes = {
        ("s3", "global"): _envelope(
            "s3",
            "global",
            [{"resource_type": "s3_bucket", "resource_id": "other-bucket", "arn": "arn:aws:s3:::other-bucket"}],
        )
    }

    filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)

    assert filtered[("s3", "global")]["resources"] == []
    assert target_results == [{"target": targets[0].arn, "status": "not_found", "module": "s3", "region": "global"}]
    assert filtered[("s3", "global")]["status"] == "partial"
    assert filtered[("s3", "global")]["errors"][0]["code"] == "not_found"
    ModuleEnvelope.model_validate(filtered[("s3", "global")])


def test_filter_module_envelopes_all_not_found_can_drive_error_status_later():
    targets = parse_targets(
        [
            "arn:aws:sns:us-east-1:123456789012:alerts",
            "arn:aws:sqs:us-east-1:123456789012:jobs",
        ]
    )
    envelopes = {
        ("sns", "us-east-1"): _envelope("sns", "us-east-1", []),
        ("sqs", "us-east-1"): _envelope("sqs", "us-east-1", []),
    }

    _filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)

    assert [result["status"] for result in target_results] == ["not_found", "not_found"]
