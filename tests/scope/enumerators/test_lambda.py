from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from scope.enumerators.aws_lambda import run
from tests.scope.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "enum" / "lambda"


def _expected_contract() -> dict:
    return json.loads((FIXTURE_DIR / "expected.json").read_text(encoding="utf-8"))


def _contract(envelope, expected: dict) -> dict:
    dumped = envelope.model_dump(mode="json")
    return {key: dumped[key] for key in expected}


def test_lambda_matches_js_fixture_contract():
    lambda_client = FakeClient(
        {
            "list_functions": {
                "Functions": [
                    {
                        "FunctionName": "my-test-function",
                        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-test-function",
                        "Runtime": "nodejs20.x",
                        "Role": "arn:aws:iam::123456789012:role/lambda-basic-execution",
                        "Handler": "index.handler",
                        "CodeSize": 1024,
                        "Timeout": 30,
                        "MemorySize": 128,
                        "LastModified": "2024-01-15T10:00:00.000+0000",
                        "Layers": [],
                        "Environment": {
                            "Variables": {
                                "LOG_LEVEL": "info",
                                "DB_HOST": "localhost",
                            },
                        },
                    },
                ],
            },
            "get_function_url_config": {},
            "get_policy": {},
        }
    )
    expected = _expected_contract()

    envelope = run(FakeFactory(**{"lambda": lambda_client}), "us-east-1")

    assert normalize_envelope(_contract(envelope, expected)) == normalize_envelope(expected)


def _function(**overrides):
    function = {
        "FunctionName": "my-test-function",
        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-test-function",
        "Runtime": "nodejs20.x",
        "Environment": {"Variables": {}},
    }
    function.update(overrides)
    return function


def test_lambda_list_functions_failure_returns_error_envelope():
    lambda_client = FakeClient(
        {
            "list_functions": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListFunctions",
            ),
        }
    )

    envelope = run(FakeFactory(**{"lambda": lambda_client}), "us-east-1")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "lambda.ListFunctions"
    assert envelope.errors[0].code == "AccessDeniedException"
    coverage = next(entry for entry in envelope.coverage if entry.check == "list_functions")
    assert coverage.status == "error"
    assert coverage.failed == 1


def test_lambda_function_url_access_denied_marks_function_partial():
    function_arn = "arn:aws:lambda:us-east-1:123456789012:function:my-test-function"
    lambda_client = FakeClient(
        {
            "list_functions": {"Functions": [_function(FunctionArn=function_arn)]},
            "get_function_url_config": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "GetFunctionUrlConfig",
            ),
            "get_policy": {},
        }
    )

    envelope = run(FakeFactory(**{"lambda": lambda_client}), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources[0]["function_url_status"] == "access_denied"
    assert envelope.errors[0].operation == "lambda.GetFunctionUrlConfig"
    assert envelope.errors[0].resource == function_arn
    coverage = next(entry for entry in envelope.coverage if entry.check == "function_url")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_lambda_does_not_emit_env_values_and_flags_policy_wildcard():
    lambda_client = FakeClient(
        {
            "list_functions": {
                "Functions": [
                    _function(
                        Environment={"Variables": {"API_KEY": "do-not-emit"}},
                    )
                ],
            },
            "get_function_url_config": {"FunctionUrl": "https://example.lambda-url.us-east-1.on.aws/"},
            "get_policy": {
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                            }
                        ]
                    }
                )
            },
        }
    )

    envelope = run(FakeFactory(**{"lambda": lambda_client}), "us-east-1")

    finding = envelope.resources[0]
    assert finding["env_var_names"] == ["API_KEY"]
    assert finding["secret_pattern_names"] == ["API_KEY"]
    assert "do-not-emit" not in json.dumps(finding)
    assert {item["type"] for item in finding["findings"]} == {
        "secret_env_vars",
        "function_url_enabled",
        "wildcard_resource_policy",
    }


def test_lambda_preserves_resource_policy_statements_and_function_url_auth_type():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "FunctionUrlInvoke",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "lambda:InvokeFunctionUrl",
                "Resource": "arn:aws:lambda:us-east-1:123456789012:function:my-test-function",
                "Condition": {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}},
            }
        ],
    }
    lambda_client = FakeClient(
        {
            "list_functions": {"Functions": [_function()]},
            "get_function_url_config": {
                "FunctionUrl": "https://example.lambda-url.us-east-1.on.aws/",
                "AuthType": "NONE",
                "InvokeMode": "BUFFERED",
                "Cors": {"AllowOrigins": ["*"]},
            },
            "get_policy": {"Policy": json.dumps(policy)},
        }
    )

    envelope = run(FakeFactory(**{"lambda": lambda_client}), "us-east-1")

    function = envelope.resources[0]
    assert function["function_url_config"]["auth_type"] == "NONE"
    assert function["function_url_config"]["invoke_mode"] == "BUFFERED"
    assert function["resource_policy_document"] == policy
    assert function["resource_policy_statements"][0]["sid"] == "FunctionUrlInvoke"
    assert function["resource_policy_statements"][0]["normalized_actions"] == ["lambda:InvokeFunctionUrl"]


def test_lambda_collects_event_source_mappings_for_sqs_sources():
    function_arn = "arn:aws:lambda:us-east-1:123456789012:function:processor"
    queue_arn = "arn:aws:sqs:us-east-1:123456789012:uploads-queue"
    lambda_client = FakeClient(
        {
            "list_functions": {
                "Functions": [
                    _function(
                        FunctionName="processor",
                        FunctionArn=function_arn,
                        Role="arn:aws:iam::123456789012:role/processor-role",
                    )
                ]
            },
            "get_function_url_config": {},
            "get_policy": {},
            "list_event_source_mappings": {
                "EventSourceMappings": [
                    {
                        "UUID": "mapping-1",
                        "EventSourceArn": queue_arn,
                        "FunctionArn": function_arn,
                        "State": "Enabled",
                        "BatchSize": 10,
                    }
                ]
            },
        }
    )

    envelope = run(FakeFactory(**{"lambda": lambda_client}), "us-east-1")

    function = envelope.resources[0]
    assert function["event_source_mappings_status"] == "present"
    assert function["event_source_mappings"] == [
        {
            "uuid": "mapping-1",
            "event_source_arn": queue_arn,
            "function_arn": function_arn,
            "state": "Enabled",
            "batch_size": 10,
        }
    ]
