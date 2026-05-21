from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from scope.enumerators.codebuild import run
from tests.scope.enumerators.fakes import FakeClient, FakeFactory
from tools.parity_diff import normalize_envelope


FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "enum" / "codebuild"


def _expected_contract() -> dict:
    return json.loads((FIXTURE_DIR / "expected.json").read_text(encoding="utf-8"))


def _contract(envelope, expected: dict) -> dict:
    dumped = envelope.model_dump(mode="json")
    return {key: dumped[key] for key in expected}


def test_codebuild_matches_js_fixture_contract():
    codebuild = FakeClient(
        {
            "list_projects": {"projects": ["test-project"]},
            "batch_get_projects": {
                "projects": [
                    {
                        "name": "test-project",
                        "arn": "arn:aws:codebuild:us-east-1:123456789012:project/test-project",
                        "serviceRole": "arn:aws:iam::123456789012:role/CodeBuildRole",
                        "source": {
                            "type": "GITHUB",
                            "location": "https://github.com/example/repo",
                            "buildspec": None,
                        },
                        "environment": {
                            "type": "LINUX_CONTAINER",
                            "image": "aws/codebuild/standard:5.0",
                            "computeType": "BUILD_GENERAL1_SMALL",
                            "privilegedMode": False,
                            "environmentVariables": [{"name": "REGION", "value": "us-east-1"}],
                        },
                        "vpcConfig": None,
                        "encryptionKey": "arn:aws:kms:us-east-1:123456789012:alias/aws/s3",
                        "lastModified": None,
                    },
                ],
                "projectsNotFound": [],
            },
        }
    )
    expected = _expected_contract()

    envelope = run(FakeFactory(codebuild=codebuild), "us-east-1")

    assert normalize_envelope(_contract(envelope, expected)) == normalize_envelope(expected)


def test_codebuild_list_projects_failure_returns_error_envelope():
    codebuild = FakeClient(
        {
            "list_projects": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "ListProjects",
            ),
        }
    )

    envelope = run(FakeFactory(codebuild=codebuild), "us-east-1")

    assert envelope.status == "error"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "codebuild.ListProjects"
    assert envelope.errors[0].code == "AccessDeniedException"
    coverage = next(entry for entry in envelope.coverage if entry.check == "list_projects")
    assert coverage.status == "error"
    assert coverage.failed == 1


def test_codebuild_batch_get_failure_marks_module_partial():
    codebuild = FakeClient(
        {
            "list_projects": {"projects": ["test-project"]},
            "batch_get_projects": ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "BatchGetProjects",
            ),
        }
    )

    envelope = run(FakeFactory(codebuild=codebuild), "us-east-1")

    assert envelope.status == "partial"
    assert envelope.resources == []
    assert envelope.errors[0].operation == "codebuild.BatchGetProjects"
    assert envelope.errors[0].resource == "batch(1)"
    coverage = next(entry for entry in envelope.coverage if entry.check == "batch_get_projects")
    assert coverage.status == "partial"
    assert coverage.failed == 1


def test_codebuild_does_not_include_environment_variable_values():
    codebuild = FakeClient(
        {
            "list_projects": {"projects": ["test-project"]},
            "batch_get_projects": {
                "projects": [
                    {
                        "name": "test-project",
                        "environment": {
                            "environmentVariables": [
                                {"name": "API_KEY", "value": "do-not-emit"},
                            ],
                        },
                    },
                ],
                "projectsNotFound": [],
            },
        }
    )

    envelope = run(FakeFactory(codebuild=codebuild), "us-east-1")

    finding = envelope.resources[0]
    assert finding["env_var_names"] == ["API_KEY"]
    assert finding["secret_pattern_names"] == ["API_KEY"]
    assert "do-not-emit" not in json.dumps(finding)
