import pytest
from botocore.exceptions import ClientError

from scope.core import retry
from scope.core.retry import with_retry


def client_error(code: str, *, status: int = 400) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": code}, "ResponseMetadata": {"HTTPStatusCode": status}},
        "TestOperation",
    )


def test_with_retry_retries_provisioned_throughput_exceeded(monkeypatch):
    monkeypatch.setattr(retry.time, "sleep", lambda _delay: None)
    attempts = 0

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise client_error("ProvisionedThroughputExceededException")
        return "ok"

    assert with_retry(operation, max_retries=2) == "ok"
    assert attempts == 2


def test_with_retry_does_not_retry_access_denied(monkeypatch):
    monkeypatch.setattr(retry.time, "sleep", lambda _delay: None)
    attempts = 0

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        raise client_error("AccessDeniedException")

    with pytest.raises(ClientError, match="AccessDeniedException"):
        with_retry(operation, max_retries=2)

    assert attempts == 1


@pytest.mark.parametrize("status", [429, 503])
def test_with_retry_retries_http_status_only_throttling(monkeypatch, status):
    monkeypatch.setattr(retry.time, "sleep", lambda _delay: None)
    attempts = 0

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise client_error("InternalError", status=status)
        return "ok"

    assert with_retry(operation, max_retries=2) == "ok"
    assert attempts == 2
