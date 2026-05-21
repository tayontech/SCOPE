from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar


T = TypeVar("T")

THROTTLE_CODES = {
    "BandwidthLimitExceeded",
    "ProvisionedThroughputExceededException",
    "RequestLimitExceeded",
    "RequestThrottledException",
    "ServiceUnavailable",
    "ServiceUnavailableException",
    "SlowDown",
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
}


def _code(err: Exception) -> str:
    response = getattr(err, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict) and error.get("Code"):
            return str(error["Code"])
    return err.__class__.__name__


def with_retry(fn: Callable[[], T], *, max_retries: int = 3, base_delay_seconds: float = 1.0) -> T:
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except Exception as err:
            response = getattr(err, "response", {})
            status = response.get("ResponseMetadata", {}).get("HTTPStatusCode") if isinstance(response, dict) else None
            is_throttle = _code(err) in THROTTLE_CODES or status in {429, 503}
            if not is_throttle or attempt >= max_retries:
                raise
            time.sleep(base_delay_seconds * (2**attempt))

    raise RuntimeError("retry loop exited unexpectedly")
