from __future__ import annotations

from typing import Any

from botocore.exceptions import (
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)


FALLBACK_COMMERCIAL_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ca-central-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "sa-east-1",
]

_EXPECTED_DISCOVERY_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthFailure",
}

_EXPECTED_DISCOVERY_UNAVAILABLE_ERRORS = (
    EndpointConnectionError,
    ConnectionClosedError,
    ConnectTimeoutError,
    ReadTimeoutError,
)


def discover_regions(ec2_client: Any) -> list[str]:
    try:
        response = ec2_client.describe_regions(AllRegions=False)
        names = [region["RegionName"] for region in response.get("Regions", []) if region.get("RegionName")]
        return sorted(names)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        if code in _EXPECTED_DISCOVERY_DENIED_CODES:
            return FALLBACK_COMMERCIAL_REGIONS.copy()
        raise
    except _EXPECTED_DISCOVERY_UNAVAILABLE_ERRORS:
        return FALLBACK_COMMERCIAL_REGIONS.copy()
