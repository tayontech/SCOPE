import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

from scope_core.regions import FALLBACK_COMMERCIAL_REGIONS, discover_regions


class FakeEc2:
    def describe_regions(self, AllRegions=False):
        assert AllRegions is False
        return {
            "Regions": [
                {"RegionName": "us-west-2"},
                {"RegionName": "us-east-1"},
            ]
        }


class AccessDeniedEc2:
    def describe_regions(self, AllRegions=False):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "DescribeRegions",
        )


class EndpointUnavailableEc2:
    def describe_regions(self, AllRegions=False):
        raise EndpointConnectionError(endpoint_url="https://ec2.us-east-1.amazonaws.com")


class UnexpectedClientErrorEc2:
    def describe_regions(self, AllRegions=False):
        raise ClientError(
            {"Error": {"Code": "InternalError", "Message": "service failed"}},
            "DescribeRegions",
        )


class UnexpectedEc2:
    def describe_regions(self, AllRegions=False):
        raise RuntimeError("denied")


class EmptyEc2:
    def describe_regions(self, AllRegions=False):
        return {"Regions": []}


def test_discover_regions_sorts_enabled_regions():
    assert discover_regions(FakeEc2()) == ["us-east-1", "us-west-2"]


def test_discover_regions_falls_back_on_access_denied_client_error():
    regions = discover_regions(AccessDeniedEc2())

    assert "us-east-1" in regions
    assert "us-west-2" in regions


def test_discover_regions_falls_back_on_endpoint_unavailable():
    regions = discover_regions(EndpointUnavailableEc2())

    assert "us-east-1" in regions
    assert "us-west-2" in regions


def test_fallback_regions_include_ap_northeast_3():
    assert "ap-northeast-3" in FALLBACK_COMMERCIAL_REGIONS


def test_discover_regions_returns_empty_success_response():
    assert discover_regions(EmptyEc2()) == []


def test_discover_regions_reraises_unexpected_client_error():
    with pytest.raises(ClientError, match="InternalError"):
        discover_regions(UnexpectedClientErrorEc2())


def test_discover_regions_reraises_unexpected_runtime_error():
    with pytest.raises(RuntimeError, match="denied"):
        discover_regions(UnexpectedEc2())
