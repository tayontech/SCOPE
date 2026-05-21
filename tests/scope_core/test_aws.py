import pytest

from scope_core.aws import ClientFactory


class FakeClient:
    def __init__(self, paginator=None):
        self.calls = []
        self.paginator = paginator or FakePaginator()

    def get_caller_identity(self):
        return {"Account": "123456789012"}

    def get_paginator(self, operation_name):
        self.calls.append(("get_paginator", operation_name))
        return self.paginator


class FakePaginator:
    def paginate(self, **kwargs):
        yield {"Items": [1, 2]}
        yield {"Items": [3]}


class MissingResultKeyPaginator:
    def paginate(self, **kwargs):
        yield {"OtherItems": [1]}


class NonListResultPaginator:
    def paginate(self, **kwargs):
        yield {"Items": "not-a-list"}


class FakeSession:
    def __init__(self, client_obj=None):
        self.created = []
        self.client_obj = client_obj or FakeClient()

    def client(self, service_name, region_name=None, config=None):
        self.created.append((service_name, region_name, config))
        return self.client_obj


def test_client_factory_caches_clients_and_account_id():
    session = FakeSession()
    factory = ClientFactory(region="us-east-1", session=session)

    assert factory.client("sts") is factory.client("sts")
    assert factory.account_id == "123456789012"
    assert factory.account_id == "123456789012"
    assert [entry[0] for entry in session.created].count("sts") == 1


def test_client_factory_uses_global_and_regional_client_regions():
    session = FakeSession()
    factory = ClientFactory(region="us-east-1", session=session)

    factory.client("sts")
    factory.client("iam")
    factory.client("organizations")
    factory.client("s3")

    created_regions = {service: region for service, region, _config in session.created}
    assert created_regions["sts"] is None
    assert created_regions["iam"] is None
    assert created_regions["organizations"] is None
    assert created_regions["s3"] == "us-east-1"


def test_client_factory_maps_internal_service_aliases_to_boto_names():
    session = FakeSession()
    factory = ClientFactory(region="us-east-1", session=session)

    factory.client("secrets")
    factory.client("bedrock_agent")
    factory.client("cognito_identity")
    factory.client("cognito_idp")

    created_services = [service for service, _region, _config in session.created]
    assert created_services == [
        "secretsmanager",
        "bedrock-agent",
        "cognito-identity",
        "cognito-idp",
    ]


def test_paginate_collects_items():
    session = FakeSession()
    factory = ClientFactory(region="us-east-1", session=session)

    items = factory.paginate(factory.client("demo"), "list_items", "Items")

    assert items == [1, 2, 3]


def test_paginate_missing_result_key_raises():
    session = FakeSession(client_obj=FakeClient(MissingResultKeyPaginator()))
    factory = ClientFactory(region="us-east-1", session=session)

    with pytest.raises(KeyError, match="Paginator page missing result key: Items"):
        factory.paginate(factory.client("demo"), "list_items", "Items")


def test_paginate_non_list_result_key_raises():
    session = FakeSession(client_obj=FakeClient(NonListResultPaginator()))
    factory = ClientFactory(region="us-east-1", session=session)

    with pytest.raises(TypeError, match="Paginator result Items must be a list"):
        factory.paginate(factory.client("demo"), "list_items", "Items")
