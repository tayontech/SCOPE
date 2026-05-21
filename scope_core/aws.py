from __future__ import annotations

from functools import cached_property
from typing import Any

import boto3
from botocore.config import Config


DEFAULT_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    user_agent_extra="SCOPE/1.14",
    max_pool_connections=20,
)


SERVICE_ALIASES = {
    "bedrock_agent": "bedrock-agent",
    "cognito_identity": "cognito-identity",
    "cognito_idp": "cognito-idp",
    "secrets": "secretsmanager",
}


class ClientFactory:
    def __init__(self, region: str, profile: str | None = None, session: Any | None = None):
        self.region = region
        self.profile = profile
        self.session = session or boto3.Session(profile_name=profile)
        self._clients: dict[str, Any] = {}

    @cached_property
    def account_id(self) -> str:
        return str(self.client("sts").get_caller_identity()["Account"])

    def client(self, service: str) -> Any:
        if service not in self._clients:
            boto_service = SERVICE_ALIASES.get(service, service)
            region_name = None if boto_service in {"iam", "sts", "organizations"} else self.region
            self._clients[service] = self.session.client(boto_service, region_name=region_name, config=DEFAULT_CONFIG)
        return self._clients[service]

    def paginate(self, client: Any, operation_name: str, result_key: str, **kwargs: Any) -> list[Any]:
        paginator = client.get_paginator(operation_name)
        items: list[Any] = []
        for page in paginator.paginate(**kwargs):
            if result_key not in page:
                raise KeyError(f"Paginator page missing result key: {result_key}")
            value = page[result_key]
            if not isinstance(value, list):
                raise TypeError(f"Paginator result {result_key} must be a list")
            items.extend(value)
        return items
