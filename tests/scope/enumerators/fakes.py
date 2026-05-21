from __future__ import annotations

from collections import defaultdict
from typing import Any


class FakeClient:
    def __init__(self, operations: dict[str, Any]):
        self.operations = operations
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.call_counts = defaultdict(int)

    def __getattr__(self, name: str):
        def call(**kwargs: Any):
            self.calls.append((name, kwargs))
            self.call_counts[name] += 1
            value = self.operations.get(name)
            if isinstance(value, list):
                index = min(self.call_counts[name] - 1, len(value) - 1)
                value = value[index]
            if isinstance(value, Exception):
                raise value
            if callable(value):
                return value(**kwargs)
            return value if value is not None else {}

        return call


class FakeFactory:
    account_id = "123456789012"

    def __init__(self, **clients: FakeClient):
        self.clients = clients

    def client(self, service: str) -> FakeClient:
        return self.clients[service]

    def paginate(self, client: FakeClient, operation_name: str, result_key: str, **kwargs: Any) -> list[Any]:
        value = getattr(client, operation_name)(**kwargs)
        if result_key not in value:
            return []
        return value[result_key]
