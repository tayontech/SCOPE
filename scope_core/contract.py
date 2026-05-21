from __future__ import annotations

from typing import Any, Protocol

from .models import ModuleEnvelope


class Enumerator(Protocol):
    def __call__(self, factory: Any, region: str, selector: Any | None = None) -> ModuleEnvelope:
        pass
