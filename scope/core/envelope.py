from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import CoverageEntry, ErrorRecord, ModuleEnvelope


def create_envelope(
    *,
    module: str,
    account_id: str,
    region: str,
    status: str,
    resources: list[dict[str, Any]] | None = None,
    coverage: list[CoverageEntry] | None = None,
    errors: list[ErrorRecord] | None = None,
) -> ModuleEnvelope:
    return ModuleEnvelope(
        module=module,
        account_id=account_id,
        region=region,
        status=status,
        resources=resources or [],
        coverage=coverage or [],
        errors=errors or [],
    )


def write_envelope(run_dir: str | Path, envelope: ModuleEnvelope) -> Path:
    directory = Path(run_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{envelope.module}.json"
    path.write_text(envelope.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path
