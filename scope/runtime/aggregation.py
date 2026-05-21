from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from scope.runtime.run_context import AccountContext
from scope.core.models import ModuleEnvelope

CONTEXT_RESOURCE_KEYS = {
    "run_id",
    "account_id",
    "account_name",
    "account_owned",
    "service",
    "region",
    "source_path",
}


def _resource_fields_with_context_escapes(resource: dict[str, Any]) -> dict[str, Any]:
    fields = {
        key: value
        for key, value in resource.items()
        if key not in CONTEXT_RESOURCE_KEYS
    }
    for key in CONTEXT_RESOURCE_KEYS:
        if key not in resource:
            continue
        fields[_next_context_escape_key(fields, key)] = resource[key]
    return fields


def _next_context_escape_key(fields: dict[str, Any], key: str) -> str:
    prefixed_key = f"resource_{key}"
    if prefixed_key not in fields:
        return prefixed_key
    context_key = f"resource_context_{key}"
    if context_key not in fields:
        return context_key
    index = 2
    while True:
        numbered_key = f"resource_context_{index}_{key}"
        if numbered_key not in fields:
            return numbered_key
        index += 1


def derive_run_status(*, valid_count: int, failed_count: int) -> str:
    if valid_count > 0 and failed_count == 0:
        return "complete"
    if valid_count > 0 and failed_count > 0:
        return "partial"
    return "error"


def aggregate_run(
    run_dir: Path,
    *,
    run_id: str,
    account: AccountContext,
    failed_work_items: list[dict[str, Any]],
    scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    modules_dir = run_dir / "modules"
    resources_path = run_dir / "resources.jsonl"
    summary_path = run_dir / "summary.json"
    valid_items: list[dict[str, Any]] = []
    failed_items = list(failed_work_items)
    services: dict[str, dict[str, Any]] = {}
    service_regions: dict[str, set[str]] = {}
    total_resources = 0
    total_errors = 0
    total_skipped = 0

    with resources_path.open("w", encoding="utf-8") as resources_file:
        paths = sorted(modules_dir.glob("*/*.json")) if modules_dir.exists() else []
        for path in paths:
            rel_path = path.relative_to(run_dir).as_posix()
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                envelope = ModuleEnvelope.model_validate(payload)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as err:
                failed_items.append({"path": rel_path, "error": type(err).__name__})
                continue

            resource_count = len(envelope.resources)
            error_count = len(envelope.errors)
            skipped_count = sum(entry.skipped for entry in envelope.coverage)
            service = str(envelope.module)
            service_summary = services.setdefault(
                service,
                {"resources": 0, "errors": 0, "skipped": 0, "regions": 0, "statuses": {}},
            )
            service_summary["resources"] += resource_count
            service_summary["errors"] += error_count
            service_summary["skipped"] += skipped_count
            service_summary["statuses"][envelope.status] = service_summary["statuses"].get(envelope.status, 0) + 1
            service_regions.setdefault(service, set()).add(envelope.region)
            total_resources += resource_count
            total_errors += error_count
            total_skipped += skipped_count
            valid_items.append(
                {
                    "module": envelope.module,
                    "region": envelope.region,
                    "status": envelope.status,
                    "resources": resource_count,
                    "errors": error_count,
                    "skipped": skipped_count,
                    "path": rel_path,
                }
            )
            for resource in envelope.resources:
                resource_fields = _resource_fields_with_context_escapes(resource)
                row = {
                    **resource_fields,
                    "run_id": run_id,
                    "account_id": account.account_id,
                    "account_name": account.account_name,
                    "account_owned": account.account_owned,
                    "service": service,
                    "region": envelope.region,
                    "source_path": rel_path,
                }
                resources_file.write(json.dumps(row, sort_keys=True) + "\n")

    for service, regions in service_regions.items():
        services[service]["regions"] = len(regions)

    summary = {
        "run_id": run_id,
        "account_id": account.account_id,
        "account_name": account.account_name,
        "account_owned": account.account_owned,
        "scope": scope or {"mode": "service", "targets": []},
        "status": derive_run_status(valid_count=len(valid_items), failed_count=len(failed_items)),
        "valid_count": len(valid_items),
        "failed_count": len(failed_items),
        "total_resources": total_resources,
        "total_errors": total_errors,
        "total_skipped": total_skipped,
        "services": services,
        "modules": valid_items,
        "failed_items": failed_items,
        "outputs": {
            "resources": "resources.jsonl",
            "summary": "summary.json",
        },
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary
