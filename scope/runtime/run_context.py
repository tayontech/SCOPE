from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ACCOUNT_ID_PATTERN = re.compile(r"^[0-9]{12}$")


@dataclass(frozen=True)
class AccountContext:
    account_id: str
    account_name: str | None
    account_owned: bool
    account_registry_source: str | None


def validate_account_id(account_id: str) -> str:
    if not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise ValueError("account_id must be exactly 12 digits")
    return account_id


def load_account_registry(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    registry: dict[str, str] = {}
    for account in payload.get("accounts", []):
        if not isinstance(account, dict):
            continue
        account_id = account.get("id")
        name = account.get("name")
        if (
            isinstance(account_id, str)
            and ACCOUNT_ID_PATTERN.fullmatch(account_id)
            and isinstance(name, str)
            and name.strip()
        ):
            registry[account_id] = name
    return registry


def resolve_account_context(
    account_id: str,
    registry_path: Path = Path("config/accounts.json"),
) -> AccountContext:
    account_id = validate_account_id(account_id)
    registry = load_account_registry(registry_path)
    account_name = registry.get(account_id)
    return AccountContext(
        account_id=account_id,
        account_name=account_name,
        account_owned=account_name is not None,
        account_registry_source=str(registry_path) if registry_path.exists() else None,
    )


def safe_slug(value: str | None) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")
    return normalized or "unknown"


def utc_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def build_run_id(context: AccountContext, started_at: datetime) -> str:
    account_id = validate_account_id(context.account_id)
    if context.account_owned and context.account_name:
        prefix = safe_slug(context.account_name)
    else:
        prefix = "external"
    return f"{prefix}-{account_id}-{utc_timestamp(started_at)}"


def resolve_run_directory(
    context: AccountContext,
    started_at: datetime,
    *,
    run_dir: Path | None,
    output_dir: Path | None,
) -> tuple[Path, str]:
    run_id = build_run_id(context, started_at)
    if run_dir is not None:
        resolved = run_dir
    else:
        parent = output_dir or Path("runs")
        resolved = parent / run_id
    if resolved.exists():
        raise FileExistsError(f"Run directory already exists: {resolved}")
    return resolved, run_id
