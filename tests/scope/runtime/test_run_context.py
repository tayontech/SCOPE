from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scope.runtime.run_context import (
    AccountContext,
    load_account_registry,
    resolve_account_context,
    resolve_run_directory,
    safe_slug,
)


def test_load_account_registry_reads_config_accounts_json(tmp_path: Path):
    path = tmp_path / "accounts.json"
    path.write_text(
        json.dumps({"accounts": [{"id": "123456789012", "name": "prod"}]}),
        encoding="utf-8",
    )

    registry = load_account_registry(path)

    assert registry == {"123456789012": "prod"}


def test_load_account_registry_missing_file_returns_empty(tmp_path: Path):
    assert load_account_registry(tmp_path / "accounts.json") == {}


def test_load_account_registry_skips_malformed_entries(tmp_path: Path):
    path = tmp_path / "accounts.json"
    path.write_text(
        json.dumps(
            {
                "accounts": [
                    {"id": "123456789012", "name": "prod"},
                    {"id": None, "name": "null id"},
                    {"id": 123456789012, "name": "numeric id"},
                    {"id": "123", "name": "short id"},
                    {"id": "../123456789012", "name": "path id"},
                    {"id": "000000000000", "name": None},
                    {"id": "111111111111", "name": ""},
                    ["not", "an", "object"],
                    None,
                ]
            }
        ),
        encoding="utf-8",
    )

    registry = load_account_registry(path)

    assert registry == {"123456789012": "prod"}


def test_resolve_account_context_marks_owned_account(tmp_path: Path):
    path = tmp_path / "accounts.json"
    path.write_text(
        json.dumps({"accounts": [{"id": "123456789012", "name": "prod"}]}),
        encoding="utf-8",
    )

    context = resolve_account_context("123456789012", path)

    assert context == AccountContext(
        account_id="123456789012",
        account_name="prod",
        account_owned=True,
        account_registry_source=str(path),
    )


def test_resolve_account_context_marks_unknown_account_external(tmp_path: Path):
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps({"accounts": []}), encoding="utf-8")

    context = resolve_account_context("999988887777", path)

    assert context.account_id == "999988887777"
    assert context.account_name is None
    assert context.account_owned is False
    assert context.account_registry_source == str(path)


def test_resolve_account_context_marks_absent_registry_external(tmp_path: Path):
    context = resolve_account_context("999988887777", tmp_path / "accounts.json")

    assert context.account_id == "999988887777"
    assert context.account_name is None
    assert context.account_owned is False
    assert context.account_registry_source is None


@pytest.mark.parametrize(
    "account_id",
    [
        "../123456789012",
        "12345678901",
        "1234567890123",
        "12345678901a",
    ],
)
def test_resolve_account_context_rejects_invalid_account_id(
    tmp_path: Path,
    account_id: str,
):
    with pytest.raises(ValueError, match="account_id must be exactly 12 digits"):
        resolve_account_context(account_id, tmp_path / "accounts.json")


def test_safe_slug_normalizes_account_name_for_paths():
    assert safe_slug("Prod Account / Main!") == "prod-account-main"
    assert safe_slug("") == "unknown"
    assert safe_slug("___") == "unknown"


def test_resolve_run_directory_uses_output_dir_and_identity(tmp_path: Path):
    context = AccountContext(
        account_id="123456789012",
        account_name="Prod Account",
        account_owned=True,
        account_registry_source="config/accounts.json",
    )
    started_at = datetime(2026, 5, 21, 0, 31, 47, tzinfo=timezone.utc)

    run_dir, run_id = resolve_run_directory(
        context,
        started_at,
        run_dir=None,
        output_dir=tmp_path,
    )

    assert run_id == "prod-account-123456789012-2026-05-21T003147Z"
    assert run_dir == tmp_path / run_id


def test_resolve_run_directory_uses_external_prefix_when_account_is_not_owned(
    tmp_path: Path,
):
    context = AccountContext(
        account_id="999988887777",
        account_name=None,
        account_owned=False,
        account_registry_source="config/accounts.json",
    )
    started_at = datetime(2026, 5, 21, 0, 31, 47, tzinfo=timezone.utc)

    run_dir, run_id = resolve_run_directory(
        context,
        started_at,
        run_dir=None,
        output_dir=tmp_path,
    )

    assert run_id == "external-999988887777-2026-05-21T003147Z"
    assert run_dir == tmp_path / run_id


def test_resolve_run_directory_converts_started_at_to_utc_for_run_id(
    tmp_path: Path,
):
    context = AccountContext(
        account_id="123456789012",
        account_name="prod",
        account_owned=True,
        account_registry_source=None,
    )
    started_at = datetime(
        2026,
        5,
        20,
        19,
        31,
        47,
        tzinfo=timezone(timedelta(hours=-5)),
    )

    run_dir, run_id = resolve_run_directory(
        context,
        started_at,
        run_dir=None,
        output_dir=tmp_path,
    )

    assert run_id == "prod-123456789012-2026-05-21T003147Z"
    assert run_dir == tmp_path / run_id


def test_resolve_run_directory_allows_precreated_explicit_run_dir_with_gate_logs(tmp_path: Path):
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "agent-log.jsonl").write_text('{"event":"gate_1"}\n', encoding="utf-8")
    (existing / "gate-2.log").write_text("approved\n", encoding="utf-8")
    context = AccountContext(
        account_id="123456789012",
        account_name="prod",
        account_owned=True,
        account_registry_source=None,
    )
    started_at = datetime(2026, 5, 21, 0, 31, 47, tzinfo=timezone.utc)

    run_dir, run_id = resolve_run_directory(context, started_at, run_dir=existing, output_dir=None)

    assert run_dir == existing
    assert run_id == "existing"


def test_resolve_run_directory_fails_if_exact_run_dir_has_runtime_artifacts(tmp_path: Path):
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "manifest.json").write_text("{}", encoding="utf-8")
    context = AccountContext(
        account_id="123456789012",
        account_name="prod",
        account_owned=True,
        account_registry_source=None,
    )
    started_at = datetime(2026, 5, 21, 0, 31, 47, tzinfo=timezone.utc)

    with pytest.raises(FileExistsError):
        resolve_run_directory(context, started_at, run_dir=existing, output_dir=None)


def test_resolve_run_directory_uses_explicit_run_dir_name_as_run_id(tmp_path: Path):
    context = AccountContext(
        account_id="123456789012",
        account_name="prod",
        account_owned=True,
        account_registry_source=None,
    )
    started_at = datetime(2026, 5, 21, 0, 31, 47, tzinfo=timezone.utc)
    requested = tmp_path / "audit-20260524-144332-all"

    run_dir, run_id = resolve_run_directory(
        context,
        started_at,
        run_dir=requested,
        output_dir=None,
    )

    assert run_id == "audit-20260524-144332-all"
    assert run_dir == requested


def test_resolve_run_directory_rejects_invalid_context_account_id(tmp_path: Path):
    context = AccountContext(
        account_id="../123456789012",
        account_name="prod",
        account_owned=True,
        account_registry_source=None,
    )
    started_at = datetime(2026, 5, 21, 0, 31, 47, tzinfo=timezone.utc)

    with pytest.raises(ValueError, match="account_id must be exactly 12 digits"):
        resolve_run_directory(context, started_at, run_dir=None, output_dir=tmp_path)
