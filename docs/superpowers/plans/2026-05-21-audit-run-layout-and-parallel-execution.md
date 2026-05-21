# Audit Run Layout and Parallel Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update the Python audit runner so real AWS runs are account-identifiable, ownership-aware, region-isolated, parallel-safe, and aggregated after enumeration.

**Architecture:** Keep enumerators unchanged and refactor the audit runner around small helper modules. `scope_runtime/run_context.py` resolves account registry and run identity, `scope_runtime/aggregation.py` builds `resources.jsonl` and `summary.json`, and `scope_runtime/audit.py` builds work items, runs them with bounded concurrency, writes `manifest.json`, and validates module envelopes.

**Tech Stack:** Python 3.11, boto3 via existing `ClientFactory`, Pydantic `ModuleEnvelope`, `pytest`, stdlib `concurrent.futures`, JSON/JSONL files.

---

## File Structure

- Create: `scope_runtime/run_context.py`
  - Owns `config/accounts.json` loading, account ownership lookup, safe filename names, run ID generation, run directory resolution, and manifest data helpers.
- Create: `scope_runtime/aggregation.py`
  - Owns scanning module envelopes, writing `resources.jsonl`, deriving `summary.json`, and run status rules.
- Modify: `scope_runtime/audit.py`
  - Adds service scope classes, work item building, `--concurrency`, bounded parallel subprocess execution, manifest lifecycle, and aggregation call.
- Modify: `scope_runtime/__main__.py`
  - Adds forwarding for `--concurrency`, optional `--run-dir`, and new `--output-dir`.
- Create: `tests/scope_runtime/test_run_context.py`
  - Covers account registry lookup, missing registry behavior, sanitization, and run directory resolution.
- Create: `tests/scope_runtime/test_aggregation.py`
  - Covers `resources.jsonl`, `summary.json`, missing/invalid module outputs, and status derivation.
- Modify: `tests/scope_runtime/test_audit_dispatch.py`
  - Updates dispatch tests for S3 account scope, no top-level compatibility copies, parallel execution, manifest, and aggregation.

## Behavioral Decisions

- `--run-dir` is an exact run directory path. If it already exists, audit fails before dispatch.
- `--output-dir` is a parent directory. Audit creates `<output-dir>/<run_id>`.
- If neither `--run-dir` nor `--output-dir` is supplied, audit creates `runs/<run_id>`.
- `--run-dir` and `--output-dir` are mutually exclusive.
- `config/accounts.json` is optional. Missing file means `account_owned: false`, not an error.
- `iam` and `sts` are global. `s3` is account-scoped and also runs once with region `global`. Other modules are regional.
- Workers only write isolated module temp dirs and logs. Aggregates are written after all workers finish.
- Top-level legacy compatibility copies like `sns.json` are removed from audit output. Consumers should read `modules/<service>/<region>.json` or post-run aggregates.

---

### Task 1: Run Context Helpers

**Files:**
- Create: `scope_runtime/run_context.py`
- Create: `tests/scope_runtime/test_run_context.py`

- [ ] **Step 1: Write failing tests for account registry loading**

Create `tests/scope_runtime/test_run_context.py` with:

```python
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scope_runtime.run_context import (
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
```

- [ ] **Step 2: Run tests to verify missing module failure**

Run:

```bash
uv run pytest tests/scope_runtime/test_run_context.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'scope_runtime.run_context'`.

- [ ] **Step 3: Implement account registry helpers**

Create `scope_runtime/run_context.py`:

```python
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AccountContext:
    account_id: str
    account_name: str | None
    account_owned: bool
    account_registry_source: str | None


def load_account_registry(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    registry: dict[str, str] = {}
    for account in payload.get("accounts", []):
        account_id = str(account.get("id", "")).strip()
        name = str(account.get("name", "")).strip()
        if account_id and name:
            registry[account_id] = name
    return registry


def resolve_account_context(account_id: str, registry_path: Path = Path("config/accounts.json")) -> AccountContext:
    registry = load_account_registry(registry_path)
    account_name = registry.get(account_id)
    return AccountContext(
        account_id=account_id,
        account_name=account_name,
        account_owned=account_name is not None,
        account_registry_source=str(registry_path) if registry_path.exists() else None,
    )
```

- [ ] **Step 4: Run account tests to verify first green**

Run:

```bash
uv run pytest tests/scope_runtime/test_run_context.py -q
```

Expected: PASS for the account registry tests; remaining tests do not exist yet.

- [ ] **Step 5: Add failing tests for slug and run directory resolution**

Append to `tests/scope_runtime/test_run_context.py`:

```python
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


def test_resolve_run_directory_uses_external_prefix_when_account_is_not_owned(tmp_path: Path):
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


def test_resolve_run_directory_fails_if_exact_run_dir_exists(tmp_path: Path):
    existing = tmp_path / "existing"
    existing.mkdir()
    context = AccountContext(
        account_id="123456789012",
        account_name="prod",
        account_owned=True,
        account_registry_source=None,
    )
    started_at = datetime(2026, 5, 21, 0, 31, 47, tzinfo=timezone.utc)

    with pytest.raises(FileExistsError):
        resolve_run_directory(context, started_at, run_dir=existing, output_dir=None)
```

- [ ] **Step 6: Run tests to verify slug/run-dir failures**

Run:

```bash
uv run pytest tests/scope_runtime/test_run_context.py -q
```

Expected: FAIL with missing `safe_slug` or `resolve_run_directory`.

- [ ] **Step 7: Implement slug and run directory helpers**

Extend `scope_runtime/run_context.py`:

```python
def safe_slug(value: str | None) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")
    return normalized or "unknown"


def utc_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def build_run_id(context: AccountContext, started_at: datetime) -> str:
    if context.account_owned and context.account_name:
        prefix = safe_slug(context.account_name)
    else:
        prefix = "external"
    return f"{prefix}-{context.account_id}-{utc_timestamp(started_at)}"


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
```

- [ ] **Step 8: Run run-context tests**

Run:

```bash
uv run pytest tests/scope_runtime/test_run_context.py -q
```

Expected: all tests pass.

- [ ] **Step 9: Commit Task 1**

Run:

```bash
git add scope_runtime/run_context.py tests/scope_runtime/test_run_context.py
git commit -m "feat: add audit run context helpers"
```

---

### Task 2: Aggregation Helpers

**Files:**
- Create: `scope_runtime/aggregation.py`
- Create: `tests/scope_runtime/test_aggregation.py`

- [ ] **Step 1: Write failing aggregation tests**

Create `tests/scope_runtime/test_aggregation.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

from scope_runtime.aggregation import aggregate_run, derive_run_status
from scope_runtime.run_context import AccountContext


def _write_envelope(path: Path, module: str, region: str, resources: list[dict], errors: list[dict] | None = None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "module": module,
                "account_id": "123456789012",
                "region": region,
                "status": "complete",
                "resources": resources,
                "coverage": [],
                "errors": errors or [],
            }
        ),
        encoding="utf-8",
    )


def test_derive_run_status_rules():
    assert derive_run_status(valid_count=2, failed_count=0) == "complete"
    assert derive_run_status(valid_count=2, failed_count=1) == "partial"
    assert derive_run_status(valid_count=0, failed_count=2) == "error"


def test_aggregate_run_writes_resources_jsonl_and_summary(tmp_path: Path):
    _write_envelope(
        tmp_path / "modules" / "ec2" / "us-east-1.json",
        "ec2",
        "us-east-1",
        [{"resource_type": "ec2_instance", "resource_id": "i-123", "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-123"}],
    )
    _write_envelope(
        tmp_path / "modules" / "iam" / "global.json",
        "iam",
        "global",
        [{"resource_type": "iam_user", "resource_id": "alice", "arn": "arn:aws:iam::123456789012:user/alice"}],
    )
    context = AccountContext("123456789012", "prod", True, "config/accounts.json")

    summary = aggregate_run(tmp_path, run_id="prod-123456789012-2026-05-21T003147Z", account=context, failed_work_items=[])

    resources_path = tmp_path / "resources.jsonl"
    rows = [json.loads(line) for line in resources_path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2
    assert rows[0]["account_id"] == "123456789012"
    assert rows[0]["account_name"] == "prod"
    assert rows[0]["account_owned"] is True
    assert rows[0]["run_id"] == "prod-123456789012-2026-05-21T003147Z"
    assert rows[0]["source_path"].startswith("modules/")
    assert summary["status"] == "complete"
    assert summary["total_resources"] == 2
    assert (tmp_path / "summary.json").exists()


def test_aggregate_run_records_invalid_module_as_failed(tmp_path: Path):
    bad_path = tmp_path / "modules" / "sns" / "us-east-1.json"
    bad_path.parent.mkdir(parents=True, exist_ok=True)
    bad_path.write_text("{bad json", encoding="utf-8")
    context = AccountContext("123456789012", None, False, None)

    summary = aggregate_run(tmp_path, run_id="external-123456789012-2026-05-21T003147Z", account=context, failed_work_items=[])

    assert summary["status"] == "error"
    assert summary["failed_count"] == 1
    assert summary["failed_items"][0]["path"] == "modules/sns/us-east-1.json"
```

- [ ] **Step 2: Run tests to verify missing module failure**

Run:

```bash
uv run pytest tests/scope_runtime/test_aggregation.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'scope_runtime.aggregation'`.

- [ ] **Step 3: Implement aggregation module**

Create `scope_runtime/aggregation.py`:

```python
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from scope_runtime.run_context import AccountContext
from scope_core.models import ModuleEnvelope


def derive_run_status(*, valid_count: int, failed_count: int) -> str:
    if valid_count == 0 and failed_count > 0:
        return "error"
    if failed_count > 0:
        return "partial"
    return "complete"


def aggregate_run(
    run_dir: Path,
    *,
    run_id: str,
    account: AccountContext,
    failed_work_items: list[dict[str, Any]],
) -> dict[str, Any]:
    modules_dir = run_dir / "modules"
    resources_path = run_dir / "resources.jsonl"
    summary_path = run_dir / "summary.json"
    valid_items: list[dict[str, Any]] = []
    failed_items = list(failed_work_items)
    total_resources = 0
    total_errors = 0

    with resources_path.open("w", encoding="utf-8") as resources_file:
        for path in sorted(modules_dir.glob("*/*.json")) if modules_dir.exists() else []:
            rel_path = path.relative_to(run_dir).as_posix()
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                envelope = ModuleEnvelope.model_validate(payload)
            except (json.JSONDecodeError, ValidationError) as err:
                failed_items.append({"path": rel_path, "error": type(err).__name__})
                continue

            resource_count = len(envelope.resources)
            error_count = len(envelope.errors)
            total_resources += resource_count
            total_errors += error_count
            valid_items.append(
                {
                    "module": envelope.module,
                    "region": envelope.region,
                    "status": envelope.status,
                    "resources": resource_count,
                    "errors": error_count,
                    "path": rel_path,
                }
            )
            for resource in envelope.resources:
                row = {
                    "run_id": run_id,
                    "account_id": account.account_id,
                    "account_name": account.account_name,
                    "account_owned": account.account_owned,
                    "service": envelope.module,
                    "region": envelope.region,
                    "source_path": rel_path,
                    **resource,
                }
                resources_file.write(json.dumps(row, sort_keys=True) + "\n")

    summary = {
        "run_id": run_id,
        "account_id": account.account_id,
        "account_name": account.account_name,
        "account_owned": account.account_owned,
        "status": derive_run_status(valid_count=len(valid_items), failed_count=len(failed_items)),
        "valid_count": len(valid_items),
        "failed_count": len(failed_items),
        "total_resources": total_resources,
        "total_errors": total_errors,
        "modules": valid_items,
        "failed_items": failed_items,
        "outputs": {
            "resources": "resources.jsonl",
            "summary": "summary.json",
        },
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary
```

- [ ] **Step 4: Run aggregation tests**

Run:

```bash
uv run pytest tests/scope_runtime/test_aggregation.py -q
```

Expected: all aggregation tests pass.

- [ ] **Step 5: Commit Task 2**

Run:

```bash
git add scope_runtime/aggregation.py tests/scope_runtime/test_aggregation.py
git commit -m "feat: aggregate audit module resources"
```

---

### Task 3: Work Queue and Service Scopes

**Files:**
- Modify: `scope_runtime/audit.py`
- Modify: `tests/scope_runtime/test_audit_dispatch.py`

- [ ] **Step 1: Add failing tests for service scopes and work item generation**

Append to `tests/scope_runtime/test_audit_dispatch.py`:

```python
def test_build_work_items_classifies_global_account_and_regional_modules(tmp_path: Path):
    work_items = audit._build_work_items(
        run_dir=tmp_path,
        modules=["iam", "sts", "s3", "ec2"],
        regions=["us-east-1", "us-west-2"],
    )

    pairs = [(item.module, item.region) for item in work_items]

    assert pairs == [
        ("iam", "global"),
        ("sts", "global"),
        ("s3", "global"),
        ("ec2", "us-east-1"),
        ("ec2", "us-west-2"),
    ]
    assert work_items[0].output_path == tmp_path / "modules" / "iam" / "global.json"
    assert work_items[-1].log_path == tmp_path / "logs" / "ec2-us-west-2.log"


def test_audit_parser_accepts_concurrency_and_output_dir():
    args = audit._parser().parse_args(["--services", "sns", "--output-dir", "runs", "--concurrency", "4"])

    assert args.services == "sns"
    assert args.output_dir == "runs"
    assert args.concurrency == 4
```

- [ ] **Step 2: Run dispatch tests to verify failure**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_build_work_items_classifies_global_account_and_regional_modules tests/scope_runtime/test_audit_dispatch.py::test_audit_parser_accepts_concurrency_and_output_dir -q
```

Expected: FAIL because `_build_work_items`, `WorkItem`, or parser args do not exist.

- [ ] **Step 3: Implement service scopes, work item, and parser args**

Modify `scope_runtime/audit.py`:

```python
from dataclasses import dataclass

GLOBAL_MODULES = {"iam", "sts"}
ACCOUNT_SCOPED_MODULES = {"s3"}
REGIONAL_MODULES = set(ALL_MODULES) - GLOBAL_MODULES - ACCOUNT_SCOPED_MODULES


@dataclass(frozen=True)
class WorkItem:
    module: str
    region: str
    enum_run_dir: Path
    output_path: Path
    log_path: Path


def _module_regions(module: str, regions: list[str]) -> list[str]:
    if module in GLOBAL_MODULES or module in ACCOUNT_SCOPED_MODULES:
        return ["global"]
    return regions


def _build_work_items(run_dir: Path, modules: list[str], regions: list[str]) -> list[WorkItem]:
    items: list[WorkItem] = []
    for module in modules:
        for region in _module_regions(module, regions):
            items.append(
                WorkItem(
                    module=module,
                    region=region,
                    enum_run_dir=run_dir / ".module-runs" / module / region,
                    output_path=_module_region_path(run_dir, module, region),
                    log_path=run_dir / "logs" / f"{module}-{region}.log",
                )
            )
    return items
```

Update `_parser()`:

```python
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--run-dir")
    output_group.add_argument("--output-dir")
    parser.add_argument("--concurrency", type=int, default=8)
```

Remove `required=True` from `--run-dir` because default output is now `runs/<run_id>`.

- [ ] **Step 4: Run focused work queue tests**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_build_work_items_classifies_global_account_and_regional_modules tests/scope_runtime/test_audit_dispatch.py::test_audit_parser_accepts_concurrency_and_output_dir -q
```

Expected: both tests pass.

- [ ] **Step 5: Commit Task 3**

Run:

```bash
git add scope_runtime/audit.py tests/scope_runtime/test_audit_dispatch.py
git commit -m "feat: build scoped audit work queue"
```

---

### Task 4: Audit Runner Manifest and Parallel Dispatch

**Files:**
- Modify: `scope_runtime/audit.py`
- Modify: `scope_runtime/__main__.py`
- Modify: `tests/scope_runtime/test_audit_dispatch.py`

- [ ] **Step 1: Replace old dispatch tests with manifest-aware tests**

Update `test_audit_all_discovers_regions_and_dispatches_python_modules` in `tests/scope_runtime/test_audit_dispatch.py` so it asserts:

```python
def test_audit_all_discovers_regions_and_dispatches_python_modules(monkeypatch, tmp_path: Path):
    commands = []

    def fake_run_command(command, log_path: Path):
        commands.append(command)
        module = command[command.index("enum") + 1]
        region = command[command.index("--region") + 1]
        run_dir = Path(command[command.index("--run-dir") + 1])
        payload = {
            "module": module,
            "account_id": "123456789012",
            "region": region,
            "status": "complete",
            "resources": [{"resource_type": f"{module}_resource", "resource_id": f"{module}-{region}"}],
            "coverage": [],
            "errors": [],
        }
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / f"{module}.json").write_text(json.dumps(payload), encoding="utf-8")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("", encoding="utf-8")
        return 0

    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    run_dir = tmp_path / "run"

    result = audit.main(["--all", "--run-dir", str(run_dir), "--concurrency", "4"])

    assert result == 0
    assert (run_dir / "manifest.json").exists()
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["account_id"] == "123456789012"
    assert manifest["account_owned"] is False
    assert manifest["concurrency"] == 4
    assert manifest["status"] == "complete"
    assert (run_dir / "summary.json").exists()
    assert (run_dir / "resources.jsonl").exists()
    assert (run_dir / "modules" / "s3" / "global.json").exists()
    assert not (run_dir / "modules" / "s3" / "us-east-1.json").exists()
    assert not (run_dir / "sns.json").exists()
```

Delete or update `test_audit_single_region_keeps_top_level_compatibility_copy`; replacement:

```python
def test_audit_single_region_writes_only_modules_and_aggregates(monkeypatch, tmp_path: Path):
    def fake_run_command(command, log_path: Path):
        module = command[command.index("enum") + 1]
        region = command[command.index("--region") + 1]
        run_dir = Path(command[command.index("--run-dir") + 1])
        payload = {
            "module": module,
            "account_id": "123456789012",
            "region": region,
            "status": "complete",
            "resources": [],
            "coverage": [],
            "errors": [],
        }
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / f"{module}.json").write_text(json.dumps(payload), encoding="utf-8")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("", encoding="utf-8")
        return 0

    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    run_dir = tmp_path / "run"

    result = audit.main(["--services", "sns", "--regions", "us-east-1", "--run-dir", str(run_dir)])

    assert result == 0
    assert (run_dir / "modules" / "sns" / "us-east-1.json").exists()
    assert not (run_dir / "sns.json").exists()
    assert (run_dir / "resources.jsonl").exists()
    assert json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))["status"] == "complete"
```

- [ ] **Step 2: Run updated audit dispatch tests to verify failures**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py -q
```

Expected: FAIL because manifest/aggregation/concurrency lifecycle is not wired yet.

- [ ] **Step 3: Implement manifest helpers in audit.py**

Add imports:

```python
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from scope_runtime.aggregation import aggregate_run
from scope_runtime.run_context import resolve_account_context, resolve_run_directory
```

Add helpers:

```python
def _write_manifest(path: Path, manifest: dict) -> None:
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
```

- [ ] **Step 4: Implement worker dispatch helper**

Add to `scope_runtime/audit.py`:

```python
def _run_work_item(item: WorkItem, profile: str | None) -> dict:
    item.enum_run_dir.mkdir(parents=True, exist_ok=True)
    item.log_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "uv",
        "run",
        "python",
        "-m",
        "scope_runtime",
        "enum",
        item.module,
        "--run-dir",
        str(item.enum_run_dir),
        "--region",
        item.region,
    ]
    if profile:
        command.extend(["--profile", profile])
    returncode = _run_command(command, item.log_path)
    envelope_path = item.enum_run_dir / f"{item.module}.json"
    if returncode != 0:
        return {"module": item.module, "region": item.region, "returncode": returncode, "error": "command_failed"}
    if not _valid_envelope(envelope_path, item.module):
        return {"module": item.module, "region": item.region, "returncode": returncode, "error": "invalid_envelope"}
    item.output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(envelope_path, item.output_path)
    return {"module": item.module, "region": item.region, "returncode": 0, "path": str(item.output_path)}


def _run_work_items(items: list[WorkItem], *, profile: str | None, concurrency: int) -> list[dict]:
    failed: list[dict] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(_run_work_item, item, profile) for item in items]
        for future in as_completed(futures):
            result = future.result()
            if result.get("error"):
                failed.append(result)
    return failed
```

- [ ] **Step 5: Rewrite main lifecycle**

In `main()`:

```python
    started_at = _now_utc()
    account_probe = ClientFactory(region="us-east-1", profile=args.profile)
    account = resolve_account_context(account_probe.account_id)
    run_dir, run_id = resolve_run_directory(
        account,
        started_at,
        run_dir=Path(args.run_dir) if args.run_dir else None,
        output_dir=Path(args.output_dir) if args.output_dir else None,
    )
    run_dir.mkdir(parents=True)
    (run_dir / "logs").mkdir()
    (run_dir / "modules").mkdir()

    modules = ALL_MODULES if args.all else _split_csv(args.services)
    if not modules:
        raise SystemExit("--all or --services is required")

    regions = _regions(args)
    items = _build_work_items(run_dir=run_dir, modules=modules, regions=regions)
    manifest = {
        "run_id": run_id,
        "started_at": _iso(started_at),
        "finished_at": None,
        "account_id": account.account_id,
        "account_name": account.account_name,
        "account_owned": account.account_owned,
        "account_registry_source": account.account_registry_source,
        "services_requested": modules,
        "regions_requested": regions,
        "concurrency": args.concurrency,
        "status": "running",
    }
    _write_manifest(run_dir / "manifest.json", manifest)

    failed_items = _run_work_items(items, profile=args.profile, concurrency=args.concurrency)
    summary = aggregate_run(run_dir, run_id=run_id, account=account, failed_work_items=failed_items)
    manifest["finished_at"] = _iso(_now_utc())
    manifest["status"] = summary["status"]
    _write_manifest(run_dir / "manifest.json", manifest)
    print(run_dir)
    return 0 if summary["status"] == "complete" else 1
```

Keep `_regions(args)` using `ClientFactory` for EC2 discovery. Use the existing `account_probe` only for account ID; avoid plumbing it into `_regions` until implementation proves reuse is clean.

- [ ] **Step 6: Add parser validation for concurrency**

After `args = _parser().parse_args(argv)`:

```python
    if args.concurrency < 1:
        raise SystemExit("--concurrency must be >= 1")
```

- [ ] **Step 7: Forward new CLI args**

Modify `scope_runtime/__main__.py`:

```python
    audit_output = audit_parser.add_mutually_exclusive_group()
    audit_output.add_argument("--run-dir")
    audit_output.add_argument("--output-dir")
    audit_parser.add_argument("--concurrency", type=int, default=8)
```

Forward:

```python
        if args.run_dir:
            forwarded.extend(["--run-dir", args.run_dir])
        if args.output_dir:
            forwarded.extend(["--output-dir", args.output_dir])
        forwarded.extend(["--concurrency", str(args.concurrency)])
```

- [ ] **Step 8: Run audit dispatch tests**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py -q
```

Expected: all audit dispatch tests pass.

- [ ] **Step 9: Run scope_runtime tests**

Run:

```bash
uv run pytest tests/scope_runtime -q
```

Expected: all `scope_runtime` tests pass.

- [ ] **Step 10: Commit Task 4**

Run:

```bash
git add scope_runtime/audit.py scope_runtime/__main__.py tests/scope_runtime/test_audit_dispatch.py
git commit -m "feat: run audit work items in parallel"
```

---

### Task 5: Region Discovery Failure and Existing Directory Behavior

**Files:**
- Modify: `tests/scope_runtime/test_audit_dispatch.py`
- Modify: `scope_runtime/audit.py`

- [ ] **Step 1: Add failing tests for failure behavior**

Add `import pytest` to `tests/scope_runtime/test_audit_dispatch.py`, then append:

```python
def test_audit_fails_when_run_dir_already_exists(monkeypatch, tmp_path: Path):
    existing = tmp_path / "existing"
    existing.mkdir()
    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)

    with pytest.raises(SystemExit) as exc:
        audit.main(["--services", "sns", "--regions", "us-east-1", "--run-dir", str(existing)])

    assert "Run directory already exists" in str(exc.value)


def test_audit_rejects_zero_concurrency():
    with pytest.raises(SystemExit) as exc:
        audit.main(["--services", "sns", "--regions", "us-east-1", "--run-dir", "/tmp/not-used", "--concurrency", "0"])

    assert "--concurrency must be >= 1" in str(exc.value)
```

- [ ] **Step 2: Run new failure tests**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_audit_fails_when_run_dir_already_exists tests/scope_runtime/test_audit_dispatch.py::test_audit_rejects_zero_concurrency -q
```

Expected: FAIL until error handling is normalized.

- [ ] **Step 3: Normalize audit main error exits**

Wrap run directory resolution and concurrency validation in clear `SystemExit` paths:

```python
    if args.concurrency < 1:
        raise SystemExit("--concurrency must be >= 1")
    try:
        run_dir, run_id = resolve_run_directory(...)
    except FileExistsError as err:
        raise SystemExit(str(err)) from err
```

Tests should expect `SystemExit`.

- [ ] **Step 4: Run focused failure tests**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_audit_fails_when_run_dir_already_exists tests/scope_runtime/test_audit_dispatch.py::test_audit_rejects_zero_concurrency -q
```

Expected: pass.

- [ ] **Step 5: Commit Task 5**

Run:

```bash
git add scope_runtime/audit.py tests/scope_runtime/test_audit_dispatch.py
git commit -m "test: lock audit runner failure behavior"
```

---

### Task 6: Full Verification and Real AWS Smoke

**Files:**
- No code changes expected unless verification finds a bug.

- [ ] **Step 1: Run schema regeneration**

Run:

```bash
uv run python -m tools.regen_schemas
```

Expected: `module-envelope schema is up to date`.

- [ ] **Step 2: Run Python tests**

Run:

```bash
uv run pytest -q
```

Expected: full Python suite passes.

- [ ] **Step 3: Run JS tests**

Run:

```bash
npm test -- --silent
```

Expected: full JS suite passes.

- [ ] **Step 4: Run constrained real AWS smoke**

Use a small regional slice first to avoid a long all-regions run:

```bash
RUN_PARENT=/tmp/scope-audit-layout-smoke
rm -rf "$RUN_PARENT"
uv run python -m scope_runtime audit --services iam,sts,s3,ec2 --regions us-east-1 --output-dir "$RUN_PARENT" --concurrency 4
find "$RUN_PARENT" -maxdepth 3 -type f | sort
```

Expected:

- one child directory under `/tmp/scope-audit-layout-smoke`
- `manifest.json`
- `resources.jsonl`
- `summary.json`
- `modules/iam/global.json`
- `modules/sts/global.json`
- `modules/s3/global.json`
- `modules/ec2/us-east-1.json`
- no top-level `iam.json`, `sts.json`, `s3.json`, or `ec2.json`

- [ ] **Step 5: Inspect smoke summary**

Run:

```bash
python3 - "$RUN_PARENT" <<'PY'
import json, sys
from pathlib import Path
parent = Path(sys.argv[1])
run_dir = next(p for p in parent.iterdir() if p.is_dir())
manifest = json.loads((run_dir / "manifest.json").read_text())
summary = json.loads((run_dir / "summary.json").read_text())
print("run_dir", run_dir)
print("manifest_status", manifest["status"])
print("account_id", manifest["account_id"])
print("account_name", manifest["account_name"])
print("account_owned", manifest["account_owned"])
print("summary_status", summary["status"])
print("total_resources", summary["total_resources"])
print("failed_count", summary["failed_count"])
for item in summary["modules"]:
    print(item["module"], item["region"], item["status"], item["resources"], item["errors"])
PY
```

Expected: manifest and summary are readable, account metadata is populated, module files validate, and any AWS access gaps are represented in module/summary status rather than crashes.

- [ ] **Step 6: Commit verification fixes if needed**

If verification required code changes, commit them:

```bash
git add <changed-files>
git commit -m "fix: stabilize audit run layout"
```

If no code changes were needed, do not create an empty commit.

---

### Task 7: Final Review

**Files:**
- Review only unless issues are found.

- [ ] **Step 1: Run final code review against the implementation range**

Ask reviewer to check:

- spec coverage against `docs/superpowers/specs/2026-05-21-audit-run-layout-and-parallel-execution-design.md`
- account registry semantics
- exact run-dir failure behavior
- safe parallel writes
- no aggregate writes inside workers
- `s3/global.json` only
- manifest and summary status rules
- full tests and real AWS smoke evidence

- [ ] **Step 2: Fix any blocking review findings**

For each finding:

1. write or update a failing test
2. run it to confirm failure
3. implement minimal fix
4. run focused test
5. run full verification from Task 6 Steps 1-3
6. commit fix

- [ ] **Step 3: Final git status**

Run:

```bash
git status --short
git log --oneline -8
```

Expected: no tracked uncommitted changes. Existing unrelated untracked files may remain.

---

## Self-Review Checklist

- Spec coverage:
  - account registry: Task 1 and Task 4
  - run naming/run dir behavior: Task 1 and Task 5
  - per-service-region raw files: Task 3 and Task 4
  - S3 account scope: Task 3 and Task 4
  - bounded parallelism: Task 4
  - manifest: Task 4
  - resources/summary aggregation: Task 2 and Task 4
  - relationship handoff: preserved by omitting `relationships.jsonl` in this slice
  - real AWS smoke: Task 6
- No placeholders: completed scan for red-flag placeholder and vague deferred-work language.
- Type consistency:
  - `AccountContext.account_owned` is boolean everywhere
  - work item fields are `module`, `region`, `enum_run_dir`, `output_path`, `log_path`
  - aggregation accepts `failed_work_items` as `list[dict[str, Any]]`
