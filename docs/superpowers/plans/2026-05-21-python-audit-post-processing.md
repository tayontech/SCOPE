# Python Audit Post-Processing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `scope_runtime audit` produce `graph.json`, `results.json`, and optional dashboard public JSON export after Python enumeration completes.

**Architecture:** Add a focused `scope_runtime/post_processing.py` module that owns graph extraction, results envelope assembly, and dashboard public export. `scope_runtime/audit.py` calls this module after `aggregate_run()` succeeds enough to write `summary.json`, while preserving enumeration status as the source of the process exit code.

**Tech Stack:** Python stdlib (`json`, `subprocess`, `shutil`, `pathlib`, `datetime`), existing Node graph builder (`bin/extract-graph.js`), pytest, existing `scope_runtime` CLI.

---

## File Structure

- Create: `scope_runtime/post_processing.py`
  - `build_graph(run_dir, graph_script=None) -> tuple[dict, list[dict]]`
  - `build_results(run_dir, run_id, account, summary, graph, timestamp, post_processing_errors) -> dict`
  - `write_results(run_dir, results) -> Path`
  - `export_dashboard_results(project_root, results_path, run_id, started_at, account, summary) -> Path`
  - `run_post_processing(...) -> dict`
- Create: `tests/scope_runtime/test_post_processing.py`
  - Unit tests for graph writing, graph failure behavior, results shape, and dashboard export/index upsert.
- Modify: `scope_runtime/audit.py`
  - Add `--dashboard-export` parser flag.
  - Call `run_post_processing()` after `aggregate_run()`.
  - Return nonzero if `results.json` cannot be written; otherwise preserve enumeration status exit behavior.
- Modify: `scope_runtime/__main__.py`
  - Add and forward `--dashboard-export`.
- Modify: `tests/scope_runtime/test_audit_dispatch.py`
  - Assert audit writes `graph.json` and `results.json`.
  - Assert CLI forwards `--dashboard-export`.
  - Assert dashboard export flag writes public JSON/index in a monkeypatched project root.
- Modify: `docs/superpowers/specs/2026-05-21-python-audit-post-processing-design.md`
  - Only if implementation reveals a necessary contract clarification.

---

### Task 1: Post-Processing Results Builder

**Files:**
- Create: `scope_runtime/post_processing.py`
- Create: `tests/scope_runtime/test_post_processing.py`

- [ ] **Step 1: Write failing test for `results.json` envelope assembly**

Create `tests/scope_runtime/test_post_processing.py` with:

```python
from __future__ import annotations

import json
from pathlib import Path

from scope_runtime.post_processing import build_results, write_results
from scope_runtime.run_context import AccountContext


def test_build_results_includes_summary_graph_modules_and_empty_attack_paths(tmp_path: Path) -> None:
    account = AccountContext("123456789012", "prod", True, "config/accounts.json")
    summary = {
        "run_id": "prod-123456789012-2026-05-21T003147Z",
        "account_id": "123456789012",
        "account_name": "prod",
        "account_owned": True,
        "timestamp": "2026-05-21T00:31:47Z",
        "status": "complete",
        "valid_count": 1,
        "failed_count": 0,
        "total_resources": 2,
        "total_errors": 0,
        "total_skipped": 1,
        "services": {
            "iam": {
                "resources": 2,
                "errors": 0,
                "skipped": 1,
                "regions": 1,
                "statuses": {"complete": 1},
            }
        },
        "modules": [
            {
                "module": "iam",
                "region": "global",
                "status": "complete",
                "resources": 2,
                "errors": 0,
                "skipped": 1,
                "path": "modules/iam/global.json",
            }
        ],
        "failed_items": [],
        "outputs": {"resources": "resources.jsonl", "summary": "summary.json"},
    }
    graph = {
        "nodes": [{"id": "role:Admin", "label": "Admin", "type": "role", "_source": "api"}],
        "edges": [],
    }

    results = build_results(
        run_dir=tmp_path,
        run_id="prod-123456789012-2026-05-21T003147Z",
        account=account,
        summary=summary,
        graph=graph,
        timestamp="2026-05-21T00:31:47Z",
        post_processing_errors=[],
    )
    path = write_results(tmp_path, results)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert path == tmp_path / "results.json"
    assert payload["source"] == "audit"
    assert payload["run_id"] == "prod-123456789012-2026-05-21T003147Z"
    assert payload["account_id"] == "123456789012"
    assert payload["account_name"] == "prod"
    assert payload["account_owned"] is True
    assert payload["region"] == "global"
    assert payload["timestamp"] == "2026-05-21T00:31:47Z"
    assert payload["status"] == "complete"
    assert payload["summary"]["total_resources"] == 2
    assert payload["summary"]["total_errors"] == 0
    assert payload["summary"]["total_skipped"] == 1
    assert payload["summary"]["services"] == summary["services"]
    assert payload["summary"]["severity"] == "low"
    assert payload["graph"] == graph
    assert payload["resources"] == {"jsonl": "resources.jsonl", "count": 2}
    assert payload["modules"] == summary["modules"]
    assert payload["attack_paths"] == []
    assert payload["principals"] == []
    assert payload["trust_relationships"] == []
    assert payload["coverage_gaps"] == []
    assert payload["post_processing"] == {"errors": []}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
uv run pytest tests/scope_runtime/test_post_processing.py::test_build_results_includes_summary_graph_modules_and_empty_attack_paths -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'scope_runtime.post_processing'`.

- [ ] **Step 3: Implement results builder and writer**

Create `scope_runtime/post_processing.py` with:

```python
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scope_runtime.run_context import AccountContext


def _summary_region(summary: dict[str, Any]) -> str:
    regions = {
        module.get("region")
        for module in summary.get("modules", [])
        if module.get("region")
    }
    if len(regions) == 1:
        return next(iter(regions))
    return "global"


def build_results(
    *,
    run_dir: Path,
    run_id: str,
    account: AccountContext,
    summary: dict[str, Any],
    graph: dict[str, Any],
    timestamp: str,
    post_processing_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "source": "audit",
        "run_id": run_id,
        "account_id": account.account_id,
        "account_name": account.account_name,
        "account_owned": account.account_owned,
        "region": _summary_region(summary),
        "timestamp": timestamp,
        "status": summary["status"],
        "summary": {
            "services": summary.get("services", {}),
            "total_resources": summary.get("total_resources", 0),
            "total_errors": summary.get("total_errors", 0),
            "total_skipped": summary.get("total_skipped", 0),
            "valid_count": summary.get("valid_count", 0),
            "failed_count": summary.get("failed_count", 0),
            "severity": "low",
        },
        "graph": graph,
        "resources": {
            "jsonl": summary.get("outputs", {}).get("resources", "resources.jsonl"),
            "count": summary.get("total_resources", 0),
        },
        "modules": summary.get("modules", []),
        "failed_items": summary.get("failed_items", []),
        "attack_paths": [],
        "principals": [],
        "trust_relationships": [],
        "coverage_gaps": [],
        "post_processing": {
            "errors": post_processing_errors,
        },
    }


def write_results(run_dir: Path, results: dict[str, Any]) -> Path:
    path = run_dir / "results.json"
    path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
uv run pytest tests/scope_runtime/test_post_processing.py::test_build_results_includes_summary_graph_modules_and_empty_attack_paths -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add scope_runtime/post_processing.py tests/scope_runtime/test_post_processing.py
git commit -m "feat: build audit results envelope"
```

---

### Task 2: Graph Extraction Wrapper

**Files:**
- Modify: `scope_runtime/post_processing.py`
- Modify: `tests/scope_runtime/test_post_processing.py`

- [ ] **Step 1: Add failing test for graph extraction from nested modules**

Append to `tests/scope_runtime/test_post_processing.py`:

```python
from scope_runtime.post_processing import build_graph


def test_build_graph_writes_graph_json_from_nested_modules(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules" / "iam"
    module_dir.mkdir(parents=True)
    (module_dir / "global.json").write_text(
        json.dumps(
            {
                "module": "iam",
                "account_id": "123456789012",
                "region": "global",
                "status": "complete",
                "resources": [
                    {
                        "resource_type": "iam_role",
                        "resource_id": "LambdaExecRole",
                        "is_service_linked": False,
                        "trust_relationships": [
                            {"principal": "lambda.amazonaws.com", "trust_type": "service"}
                        ],
                    }
                ],
                "coverage": [],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )

    graph, errors = build_graph(tmp_path)

    assert errors == []
    assert (tmp_path / "graph.json").exists()
    assert any(node["id"] == "role:LambdaExecRole" for node in graph["nodes"])
    assert any(edge["target"] == "role:LambdaExecRole" for edge in graph["edges"])
    assert json.loads((tmp_path / "graph.json").read_text(encoding="utf-8")) == graph
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
uv run pytest tests/scope_runtime/test_post_processing.py::test_build_graph_writes_graph_json_from_nested_modules -q
```

Expected: FAIL with `ImportError` or missing `build_graph`.

- [ ] **Step 3: Implement `build_graph()`**

Update `scope_runtime/post_processing.py`:

```python
import subprocess
import sys


def _default_graph_script() -> Path:
    return Path(__file__).resolve().parents[1] / "bin" / "extract-graph.js"


def _empty_graph() -> dict[str, list[Any]]:
    return {"nodes": [], "edges": []}


def build_graph(run_dir: Path, graph_script: Path | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    script = graph_script or _default_graph_script()
    try:
        completed = subprocess.run(
            ["node", str(script), str(run_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError as err:
        graph = _empty_graph()
        _write_graph(run_dir, graph)
        return graph, [{"stage": "graph", "error": type(err).__name__, "message": str(err)}]

    if completed.returncode != 0:
        graph = _empty_graph()
        _write_graph(run_dir, graph)
        return graph, [
            {
                "stage": "graph",
                "error": "command_failed",
                "returncode": completed.returncode,
                "stderr": completed.stderr.strip(),
            }
        ]

    try:
        graph = json.loads(completed.stdout)
    except json.JSONDecodeError as err:
        graph = _empty_graph()
        _write_graph(run_dir, graph)
        return graph, [{"stage": "graph", "error": "JSONDecodeError", "message": str(err)}]

    if not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        graph = _empty_graph()
        _write_graph(run_dir, graph)
        return graph, [{"stage": "graph", "error": "invalid_graph_shape"}]

    _write_graph(run_dir, graph)
    return graph, []


def _write_graph(run_dir: Path, graph: dict[str, Any]) -> Path:
    path = run_dir / "graph.json"
    path.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
```

Remove `import sys` if your editor inserted it and it is unused.

- [ ] **Step 4: Run graph test to verify it passes**

Run:

```bash
uv run pytest tests/scope_runtime/test_post_processing.py::test_build_graph_writes_graph_json_from_nested_modules -q
```

Expected: PASS.

- [ ] **Step 5: Add failing test for graph extraction failure**

Append to `tests/scope_runtime/test_post_processing.py`:

```python
def test_build_graph_records_failure_and_writes_empty_graph(tmp_path: Path) -> None:
    graph, errors = build_graph(tmp_path, graph_script=tmp_path / "missing-extract-graph.js")

    assert graph == {"nodes": [], "edges": []}
    assert errors
    assert errors[0]["stage"] == "graph"
    assert (tmp_path / "graph.json").exists()
    assert json.loads((tmp_path / "graph.json").read_text(encoding="utf-8")) == {"nodes": [], "edges": []}
```

- [ ] **Step 6: Run failure test to verify it passes**

Run:

```bash
uv run pytest tests/scope_runtime/test_post_processing.py::test_build_graph_records_failure_and_writes_empty_graph -q
```

Expected: PASS.

- [ ] **Step 7: Run post-processing tests**

Run:

```bash
uv run pytest tests/scope_runtime/test_post_processing.py -q
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

Run:

```bash
git add scope_runtime/post_processing.py tests/scope_runtime/test_post_processing.py
git commit -m "feat: build audit graph artifact"
```

---

### Task 3: Dashboard Public Export

**Files:**
- Modify: `scope_runtime/post_processing.py`
- Modify: `tests/scope_runtime/test_post_processing.py`

- [ ] **Step 1: Add failing dashboard export test**

Append to `tests/scope_runtime/test_post_processing.py`:

```python
from datetime import datetime, timezone

from scope_runtime.post_processing import export_dashboard_results


def test_export_dashboard_results_writes_public_json_and_upserts_index(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    results_path = run_dir / "results.json"
    results_path.write_text('{"source":"audit"}\n', encoding="utf-8")
    account = AccountContext("123456789012", "prod", True, "config/accounts.json")
    summary = {
        "status": "complete",
        "total_errors": 0,
        "total_resources": 3,
        "services": {"iam": {}, "sts": {}},
    }

    export_path = export_dashboard_results(
        project_root=project_root,
        results_path=results_path,
        run_id="prod-123456789012-2026-05-21T003147Z",
        started_at=datetime(2026, 5, 21, 0, 31, 47, tzinfo=timezone.utc),
        account=account,
        summary=summary,
    )

    assert export_path == project_root / "dashboard" / "public" / "prod-123456789012-2026-05-21T003147Z.json"
    assert export_path.read_text(encoding="utf-8") == '{"source":"audit"}\n'
    index = json.loads((project_root / "dashboard" / "public" / "index.json").read_text(encoding="utf-8"))
    assert index["version"] == "1.1.0"
    assert index["runs"] == [
        {
            "run_id": "prod-123456789012-2026-05-21T003147Z",
            "date": "2026-05-21T00:31:47Z",
            "source": "audit",
            "target": "prod",
            "risk": "low",
            "status": "complete",
            "file": "prod-123456789012-2026-05-21T003147Z.json",
        }
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
uv run pytest tests/scope_runtime/test_post_processing.py::test_export_dashboard_results_writes_public_json_and_upserts_index -q
```

Expected: FAIL with missing `export_dashboard_results`.

- [ ] **Step 3: Implement dashboard export**

Update `scope_runtime/post_processing.py`:

```python
import shutil
from datetime import datetime, timezone


def export_dashboard_results(
    *,
    project_root: Path,
    results_path: Path,
    run_id: str,
    started_at: datetime,
    account: AccountContext,
    summary: dict[str, Any],
) -> Path:
    public_dir = project_root / "dashboard" / "public"
    public_dir.mkdir(parents=True, exist_ok=True)
    export_path = public_dir / f"{run_id}.json"
    shutil.copy2(results_path, export_path)

    index_path = public_dir / "index.json"
    if index_path.exists():
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            index = {"version": "1.1.0", "runs": []}
    else:
        index = {"version": "1.1.0", "runs": []}

    runs = [run for run in index.get("runs", []) if run.get("run_id") != run_id]
    runs.insert(
        0,
        {
            "run_id": run_id,
            "date": started_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source": "audit",
            "target": account.account_name or account.account_id,
            "risk": "low",
            "status": summary.get("status", "error"),
            "file": f"{run_id}.json",
        },
    )
    index = {"version": "1.1.0", "updated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "runs": runs}
    index_path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return export_path
```

- [ ] **Step 4: Relax test for `updated` timestamp and run**

Modify the index assertion in `test_export_dashboard_results_writes_public_json_and_upserts_index`:

```python
    assert index["version"] == "1.1.0"
    assert "updated" in index
    assert index["runs"] == [
```

Run:

```bash
uv run pytest tests/scope_runtime/test_post_processing.py::test_export_dashboard_results_writes_public_json_and_upserts_index -q
```

Expected: PASS.

- [ ] **Step 5: Add deterministic upsert test**

Append:

```python
def test_export_dashboard_results_replaces_existing_run_and_preserves_others(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    public_dir = project_root / "dashboard" / "public"
    public_dir.mkdir(parents=True)
    (public_dir / "index.json").write_text(
        json.dumps(
            {
                "version": "1.1.0",
                "runs": [
                    {"run_id": "old", "file": "old.json", "source": "audit"},
                    {"run_id": "current", "file": "stale.json", "source": "audit"},
                ],
            }
        ),
        encoding="utf-8",
    )
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    results_path = run_dir / "results.json"
    results_path.write_text("{}\n", encoding="utf-8")
    account = AccountContext("123456789012", None, False, None)

    export_dashboard_results(
        project_root=project_root,
        results_path=results_path,
        run_id="current",
        started_at=datetime(2026, 5, 21, 0, 31, 47, tzinfo=timezone.utc),
        account=account,
        summary={"status": "partial"},
    )

    index = json.loads((public_dir / "index.json").read_text(encoding="utf-8"))
    assert [run["run_id"] for run in index["runs"]] == ["current", "old"]
    assert index["runs"][0]["file"] == "current.json"
    assert index["runs"][0]["target"] == "123456789012"
    assert index["runs"][0]["status"] == "partial"
```

- [ ] **Step 6: Run dashboard export tests**

Run:

```bash
uv run pytest tests/scope_runtime/test_post_processing.py::test_export_dashboard_results_writes_public_json_and_upserts_index tests/scope_runtime/test_post_processing.py::test_export_dashboard_results_replaces_existing_run_and_preserves_others -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```bash
git add scope_runtime/post_processing.py tests/scope_runtime/test_post_processing.py
git commit -m "feat: export audit results for dashboard"
```

---

### Task 4: Wire Post-Processing Into Audit CLI

**Files:**
- Modify: `scope_runtime/audit.py`
- Modify: `scope_runtime/__main__.py`
- Modify: `tests/scope_runtime/test_audit_dispatch.py`

- [ ] **Step 1: Add failing audit integration test for `graph.json` and `results.json`**

Append to `tests/scope_runtime/test_audit_dispatch.py`:

```python
def test_audit_writes_graph_and_results_after_aggregation(monkeypatch, tmp_path: Path):
    def fake_run_command(command, log_path: Path):
        module = command[command.index("enum") + 1]
        region = command[command.index("--logical-region") + 1]
        run_dir = Path(command[command.index("--run-dir") + 1])
        payload = {
            "module": module,
            "account_id": "123456789012",
            "region": region,
            "status": "complete",
            "resources": [
                {
                    "resource_type": "iam_role",
                    "resource_id": "LambdaExecRole",
                    "is_service_linked": False,
                    "trust_relationships": [
                        {"principal": "lambda.amazonaws.com", "trust_type": "service"}
                    ],
                }
            ],
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
    result = audit.main(["--services", "iam", "--run-dir", str(run_dir)])

    assert result == 0
    assert (run_dir / "graph.json").exists()
    assert (run_dir / "results.json").exists()
    results = json.loads((run_dir / "results.json").read_text(encoding="utf-8"))
    assert results["source"] == "audit"
    assert results["summary"]["total_resources"] == 1
    assert any(node["id"] == "role:LambdaExecRole" for node in results["graph"]["nodes"])
    assert results["attack_paths"] == []
```

- [ ] **Step 2: Run integration test to verify it fails**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_audit_writes_graph_and_results_after_aggregation -q
```

Expected: FAIL because `graph.json` and `results.json` are not written by `audit.main()` yet.

- [ ] **Step 3: Implement `run_post_processing()` helper**

Append to `scope_runtime/post_processing.py`:

```python
def run_post_processing(
    *,
    run_dir: Path,
    run_id: str,
    account: AccountContext,
    summary: dict[str, Any],
    dashboard_export: bool = False,
    project_root: Path | None = None,
    started_at: datetime | None = None,
) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    effective_started_at = started_at or datetime.now(timezone.utc)
    timestamp = effective_started_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    graph, graph_errors = build_graph(run_dir)
    errors.extend(graph_errors)
    results = build_results(
        run_dir=run_dir,
        run_id=run_id,
        account=account,
        summary=summary,
        graph=graph,
        timestamp=timestamp,
        post_processing_errors=errors,
    )
    results_path = write_results(run_dir, results)
    if dashboard_export:
        try:
            export_dashboard_results(
                project_root=project_root or Path.cwd(),
                results_path=results_path,
                run_id=run_id,
                started_at=effective_started_at,
                account=account,
                summary=summary,
            )
        except OSError as err:
            errors.append({"stage": "dashboard_export", "error": type(err).__name__, "message": str(err)})
            results = build_results(
                run_dir=run_dir,
                run_id=run_id,
                account=account,
                summary=summary,
                graph=graph,
                timestamp=timestamp,
                post_processing_errors=errors,
            )
            write_results(run_dir, results)
    return results
```

- [ ] **Step 4: Wire audit parser and post-processing call**

Modify `scope_runtime/audit.py` imports:

```python
from scope_runtime.post_processing import run_post_processing
```

Add parser flag in `_parser()`:

```python
    parser.add_argument("--dashboard-export", action="store_true")
```

Modify `main()` after `summary = aggregate_run(...)`:

```python
    try:
        run_post_processing(
            run_dir=run_dir,
            run_id=run_id,
            account=account,
            summary=summary,
            dashboard_export=args.dashboard_export,
            started_at=started_at,
        )
    except OSError as err:
        manifest["finished_at"] = _iso(_now_utc())
        manifest["status"] = "error"
        manifest["post_processing_error"] = {"error": type(err).__name__, "message": str(err)}
        _write_manifest(run_dir / "manifest.json", manifest)
        print(run_dir)
        return 1
```

Keep the existing final manifest update after this block.

- [ ] **Step 5: Forward dashboard flag from `__main__.py`**

Modify `scope_runtime/__main__.py`:

```python
    audit_parser.add_argument("--dashboard-export", action="store_true")
```

and in audit forwarding:

```python
        if args.dashboard_export:
            forwarded.append("--dashboard-export")
```

- [ ] **Step 6: Run integration test to verify it passes**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_audit_writes_graph_and_results_after_aggregation -q
```

Expected: PASS.

- [ ] **Step 7: Add CLI forwarding test for dashboard export**

Modify `test_module_cli_forwards_audit_output_dir_and_concurrency` in `tests/scope_runtime/test_audit_dispatch.py` so the input includes `"--dashboard-export"` and expected forwarded list includes `"--dashboard-export"` before `"--concurrency"`:

```python
            "--dashboard-export",
```

and:

```python
        "--dashboard-export",
        "--concurrency",
```

- [ ] **Step 8: Run forwarding test**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_module_cli_forwards_audit_output_dir_and_concurrency -q
```

Expected: PASS.

- [ ] **Step 9: Run audit dispatch tests**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py -q
```

Expected: all tests pass.

- [ ] **Step 10: Commit**

Run:

```bash
git add scope_runtime/audit.py scope_runtime/__main__.py scope_runtime/post_processing.py tests/scope_runtime/test_audit_dispatch.py
git commit -m "feat: run audit post-processing"
```

---

### Task 5: Dashboard Export Integration in Audit

**Files:**
- Modify: `scope_runtime/audit.py`
- Modify: `tests/scope_runtime/test_audit_dispatch.py`

- [ ] **Step 1: Add failing audit-level dashboard export test**

Append to `tests/scope_runtime/test_audit_dispatch.py`:

```python
def test_audit_dashboard_export_writes_public_results(monkeypatch, tmp_path: Path):
    def fake_run_command(command, log_path: Path):
        module = command[command.index("enum") + 1]
        region = command[command.index("--logical-region") + 1]
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

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(audit, "_now_utc", lambda: FIXED_NOW)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    run_dir = tmp_path / "run"
    result = audit.main(["--services", "sts", "--run-dir", str(run_dir), "--dashboard-export"])

    assert result == 0
    public_result = tmp_path / "dashboard" / "public" / f"{EXTERNAL_RUN_ID}.json"
    assert public_result.exists()
    assert json.loads(public_result.read_text(encoding="utf-8"))["run_id"] == EXTERNAL_RUN_ID
    index = json.loads((tmp_path / "dashboard" / "public" / "index.json").read_text(encoding="utf-8"))
    assert index["runs"][0]["run_id"] == EXTERNAL_RUN_ID
    assert index["runs"][0]["source"] == "audit"
```

- [ ] **Step 2: Run test to verify it fails if project root is wrong**

Run:

```bash
uv run pytest tests/scope_runtime/test_audit_dispatch.py::test_audit_dashboard_export_writes_public_results -q
```

Expected: PASS if Task 4 used `Path.cwd()` as project root. If it fails because export went to repo root, update `run_post_processing()` call in `audit.main()` to pass `project_root=Path.cwd()` explicitly, then rerun.

- [ ] **Step 3: Run runtime tests**

Run:

```bash
uv run pytest tests/scope_runtime -q
```

Expected: all runtime tests pass.

- [ ] **Step 4: Commit**

Run:

```bash
git add scope_runtime/audit.py tests/scope_runtime/test_audit_dispatch.py
git commit -m "feat: support audit dashboard export flag"
```

---

### Task 6: Final Verification and Real AWS Smoke

**Files:**
- No planned code changes.

- [ ] **Step 1: Run focused tests**

Run:

```bash
uv run pytest tests/scope_runtime tests/scope_core/test_base_enum.py -q
```

Expected: all tests pass.

- [ ] **Step 2: Run full Python test suite**

Run:

```bash
uv run pytest -q
```

Expected: all tests pass.

- [ ] **Step 3: Run JS test suite**

Run:

```bash
npm test -- --silent
```

Expected: all tests pass.

- [ ] **Step 4: Verify generated schema is current**

Run:

```bash
uv run python -m tools.regen_schemas
```

Expected: `module-envelope schema is up to date`.

- [ ] **Step 5: Run real AWS smoke with post-processing**

Run:

```bash
RUN_PARENT=/tmp/scope-post-processing-smoke
rm -rf "$RUN_PARENT"
uv run python -m scope_runtime audit --services iam,sts,s3,ec2 --regions us-east-1 --output-dir "$RUN_PARENT" --concurrency 4 --dashboard-export
```

Expected: command exits 0 and prints a run directory.

- [ ] **Step 6: Inspect real AWS smoke artifacts**

Replace `<RUN_DIR>` with the printed path:

```bash
RUN_DIR=<RUN_DIR>
uv run python - <<'PY'
import json
import os
from pathlib import Path
run = Path(os.environ['RUN_DIR'])
summary = json.loads((run / 'summary.json').read_text())
results = json.loads((run / 'results.json').read_text())
graph = json.loads((run / 'graph.json').read_text())
print('summary_status', summary['status'])
print('results_status', results['status'])
print('total_resources', summary['total_resources'])
print('failed_count', summary['failed_count'])
print('graph_nodes', len(graph['nodes']))
print('graph_edges', len(graph['edges']))
print('dashboard_export', (Path('dashboard/public') / f"{results['run_id']}.json").exists())
PY
```

Expected:

```text
summary_status complete
results_status complete
total_resources <nonzero>
failed_count 0
graph_nodes <nonzero>
graph_edges <number, may be 0 in tiny accounts>
dashboard_export True
```

If `summary_status` is `partial` due real AWS permissions, verify `results.json` exists and `post_processing.errors` only contains real post-processing errors, not enumeration access-denied records.

- [ ] **Step 7: Commit any final doc/test adjustments**

Only if verification required changes:

```bash
git add <changed-files>
git commit -m "fix: finalize audit post-processing"
```

- [ ] **Step 8: Final status**

Report:

- commits created
- test commands and pass/fail results
- real AWS smoke run directory
- `summary.status`, `total_resources`, `graph.nodes`, `graph.edges`
- dashboard export path
