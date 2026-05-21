from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scope_runtime.run_context import AccountContext


def _derive_region(modules: list[dict[str, Any]]) -> str:
    regions = {module.get("region") for module in modules if module.get("region")}
    if len(regions) == 1:
        return regions.pop()
    return "global"


def _default_graph_script() -> Path:
    return Path(__file__).resolve().parents[1] / "bin" / "extract-graph.js"


def _empty_graph() -> dict[str, list[Any]]:
    return {"nodes": [], "edges": []}


def _write_graph(run_dir: Path, graph: dict[str, Any]) -> Path:
    path = run_dir / "graph.json"
    path.write_text(json.dumps(graph, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _graph_error(message: str, **details: Any) -> dict[str, Any]:
    error: dict[str, Any] = {"stage": "graph", "message": message}
    error.update({key: value for key, value in details.items() if value})
    return error


def _is_graph_shape(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("nodes"), list) and isinstance(
        value.get("edges"), list
    )


def build_graph(
    run_dir: Path, graph_script: Path | None = None
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    script = graph_script or _default_graph_script()

    try:
        result = subprocess.run(
            ["node", str(script), str(run_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError as exc:
        graph = _empty_graph()
        _write_graph(run_dir, graph)
        return graph, [_graph_error("graph builder failed to start", error=str(exc))]

    if result.returncode != 0:
        graph = _empty_graph()
        _write_graph(run_dir, graph)
        return graph, [
            _graph_error(
                "graph builder failed",
                returncode=result.returncode,
                stderr=result.stderr.strip(),
                stdout=result.stdout.strip(),
            )
        ]

    try:
        graph = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        graph = _empty_graph()
        _write_graph(run_dir, graph)
        return graph, [_graph_error("graph builder emitted invalid JSON", error=str(exc))]

    if not _is_graph_shape(graph):
        graph = _empty_graph()
        _write_graph(run_dir, graph)
        return graph, [_graph_error("graph builder emitted invalid graph shape")]

    _write_graph(run_dir, graph)
    return graph, []


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
    modules = summary.get("modules", [])
    scope = dict(summary.get("scope", {"mode": "service", "targets": []}))
    target_results = [dict(result) for result in summary.get("target_results", [])]
    return {
        "source": "audit",
        "run_id": run_id,
        "account_id": account.account_id,
        "account_name": account.account_name,
        "account_owned": account.account_owned,
        "scope": scope,
        "target_results": target_results,
        "region": _derive_region(modules),
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
        "modules": modules,
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
            errors.append(
                {"stage": "dashboard_export", "error": type(err).__name__, "message": str(err)}
            )
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

    if not isinstance(index, dict):
        index = {"version": "1.1.0", "runs": []}
    raw_runs = index.get("runs", [])
    if not isinstance(raw_runs, list):
        raw_runs = []
    runs = [run for run in raw_runs if isinstance(run, dict) and run.get("run_id") != run_id]
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

    index = {
        "version": "1.1.0",
        "updated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "runs": runs,
    }
    index_path.write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return export_path
