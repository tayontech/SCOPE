from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scope.runtime.run_context import AccountContext
from scope.runtime.graph import build_graph_from_run, write_graph


def _derive_region(modules: list[dict[str, Any]]) -> str:
    regions = {module.get("region") for module in modules if module.get("region")}
    if len(regions) == 1:
        return regions.pop()
    return "global"


def _empty_graph() -> dict[str, list[Any]]:
    return {"nodes": [], "edges": []}


def _graph_error(message: str, **details: Any) -> dict[str, Any]:
    error: dict[str, Any] = {"stage": "graph", "message": message}
    error.update({key: value for key, value in details.items() if value})
    return error


def build_graph(
    run_dir: Path, graph_script: Path | None = None
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if graph_script is not None:
        graph = _empty_graph()
        write_graph(run_dir, graph)
        return graph, [
            _graph_error(
                "external graph scripts are no longer supported",
                graph_script=str(graph_script),
            )
        ]

    try:
        graph = build_graph_from_run(run_dir)
    except Exception as exc:
        graph = _empty_graph()
        write_graph(run_dir, graph)
        return graph, [_graph_error("python graph builder failed", error=str(exc))]

    write_graph(run_dir, graph)
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
        "public_exposure_findings": [],
        "candidate_attack_paths": [],
        "attack_validation": [],
        "attack_paths": [],
        "attack_path_groups": [],
        "security_observations": [],
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


def _utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


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


def _legacy_runs_to_reports(runs: Any) -> list[dict[str, Any]]:
    if not isinstance(runs, list):
        return []
    reports: list[dict[str, Any]] = []
    seen: set[str] = set()
    for run in runs:
        if not isinstance(run, dict) or run.get("source") != "audit":
            continue
        run_id = run.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            continue
        if run_id in seen:
            continue
        seen.add(run_id)
        file_name = run.get("file") if isinstance(run.get("file"), str) else f"{run_id}.json"
        report: dict[str, Any] = {
            "report_id": run_id,
            "created_at": run.get("date") or run.get("created_at") or "",
            "target": run.get("target") or "",
            "risk": run.get("risk") or "low",
            "status": run.get("status") or "complete",
            "audit": {
                "run_id": run_id,
                "file": file_name,
            },
        }
        if isinstance(run.get("account_id"), str):
            report["account_id"] = run["account_id"]
        reports.append(report)
    return reports


def _load_dashboard_index(index_path: Path) -> dict[str, Any]:
    if not index_path.exists():
        return {"version": "2.0.0", "reports": []}
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"version": "2.0.0", "reports": []}
    if not isinstance(index, dict):
        return {"version": "2.0.0", "reports": []}
    reports = index.get("reports")
    if not isinstance(reports, list):
        reports = _legacy_runs_to_reports(index.get("runs"))
    return {
        "version": "2.0.0",
        "reports": [report for report in reports if isinstance(report, dict)],
    }


def _upsert_report(index: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    reports = [
        existing
        for existing in index.get("reports", [])
        if isinstance(existing, dict) and existing.get("report_id") != report["report_id"]
    ]
    reports.insert(0, report)
    return {
        "version": "2.0.0",
        "updated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "reports": reports,
    }


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
    index = _load_dashboard_index(index_path)
    report = {
        "report_id": run_id,
        "created_at": _utc_iso(started_at),
        "account_id": account.account_id,
        "target": account.account_name or account.account_id,
        "risk": "low",
        "status": summary.get("status", "error"),
        "audit": {
            "run_id": run_id,
            "file": f"{run_id}.json",
        },
    }
    index = _upsert_report(index, report)
    index_path.write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return export_path
