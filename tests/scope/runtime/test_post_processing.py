from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from scope.runtime.post_processing import (
    build_graph,
    build_results,
    export_dashboard_results,
    write_results,
)
from scope.runtime.run_context import AccountContext


def test_build_results_includes_summary_graph_modules_and_empty_attack_paths(tmp_path: Path) -> None:
    account = AccountContext("123456789012", "prod", True, "config/accounts.json")
    summary = {
        "run_id": "prod-123456789012-2026-05-21T003147Z",
        "account_id": "123456789012",
        "account_name": "prod",
        "account_owned": True,
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
    assert payload["candidate_attack_paths"] == []
    assert payload["attack_validation"] == []
    assert payload["attack_paths"] == []
    assert payload["security_observations"] == []
    assert payload["principals"] == []
    assert payload["trust_relationships"] == []
    assert payload["coverage_gaps"] == []
    assert payload["post_processing"] == {"errors": []}


def test_build_results_uses_explicit_timestamp_when_summary_omits_timestamp(tmp_path: Path) -> None:
    account = AccountContext("123456789012", "prod", True, "config/accounts.json")
    results = build_results(
        run_dir=tmp_path,
        run_id="prod-123456789012-2026-05-21T003147Z",
        account=account,
        summary={
            "status": "complete",
            "modules": [],
        },
        graph={"nodes": [], "edges": []},
        timestamp="2026-05-21T00:31:47Z",
        post_processing_errors=[],
    )

    assert results["timestamp"] == "2026-05-21T00:31:47Z"


def test_build_results_includes_scope_metadata(tmp_path: Path) -> None:
    account = AccountContext(
        account_id="123456789012",
        account_name="dev",
        account_owned=True,
        account_registry_source="config/aws_accounts.json",
    )
    target_results = [
        {
            "target": "arn:aws:s3:::my-bucket",
            "status": "resolved",
            "module": "s3",
            "region": "global",
        }
    ]
    results = build_results(
        run_dir=tmp_path,
        run_id="run-1",
        account=account,
        summary={
            "status": "complete",
            "modules": [],
            "scope": {"mode": "target", "targets": ["arn:aws:s3:::my-bucket"]},
            "target_results": target_results,
        },
        graph={"nodes": [], "edges": []},
        timestamp="2026-05-21T00:00:00Z",
        post_processing_errors=[],
    )

    assert results["scope"] == {"mode": "target", "targets": ["arn:aws:s3:::my-bucket"]}
    assert results["target_results"] == target_results


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
    assert graph["schema_version"] == "2.0"
    assert graph["metadata"]["source"] == "scope-runtime"
    assert any(node["id"] == "role:LambdaExecRole" for node in graph["nodes"])
    assert any(edge["target"] == "role:LambdaExecRole" for edge in graph["edges"])
    assert any(edge["id"].startswith("edge:") for edge in graph["edges"])
    assert json.loads((tmp_path / "graph.json").read_text(encoding="utf-8")) == graph


def test_build_graph_rejects_external_graph_scripts_and_writes_empty_graph(tmp_path: Path) -> None:
    graph, errors = build_graph(tmp_path, graph_script=tmp_path / "external-graph.js")

    assert graph == {"nodes": [], "edges": []}
    assert errors
    assert errors[0]["stage"] == "graph"
    assert errors[0]["message"] == "external graph scripts are no longer supported"
    assert (tmp_path / "graph.json").exists()
    assert json.loads((tmp_path / "graph.json").read_text(encoding="utf-8")) == {
        "nodes": [],
        "edges": [],
    }


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

    assert (
        export_path
        == project_root / "dashboard" / "public" / "prod-123456789012-2026-05-21T003147Z.json"
    )
    assert export_path.read_text(encoding="utf-8") == '{"source":"audit"}\n'
    index = json.loads(
        (project_root / "dashboard" / "public" / "index.json").read_text(encoding="utf-8")
    )
    assert index["version"] == "1.1.0"
    assert "updated" in index
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


def test_export_dashboard_results_replaces_malformed_index_shape(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    public_dir = project_root / "dashboard" / "public"
    public_dir.mkdir(parents=True)
    (public_dir / "index.json").write_text('{"runs": "bad"}\n', encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    results_path = run_dir / "results.json"
    results_path.write_text("{}\n", encoding="utf-8")
    account = AccountContext("123456789012", "prod", True, "config/accounts.json")

    export_dashboard_results(
        project_root=project_root,
        results_path=results_path,
        run_id="current",
        started_at=datetime(2026, 5, 21, 0, 31, 47, tzinfo=timezone.utc),
        account=account,
        summary={"status": "complete"},
    )

    index = json.loads((public_dir / "index.json").read_text(encoding="utf-8"))
    assert index["version"] == "1.1.0"
    assert len(index["runs"]) == 1
    assert index["runs"][0]["run_id"] == "current"
    assert index["runs"][0]["target"] == "prod"
