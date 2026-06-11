from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

import scope.runtime.__main__ as cli
import scope.runtime.audit as audit


class FakeClientFactory:
    account_id = "123456789012"

    def __init__(self, region: str, profile: str | None = None):
        self.region = region
        self.profile = profile

    def client(self, service: str):
        assert service == "ec2"
        return FakeEc2()


class FakeEc2:
    def describe_regions(self, AllRegions: bool):
        assert AllRegions is False
        return {"Regions": [{"RegionName": "us-east-1"}, {"RegionName": "us-west-2"}]}


FIXED_NOW = datetime(2026, 5, 21, 0, 31, 47, tzinfo=timezone.utc)
EXTERNAL_RUN_ID = "external-123456789012-2026-05-21T003147Z"


def _command_logical_region(command: list[str]) -> str:
    if "--logical-region" in command:
        return command[command.index("--logical-region") + 1]
    return command[command.index("--region") + 1]


def test_audit_all_discovers_regions_and_dispatches_python_modules(monkeypatch, tmp_path: Path):
    commands = []

    def fake_run_command(command, log_path: Path):
        commands.append(command)
        module = command[command.index("enum") + 1]
        region = _command_logical_region(command)
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
        manifest = json.loads((run_dir.parents[2] / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["status"] == "running"
        assert manifest["finished_at"] is None
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
    assert (run_dir / "modules" / "cloudfront" / "global.json").exists()
    assert (run_dir / "modules" / "route53" / "global.json").exists()
    assert not (run_dir / "modules" / "s3" / "us-east-1.json").exists()
    assert not (run_dir / "modules" / "cloudfront" / "us-east-1.json").exists()
    assert not (run_dir / "modules" / "route53" / "us-east-1.json").exists()
    assert not (run_dir / "sns.json").exists()
    modules = []
    for command in commands:
        module = command[command.index("enum") + 1]
        if module not in modules:
            modules.append(module)
    assert set(modules) == set(audit.ALL_MODULES)
    assert "ecs" in modules
    regions = {command[command.index("--region") + 1] for command in commands}
    assert {"global", "us-east-1", "us-west-2"} <= regions
    assert "lambda" in modules
    assert "aws_lambda" not in modules
    assert (run_dir / "modules" / "sns" / "us-east-1.json").exists()
    assert (run_dir / "modules" / "sns" / "us-west-2.json").exists()


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


def test_audit_dispatches_ecs_as_regional_module(monkeypatch, tmp_path: Path):
    commands = []

    def fake_run_command(command, log_path: Path):
        commands.append(command)
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

    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    run_dir = tmp_path / "run"

    result = audit.main(["--services", "ecs", "--regions", "us-east-1", "--run-dir", str(run_dir)])

    assert result == 0
    assert commands[0][commands[0].index("enum") + 1] == "ecs"
    assert commands[0][commands[0].index("--region") + 1] == "us-east-1"
    assert commands[0][commands[0].index("--logical-region") + 1] == "us-east-1"
    assert (run_dir / "modules" / "ecs" / "us-east-1.json").exists()


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
    assert results["candidate_attack_paths"] == []
    assert results["attack_validation"] == []
    assert results["security_observations"] == []


def test_audit_returns_nonzero_when_envelope_missing(monkeypatch, tmp_path: Path):
    def fake_run_command(command, log_path: Path):
        return 0

    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    result = audit.main(["--services", "sns", "--regions", "us-east-1", "--run-dir", str(tmp_path / "run")])

    assert result == 1


def test_audit_rejects_invalid_region_path_component(monkeypatch, tmp_path: Path):
    outside = tmp_path / "outside"
    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)

    with pytest.raises(SystemExit) as exc:
        audit.main(["--services", "sns", "--regions", "../../outside", "--run-dir", str(tmp_path / "run")])

    assert "Invalid region" in str(exc.value)
    assert not outside.exists()


def test_audit_rejects_unknown_service(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)

    with pytest.raises(SystemExit) as exc:
        audit.main(["--services", "../../x", "--regions", "us-east-1", "--run-dir", str(tmp_path / "run")])

    assert "Unknown service" in str(exc.value)


def test_audit_rejects_duplicate_service(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)

    with pytest.raises(SystemExit) as exc:
        audit.main(["--services", "sns,sns", "--regions", "us-east-1", "--run-dir", str(tmp_path / "run")])

    assert "Duplicate service" in str(exc.value)


def test_audit_rejects_duplicate_region(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)

    with pytest.raises(SystemExit) as exc:
        audit.main(["--services", "sns", "--regions", "us-east-1,us-east-1", "--run-dir", str(tmp_path / "run")])

    assert "Duplicate region" in str(exc.value)


def test_audit_rejects_service_region_mismatch(monkeypatch, tmp_path: Path):
    def fake_run_command(command, log_path: Path):
        module = command[command.index("enum") + 1]
        run_dir = Path(command[command.index("--run-dir") + 1])
        payload = {
            "module": module,
            "account_id": "123456789012",
            "region": "us-west-2",
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

    result = audit.main(["--services", "ec2", "--regions", "us-east-1", "--run-dir", str(run_dir)])

    assert result == 1
    assert not (run_dir / "modules" / "ec2" / "us-east-1.json").exists()
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "error"
    assert summary["failed_items"][0]["error"] == "invalid_envelope"


def test_run_work_item_writes_only_isolated_temp_output(monkeypatch, tmp_path: Path):
    item = audit.WorkItem(
        module="sns",
        region="us-east-1",
        enum_run_dir=tmp_path / ".module-runs" / "sns" / "us-east-1",
        output_path=tmp_path / "modules" / "sns" / "us-east-1.json",
        log_path=tmp_path / "logs" / "sns-us-east-1.log",
    )

    def fake_run_command(command, log_path: Path):
        payload = {
            "module": "sns",
            "account_id": "123456789012",
            "region": "us-east-1",
            "status": "complete",
            "resources": [],
            "coverage": [],
            "errors": [],
        }
        item.enum_run_dir.mkdir(parents=True, exist_ok=True)
        (item.enum_run_dir / "sns.json").write_text(json.dumps(payload), encoding="utf-8")
        log_path.write_text("", encoding="utf-8")
        return 0

    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    result = audit._run_work_item(item, profile=None)

    assert result["returncode"] == 0
    assert result["envelope_path"] == item.enum_run_dir / "sns.json"
    assert result["output_path"] == item.output_path
    assert not item.output_path.exists()


def test_run_work_item_invokes_scope_cli_with_current_python(monkeypatch, tmp_path: Path):
    item = audit.WorkItem(
        module="sns",
        region="us-east-1",
        enum_run_dir=tmp_path / ".module-runs" / "sns" / "us-east-1",
        output_path=tmp_path / "modules" / "sns" / "us-east-1.json",
        log_path=tmp_path / "logs" / "sns-us-east-1.log",
    )
    commands = []

    def fake_run_command(command, log_path: Path):
        commands.append(command)
        item.enum_run_dir.mkdir(parents=True, exist_ok=True)
        (item.enum_run_dir / "sns.json").write_text(
            json.dumps(
                {
                    "module": "sns",
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "status": "complete",
                    "resources": [],
                    "coverage": [],
                    "errors": [],
                }
            ),
            encoding="utf-8",
        )
        log_path.write_text("", encoding="utf-8")
        return 0

    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    audit._run_work_item(item, profile=None)

    assert commands[0][:3] == [sys.executable, "-m", "scope"]
    assert commands[0][3] == "enum"


def test_s3_work_item_uses_real_execution_region_and_global_output(monkeypatch, tmp_path: Path):
    item = audit.WorkItem(
        module="s3",
        region="global",
        execution_region="us-east-1",
        enum_run_dir=tmp_path / ".module-runs" / "s3" / "global",
        output_path=tmp_path / "modules" / "s3" / "global.json",
        log_path=tmp_path / "logs" / "s3-global.log",
    )
    commands = []

    def fake_run_command(command, log_path: Path):
        commands.append(command)
        region = command[command.index("--region") + 1]
        logical_region = command[command.index("--logical-region") + 1]
        run_dir = Path(command[command.index("--run-dir") + 1])
        assert region == "us-east-1"
        assert logical_region == "global"
        payload = {
            "module": "s3",
            "account_id": "123456789012",
            "region": logical_region,
            "status": "complete",
            "resources": [],
            "coverage": [],
            "errors": [],
        }
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "s3.json").write_text(json.dumps(payload), encoding="utf-8")
        log_path.write_text("", encoding="utf-8")
        return 0

    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    failed = audit._run_work_items([item], profile=None, concurrency=1)

    assert failed == []
    assert commands[0][commands[0].index("--region") + 1] != "global"
    assert item.output_path == tmp_path / "modules" / "s3" / "global.json"
    assert json.loads(item.output_path.read_text(encoding="utf-8"))["region"] == "global"


def test_run_work_items_waits_for_all_workers_before_final_copy(monkeypatch, tmp_path: Path):
    fast_finished = threading.Event()
    fast_output = tmp_path / "modules" / "sns" / "us-east-1.json"

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
        if module == "sns":
            fast_finished.set()
        else:
            assert fast_finished.wait(timeout=2)
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline and not fast_output.exists():
                time.sleep(0.01)
            assert not fast_output.exists()
        return 0

    items = [
        audit.WorkItem(
            module="sns",
            region="us-east-1",
            enum_run_dir=tmp_path / ".module-runs" / "sns" / "us-east-1",
            output_path=fast_output,
            log_path=tmp_path / "logs" / "sns-us-east-1.log",
        ),
        audit.WorkItem(
            module="sqs",
            region="us-east-1",
            enum_run_dir=tmp_path / ".module-runs" / "sqs" / "us-east-1",
            output_path=tmp_path / "modules" / "sqs" / "us-east-1.json",
            log_path=tmp_path / "logs" / "sqs-us-east-1.log",
        ),
    ]

    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    failed = audit._run_work_items(items, profile=None, concurrency=2)

    assert failed == []
    assert fast_output.exists()
    assert items[1].output_path.exists()


def test_audit_records_worker_exception_and_finishes_manifest(monkeypatch, tmp_path: Path):
    def fake_run_command(command, log_path: Path):
        module = command[command.index("enum") + 1]
        if module == "sns":
            raise RuntimeError("boom")
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

    result = audit.main(["--services", "sns,sqs", "--regions", "us-east-1", "--run-dir", str(run_dir), "--concurrency", "2"])

    assert result == 1
    assert (run_dir / "summary.json").exists()
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "partial"
    assert summary["failed_items"][0]["module"] == "sns"
    assert summary["failed_items"][0]["error"] == "worker_exception"
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "partial"
    assert manifest["finished_at"] is not None
    assert (run_dir / "modules" / "sqs" / "us-east-1.json").exists()


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


def test_build_work_items_rejects_duplicate_explicit_pairs(tmp_path: Path):
    with pytest.raises(SystemExit) as exc:
        audit._build_work_items(
            run_dir=tmp_path,
            modules=["sns"],
            regions=["us-east-1"],
            explicit_pairs=[("sns", "us-east-1"), ("sns", "us-east-1")],
        )

    assert "Duplicate" in str(exc.value)


def test_audit_parser_accepts_concurrency_and_output_dir():
    args = audit._parser().parse_args(["--services", "sns", "--output-dir", "runs", "--concurrency", "4"])

    assert args.services == "sns"
    assert args.output_dir == "runs"
    assert args.concurrency == 4


def test_audit_parser_accepts_target_and_target_file():
    target_args = audit._parser().parse_args(["--target", "arn:aws:s3:::my-bucket"])
    file_args = audit._parser().parse_args(["--target-file", "targets.txt"])

    assert target_args.target == "arn:aws:s3:::my-bucket"
    assert file_args.target_file == "targets.txt"


def test_audit_target_lambda_plans_single_region_and_context(monkeypatch, tmp_path: Path):
    commands = []

    def fake_run_command(command, log_path: Path):
        commands.append(command)
        module = command[command.index("enum") + 1]
        region = command[command.index("--logical-region") + 1]
        run_dir = Path(command[command.index("--run-dir") + 1])
        resources = []
        if module == "lambda":
            resources = [
                {
                    "resource_type": "lambda_function",
                    "resource_id": "my-func",
                    "arn": "arn:aws:lambda:us-east-1:123456789012:function:my-func",
                    "role": "arn:aws:iam::123456789012:role/LambdaExecRole",
                },
                {
                    "resource_type": "lambda_function",
                    "resource_id": "other",
                    "arn": "arn:aws:lambda:us-east-1:123456789012:function:other",
                },
            ]
        elif module == "iam":
            resources = [
                {"resource_type": "iam_role", "resource_id": "LambdaExecRole", "arn": "arn:aws:iam::123456789012:role/LambdaExecRole"},
                {"resource_type": "iam_role", "resource_id": "OtherRole", "arn": "arn:aws:iam::123456789012:role/OtherRole"},
            ]
        payload = {
            "module": module,
            "account_id": "123456789012",
            "region": region,
            "status": "complete",
            "resources": resources,
            "coverage": [],
            "errors": [],
        }
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / f"{module}.json").write_text(json.dumps(payload), encoding="utf-8")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("", encoding="utf-8")
        return 0

    class NoEc2DiscoveryFactory(FakeClientFactory):
        def client(self, service: str):
            raise AssertionError("target mode must not discover regions")

    monkeypatch.setattr(audit, "ClientFactory", NoEc2DiscoveryFactory)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    run_dir = tmp_path / "run"
    result = audit.main(
        [
            "--target",
            "arn:aws:lambda:us-east-1:123456789012:function:my-func",
            "--run-dir",
            str(run_dir),
            "--concurrency",
            "3",
        ]
    )

    assert result == 0
    pairs = [(command[command.index("enum") + 1], command[command.index("--logical-region") + 1]) for command in commands]
    assert set(pairs) == {("lambda", "us-east-1"), ("iam", "global"), ("sts", "global")}
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["scope"] == {
        "mode": "target",
        "targets": ["arn:aws:lambda:us-east-1:123456789012:function:my-func"],
    }
    assert manifest["services_requested"] == ["lambda", "iam", "sts"]
    assert manifest["regions_requested"] == ["us-east-1"]
    resources = [
        json.loads(line)
        for line in (run_dir / "resources.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [(resource["service"], resource["resource_id"], resource["scope_match"]) for resource in resources] == [
        ("iam", "LambdaExecRole", "context"),
        ("lambda", "my-func", "target"),
    ]
    assert all(resource["scope_source"] == "arn:aws:lambda:us-east-1:123456789012:function:my-func" for resource in resources)


def test_audit_target_file_partial_when_one_target_not_found(monkeypatch, tmp_path: Path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        "arn:aws:s3:::existing-bucket\n"
        "arn:aws:sns:us-east-1:123456789012:missing-topic\n",
        encoding="utf-8",
    )

    def fake_run_command(command, log_path: Path):
        module = command[command.index("enum") + 1]
        region = command[command.index("--logical-region") + 1]
        run_dir = Path(command[command.index("--run-dir") + 1])
        resources = []
        if module == "s3":
            resources = [{"resource_type": "s3_bucket", "resource_id": "existing-bucket", "arn": "arn:aws:s3:::existing-bucket"}]
        payload = {
            "module": module,
            "account_id": "123456789012",
            "region": region,
            "status": "complete",
            "resources": resources,
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

    result = audit.main(["--target-file", str(target_file), "--run-dir", str(tmp_path / "run")])

    summary = json.loads((tmp_path / "run" / "summary.json").read_text(encoding="utf-8"))
    assert result == 1
    assert summary["status"] == "partial"
    assert summary["target_results"] == [
        {"target": "arn:aws:s3:::existing-bucket", "status": "resolved", "module": "s3", "region": "global"},
        {"target": "arn:aws:sns:us-east-1:123456789012:missing-topic", "status": "not_found", "module": "sns", "region": "us-east-1"},
    ]


def test_audit_target_error_when_all_targets_not_found(monkeypatch, tmp_path: Path):
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

    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    run_dir = tmp_path / "run"
    result = audit.main(["--target", "arn:aws:sns:us-east-1:123456789012:missing-topic", "--run-dir", str(run_dir)])

    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert result == 1
    assert summary["status"] == "error"
    assert summary["target_results"][0]["status"] == "not_found"


def test_audit_target_file_combines_targets_in_one_run(monkeypatch, tmp_path: Path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        "arn:aws:s3:::my-bucket\n"
        "arn:aws:sns:us-west-2:123456789012:alerts\n",
        encoding="utf-8",
    )
    commands = []

    def fake_run_command(command, log_path: Path):
        commands.append(command)
        module = command[command.index("enum") + 1]
        region = command[command.index("--logical-region") + 1]
        run_dir = Path(command[command.index("--run-dir") + 1])
        resources = []
        if module == "s3":
            resources = [{"resource_type": "s3_bucket", "resource_id": "my-bucket", "arn": "arn:aws:s3:::my-bucket"}]
        if module == "sns":
            resources = [{"resource_type": "sns_topic", "resource_id": "alerts", "arn": "arn:aws:sns:us-west-2:123456789012:alerts"}]
        payload = {
            "module": module,
            "account_id": "123456789012",
            "region": region,
            "status": "complete",
            "resources": resources,
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
    result = audit.main(["--target-file", str(target_file), "--run-dir", str(run_dir)])

    assert result == 0
    pairs = [(command[command.index("enum") + 1], command[command.index("--logical-region") + 1]) for command in commands]
    assert set(pairs) == {("s3", "global"), ("sns", "us-west-2"), ("sts", "global")}
    assert (run_dir / "manifest.json").exists()
    assert (run_dir / "summary.json").exists()
    assert (run_dir / "results.json").exists()


def test_module_cli_forwards_audit_output_dir_and_concurrency(monkeypatch):
    forwarded = []

    def fake_audit_main(argv):
        forwarded.extend(argv)
        return 0

    monkeypatch.setattr(audit, "main", fake_audit_main)

    result = cli.main(
        [
            "audit",
            "--services",
            "sns",
            "--regions",
            "us-east-1",
            "--output-dir",
            "/tmp/x",
            "--dashboard-export",
            "--concurrency",
            "4",
        ]
    )

    assert result == 0
    assert forwarded == [
        "--services",
        "sns",
        "--regions",
        "us-east-1",
        "--output-dir",
        "/tmp/x",
        "--dashboard-export",
        "--concurrency",
        "4",
    ]


def test_module_cli_forwards_target_arguments(monkeypatch):
    forwarded = []

    def fake_audit_main(argv):
        forwarded.extend(argv)
        return 0

    monkeypatch.setattr(audit, "main", fake_audit_main)

    result = cli.main(
        [
            "audit",
            "--target",
            "arn:aws:lambda:us-east-1:123456789012:function:my-func",
            "--output-dir",
            "/tmp/runs",
            "--concurrency",
            "2",
        ]
    )

    assert result == 0
    assert forwarded == [
        "--target",
        "arn:aws:lambda:us-east-1:123456789012:function:my-func",
        "--output-dir",
        "/tmp/runs",
        "--concurrency",
        "2",
    ]


def test_audit_output_dir_is_parent_for_generated_run_id(monkeypatch, tmp_path: Path):
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

    output_dir = tmp_path / "audit-parent"
    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(audit, "_now_utc", lambda: FIXED_NOW)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    result = audit.main(["--services", "sns", "--regions", "us-east-1", "--output-dir", str(output_dir)])

    run_dir = output_dir / EXTERNAL_RUN_ID
    assert result == 0
    assert (run_dir / "manifest.json").exists()
    assert (run_dir / "modules" / "sns" / "us-east-1.json").exists()
    assert not (output_dir / "manifest.json").exists()


def test_audit_defaults_to_runs_parent_for_generated_run_id(monkeypatch, tmp_path: Path):
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

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(audit, "_now_utc", lambda: FIXED_NOW)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    result = audit.main(["--services", "sns", "--regions", "us-east-1"])

    run_dir = tmp_path / "runs" / EXTERNAL_RUN_ID
    assert result == 0
    assert (run_dir / "manifest.json").exists()
    assert (run_dir / "modules" / "sns" / "us-east-1.json").exists()


def test_audit_global_only_services_skip_region_discovery(monkeypatch, tmp_path: Path):
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

    class NoEc2ClientFactory(FakeClientFactory):
        def client(self, service: str):
            raise AssertionError("EC2 discovery should not be called")

    monkeypatch.setattr(audit, "ClientFactory", NoEc2ClientFactory)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    run_dir = tmp_path / "run"

    result = audit.main(["--services", "iam", "--run-dir", str(run_dir)])

    assert result == 0
    assert (run_dir / "modules" / "iam" / "global.json").exists()
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["regions_requested"] == []


def test_audit_mkdir_race_file_exists_becomes_system_exit(monkeypatch, tmp_path: Path):
    run_dir = tmp_path / "run"
    original_mkdir = Path.mkdir

    def racing_mkdir(self, *args, **kwargs):
        if self == run_dir:
            raise FileExistsError(f"Race created {self}")
        return original_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(Path, "mkdir", racing_mkdir)

    with pytest.raises(SystemExit) as exc:
        audit.main(["--services", "sns", "--regions", "us-east-1", "--run-dir", str(run_dir)])

    assert "Run directory already exists" in str(exc.value)


def test_audit_allows_precreated_run_dir_with_gate_log(monkeypatch, tmp_path: Path):
    def fake_run_command(command, log_path: Path):
        module = command[command.index("enum") + 1]
        region = command[command.index("--logical-region") + 1]
        module_run_dir = Path(command[command.index("--run-dir") + 1])
        payload = {
            "module": module,
            "account_id": "123456789012",
            "region": region,
            "status": "complete",
            "resources": [],
            "coverage": [],
            "errors": [],
        }
        module_run_dir.mkdir(parents=True, exist_ok=True)
        (module_run_dir / f"{module}.json").write_text(json.dumps(payload), encoding="utf-8")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("", encoding="utf-8")
        return 0

    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "agent-log.jsonl").write_text('{"event":"gate_1"}\n', encoding="utf-8")
    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(audit, "_run_command", fake_run_command)

    result = audit.main(["--services", "sts", "--run-dir", str(existing)])

    assert result == 0
    assert (existing / "agent-log.jsonl").read_text(encoding="utf-8") == '{"event":"gate_1"}\n'
    assert (existing / "manifest.json").exists()
    assert (existing / "modules" / "sts" / "global.json").exists()


def test_audit_fails_when_run_dir_already_has_runtime_artifacts(monkeypatch, tmp_path: Path):
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "manifest.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(audit, "ClientFactory", FakeClientFactory)

    with pytest.raises(SystemExit) as exc:
        audit.main(["--services", "sns", "--regions", "us-east-1", "--run-dir", str(existing)])

    assert "Run directory already exists" in str(exc.value)


def test_audit_rejects_zero_concurrency():
    with pytest.raises(SystemExit) as exc:
        audit.main(["--services", "sns", "--regions", "us-east-1", "--run-dir", "/tmp/not-used", "--concurrency", "0"])

    assert "--concurrency must be >= 1" in str(exc.value)


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
    public_result = tmp_path / "dashboard" / "public" / "run.json"
    assert public_result.exists()
    assert json.loads(public_result.read_text(encoding="utf-8"))["run_id"] == "run"
    index = json.loads((tmp_path / "dashboard" / "public" / "index.json").read_text(encoding="utf-8"))
    assert index["reports"][0]["report_id"] == "run"
    assert index["reports"][0]["audit"]["run_id"] == "run"
    assert index["reports"][0]["audit"]["file"] == "run.json"
    assert "runs" not in index
