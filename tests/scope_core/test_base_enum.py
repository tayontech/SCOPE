import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import scope_runtime.__main__ as scope_runtime_main
import scope_core.base_enum as base_enum
from scope_core.base_enum import dispatch, main_for
from scope_core.models import ModuleEnvelope


class FakeFactory:
    account_id = "123456789012"


def test_dispatch_writes_successful_module_envelope(tmp_path: Path):
    def run(factory: FakeFactory, region: str) -> ModuleEnvelope:
        assert factory.account_id == "123456789012"
        assert region == "global"
        return ModuleEnvelope(
            module="sts",
            account_id=factory.account_id,
            region=region,
            status="complete",
            resources=[{"resource_type": "sts_identity"}],
            coverage=[],
            errors=[],
        )

    path = dispatch(module_name="sts", run_fn=run, run_dir=tmp_path, region="global", factory=FakeFactory())
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert path == tmp_path / "sts.json"
    assert payload["module"] == "sts"
    assert payload["status"] == "complete"
    assert payload["resources"] == [{"resource_type": "sts_identity"}]
    assert "findings" not in payload
    assert payload["errors"] == []


def test_dispatch_passes_selector_to_selector_aware_run(tmp_path: Path):
    received = {}

    def run(factory, region, selector=None):
        received["selector"] = selector
        return ModuleEnvelope(
            module="sts",
            account_id="123456789012",
            region=region,
            status="complete",
            resources=[],
            coverage=[],
            errors=[],
        )

    selector = {"mode": "target", "targets": [{"arn": "arn:aws:sts::123456789012:assumed-role/Admin/session"}]}
    dispatch(module_name="sts", run_fn=run, run_dir=tmp_path, region="global", factory=object(), selector=selector)

    assert received["selector"] == selector


def test_dispatch_passes_selector_to_keyword_only_selector_run(tmp_path: Path):
    received = {}

    def run(factory, region, *, selector=None):
        received["selector"] = selector
        return ModuleEnvelope(
            module="sts",
            account_id="123456789012",
            region=region,
            status="complete",
            resources=[],
            coverage=[],
            errors=[],
        )

    selector = {"mode": "target"}
    dispatch(module_name="sts", run_fn=run, run_dir=tmp_path, region="global", factory=object(), selector=selector)

    assert received["selector"] == selector


def test_dispatch_keeps_two_argument_enumerators_working(tmp_path: Path):
    called = {}

    def run(factory, region):
        called["region"] = region
        return ModuleEnvelope(
            module="sts",
            account_id="123456789012",
            region=region,
            status="complete",
            resources=[],
            coverage=[],
            errors=[],
        )

    dispatch(module_name="sts", run_fn=run, run_dir=tmp_path, region="global", factory=object(), selector={"mode": "target"})

    assert called["region"] == "global"


def test_dispatch_writes_error_envelope_on_runtime_failure(tmp_path: Path):
    def run(factory: FakeFactory, region: str) -> ModuleEnvelope:
        raise RuntimeError("boom")

    path = dispatch(module_name="sts", run_fn=run, run_dir=tmp_path, region="global", factory=FakeFactory())
    payload = json.loads(path.read_text(encoding="utf-8"))
    log_payload = json.loads((tmp_path / "agent-log.jsonl").read_text(encoding="utf-8"))

    assert path == tmp_path / "sts.json"
    assert payload["module"] == "sts"
    assert payload["account_id"] == "123456789012"
    assert payload["region"] == "global"
    assert payload["status"] == "error"
    assert payload["resources"] == []
    assert "findings" not in payload
    assert payload["errors"][0]["operation"] == "sts.run"
    assert payload["errors"][0]["code"] == "RuntimeError"
    assert payload["errors"][0]["message"] == "boom"
    assert log_payload["type"] == "error"
    assert log_payload["action"] == "sts.run"


def test_dispatch_rejects_non_envelope_return(tmp_path: Path):
    def run(factory: FakeFactory, region: str) -> dict[str, str]:
        return {"status": "complete"}

    path = dispatch(module_name="sts", run_fn=run, run_dir=tmp_path, region="global", factory=FakeFactory())
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["status"] == "error"
    assert payload["resources"] == []
    assert "findings" not in payload
    assert payload["errors"][0]["code"] == "TypeError"


def test_dispatch_rejects_module_mismatch(tmp_path: Path):
    def run(factory: FakeFactory, region: str) -> ModuleEnvelope:
        return ModuleEnvelope(
            module="iam",
            account_id=factory.account_id,
            region=region,
            status="complete",
            resources=[],
            coverage=[],
            errors=[],
        )

    path = dispatch(module_name="sts", run_fn=run, run_dir=tmp_path, region="global", factory=FakeFactory())
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert path == tmp_path / "sts.json"
    assert payload["module"] == "sts"
    assert payload["status"] == "error"
    assert payload["errors"][0]["code"] == "ValueError"


def test_dispatch_falls_back_to_unknown_account_if_factory_lookup_fails(tmp_path: Path):
    class BrokenFactory:
        @property
        def account_id(self) -> str:
            raise RuntimeError("sts unavailable")

    def run(factory: BrokenFactory, region: str) -> ModuleEnvelope:
        raise ValueError("cannot enumerate")

    path = dispatch(module_name="sts", run_fn=run, run_dir=tmp_path, region="global", factory=BrokenFactory())
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["account_id"] == "unknown"
    assert payload["status"] == "error"
    assert payload["errors"][0]["code"] == "ValueError"


def test_dispatch_falls_back_to_unknown_account_if_factory_id_is_malformed(tmp_path: Path):
    class MalformedFactory:
        account_id = "not-ready"

    def run(factory: MalformedFactory, region: str) -> ModuleEnvelope:
        raise ValueError("cannot enumerate")

    path = dispatch(module_name="sts", run_fn=run, run_dir=tmp_path, region="global", factory=MalformedFactory())
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["account_id"] == "unknown"
    assert payload["status"] == "error"
    assert payload["errors"][0]["code"] == "ValueError"


def test_dispatch_writes_error_envelope_when_logging_fails(tmp_path: Path):
    (tmp_path / "agent-log.jsonl").mkdir()

    def run(factory: FakeFactory, region: str) -> ModuleEnvelope:
        raise RuntimeError("boom")

    path = dispatch(module_name="sts", run_fn=run, run_dir=tmp_path, region="global", factory=FakeFactory())
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert path == tmp_path / "sts.json"
    assert payload["status"] == "error"
    assert payload["errors"][0]["code"] == "RuntimeError"


def test_build_parser_rejects_unknown_module(tmp_path: Path):
    with pytest.raises(SystemExit):
        base_enum.build_parser().parse_args(["typo", "--run-dir", str(tmp_path)])


def test_main_for_wires_arguments_to_dispatch(monkeypatch, tmp_path: Path, capsys):
    calls = {}

    class FakeClientFactory:
        def __init__(self, region: str, profile: str | None = None):
            self.region = region
            self.profile = profile

    def fake_dispatch(**kwargs):
        calls.update(kwargs)
        return tmp_path / "sts.json"

    monkeypatch.setattr(base_enum, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(base_enum, "dispatch", fake_dispatch)

    def run(factory: FakeClientFactory, region: str) -> ModuleEnvelope:
        raise AssertionError("dispatch is stubbed")

    result = main_for(run, "sts", ["sts", "--run-dir", str(tmp_path), "--region", "global", "--profile", "dev"])

    assert result == 0
    assert calls["module_name"] == "sts"
    assert calls["run_fn"] is run
    assert calls["run_dir"] == str(tmp_path)
    assert calls["region"] == "global"
    assert calls["factory"].region == "global"
    assert calls["factory"].profile == "dev"
    assert capsys.readouterr().out == f"{tmp_path / 'sts.json'}\n"


def test_main_for_rejects_module_mismatch(tmp_path: Path):
    def run(factory: FakeFactory, region: str) -> ModuleEnvelope:
        raise AssertionError("should not run for mismatched module")

    with pytest.raises(SystemExit):
        main_for(run, "sts", ["iam", "--run-dir", str(tmp_path)])


def test_scope_runtime_rejects_unknown_module_before_dispatch(monkeypatch, tmp_path: Path):
    def fail_dispatch(**kwargs):
        raise AssertionError("dispatch should not run for invalid module names")

    monkeypatch.setattr(scope_runtime_main, "dispatch", fail_dispatch)

    with pytest.raises(SystemExit):
        scope_runtime_main.main(["enum", "typo", "--run-dir", str(tmp_path)])


def test_scope_runtime_enum_wires_imported_module_to_dispatch(monkeypatch, tmp_path: Path, capsys):
    calls = {}

    class FakeClientFactory:
        def __init__(self, region: str, profile: str | None = None):
            self.region = region
            self.profile = profile

    def imported_run(factory: FakeClientFactory, region: str) -> ModuleEnvelope:
        return ModuleEnvelope(
            module="sts",
            account_id="123456789012",
            region=region,
            status="complete",
            resources=[],
            coverage=[],
            errors=[],
        )

    def fake_import_module(name: str):
        calls["import_name"] = name
        return SimpleNamespace(run=imported_run)

    def fake_dispatch(**kwargs):
        calls.update(kwargs)
        calls["run_fn"](kwargs["factory"], kwargs["region"])
        return tmp_path / "sts.json"

    monkeypatch.setattr(scope_runtime_main, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(scope_runtime_main.importlib, "import_module", fake_import_module)
    monkeypatch.setattr(scope_runtime_main, "dispatch", fake_dispatch)

    result = scope_runtime_main.main(["enum", "sts", "--run-dir", str(tmp_path), "--region", "global", "--profile", "dev"])

    assert result == 0
    assert calls["module_name"] == "sts"
    assert calls["import_name"] == "enumerators.sts"
    assert calls["run_dir"] == tmp_path
    assert calls["region"] == "global"
    assert calls["factory"].profile == "dev"
    assert capsys.readouterr().out == f"{tmp_path / 'sts.json'}\n"


def test_scope_runtime_enum_parses_selector_json_for_dispatch(monkeypatch, tmp_path: Path):
    calls = {}

    class FakeClientFactory:
        def __init__(self, region: str, profile: str | None = None):
            self.region = region
            self.profile = profile

    def imported_run(factory: FakeClientFactory, region: str) -> ModuleEnvelope:
        return ModuleEnvelope(
            module="sts",
            account_id="123456789012",
            region=region,
            status="complete",
            resources=[],
            coverage=[],
            errors=[],
        )

    def fake_import_module(name: str):
        calls["import_name"] = name
        return SimpleNamespace(run=imported_run)

    def fake_dispatch(**kwargs):
        calls.update(kwargs)
        return tmp_path / "sts.json"

    monkeypatch.setattr(scope_runtime_main, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(scope_runtime_main.importlib, "import_module", fake_import_module)
    monkeypatch.setattr(scope_runtime_main, "dispatch", fake_dispatch)

    result = scope_runtime_main.main(
        ["enum", "sts", "--run-dir", str(tmp_path), "--region", "global", "--selector-json", '{"mode":"target"}']
    )

    assert result == 0
    assert calls["selector"] == {"mode": "target"}


def test_scope_runtime_invalid_selector_json_writes_error_envelope(tmp_path: Path):
    result = scope_runtime_main.main(["enum", "sts", "--run-dir", str(tmp_path), "--selector-json", "{"])
    payload = json.loads((tmp_path / "sts.json").read_text(encoding="utf-8"))

    assert result == 0
    assert (tmp_path / "sts.json").exists()
    assert payload["status"] == "error"
    assert payload["errors"][0]["code"] == "JSONDecodeError"


def test_scope_runtime_enum_maps_lambda_service_to_import_safe_module(monkeypatch, tmp_path: Path):
    calls = {}

    class FakeClientFactory:
        def __init__(self, region: str, profile: str | None = None):
            self.region = region
            self.profile = profile

    def imported_run(factory: FakeClientFactory, region: str) -> ModuleEnvelope:
        return ModuleEnvelope(
            module="lambda",
            account_id="123456789012",
            region=region,
            status="complete",
            resources=[],
            coverage=[],
            errors=[],
        )

    def fake_import_module(name: str):
        calls["import_name"] = name
        return SimpleNamespace(run=imported_run)

    def fake_dispatch(**kwargs):
        calls.update(kwargs)
        calls["run_fn"](kwargs["factory"], kwargs["region"])
        return tmp_path / "lambda.json"

    monkeypatch.setattr(scope_runtime_main, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(scope_runtime_main.importlib, "import_module", fake_import_module)
    monkeypatch.setattr(scope_runtime_main, "dispatch", fake_dispatch)

    result = scope_runtime_main.main(["enum", "lambda", "--run-dir", str(tmp_path), "--region", "us-east-1"])

    assert result == 0
    assert calls["module_name"] == "lambda"
    assert calls["import_name"] == "enumerators.aws_lambda"


def test_scope_runtime_missing_valid_module_writes_error_envelope(monkeypatch, tmp_path: Path, capsys):
    class FakeClientFactory:
        account_id = "123456789012"

        def __init__(self, region: str, profile: str | None = None):
            self.region = region
            self.profile = profile

    def fake_import_module(name: str):
        assert name == "enumerators.s3"
        raise ModuleNotFoundError("No module named 'enumerators.s3'")

    monkeypatch.setattr(scope_runtime_main, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(scope_runtime_main.importlib, "import_module", fake_import_module)

    result = scope_runtime_main.main(["enum", "s3", "--run-dir", str(tmp_path), "--region", "us-east-1"])
    payload = json.loads((tmp_path / "s3.json").read_text(encoding="utf-8"))

    assert result == 0
    assert payload["module"] == "s3"
    assert payload["status"] == "error"
    assert payload["errors"][0]["code"] == "ModuleNotFoundError"
    assert capsys.readouterr().out == f"{tmp_path / 's3.json'}\n"


def test_scope_runtime_factory_construction_failure_writes_error_envelope(monkeypatch, tmp_path: Path):
    class FailingClientFactory:
        def __init__(self, region: str, profile: str | None = None):
            raise RuntimeError(f"profile {profile} missing")

    def imported_run(factory, region: str):
        _ = factory.account_id

    def fake_import_module(name: str):
        assert name == "enumerators.sts"
        return SimpleNamespace(run=imported_run)

    monkeypatch.setattr(scope_runtime_main, "ClientFactory", FailingClientFactory)
    monkeypatch.setattr(scope_runtime_main.importlib, "import_module", fake_import_module)

    result = scope_runtime_main.main(["enum", "sts", "--run-dir", str(tmp_path), "--profile", "missing"])
    payload = json.loads((tmp_path / "sts.json").read_text(encoding="utf-8"))

    assert result == 0
    assert payload["module"] == "sts"
    assert payload["account_id"] == "unknown"
    assert payload["status"] == "error"
    assert payload["errors"][0]["code"] == "RuntimeError"


def test_scope_runtime_valid_module_missing_run_writes_error_envelope(monkeypatch, tmp_path: Path):
    class FakeClientFactory:
        account_id = "123456789012"

        def __init__(self, region: str, profile: str | None = None):
            self.region = region
            self.profile = profile

    def fake_import_module(name: str):
        assert name == "enumerators.s3"
        return SimpleNamespace()

    monkeypatch.setattr(scope_runtime_main, "ClientFactory", FakeClientFactory)
    monkeypatch.setattr(scope_runtime_main.importlib, "import_module", fake_import_module)

    result = scope_runtime_main.main(["enum", "s3", "--run-dir", str(tmp_path), "--region", "us-east-1"])
    payload = json.loads((tmp_path / "s3.json").read_text(encoding="utf-8"))

    assert result == 0
    assert payload["module"] == "s3"
    assert payload["status"] == "error"
    assert payload["errors"][0]["code"] == "AttributeError"
