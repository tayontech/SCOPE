from __future__ import annotations

import argparse
import inspect
from pathlib import Path
from typing import Any, get_args

from .aws import ClientFactory
from .contract import Enumerator
from .envelope import create_envelope, write_envelope
from .logger import JsonlLogger
from .models import ErrorRecord, ModuleEnvelope, ModuleName


KNOWN_MODULES = tuple(get_args(ModuleName))


def dispatch(
    *,
    module_name: str,
    run_fn: Enumerator,
    run_dir: str | Path,
    region: str,
    factory: Any,
    selector: Any | None = None,
) -> Path:
    logger = _logger_or_none(run_dir, module_name)

    try:
        envelope = _call_run_fn(run_fn, factory, region, selector)
        if not isinstance(envelope, ModuleEnvelope):
            raise TypeError(f"{module_name} enumerator returned {type(envelope).__name__}, expected ModuleEnvelope")
        if envelope.module != module_name:
            raise ValueError(f"{module_name} enumerator returned module {envelope.module}")
        return write_envelope(run_dir, envelope)
    except Exception as err:
        error_envelope = create_envelope(
            module=module_name,
            account_id=_account_id_or_unknown(factory),
            region=region,
            status="error",
            resources=[],
            coverage=[],
            errors=[
                ErrorRecord(
                    operation=f"{module_name}.run",
                    resource=None,
                    code=err.__class__.__name__,
                    message=str(err),
                )
            ],
        )
        try:
            if logger is not None:
                logger.log("error", f"{module_name}.run", {"error": str(err), "code": err.__class__.__name__})
                logger.flush()
        except Exception:
            pass
        return write_envelope(run_dir, error_envelope)


def _call_run_fn(run_fn: Enumerator, factory: Any, region: str, selector: Any | None = None) -> ModuleEnvelope:
    signature = inspect.signature(run_fn)
    parameters = signature.parameters.values()
    positional = [
        parameter
        for parameter in parameters
        if parameter.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if "selector" in signature.parameters:
        return run_fn(factory, region, selector=selector)
    if len(positional) >= 3:
        return run_fn(factory, region, selector)
    return run_fn(factory, region)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scope-enum")
    parser.add_argument("module", choices=KNOWN_MODULES)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--region", default="global")
    parser.add_argument("--logical-region", default=None)
    parser.add_argument("--profile", default=None)
    return parser


def main_for(run_fn: Enumerator, module_name: str, argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.module != module_name:
        parser.error(f"module must be {module_name}")
    logical_region = args.logical_region or args.region
    factory = LazyClientFactory(region=args.region, profile=args.profile)
    path = dispatch(module_name=module_name, run_fn=run_fn, run_dir=args.run_dir, region=logical_region, factory=factory)
    print(path)
    return 0


class LazyClientFactory:
    def __init__(self, region: str, profile: str | None = None, factory_cls: Any | None = None):
        self.region = region
        self.profile = profile
        self._factory_cls = factory_cls
        self._factory: Any | None = None

    @property
    def account_id(self) -> str:
        return self._resolved.account_id

    def client(self, service: str) -> Any:
        return self._resolved.client(service)

    def paginate(self, client: Any, operation_name: str, result_key: str, **kwargs: Any) -> list[Any]:
        return self._resolved.paginate(client, operation_name, result_key, **kwargs)

    @property
    def _resolved(self) -> Any:
        if self._factory is None:
            factory_cls = self._factory_cls or ClientFactory
            self._factory = factory_cls(region=self.region, profile=self.profile)
        return self._factory


def _account_id_or_unknown(factory: Any) -> str:
    try:
        account_id = getattr(factory, "account_id", "unknown")
    except Exception:
        return "unknown"

    if isinstance(account_id, str) and len(account_id) == 12 and account_id.isdigit():
        return account_id
    return "unknown"


def _logger_or_none(run_dir: str | Path, module_name: str) -> JsonlLogger | None:
    try:
        return JsonlLogger(run_dir, module_name)
    except Exception:
        return None
