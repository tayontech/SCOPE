from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
from typing import Any

from scope_core.aws import ClientFactory
from scope_core.base_enum import KNOWN_MODULES, LazyClientFactory, _call_run_fn, dispatch


MODULE_IMPORTS = {
    "lambda": "aws_lambda",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scope_runtime")
    subcommands = parser.add_subparsers(dest="command", required=True)

    enum_parser = subcommands.add_parser("enum")
    enum_parser.add_argument("module", choices=KNOWN_MODULES)
    enum_parser.add_argument("--run-dir", required=True)
    enum_parser.add_argument("--region", default="global")
    enum_parser.add_argument("--logical-region", default=None)
    enum_parser.add_argument("--profile", default=None)
    enum_parser.add_argument("--selector-json", default=None)

    audit_parser = subcommands.add_parser("audit")
    audit_group = audit_parser.add_mutually_exclusive_group(required=True)
    audit_group.add_argument("--all", action="store_true")
    audit_group.add_argument("--services")
    audit_group.add_argument("--target")
    audit_group.add_argument("--target-file")
    audit_parser.add_argument("--regions")
    audit_output = audit_parser.add_mutually_exclusive_group()
    audit_output.add_argument("--run-dir")
    audit_output.add_argument("--output-dir")
    audit_parser.add_argument("--dashboard-export", action="store_true")
    audit_parser.add_argument("--concurrency", type=int, default=8)
    audit_parser.add_argument("--profile", default=None)

    args = parser.parse_args(argv)

    if args.command == "enum":
        logical_region = args.logical_region or args.region
        selector = None
        selector_error = None
        if args.selector_json:
            try:
                selector = json.loads(args.selector_json)
            except json.JSONDecodeError as err:
                selector_error = err
        factory = LazyClientFactory(region=args.region, profile=args.profile, factory_cls=ClientFactory)

        def run(factory: Any, region: str, selector: Any | None = None):
            if selector_error is not None:
                raise selector_error
            import_name = MODULE_IMPORTS.get(args.module, args.module)
            module = importlib.import_module(f"enumerators.{import_name}")
            return _call_run_fn(module.run, factory, region, selector)

        path = dispatch(
            module_name=args.module,
            run_fn=run,
            run_dir=Path(args.run_dir),
            region=logical_region,
            factory=factory,
            selector=selector,
        )
        print(path)
        return 0

    if args.command == "audit":
        from scope_runtime.audit import main as audit_main

        forwarded = []
        if args.all:
            forwarded.append("--all")
        if args.services:
            forwarded.extend(["--services", args.services])
        if args.target:
            forwarded.extend(["--target", args.target])
        if args.target_file:
            forwarded.extend(["--target-file", args.target_file])
        if args.regions:
            forwarded.extend(["--regions", args.regions])
        if args.run_dir:
            forwarded.extend(["--run-dir", args.run_dir])
        if args.output_dir:
            forwarded.extend(["--output-dir", args.output_dir])
        if args.dashboard_export:
            forwarded.append("--dashboard-export")
        forwarded.extend(["--concurrency", str(args.concurrency)])
        if args.profile:
            forwarded.extend(["--profile", args.profile])
        return audit_main(forwarded)

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
