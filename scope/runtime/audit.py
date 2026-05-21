from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from pydantic import ValidationError

from scope.runtime.aggregation import aggregate_run
from scope.runtime.post_processing import run_post_processing
from scope.runtime.run_context import resolve_account_context, resolve_run_directory
from scope.core.aws import ClientFactory
from scope.core.models import ModuleEnvelope
from scope.core.regions import discover_regions
from scope.runtime.targets import (
    TargetParseError,
    TargetScope,
    build_scope_metadata,
    filter_module_envelopes_for_targets,
    parse_targets,
    read_target_file,
    required_work_items_for_targets,
)


ALL_MODULES = [
    "apigateway",
    "bedrock",
    "codebuild",
    "cognito",
    "dynamodb",
    "ec2",
    "iam",
    "kms",
    "lambda",
    "rds",
    "s3",
    "secrets",
    "sns",
    "sqs",
    "ssm",
    "sts",
]
GLOBAL_MODULES = {"iam", "sts"}
ACCOUNT_SCOPED_MODULES = {"s3"}
REGIONAL_MODULES = set(ALL_MODULES) - GLOBAL_MODULES - ACCOUNT_SCOPED_MODULES
REGION_COMPONENT_PATTERN = re.compile(r"^[a-z]{2}-[a-z-]+-[0-9]+$")


@dataclass(frozen=True)
class WorkItem:
    module: str
    region: str
    enum_run_dir: Path
    output_path: Path
    log_path: Path
    execution_region: str | None = None


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.concurrency < 1:
        raise SystemExit("--concurrency must be >= 1")

    try:
        scope_mode, target_scopes, modules, regions = _requested_scope(args)
    except TargetParseError as err:
        raise SystemExit(str(err)) from err

    started_at = _now_utc()
    account_probe = ClientFactory(region="us-east-1", profile=args.profile)
    account = resolve_account_context(account_probe.account_id)
    try:
        run_dir, run_id = resolve_run_directory(
            account,
            started_at,
            run_dir=Path(args.run_dir) if args.run_dir else None,
            output_dir=Path(args.output_dir) if args.output_dir else None,
        )
    except FileExistsError as err:
        raise SystemExit(str(err)) from err

    try:
        run_dir.mkdir(parents=True)
    except FileExistsError as err:
        raise SystemExit(f"Run directory already exists: {run_dir}") from err
    (run_dir / "logs").mkdir()
    (run_dir / "modules").mkdir()

    explicit_pairs = required_work_items_for_targets(target_scopes) if scope_mode == "target" else None
    items = _build_work_items(
        run_dir=run_dir,
        modules=modules,
        regions=regions,
        explicit_pairs=explicit_pairs,
    )
    scope = build_scope_metadata(mode=scope_mode, targets=target_scopes)
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
        "scope": scope,
        "concurrency": args.concurrency,
        "status": "running",
    }
    _write_manifest(run_dir / "manifest.json", manifest)

    failed_items = _run_work_items(items, profile=args.profile, concurrency=args.concurrency)
    target_results = _apply_target_filter(run_dir, items, target_scopes) if scope_mode == "target" else []
    summary = aggregate_run(
        run_dir,
        run_id=run_id,
        account=account,
        failed_work_items=failed_items,
        scope=scope,
    )
    if scope_mode == "target":
        summary["target_results"] = target_results
        summary["status"] = _derive_target_run_status(summary["status"], target_results)
        (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
        manifest["post_processing_error"] = {
            "error": type(err).__name__,
            "message": str(err),
        }
        _write_manifest(run_dir / "manifest.json", manifest)
        print(run_dir)
        return 1
    manifest["finished_at"] = _iso(_now_utc())
    manifest["status"] = summary["status"]
    _write_manifest(run_dir / "manifest.json", manifest)
    print(run_dir)
    return 0 if summary["status"] == "complete" else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scope audit")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true")
    group.add_argument("--services")
    group.add_argument("--target")
    group.add_argument("--target-file")
    parser.add_argument("--regions")
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--run-dir")
    output_group.add_argument("--output-dir")
    parser.add_argument("--dashboard-export", action="store_true")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--profile", default=None)
    return parser


def _regions(args: argparse.Namespace, modules: list[str]) -> list[str]:
    if args.regions:
        return _validate_regions(_split_csv(args.regions))
    if not _needs_region_discovery(modules):
        return []
    factory = ClientFactory(region="us-east-1", profile=args.profile)
    return _validate_regions(discover_regions(factory.client("ec2")))


def _requested_scope(args: argparse.Namespace) -> tuple[str, list[TargetScope], list[str], list[str]]:
    if args.target:
        targets = parse_targets([args.target])
        pairs = required_work_items_for_targets(targets)
        return "target", targets, _ordered_unique([module for module, _region in pairs]), _regional_regions(pairs)

    if args.target_file:
        targets = read_target_file(Path(args.target_file))
        pairs = required_work_items_for_targets(targets)
        return "target", targets, _ordered_unique([module for module, _region in pairs]), _regional_regions(pairs)

    if args.all:
        modules = list(ALL_MODULES)
        return "all", [], modules, _regions(args, modules)

    modules = _validate_modules(_split_csv(args.services))
    if not modules:
        raise SystemExit("--all or --services is required")
    return "service", [], modules, _regions(args, modules)


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _ordered_unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _regional_regions(pairs: list[tuple[str, str]]) -> list[str]:
    return _ordered_unique([region for _module, region in pairs if region != "global"])


def _validate_modules(modules: list[str]) -> list[str]:
    seen: set[str] = set()
    for module in modules:
        if module not in ALL_MODULES:
            raise SystemExit(f"Unknown service: {module}")
        if module in seen:
            raise SystemExit(f"Duplicate service: {module}")
        seen.add(module)
    return modules


def _validate_regions(regions: list[str]) -> list[str]:
    seen: set[str] = set()
    for region in regions:
        if not REGION_COMPONENT_PATTERN.fullmatch(region):
            raise SystemExit(f"Invalid region: {region}")
        if region in seen:
            raise SystemExit(f"Duplicate region: {region}")
        seen.add(region)
    return regions


def _needs_region_discovery(modules: list[str]) -> bool:
    return any(module not in GLOBAL_MODULES and module not in ACCOUNT_SCOPED_MODULES for module in modules)


def _module_region_path(run_dir: Path, module: str, region: str) -> Path:
    return run_dir / "modules" / module / f"{region}.json"


def _module_regions(module: str, regions: list[str]) -> list[str]:
    if module in GLOBAL_MODULES or module in ACCOUNT_SCOPED_MODULES:
        return ["global"]
    return regions


def _build_work_items(
    run_dir: Path,
    modules: list[str],
    regions: list[str],
    explicit_pairs: list[tuple[str, str]] | None = None,
) -> list[WorkItem]:
    items: list[WorkItem] = []
    if explicit_pairs is not None:
        pairs = _validate_explicit_pairs(explicit_pairs)
    else:
        modules = _validate_modules(modules)
        regions = _validate_regions(regions)
        pairs = [
            (module, region)
            for module in modules
            for region in _module_regions(module, regions)
        ]
    for module, region in pairs:
        items.append(
            WorkItem(
                module=module,
                region=region,
                enum_run_dir=run_dir / ".module-runs" / module / region,
                output_path=_module_region_path(run_dir, module, region),
                log_path=run_dir / "logs" / f"{module}-{region}.log",
                execution_region=_execution_region(module, region),
            )
        )
    return items


def _validate_explicit_pairs(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    validated: list[tuple[str, str]] = []
    for module, region in pairs:
        if module not in ALL_MODULES:
            raise SystemExit(f"Unknown service: {module}")
        if region != "global":
            _validate_regions([region])
        pair = (module, region)
        if pair in seen:
            raise SystemExit(f"Duplicate work item: {module}/{region}")
        seen.add(pair)
        validated.append((module, region))
    return validated


def _execution_region(module: str, region: str) -> str:
    if module == "s3" and region == "global":
        return "us-east-1"
    return region


def _write_manifest(path: Path, manifest: dict) -> None:
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _apply_target_filter(
    run_dir: Path,
    items: list[WorkItem],
    targets: list[TargetScope],
) -> list[dict[str, str]]:
    envelopes: dict[tuple[str, str], dict] = {}
    for item in items:
        if not item.output_path.exists():
            continue
        envelopes[(item.module, item.region)] = json.loads(item.output_path.read_text(encoding="utf-8"))

    filtered, target_results = filter_module_envelopes_for_targets(envelopes, targets)
    for (module, region), payload in filtered.items():
        path = _module_region_path(run_dir, module, region)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target_results


def _derive_target_run_status(summary_status: str, target_results: list[dict[str, str]]) -> str:
    if not target_results:
        return summary_status
    resolved_count = sum(1 for result in target_results if result.get("status") == "resolved")
    if resolved_count == len(target_results):
        return "complete" if summary_status == "complete" else summary_status
    if resolved_count == 0:
        return "error"
    return "partial"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _run_work_item(item: WorkItem, profile: str | None) -> dict:
    item.enum_run_dir.mkdir(parents=True, exist_ok=True)
    item.log_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "scope",
        "enum",
        item.module,
        "--run-dir",
        str(item.enum_run_dir),
        "--region",
        item.execution_region or item.region,
        "--logical-region",
        item.region,
    ]
    if profile:
        command.extend(["--profile", profile])
    returncode = _run_command(command, item.log_path)
    envelope_path = item.enum_run_dir / f"{item.module}.json"
    result = {
        "module": item.module,
        "region": item.region,
        "returncode": returncode,
        "envelope_path": envelope_path,
        "output_path": item.output_path,
    }
    if returncode != 0:
        result["error"] = "command_failed"
    return result


def _run_work_items(items: list[WorkItem], *, profile: str | None, concurrency: int) -> list[dict]:
    failed: list[dict] = []
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(_run_work_item, item, profile): item for item in items}
        for future in as_completed(futures):
            item = futures[future]
            try:
                results.append(future.result())
            except Exception as err:
                failed.append(
                    {
                        "module": item.module,
                        "region": item.region,
                        "returncode": None,
                        "error": "worker_exception",
                        "detail": str(err),
                    }
                )

    for result in results:
        if result.get("error"):
            failed.append(_failed_work_item(result))
            continue
        envelope_path = result["envelope_path"]
        if not _valid_envelope(envelope_path, result["module"], result["region"]):
            result["error"] = "invalid_envelope"
            failed.append(_failed_work_item(result))
            continue
        output_path = result["output_path"]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(envelope_path, output_path)
    return failed


def _failed_work_item(result: dict) -> dict:
    return {
        "module": result["module"],
        "region": result["region"],
        "returncode": result["returncode"],
        "error": result["error"],
    }


def _run_command(command: Sequence[str], log_path: Path) -> int:
    with log_path.open("w", encoding="utf-8") as log:
        completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=False)
    return completed.returncode


def _valid_envelope(path: Path, module: str, region: str) -> bool:
    if not path.exists():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        envelope = ModuleEnvelope.model_validate(payload)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError):
        return False
    return envelope.module == module and envelope.region == region
