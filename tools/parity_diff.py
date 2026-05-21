from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _finding_sort_key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(finding.get("resource_type", "")),
        str(finding.get("resource_id", "")),
        str(finding.get("arn", "")),
        _canonical_json(finding),
    )


def _coverage_sort_key(entry: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(entry.get("check", "")),
        str(entry.get("scope", "")),
        str(entry.get("status", "")),
        _canonical_json(entry),
    )


def _error_sort_key(error: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(error.get("operation", "")),
        str(error.get("resource", "")),
        str(error.get("code", "")),
        str(error.get("message", "")),
        _canonical_json(error),
    )


def normalize_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    normalized = json.loads(json.dumps(envelope, sort_keys=True))
    normalized.pop("timestamp", None)
    if isinstance(normalized.get("resources"), list):
        normalized["resources"] = sorted(normalized["resources"], key=_finding_sort_key)
    if isinstance(normalized.get("coverage"), list):
        normalized["coverage"] = sorted(normalized["coverage"], key=_coverage_sort_key)
    if isinstance(normalized.get("errors"), list):
        normalized["errors"] = sorted(normalized["errors"], key=_error_sort_key)
    return normalized


def diff_envelopes(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    normalized_left = normalize_envelope(left)
    normalized_right = normalize_envelope(right)
    return {
        "equal": normalized_left == normalized_right,
        "left": normalized_left,
        "right": normalized_right,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.parity_diff")
    parser.add_argument("left")
    parser.add_argument("right")
    args = parser.parse_args(argv)

    left = json.loads(Path(args.left).read_text(encoding="utf-8"))
    right = json.loads(Path(args.right).read_text(encoding="utf-8"))
    diff = diff_envelopes(left, right)
    print(json.dumps(diff, indent=2))
    return 0 if diff["equal"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
