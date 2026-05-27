from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
HOOK = ROOT / "config/hooks/scope-spl-lint.sh"


def run_hook(file_path: Path, body: str) -> subprocess.CompletedProcess[str]:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(body)
    hook_input = json.dumps(
        {
            "tool_name": "Write",
            "tool_input": {"file_path": str(file_path)},
        }
    )
    return subprocess.run(
        ["bash", str(HOOK)],
        input=hook_input,
        text=True,
        capture_output=True,
        check=False,
    )


def parse_decision(stdout: str) -> dict[str, Any] | None:
    if not stdout.strip():
        return None
    return json.loads(stdout)


def assert_blocked(result: subprocess.CompletedProcess[str], expected: str) -> None:
    assert result.returncode == 0, result.stderr
    decision = parse_decision(result.stdout)
    assert decision is not None
    assert decision["decision"] == "block"
    assert expected in decision["reason"]


def test_spl_lint_hook_covers_controls_detections_md(tmp_path: Path) -> None:
    result = run_hook(
        tmp_path / "runs/audit-1/controls/controls-1/detections.md",
        """
# SPL Detections

```spl
index=* earliest=-24h latest=now eventName=CreateUser
| stats count by userIdentity.arn
```
""",
    )

    assert_blocked(result, "'index=*' is not allowed")


def test_spl_lint_hook_allows_transaction_and_streamstats_choices(tmp_path: Path) -> None:
    result = run_hook(
        tmp_path / "runs/audit-1/controls/controls-1/detections.json",
        json.dumps(
            [
                {
                    "name": "Composite Design Guidance Only",
                    "spl": "index=cloudtrail earliest=-1h latest=now [COMPOSITE] eventName=CreateUser | transaction userIdentity.arn",
                }
            ]
        ),
    )

    assert result.returncode == 0, result.stderr
    assert parse_decision(result.stdout) is None


def test_spl_lint_hook_ignores_unrelated_files(tmp_path: Path) -> None:
    result = run_hook(
        tmp_path / "notes.md",
        "index=*",
    )

    assert result.returncode == 0, result.stderr
    assert parse_decision(result.stdout) is None


def test_spl_lint_hook_blocks_outputlookup_in_detections(tmp_path: Path) -> None:
    result = run_hook(
        tmp_path / "runs/audit-1/controls/controls-1/detections.md",
        """
# SPL Detections

```spl
index=aws_api earliest=-24h latest=now eventName=CreateUser
| stats count by userIdentity.arn
| outputlookup generated_detection_baseline.csv
```
""",
    )

    assert_blocked(result, "'outputlookup' is not allowed")


def test_spl_lint_hook_blocks_expensive_correlation_commands(tmp_path: Path) -> None:
    for command in ["join", "append", "appendcols", "selfjoin", "map"]:
        result = run_hook(
            tmp_path / f"runs/audit-1/controls/controls-1/{command}-detections.md",
            f"""
# SPL Detections

```spl
index=aws_api earliest=-24h latest=now eventName=CreateUser
| {command} userIdentity.arn
```
""",
        )

        assert_blocked(result, "Expensive correlation/fan-out command detected")


def test_spl_lint_hook_blocks_side_effect_commands(tmp_path: Path) -> None:
    for command in ["collect", "mcollect", "tscollect", "outputcsv", "delete", "sendemail", "sendalert", "script", "run"]:
        result = run_hook(
            tmp_path / f"runs/audit-1/controls/controls-1/{command}-detections.md",
            f"""
# SPL Detections

```spl
index=aws_api earliest=-24h latest=now eventName=CreateUser
| {command} generated_target
```
""",
        )

        assert_blocked(result, "Side-effect command detected")


def test_spl_lint_hook_allows_environment_dependent_commands(tmp_path: Path) -> None:
    for command in ["rest", "lookup", "inputlookup", "tstats"]:
        result = run_hook(
            tmp_path / f"runs/audit-1/controls/controls-1/{command}-detections.md",
            f"""
# SPL Detections

```spl
index=aws_api earliest=-24h latest=now eventName=CreateUser
| {command} generated_target
```
""",
        )

        assert result.returncode == 0, result.stderr
        assert parse_decision(result.stdout) is None
