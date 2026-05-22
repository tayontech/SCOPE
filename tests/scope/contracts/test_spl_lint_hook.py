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


def test_spl_lint_hook_covers_controls_detections_json(tmp_path: Path) -> None:
    result = run_hook(
        tmp_path / "runs/audit-1/controls/controls-1/detections.json",
        json.dumps(
            [
                {
                    "name": "Bad Composite",
                    "spl": "index=cloudtrail earliest=-1h latest=now [COMPOSITE] eventName=CreateUser | transaction userIdentity.arn",
                }
            ]
        ),
    )

    assert_blocked(result, "Composite detection uses 'transaction'")


def test_spl_lint_hook_ignores_unrelated_files(tmp_path: Path) -> None:
    result = run_hook(
        tmp_path / "notes.md",
        "index=*",
    )

    assert result.returncode == 0, result.stderr
    assert parse_decision(result.stdout) is None
