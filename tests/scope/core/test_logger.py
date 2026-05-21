import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from scope.core.logger import JsonlLogger


def test_jsonl_logger_serializes_non_json_details(tmp_path: Path):
    logger = JsonlLogger(tmp_path, module="sts")

    logger.log(
        "event",
        "serialize",
        {
            "path": tmp_path / "sts.json",
            "time": datetime(2026, 5, 18, 12, 0, tzinfo=timezone.utc),
            "amount": Decimal("1.23"),
        },
    )

    payload = json.loads((tmp_path / "agent-log.jsonl").read_text(encoding="utf-8"))

    assert payload["details"]["path"] == str(tmp_path / "sts.json")
    assert payload["details"]["time"] == "2026-05-18 12:00:00+00:00"
    assert payload["details"]["amount"] == "1.23"
