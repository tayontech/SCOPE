from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class JsonlLogger:
    def __init__(self, run_dir: str | Path, module: str | None = None):
        self.run_dir = Path(run_dir)
        self.module = module
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.run_dir / "agent-log.jsonl"

    def log(self, record_type: str, action: str, details: dict[str, Any] | None = None) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "type": record_type,
            "module": self.module,
            "action": action,
            "details": details or {},
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str, separators=(",", ":")) + "\n")

    def flush(self) -> None:
        return None
