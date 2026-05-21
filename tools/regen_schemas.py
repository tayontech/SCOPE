from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scope_core.models import ModuleEnvelope  # noqa: E402


MODULE_SCHEMA = ROOT / "config" / "schemas" / "module-envelope.schema.json"


def generate_module_schema() -> dict:
    schema = ModuleEnvelope.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "scope-module-envelope"
    schema["title"] = "SCOPE Module Output Envelope"
    schema["required"] = ["module", "account_id", "region", "timestamp", "status", "resources"]
    schema["properties"]["account_id"] = {
        "oneOf": [
            {"type": "string", "pattern": "^\\d{12}$"},
            {"const": "unknown"},
        ],
        "description": (
            "12-digit AWS account ID, or 'unknown' when status is 'error' "
            "(pre-STS crash). The 'unknown' case is enforced by runtime "
            "validation and the validation hook."
        ),
    }
    schema["description"] = (
        "Shared envelope for all per-module enumeration output files. "
        "Validated by scope-schema-validate.sh hook."
    )
    return schema


def render_schema() -> str:
    return json.dumps(generate_module_schema(), indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.regen_schemas")
    parser.add_argument("--write", action="store_true", help="overwrite config/schemas/module-envelope.schema.json")
    args = parser.parse_args(argv)

    rendered = render_schema()
    if args.write:
        MODULE_SCHEMA.write_text(rendered, encoding="utf-8")
        print(f"wrote {MODULE_SCHEMA}")
        return 0

    existing = MODULE_SCHEMA.read_text(encoding="utf-8")
    if existing != rendered:
        print("module-envelope schema drift detected; run python -m tools.regen_schemas --write", file=sys.stderr)
        return 1

    print("module-envelope schema is up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
