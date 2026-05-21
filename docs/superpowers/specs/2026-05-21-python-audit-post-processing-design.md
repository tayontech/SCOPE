# Python Audit Post-Processing Design

## Goal

Make `scope_runtime audit` the source of truth for audit orchestration after enumeration. A completed Python audit run should produce stable machine-readable artifacts that downstream agents, dashboard code, and future relationship builders can consume without rediscovering module layout or carrying raw enum state around.

## Current State

Python enumeration now writes module envelopes under:

```text
<run_dir>/modules/<service>/<region>.json
```

The audit CLI also writes:

```text
manifest.json
summary.json
resources.jsonl
```

`bin/extract-graph.js` can read the new nested module layout, but graph creation is still a separate manual command. The agent prompts have been partially updated to understand nested module files, but the broader pipeline still treats agents as orchestration glue in places. That keeps old assumptions alive and makes dashboard/report generation depend on agent behavior.

## Decision

Build a Python post-processing layer inside `scope_runtime audit`.

The audit CLI should:

1. Run enumerators.
2. Aggregate module resources.
3. Build `graph.json`.
4. Write a dashboard/agent-ready `results.json`.
5. Optionally export dashboard public data.

Agents should consume those artifacts. They should not decide where module files live, reconstruct run metadata, or infer service completion from filesystem conventions.

## Artifact Contract

Every non-skipped audit run should produce:

```text
manifest.json
summary.json
resources.jsonl
graph.json
results.json
modules/<service>/<region>.json
```

### `manifest.json`

Run metadata:

- `run_id`
- start/end timestamps
- `account_id`
- `account_name`
- `account_owned`
- requested services/regions
- concurrency
- final status

### `summary.json`

Enumeration rollup:

- valid/failed module counts
- total resources
- total errors
- total skipped checks
- per-service resource/error/skipped/status counts
- module output paths
- failed work items

### `resources.jsonl`

One resource per line with normalized context fields:

- `run_id`
- `account_id`
- `account_name`
- `account_owned`
- `service`
- `region`
- `source_path`
- original resource fields

This remains the flat inventory substrate for future relationship building and simple analytics.

### `graph.json`

Deterministic graph shape:

```json
{
  "nodes": [],
  "edges": []
}
```

For this slice, graph building can continue to call the existing `bin/extract-graph.js` implementation from Python. A later slice can port graph construction to Python once relationship semantics settle.

Failure to build `graph.json` should not invalidate enumeration. The audit status remains based on enumeration status, and graph failure is recorded in `results.json.post_processing.errors`.

### `results.json`

Dashboard/agent-ready audit envelope:

```json
{
  "source": "audit",
  "run_id": "...",
  "account_id": "...",
  "account_name": null,
  "account_owned": false,
  "region": "global",
  "timestamp": "2026-05-21T00:31:47Z",
  "status": "complete",
  "summary": {
    "services": {},
    "total_resources": 0,
    "total_errors": 0,
    "total_skipped": 0,
    "severity": "low"
  },
  "graph": {
    "nodes": [],
    "edges": []
  },
  "resources": {
    "jsonl": "resources.jsonl",
    "count": 0
  },
  "modules": [],
  "attack_paths": [],
  "principals": [],
  "trust_relationships": [],
  "coverage_gaps": [],
  "post_processing": {
    "errors": []
  }
}
```

`attack_paths` starts empty in this CLI slice. Attack-path agents can later read `results.json`, append/replace attack-path content, and preserve the same outer envelope.

## Dashboard Export

Add an explicit audit option:

```bash
uv run python -m scope_runtime audit ... --dashboard-export
```

When enabled, the CLI copies `results.json` to:

```text
dashboard/public/<run_id>.json
```

and upserts:

```text
dashboard/public/index.json
```

with:

- `run_id`
- `date`
- `source: "audit"`
- `target`
- `risk`
- `status`
- `file`

Dashboard HTML generation remains separate for now:

```bash
RUN_DIR=<run_dir> npm --prefix dashboard run dashboard
```

Reason: dashboard generation invokes Node/Vite and is heavier than audit post-processing. The CLI should make dashboard data available first; generating the portable HTML can remain an explicit follow-up until the dashboard is redesigned.

## Agent Boundary

After this change, agents should treat the run directory as a stable API:

- Prefer `results.json` for run metadata, summary, graph, and future attack paths.
- Prefer `resources.jsonl` for inventory-wide scans.
- Read `modules/<service>/<region>.json` only for service-specific details.
- Do not infer completed services by checking top-level `<service>.json`.
- Do not reconstruct graph from raw modules if `graph.json` exists.

This reduces agent responsibility to reasoning, reporting, and enrichment.

## Error Handling

Post-processing failures are non-destructive:

- If graph extraction fails, write `results.json` with an empty graph and a post-processing error.
- If dashboard export fails, leave run artifacts intact and return nonzero only if enumeration itself failed.
- If `results.json` cannot be written, audit should return nonzero because downstream handoff is broken.

## Testing

Add Python tests for:

- `graph.json` is written from nested module files.
- `results.json` includes summary, graph, modules, resources pointer, and empty attack paths.
- graph extraction failure records an error but preserves enumeration status.
- dashboard export writes `dashboard/public/<run_id>.json`.
- dashboard export upserts `dashboard/public/index.json` deterministically.

Keep existing JS graph tests. They protect the current graph builder until it is ported to Python.

## Out Of Scope

- Rebuilding the dashboard UI.
- Porting `bin/extract-graph.js` to Python.
- Relationship builder semantics beyond the existing graph output.
- Attack-path generation inside Python.
- Defend/synthesizer rewrites.

Those are follow-up slices after the Python audit handoff is stable.
