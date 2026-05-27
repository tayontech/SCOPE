---
name: scope-evidence-logging
description: Use when attaching schema-valid SCOPE evidence handles to attack candidates, hops, observations, assumptions, and caveats.
---

# SCOPE Evidence Logging

Use this skill inside `scope-attack-analyze` when populating evidence objects that must pass `scope.attack.schema`.

The valid evidence types: `graph_edge`, `module_resource`, `policy_document`, `runtime_assumption`, `coverage_caveat`.

Represent ARNs through the `arn` field, not as an evidence type. Every evidence object needs at least one of `id`, `source_path`, or `arn`.

## Evidence Handles

- Use `graph_edge` for graph edge IDs from `$RUN_DIR/graph.json`. Put the stable edge ID in `id`, and include `source_path` when the graph edge cites a module file.
- Use `module_resource` for module files/resources under `$RUN_DIR/modules/**`. Put the module-relative file path in `source_path`, the resource identifier in `id` when available, and the resource ARN in `arn` when present.
- Use `policy_document` for IAM, trust, permission boundary, and resource policy documents stored in runtime artifacts. Put a stable policy, statement, or resource handle in `id`; include `source_path` and `field` when the document came from a module resource field.
- Use `runtime_assumption` only when the path depends on behavior the run artifacts cannot prove, such as attacker control of a federated subject or an event payload. Put a stable assumption handle in `id` or cite the related `arn`.
- Use `coverage_caveat` when module status, coverage check, or field status leaves part of a hop unknown. Cite the module file with `source_path`; include `field` for the specific coverage or resource field status when known.

## Rules

- No placeholders.
- No nonexistent file paths.
- Do not invent IDs from files the run did not produce.
- Do not use `arn` as an evidence type.
- Prefer graph edge `id` plus module `source_path` when a graph relationship supports a hop.
- Cite the smallest useful handle: edge ID for relationships, module resource for resource facts, policy document for policy statements, runtime assumption for unobserved behavior, coverage caveat for known collection gaps.
