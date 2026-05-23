# SCOPE Config Directory

This directory contains runtime contracts, installer templates, safety hooks, settings, schemas, and project documentation sources. Durable learned and expert context lives in `knowledge/`.

## Keep

- `hooks/`: installed by `bin/install.js`; enforces AWS safety, schema validation, SPL linting, artifact checks, and AWS call logging.
- `schemas/`: canonical JSON contracts for audit, controls, exploit, and module envelope outputs.
- `settings/`: platform hook and MCP templates consumed by `bin/install.js`.
- `scps/`: optional organization SCP context read by audit, controls policy, and verification flows.
- `project-docs/PROJECT.md`: source for generated `CLAUDE.md`, `GEMINI.md`, and `AGENTS.md`.
- `project-docs/LLM-CONTEXT.md`: current reviewer and implementation-agent orientation.
- `splunk-patterns.md`: SPL generation and linting guidance.
- `models.json`: installer model routing source.
- `accounts.example.json`, `index.example.json`: operator templates for local configuration.
- `mcp-setup.md`: SIEM MCP setup guidance.

## Durable Knowledge

Curated reasoning notes, durable observations, coverage gaps, and stable environment context belong in `knowledge/`. Agents load that context through `skills/scope-knowledge-load/SKILL.md`.

## Historical Project Docs

The remaining files in `project-docs/` are design records and implementation plans. They are useful for understanding why a feature exists, but they are not active implementation instructions. Prefer `LLM-CONTEXT.md`, `ARCHITECTURE.md`, current agents, current skills, schemas, and tests when reviewing or changing code.

Do not execute historical implementation-plan steps without checking current tests and source files first.
