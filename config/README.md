# SCOPE Config Directory

This directory contains runtime contracts, installer templates, safety hooks, settings, schemas, and the installed project instruction source. Durable learned and expert context lives in `knowledge/`.

## Keep

- `hooks/`: installed by `uv run python -m scope.install`; enforces AWS safety, schema validation, SPL linting, artifact checks, and AWS call logging.
- `schemas/`: canonical JSON contracts for audit, controls, exploit, and module envelope outputs.
- `settings/`: platform hook and MCP templates consumed by `uv run python -m scope.install`.
- `project-docs/PROJECT.md`: source for generated `CLAUDE.md`, `GEMINI.md`, and `AGENTS.md`.
- `splunk-patterns.md`: SPL generation and linting guidance.
- `models.json`: installer model routing source for Claude, Gemini, and Codex reasoning/inherit behavior. Top-level agents inherit the active session model. It does not define enumeration models because AWS enumeration runs through deterministic Python, and it does not pin Antigravity because Antigravity has its own model selector.
- `accounts.example.json`: operator template for local account selection.
- `mcp-setup.md`: SIEM MCP setup guidance.

## Durable Knowledge

Curated reasoning notes, durable observations, coverage gaps, and stable environment context belong in `knowledge/`. Agents load that context through `skills/scope-knowledge-load/SKILL.md`.

## Project Docs

`config/project-docs/` intentionally contains only `PROJECT.md`, the installer source for platform instruction files. Reviewer context lives in `docs/LLM-CONTEXT.md`. Detailed implementation blueprints and private planning notes stay out of the committed documentation surface.

## Platform Install Notes

Antigravity CLI is the preferred Google target. Workspace installs use `.agents/skills/`, `.agents/hooks.json`, `.agents/mcp_config.json`, and `.agents/plugins/scope/agents/`.

Gemini CLI and Codex also share `.agents/skills/` for installed SCOPE skills. Gemini's `.gemini/skills/` path is legacy for SCOPE installs; the installer warns when stale SCOPE skills remain there. Gemini support remains for enterprise/API-key users and migration compatibility after Google's June 18, 2026 consumer transition to Antigravity CLI.
