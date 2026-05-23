# SCOPE Config Directory

This directory contains runtime reference data, installer templates, safety hooks, schemas, and project documentation sources.

## Keep

- `hooks/`: installed by `bin/install.js`; enforces AWS safety, schema validation, SPL linting, artifact checks, and AWS call logging.
- `schemas/`: canonical JSON contracts for audit, controls, exploit, and module envelope outputs.
- `settings/`: platform hook and MCP templates consumed by `bin/install.js`.
- `scps/`: optional organization SCP context read by audit, controls policy, and verification flows.
- `project-docs/PROJECT.md`: source for generated `CLAUDE.md`, `GEMINI.md`, and `AGENTS.md`.
- `project-docs/LLM-CONTEXT.md`: current reviewer and implementation-agent orientation.
- `exploit-reasoning-notes.md`: curated expert notes for complex exploit reasoning.
- `hunt-reasoning-notes.md`: curated expert notes for complex hunt reasoning.
- `splunk-patterns.md`: SPL generation and linting guidance.
- `models.json`: installer model routing source.
- `accounts.example.json`, `index.example.json`, `observations.example.md`: operator templates for local configuration.
- `mcp-setup.md`: SIEM MCP setup guidance.

## Historical Project Docs

The remaining files in `project-docs/` are design records and implementation plans. They are useful for understanding why a feature exists, but they are not active implementation instructions. Prefer `LLM-CONTEXT.md`, `ARCHITECTURE.md`, current agents, current skills, schemas, and tests when reviewing or changing code.

Do not execute historical implementation-plan steps without checking current tests and source files first.
