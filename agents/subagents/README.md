# Subagent Source Files

These `.md` files are **platform-agnostic source** — not the runtime agents.

Frontmatter fields like `model: reasoning`, `tools: Bash, Read`, and `maxTurns: 25` are platform-agnostic source directives. The installer transforms them per runtime.

## How deployment works

`uv run python -m scope.install` reads these source files and transforms them per-platform:

| Field | Claude (`.claude/agents/`) | Antigravity (`.agents/plugins/scope/agents/`) | Gemini (`.gemini/agents/`) | Codex (`.codex/agents/`) |
|-------|---------------------------|------------------------------------------------|---------------------------|--------------------------|
| `model: reasoning` | Resolves to `opus[1m]` | Stripped; Antigravity runtime model selector owns model choice | Resolves to `pro` | Resolves to `gpt-5.5` in TOML |
| `tools: Bash, Read` | Kept | Replaced with Gemini-compatible tool names | Replaced with `run_shell_command`, `read_file`, etc. | Stripped from Markdown; TOML owns runtime config |
| `maxTurns: 25` | Kept if present | Replaced with `max_turns` from installer defaults | Replaced with `max_turns` from installer defaults | Stripped |

## Edit here, deploy with install

1. Edit files in this directory
2. Run `uv run python -m scope.install --all --local` to deploy to all platforms
3. Platform-specific agents appear in `.claude/agents/`, `.agents/plugins/scope/agents/`, `.gemini/agents/`, and `.codex/agents/`

## Controls subagents

`scope-controls` dispatches six controls subagents. Five Wave 1 producers write org-wide issues, detections, monitoring dashboard ideas, policy replacements, and remediation artifacts before `scope-controls-validate` reviews them.

- `scope-controls-dashboards` - monitoring dashboard ideas for security-relevant conditions that should be watched over time instead of promoted directly to detections.
