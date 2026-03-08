# Subagent Source Files

These `.md` files are **platform-agnostic source** — not the runtime agents.

Frontmatter fields like `model: haiku`, `tools: Bash, Read`, and `maxTurns: 25` are **Claude Code directives**. They do not apply to Gemini or Codex.

## How deployment works

`bin/install.js` reads these source files and transforms them per-platform:

| Field | Claude (`.claude/agents/`) | Gemini (`.gemini/agents/`) | Codex (`.codex/agents/`) |
|-------|---------------------------|---------------------------|--------------------------|
| `model: haiku` | Kept (routes to Haiku) | Stripped | Stripped |
| `tools: Bash, Read` | Kept | Replaced with `run_shell_command`, `read_file`, etc. | Stripped (via TOML) |
| `maxTurns: 25` | Kept | Replaced with `max_turns: 50` | Stripped |

## Edit here, deploy with install

1. Edit files in this directory
2. Run `node bin/install.js --local` to deploy to all platforms
3. Platform-specific agents appear in `.claude/agents/`, `.gemini/agents/`, `.codex/agents/`
