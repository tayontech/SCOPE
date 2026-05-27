from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MODELS_CONFIG_PATH = REPO_ROOT / "config" / "models.json"

INSTALLABLE_AGENTS = {
    "scope-audit",
    "scope-controls",
    "scope-exploit",
    "scope-investigate",
}

TOP_LEVEL_SUBAGENTS = {
    "scope-controls",
}

EDITOR_DIRS = {
    "claude": {
        "global": Path.home() / ".claude" / "skills",
        "local": Path.cwd() / ".claude" / "skills",
    },
    "gemini": {
        "global": Path.home() / ".agents" / "skills",
        "local": Path.cwd() / ".agents" / "skills",
    },
    "antigravity": {
        "global": Path.home() / ".gemini" / "antigravity-cli" / "skills",
        "local": Path.cwd() / ".agents" / "skills",
    },
    "codex": {
        "global": Path.home() / ".agents" / "skills",
        "local": Path.cwd() / ".agents" / "skills",
    },
}

SKILL_STRIP_KEYS = {"model", "maxTurns", "max_turns", "timeout_mins", "kind"}
GEMINI_STRIP_KEYS = {
    "argument-hint",
    "disable-model-invocation",
    "color",
    "compatibility",
    "memory",
    "context",
    "agent",
    "model",
    "maxTurns",
    "max_turns",
}
GEMINI_SUBAGENT_STRIP_KEYS = {
    "argument-hint",
    "disable-model-invocation",
    "allowed-tools",
    "tools",
    "color",
    "compatibility",
    "memory",
    "context",
    "agent",
    "maxTurns",
}
CODEX_STRIP_KEYS = {
    "argument-hint",
    "color",
    "compatibility",
    "disable-model-invocation",
    "allowed-tools",
    "tools",
    "memory",
    "context",
    "agent",
    "model",
    "maxTurns",
    "max_turns",
}

GEMINI_AGENT_CONFIG = {
    "scope-attack-analyze": {"max_turns": 60, "tools": ["run_shell_command", "read_file", "grep_search", "write_file"]},
    "scope-public-exposure-analysis": {"max_turns": 40, "tools": ["run_shell_command", "read_file", "grep_search", "write_file"]},
    "scope-controls": {"max_turns": 60, "tools": ["run_shell_command", "read_file", "grep_search", "write_file"]},
    "scope-controls-org-wide": {"max_turns": 40, "tools": ["run_shell_command", "read_file", "grep_search", "write_file"]},
    "scope-controls-policy": {"max_turns": 40, "tools": ["run_shell_command", "read_file", "grep_search", "write_file"]},
    "scope-controls-remediation": {"max_turns": 40, "tools": ["run_shell_command", "read_file", "grep_search", "write_file"]},
    "scope-controls-detections": {"max_turns": 40, "tools": ["run_shell_command", "read_file", "grep_search", "write_file"]},
    "scope-controls-dashboards": {"max_turns": 40, "tools": ["run_shell_command", "read_file", "grep_search", "write_file"]},
    "scope-controls-validate": {"max_turns": 40, "tools": ["run_shell_command", "read_file", "grep_search", "write_file"]},
    "scope-investigate-run": {"max_turns": 40, "tools": ["run_shell_command", "read_file", "grep_search", "write_file"]},
    "scope-investigate-intel": {"max_turns": 40, "tools": ["run_shell_command", "read_file", "grep_search", "write_file", "google_web_search", "web_fetch"]},
    "scope-investigate-alert": {"max_turns": 40, "tools": ["run_shell_command", "read_file", "grep_search", "write_file"]},
    "scope-awscli-replay": {"max_turns": 40, "tools": ["read_file", "grep_search", "google_web_search", "web_fetch"]},
    "scope-research": {"max_turns": 40, "tools": ["run_shell_command", "read_file", "grep_search", "google_web_search", "web_fetch"]},
    "scope-verify": {"max_turns": 30, "tools": ["run_shell_command", "read_file", "grep_search", "write_file", "google_web_search", "web_fetch"]},
}


@dataclass
class MarkdownSource:
    name: str
    content: str


@dataclass
class Frontmatter:
    frontmatter: dict[str, str]
    body: str


def _models_config() -> dict[str, dict[str, str]]:
    try:
        return json.loads(MODELS_CONFIG_PATH.read_text())
    except Exception as exc:
        raise SystemExit(f"Error: config/models.json not found or invalid JSON.\n  Path: {MODELS_CONFIG_PATH}\n  {exc}") from exc


def parse_frontmatter(content: str) -> Frontmatter | None:
    if not content.startswith("---"):
        return None
    first_end = content.find("\n---", 3)
    if first_end == -1:
        return None

    raw = content[4:first_end]
    body = content[first_end + 4 :]
    if body.startswith("\n"):
        body = body[1:]

    frontmatter: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key:
            frontmatter[key] = value
    return Frontmatter(frontmatter=frontmatter, body=body)


def rebuild_frontmatter(frontmatter: dict[str, str], omit_keys: set[str] | list[str]) -> str:
    omit = set(omit_keys)
    lines: list[str] = []
    for key, value in frontmatter.items():
        if key in omit:
            continue
        needs_quoting = ": " in value or " #" in value or re.match(r"^[#[{>|]", value) is not None
        if needs_quoting:
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'{key}: "{escaped}"')
        else:
            lines.append(f"{key}: {value}")
    return "\n".join(lines)


def resolve_includes(content: str, repo_root: Path = REPO_ROOT) -> str:
    directives = list(re.finditer(r"^@include\s+(\S+)$", content, re.MULTILINE))
    if not directives:
        return content

    expanded = content
    for directive in directives:
        include_path = repo_root / directive.group(1)
        if not include_path.exists():
            raise SystemExit(f"Error: @include references missing file: {include_path}")
        included = include_path.read_text()
        if re.search(r"^@include\s+\S+$", included, re.MULTILINE):
            raise SystemExit(f"Error: @include nesting not allowed. File {include_path} contains @include directives.")
        expanded = expanded.replace(directive.group(0), included.rstrip())

    if re.search(r"^@include\s+\S+$", expanded, re.MULTILINE):
        raise SystemExit("Error: Unresolved @include directive remains after expansion. Check for edge cases.")
    return expanded


def resolve_model_tier(model_value: str | None, platform: str) -> str | None:
    if not model_value:
        return None
    config = _models_config()
    if model_value in {"reasoning", "inherit"}:
        if model_value == "inherit":
            return None
        resolved = config.get(platform, {}).get(model_value)
        if not resolved:
            raise SystemExit(f"Error: config/models.json missing key [{platform}][{model_value}]")
        return resolved

    for tiers in config.values():
        for tier, model in tiers.items():
            if model == model_value and tier != "inherit":
                resolved = config.get(platform, {}).get(tier)
                if resolved:
                    return resolved
    return model_value


def display_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~")
    except Exception:
        return str(path)


def write_skill(skill_name: str, content: str, target_dir: Path, omit_keys: set[str] | list[str]) -> Path | None:
    parsed = parse_frontmatter(content)
    if parsed:
        fm = rebuild_frontmatter(parsed.frontmatter, omit_keys)
        content = f"---\n{fm}\n---\n\n{parsed.body}"
    else:
        return None

    dest = target_dir / skill_name
    dest.mkdir(parents=True, exist_ok=True)
    dest_file = dest / "SKILL.md"
    dest_file.write_text(content)
    return dest_file


def discover_agents(agents_dir: Path) -> list[MarkdownSource]:
    if not agents_dir.exists():
        raise SystemExit("Error: agents/ directory not found. Run this command from the SCOPE repo root.")

    agents: list[MarkdownSource] = []
    skipped: list[str] = []
    for path in sorted(agents_dir.glob("*.md")):
        content = path.read_text()
        parsed = parse_frontmatter(content)
        if not parsed or not parsed.frontmatter.get("name"):
            print(f"  WARN: Skipping {path.name} - no frontmatter or missing name field")
            continue
        name = path.stem
        if name not in INSTALLABLE_AGENTS:
            skipped.append(name)
            continue
        agents.append(MarkdownSource(name=name, content=content))

    if skipped:
        as_subagents = [name for name in skipped if name in TOP_LEVEL_SUBAGENTS]
        truly_skipped = [name for name in skipped if name not in TOP_LEVEL_SUBAGENTS]
        if as_subagents:
            print(f"Skipped {len(as_subagents)} agent(s) from skills (will be deployed as subagents): {', '.join(as_subagents)}")
        if truly_skipped:
            print(f"Skipped {len(truly_skipped)} inline-only agent(s): {', '.join(truly_skipped)}")
    return agents


def discover_subagents(subagents_dir: Path) -> list[MarkdownSource]:
    subagents: list[MarkdownSource] = []
    if subagents_dir.exists():
        for path in sorted(subagents_dir.glob("*.md")):
            content = path.read_text()
            parsed = parse_frontmatter(content)
            if not parsed or not parsed.frontmatter.get("name"):
                print(f"  WARN: Skipping subagent {path.name} - no frontmatter or missing name field")
                continue
            subagents.append(MarkdownSource(name=path.stem, content=content))

    agents_dir = subagents_dir.parent
    for name in sorted(TOP_LEVEL_SUBAGENTS):
        path = agents_dir / f"{name}.md"
        if not path.exists():
            print(f"  WARN: TOP_LEVEL_SUBAGENT {name}.md not found in agents/")
            continue
        subagents.append(MarkdownSource(name=name, content=path.read_text()))
    return subagents


def install_for_editor(editor: str, scope: str, agents: list[MarkdownSource]) -> int:
    target_dir = EDITOR_DIRS[editor][scope]
    count = 0
    for agent in agents:
        parsed = parse_frontmatter(agent.content)
        resolved_content = agent.content
        if parsed:
            expanded_body = resolve_includes(parsed.body)
            fm = rebuild_frontmatter(parsed.frontmatter, [])
            resolved_content = f"---\n{fm}\n---\n\n{expanded_body}"

        if editor == "claude":
            dest_file = write_skill(agent.name, resolved_content, target_dir, SKILL_STRIP_KEYS)
        elif editor in {"gemini", "antigravity"}:
            dest_file = write_skill(agent.name, resolved_content, target_dir, GEMINI_STRIP_KEYS)
        else:
            dest_file = write_skill(agent.name, resolved_content, target_dir, CODEX_STRIP_KEYS)

        if dest_file:
            print(f"  Installing {agent.name} -> {display_path(dest_file)}")
            count += 1

    print(f"Installed {count} agent{'s' if count != 1 else ''} to {editor} ({scope})")
    return count


def prune_stale_subagent_files(agents_dir: Path, installed_names: set[str]) -> int:
    if not agents_dir.exists():
        return 0
    pruned = 0
    for path in agents_dir.glob("*.md"):
        if path.stem not in installed_names:
            path.unlink()
            print(f"  Pruned stale subagent: {display_path(path)}")
            pruned += 1
    if pruned:
        print(f"Pruned {pruned} stale subagent file(s)")
    return pruned


def prune_stale_toml_files(agents_dir: Path, installed_names: set[str]) -> int:
    if not agents_dir.exists():
        return 0
    pruned = 0
    for path in agents_dir.glob("*.toml"):
        if path.stem not in installed_names:
            path.unlink()
            print(f"  Pruned stale Codex config layer: {display_path(path)}")
            pruned += 1
    if pruned:
        print(f"Pruned {pruned} stale Codex .toml file(s)")
    return pruned


def subagent_target_dir(editor: str, scope: str) -> Path:
    base = Path.home() if scope == "global" else Path.cwd()
    if editor == "claude":
        return base / ".claude" / "agents"
    if editor == "gemini":
        return base / ".gemini" / "agents"
    if editor == "antigravity":
        return base / ".agents" / "plugins" / "scope" / "agents"
    return base / ".codex" / "agents"


def install_subagents_claude(subagents: list[MarkdownSource], scope: str) -> int:
    agents_dir = subagent_target_dir("claude", scope)
    agents_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for subagent in subagents:
        parsed = parse_frontmatter(subagent.content)
        content = subagent.content
        if parsed:
            original_model = parsed.frontmatter.get("model")
            include_count = len(re.findall(r"^@include\s+\S+$", parsed.body, re.MULTILINE))
            body = resolve_includes(parsed.body)
            resolved_model = resolve_model_tier(parsed.frontmatter.get("model"), "claude")
            omit_keys: set[str] = set()
            if resolved_model is None:
                omit_keys.add("model")
            else:
                parsed.frontmatter["model"] = resolved_model
            fm = rebuild_frontmatter(parsed.frontmatter, omit_keys)
            content = f"---\n{fm}\n---\n\n{body}"
            print(f"    [{subagent.name}] includes={include_count} tier={original_model or 'inherit'}->{resolved_model or 'inherit'} chars={len(content)}")
        dest = agents_dir / f"{subagent.name}.md"
        dest.write_text(content)
        print(f"  Installing subagent {subagent.name} -> {display_path(dest)}")
        count += 1
    print(f"Installed {count} subagent{'s' if count != 1 else ''} to claude ({scope})")
    return count


def install_subagents_gemini(subagents: list[MarkdownSource], scope: str) -> int:
    agents_dir = subagent_target_dir("gemini", scope)
    agents_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for subagent in subagents:
        parsed = parse_frontmatter(subagent.content)
        content = subagent.content
        if parsed:
            original_model = parsed.frontmatter.get("model")
            include_count = len(re.findall(r"^@include\s+\S+$", parsed.body, re.MULTILINE))
            body = resolve_includes(parsed.body)
            config = GEMINI_AGENT_CONFIG.get(subagent.name)
            if config:
                parsed.frontmatter["max_turns"] = str(config["max_turns"])
            resolved_model = resolve_model_tier(parsed.frontmatter.get("model"), "gemini")
            omit_keys = set(GEMINI_SUBAGENT_STRIP_KEYS)
            if resolved_model is not None:
                parsed.frontmatter["model"] = resolved_model
            else:
                omit_keys.add("model")
            fm = rebuild_frontmatter(parsed.frontmatter, omit_keys)
            tools_yaml = ""
            if config and config.get("tools"):
                tools_yaml = "\ntools:\n" + "\n".join(f"  - {tool}" for tool in config["tools"])
            content = f"---\n{fm}{tools_yaml}\n---\n\n{body}"
            print(f"    [{subagent.name}] includes={include_count} tier={original_model or 'inherit'}->{resolved_model or 'inherit'} chars={len(content)}")
        dest = agents_dir / f"{subagent.name}.md"
        dest.write_text(content)
        print(f"  Installing subagent {subagent.name} -> {display_path(dest)}")
        count += 1
    print(f"Installed {count} subagent{'s' if count != 1 else ''} to gemini ({scope})")
    return count


def install_subagents_antigravity(subagents: list[MarkdownSource], scope: str) -> int:
    if scope == "global":
        print("  Skipping global Antigravity subagents - global plugin path is not pinned by current Google docs")
        return 0

    plugin_dir = Path.cwd() / ".agents" / "plugins" / "scope"
    agents_dir = plugin_dir / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "plugin.json").write_text(json.dumps({"name": "scope"}, indent=2) + "\n")

    count = 0
    for subagent in subagents:
        parsed = parse_frontmatter(subagent.content)
        content = subagent.content
        if parsed:
            original_model = parsed.frontmatter.get("model")
            include_count = len(re.findall(r"^@include\s+\S+$", parsed.body, re.MULTILINE))
            body = resolve_includes(parsed.body)
            config = GEMINI_AGENT_CONFIG.get(subagent.name)
            if config:
                parsed.frontmatter["max_turns"] = str(config["max_turns"])
            omit_keys = set(GEMINI_SUBAGENT_STRIP_KEYS)
            omit_keys.add("model")
            fm = rebuild_frontmatter(parsed.frontmatter, omit_keys)
            tools_yaml = ""
            if config and config.get("tools"):
                tools_yaml = "\ntools:\n" + "\n".join(f"  - {tool}" for tool in config["tools"])
            content = f"---\n{fm}{tools_yaml}\n---\n\n{body}"
            print(f"    [{subagent.name}] includes={include_count} tier={original_model or 'inherit'}->selected-antigravity-model chars={len(content)}")
        dest = agents_dir / f"{subagent.name}.md"
        dest.write_text(content)
        print(f"  Installing Antigravity plugin subagent {subagent.name} -> {display_path(dest)}")
        count += 1
    print(f"Installed {count} subagent{'s' if count != 1 else ''} to antigravity ({scope})")
    return count


def toml_literal(value: str) -> str:
    return value.replace("'''", "'''\"'\"'''")


def toml_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def install_subagents_codex(subagents: list[MarkdownSource], scope: str, splunk_mcp: bool) -> int:
    agents_dir = subagent_target_dir("codex", scope)
    agents_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    toml_entries: list[str] = []
    no_register = {"scope-verify"}

    for subagent in subagents:
        parsed = parse_frontmatter(subagent.content)
        content = subagent.content
        description = subagent.name
        source_frontmatter: dict[str, str] = {}
        expanded_body = ""

        if parsed:
            original_model = parsed.frontmatter.get("model")
            include_count = len(re.findall(r"^@include\s+\S+$", parsed.body, re.MULTILINE))
            expanded_body = resolve_includes(parsed.body)
            source_frontmatter = dict(parsed.frontmatter)
            description = parsed.frontmatter.get("description", description)
            resolved_model = resolve_model_tier(parsed.frontmatter.get("model"), "codex")
            fm = rebuild_frontmatter(parsed.frontmatter, CODEX_STRIP_KEYS)
            content = f"---\n{fm}\n---\n\n{expanded_body}"
            print(f"    [{subagent.name}] includes={include_count} tier={original_model or 'inherit'}->{resolved_model or 'inherit'} chars={len(content)}")
        else:
            expanded_body = subagent.content

        dest_md = agents_dir / f"{subagent.name}.md"
        dest_md.write_text(content)
        print(f"  Installing subagent {subagent.name} -> {display_path(dest_md)}")
        count += 1

        if subagent.name in no_register:
            continue

        codex_model = resolve_model_tier(source_frontmatter.get("model"), "codex") or _models_config()["codex"]["reasoning"]
        agent_toml = "\n".join(
            [
                "# SCOPE subagent config layer - auto-generated by scope.install",
                f'# Referenced from .codex/config.toml via config_file = "agents/{subagent.name}.toml"',
                "",
                f'model = "{toml_string(codex_model)}"',
                'model_reasoning_effort = "high"',
                'sandbox_mode = "workspace-write"',
                "",
                "# developer_instructions is sent as role=developer to the spawned agent.",
                "# Inlined from the source subagent Markdown body.",
                "developer_instructions = '''",
                toml_literal(expanded_body.rstrip()),
                "'''",
            ]
        ) + "\n"
        dest_toml = agents_dir / f"{subagent.name}.toml"
        dest_toml.write_text(agent_toml)
        print(f"  Installing config layer  {subagent.name} -> {display_path(dest_toml)}")

        toml_entries.extend(
            [
                f"[agents.{subagent.name}]",
                f'description = "{toml_string(description)}"',
                f'config_file = "agents/{subagent.name}.toml"',
                "",
            ]
        )

    config_toml_path = (Path.cwd() if scope == "local" else Path.home()) / ".codex" / "config.toml"
    config_toml_path.parent.mkdir(parents=True, exist_ok=True)
    existing = config_toml_path.read_text() if config_toml_path.exists() else ""
    config = ensure_codex_features(existing)
    if splunk_mcp:
        config = ensure_codex_splunk_mcp(config)
    scope_block = build_codex_scope_block(toml_entries)
    config = upsert_codex_scope_block(config, scope_block)
    config_toml_path.write_text(config)
    print(f"  Config: {display_path(config_toml_path)}")
    print(f"Installed {count} subagent{'s' if count != 1 else ''} to codex ({scope})")
    return count


def ensure_codex_features(config: str) -> str:
    if re.search(r"^\[features\]", config, re.MULTILINE):
        if not re.search(r"^\s*multi_agent\s*=", config, re.MULTILINE):
            config = re.sub(r"(\[features\][^\n]*\n)", r"\1multi_agent = true\n", config, count=1)
            print("  Injected multi_agent = true into existing [features] section")
        return config
    features = "[features]\nmulti_agent = true\n"
    print("  Added [features] section with multi_agent = true")
    return f"{features}\n{config}" if config else features


def ensure_codex_splunk_mcp(config: str) -> str:
    if re.search(r"^\[mcp_servers\.splunk-mcp-server\]", config, re.MULTILINE):
        return config
    mcp_block = '\n[mcp_servers.splunk-mcp-server]\nurl = "${SPLUNK_URL}"\n'
    print("  Added [mcp_servers.splunk-mcp-server] to config.toml")
    return config.rstrip() + "\n" + mcp_block + "\n"


def build_codex_scope_block(toml_entries: list[str]) -> str:
    header = "# --- SCOPE subagent registrations (auto-generated) ---"
    footer = "# --- END SCOPE subagent registrations ---"
    agents_global = "[agents]\nmax_threads = 16\nmax_depth = 2\njob_max_runtime_seconds = 3600\n"
    return "\n".join([header, "", agents_global, *toml_entries, footer])


def upsert_codex_scope_block(config: str, scope_block: str) -> str:
    header = "# --- SCOPE subagent registrations (auto-generated) ---"
    footer = "# --- END SCOPE subagent registrations ---"
    pattern = re.compile(re.escape(header) + r"[\s\S]*?" + re.escape(footer))
    if pattern.search(config):
        print("  Updated SCOPE block in config.toml")
        return pattern.sub(scope_block, config)
    print("  Added SCOPE block to config.toml")
    return config.rstrip() + "\n\n" + scope_block + "\n" if config else scope_block + "\n"


def strip_splunk_mcp_servers(content: str) -> str:
    parsed = json.loads(content)
    mcp_servers = parsed.get("mcpServers")
    if isinstance(mcp_servers, dict) and "splunk-mcp-server" in mcp_servers:
        del mcp_servers["splunk-mcp-server"]
        if not mcp_servers:
            del parsed["mcpServers"]
    return json.dumps(parsed, indent=2) + "\n"


def install_hooks(editor: str, scope: str, splunk_mcp: bool) -> None:
    settings_map = {
        "claude": {"src": "config/settings/claude.settings.json", "dest": ".claude/settings.json", "hooks_dir": ".claude/hooks"},
        "gemini": {"src": "config/settings/gemini.settings.json", "dest": ".gemini/settings.json", "hooks_dir": ".gemini/hooks"},
        "antigravity": {
            "src": "config/settings/antigravity.hooks.json",
            "dest": ".agents/hooks.json" if scope == "local" else ".gemini/config/hooks.json",
            "hooks_dir": ".agents/hooks" if scope == "local" else ".gemini/config/hooks",
        },
        "codex": {"src": "config/settings/codex.hooks.json", "dest": ".codex/hooks.json", "hooks_dir": ".codex/hooks"},
    }
    entry = settings_map[editor]
    src_settings = REPO_ROOT / entry["src"]
    if not src_settings.exists():
        return

    base = Path.home() if scope == "global" else Path.cwd()
    src_hooks_dir = REPO_ROOT / "config" / "hooks"
    dest_hooks_dir = base / entry["hooks_dir"]
    if src_hooks_dir.exists():
        dest_hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_files = sorted(src_hooks_dir.glob("*.sh"))
        for src in hook_files:
            dest = dest_hooks_dir / src.name
            shutil.copy2(src, dest)
            dest.chmod(0o755)
        print(f"  Installed {len(hook_files)} hook scripts -> {entry['hooks_dir']}/")

    content = src_settings.read_text().replace("__HOOKS_DIR__", str(base / entry["hooks_dir"]))
    if editor == "gemini" and not splunk_mcp:
        content = strip_splunk_mcp_servers(content)

    dest_file = base / entry["dest"]
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    dest_file.write_text(content)
    print(f"  Updated hook settings -> {entry['dest']}")


def install_mcp_config(editor: str, scope: str, splunk_mcp: bool) -> None:
    if not splunk_mcp:
        if editor == "claude" and scope == "local":
            print("  Skipping .mcp.json - Splunk MCP disabled")
        if editor == "antigravity":
            print("  Skipping Antigravity mcp_config.json - Splunk MCP disabled")
        return
    if editor == "antigravity":
        src_mcp = REPO_ROOT / "config" / "settings" / "antigravity.mcp_config.json"
        if not src_mcp.exists():
            return
        base = Path.cwd() if scope == "local" else Path.home()
        dest = base / (".agents/mcp_config.json" if scope == "local" else ".gemini/antigravity-cli/mcp_config.json")
        if dest.exists():
            print(f"  {display_path(dest)} already exists - skipping (edit manually to update)")
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_mcp, dest)
        print(f"  Created {display_path(dest)} - set SPLUNK_URL and SPLUNK_TOKEN env vars to enable Splunk MCP")
        return
    if editor != "claude" or scope != "local":
        return
    src_mcp = REPO_ROOT / "config" / "settings" / "mcp.json"
    if not src_mcp.exists():
        return
    dest = Path.cwd() / ".mcp.json"
    if dest.exists():
        print("  .mcp.json already exists - skipping (edit manually to update)")
        return
    shutil.copy2(src_mcp, dest)
    print("  Created .mcp.json - set SPLUNK_URL and SPLUNK_TOKEN env vars to enable Splunk MCP")


def cleanup_old_modules(scope: str) -> None:
    bases = [
        (Path.cwd() if scope == "local" else Path.home()) / ".claude" / "skills",
        (Path.cwd() if scope == "local" else Path.home()) / ".agents" / "skills",
    ]
    stale_dirs: list[Path] = []
    for base in bases:
        if not base.exists():
            continue
        stale_dirs.extend(path for path in base.iterdir() if path.is_dir() and path.name.startswith("scope-audit-"))

    if stale_dirs:
        print("\n  WARN: Stale module skill directories found (from pre-Phase-3 installs):", file=sys.stderr)
        for path in stale_dirs:
            print(f"    - {display_path(path)}", file=sys.stderr)
        print("  These are now replaced by subagents in .claude/agents/, .gemini/agents/, .agents/plugins/scope/agents/, and .codex/agents/.", file=sys.stderr)
        print("  Remove stale directories manually:", file=sys.stderr)
        for path in stale_dirs:
            print(f'    rm -rf "{display_path(path)}"', file=sys.stderr)
        print("", file=sys.stderr)


def check_legacy_gemini_skills(scope: str) -> None:
    legacy_base = (Path.home() if scope == "global" else Path.cwd()) / ".gemini" / "skills"
    if not legacy_base.exists():
        return
    scope_skills = ["scope-audit", "scope-controls", "scope-exploit", "scope-investigate"]
    found = [skill for skill in scope_skills if (legacy_base / skill).exists()]
    if found:
        print(
            f"  WARN: .gemini/skills/ contains {len(found)} legacy SCOPE skill(s): {', '.join(found)}",
            file=sys.stderr,
        )
        print("  New Gemini/Antigravity workspace installs use .agents/skills/ as the shared skills path.", file=sys.stderr)


def install_project_docs(editors: list[str], scope: str) -> None:
    project_root = Path.cwd() if scope == "local" else Path.home()
    src = REPO_ROOT / "config" / "project-docs" / "PROJECT.md"
    if not src.exists():
        return
    doc_map = {"claude": "CLAUDE.md", "gemini": "GEMINI.md", "antigravity": "AGENTS.md", "codex": "AGENTS.md"}
    for editor in editors:
        filename = doc_map.get(editor)
        if not filename:
            continue
        shutil.copy2(src, project_root / filename)
        print(f"  -> {filename} (project docs from PROJECT.md)")


def run_install(editors: list[str], scope: str, splunk_mcp: bool) -> None:
    agents_dir = REPO_ROOT / "agents"
    agents = discover_agents(agents_dir)
    if not agents:
        print("No agents found in agents/ directory.")
        raise SystemExit(0)

    print(f"Found {len(agents)} agent{'s' if len(agents) != 1 else ''}: {', '.join(agent.name for agent in agents)}\n")
    for editor in editors:
        install_for_editor(editor, scope, agents)
    for editor in editors:
        install_hooks(editor, scope, splunk_mcp)
    for editor in editors:
        install_mcp_config(editor, scope, splunk_mcp)

    subagents = discover_subagents(agents_dir / "subagents")
    installed_names = {subagent.name for subagent in subagents}
    if subagents:
        print(f"\nFound {len(subagents)} subagent(s): {', '.join(subagent.name for subagent in subagents)}\n")
        for editor in editors:
            if editor == "claude":
                install_subagents_claude(subagents, scope)
            elif editor == "gemini":
                install_subagents_gemini(subagents, scope)
            elif editor == "antigravity":
                install_subagents_antigravity(subagents, scope)
            elif editor == "codex":
                install_subagents_codex(subagents, scope, splunk_mcp)
            agents_target = subagent_target_dir(editor, scope)
            prune_stale_subagent_files(agents_target, installed_names)
            if editor == "codex":
                prune_stale_toml_files(agents_target, installed_names)

    cleanup_old_modules(scope)
    if "gemini" in editors or "antigravity" in editors:
        check_legacy_gemini_skills(scope)
    install_project_docs(editors, scope)


def prompt_user(question: str) -> str:
    return input(question).strip()


def run_interactive() -> tuple[list[str], str, bool]:
    purple = "\033[35m"
    dim = "\033[2m"
    bold = "\033[1m"
    reset = "\033[0m"

    print("")
    print(purple + "   ___  ___ ___  ___ ___")
    print("  / __|/ __/ _ \\| _ \\ __|")
    print("  \\__ \\ (_| (_) |  _/ _|")
    print("  |___/\\___\\___/|_| |___|" + reset)
    print("")
    print(dim + "  Security Cloud Ops Purple Engagement" + reset)
    print(dim + "  AI agent suite for AWS purple team operations" + reset)
    print("")
    print(bold + "  Which runtime(s) would you like to install for?" + reset)
    print("")
    print(purple + "  1) Claude Code   " + dim + "(.claude/)" + reset)
    print(purple + "  2) Antigravity CLI " + dim + "(.agents/)" + reset)
    print(purple + "  3) Gemini CLI    " + dim + "legacy Google target (.gemini/ + .agents/)" + reset)
    print(purple + "  4) Codex         " + dim + "(.codex/ + .agents/)" + reset)
    print(purple + "  5) All" + reset)
    print("")
    choice = prompt_user(purple + "  Choice: " + reset)
    if choice == "1":
        editors = ["claude"]
    elif choice == "2":
        editors = ["antigravity"]
    elif choice == "3":
        editors = ["gemini"]
    elif choice == "4":
        editors = ["codex"]
    elif choice == "5":
        editors = ["claude", "antigravity", "gemini", "codex"]
    else:
        raise SystemExit("Invalid choice. Enter 1-5.")

    print("")
    print(bold + "  Install scope:" + reset)
    print("")
    print(purple + "  1) Local     " + dim + "(./<editor>/ in project)" + reset)
    print(purple + "  2) Global    " + dim + "(~/.<editor>/ in home)" + reset)
    print("")
    scope_choice = prompt_user(purple + "  Choice: " + reset)
    if scope_choice not in {"1", "2"}:
        raise SystemExit("Invalid choice. Enter 1 or 2.")
    scope = "global" if scope_choice == "2" else "local"

    print("")
    print(bold + "  Configure bundled Splunk MCP defaults?" + reset)
    print("")
    print(purple + "  1) Yes      " + dim + "(requires Splunk MCP endpoint and encrypted token)" + reset)
    print(purple + "  2) No       " + dim + "(manual SPL mode or custom SIEM MCP later)" + reset)
    print("")
    mcp_choice = prompt_user(purple + "  Choice: " + reset)
    if mcp_choice not in {"1", "2"}:
        raise SystemExit("Invalid choice. Enter 1 or 2.")
    return editors, scope, mcp_choice == "1"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uv run python -m scope.install",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Install SCOPE agents and subagents into AI editor config directories.",
        epilog="""What gets installed:
  Skills      Operator-invoked slash commands (scope-audit, scope-controls, scope-exploit, scope-investigate)
              -> .claude/skills/ (Claude Code)
              -> .agents/skills/ (Antigravity workspace, Gemini CLI workspace, and Codex)
              -> ~/.gemini/antigravity-cli/skills/ (Antigravity global)
  Subagents   Orchestrator-dispatched workers (attack analysis, controls, investigation, research)
              -> .claude/agents/ (Claude Code)
              -> .agents/plugins/scope/agents/ (Antigravity workspace plugin)
              -> .gemini/agents/ (Gemini CLI) - requires experimental.enableAgents: true
              -> .codex/agents/ + .codex/config.toml (Codex)
              Note: scope-verify installs for discoverability but runtime agents read it inline
              Note (Codex): installer also adds [features] multi_agent = true
              Note: Gemini CLI is legacy for consumer/free/Pro/Ultra users after Google's June 18, 2026 transition to Antigravity CLI

Examples:
  uv run python -m scope.install --all
  uv run python -m scope.install --all --with-splunk-mcp
  uv run python -m scope.install --claude --global
  uv run python -m scope.install --antigravity --local
  uv run python -m scope.install --gemini --local
  uv run python -m scope.install --codex --local
  uv run python -m scope.install --claude --no-splunk-mcp

Invocation syntax varies by editor:
  Claude Code:  /scope:audit <target>
  Antigravity CLI: /scope:audit <target>
  Gemini CLI:   /scope:audit <target>
  Codex:        $scope-audit <target>
""",
    )
    editors = parser.add_argument_group("Editors")
    editors.add_argument("--claude", action="store_true", help="Install to Claude Code")
    editors.add_argument("--antigravity", action="store_true", help="Install to Antigravity CLI")
    editors.add_argument("--gemini", action="store_true", help="Install to Gemini CLI (legacy Google target)")
    editors.add_argument("--codex", action="store_true", help="Install to Codex")
    editors.add_argument("--all", action="store_true", help="Install to all supported editors")

    scope = parser.add_argument_group("Scope")
    scope.add_argument("--local", action="store_true", help="Install to current project directory (default)")
    scope.add_argument("--global", dest="global_scope", action="store_true", help="Install to user home directory")

    options = parser.add_argument_group("Options")
    mcp_group = options.add_mutually_exclusive_group()
    mcp_group.add_argument("--with-splunk-mcp", action="store_true", help="Install bundled Splunk MCP defaults")
    mcp_group.add_argument("--no-splunk-mcp", action="store_true", help="Skip bundled Splunk MCP config")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    editors: list[str] = []
    if args.claude or args.all:
        editors.append("claude")
    if args.antigravity or args.all:
        editors.append("antigravity")
    if args.gemini or args.all:
        editors.append("gemini")
    if args.codex or args.all:
        editors.append("codex")

    if not editors:
        editors, scope, splunk_mcp = run_interactive()
        run_install(editors, scope, splunk_mcp)
        return

    scope = "global" if args.global_scope else "local"
    splunk_mcp = args.with_splunk_mcp
    run_install(editors, scope, splunk_mcp)


if __name__ == "__main__":
    main()
