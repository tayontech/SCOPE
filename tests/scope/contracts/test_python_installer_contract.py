from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def read_repo_file(relative_path: str) -> str:
    return (ROOT / relative_path).read_text()


def test_python_installer_module_exposes_canonical_help(capsys) -> None:
    installer = importlib.import_module("scope.install")

    try:
        installer.main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0

    help_text = capsys.readouterr().out
    for flag in [
        "--claude",
        "--gemini",
        "--antigravity",
        "--codex",
        "--all",
        "--local",
        "--global",
        "--with-splunk-mcp",
        "--no-splunk-mcp",
    ]:
        assert flag in help_text

    assert "uv run python -m scope.install --all" in help_text
    assert "Gemini CLI is legacy" in help_text
    assert "Antigravity CLI" in help_text
    assert "node bin/install.js" not in help_text


def test_node_installer_is_removed_from_active_surface() -> None:
    assert not (ROOT / "bin" / "install.js").exists()

    active_docs = [
        "README.md",
        "config/README.md",
        "config/mcp-setup.md",
        "docs/LLM-CONTEXT.md",
    ]
    for relative_path in active_docs:
        body = read_repo_file(relative_path)
        assert "uv run python -m scope.install" in body, f"{relative_path} should document Python installer"
        assert "node bin/install.js" not in body, f"{relative_path} should not document Node installer"


def test_node_tooling_remains_dashboard_scoped() -> None:
    readme = read_repo_file("README.md")
    assert "cd dashboard && npm run dashboard" in readme

    assert not (ROOT / "package.json").exists()
    assert not (ROOT / "tests" / "js" / "run-all.js").exists()
    dashboard_package = read_repo_file("dashboard/package.json")
    assert '"dashboard": "node ../bin/generate-report.js"' in dashboard_package


def test_model_routing_has_no_enum_agent_tier() -> None:
    models = json.loads((ROOT / "config" / "models.json").read_text())
    assert "antigravity" not in models, "Antigravity should use the selected runtime model, not installer pinning"
    assert models["claude"]["reasoning"] == "opus[1m]"
    assert models["gemini"]["reasoning"] == "pro"
    assert models["codex"]["reasoning"] == "gpt-5.5"
    for platform, tiers in models.items():
        assert "enum" not in tiers, f"{platform} should not define an enum agent model"
        assert "reasoning" in tiers
        assert "inherit" in tiers

    installer = read_repo_file("scope/install.py")
    assert '"enum"' not in installer
    assert "model_value in {\"reasoning\", \"inherit\"}" in installer
    assert 'model_reasoning_effort = "high"' in installer
    assert "larger context" in read_repo_file("README.md")
    assert "Claude subagents use `opus[1m]`" in read_repo_file("docs/LLM-CONTEXT.md")


def test_source_agents_keep_top_level_model_inherited_and_subagents_reasoning_tier() -> None:
    top_level_agents = [
        "agents/scope-audit.md",
        "agents/scope-controls.md",
        "agents/scope-exploit.md",
        "agents/scope-investigate.md",
    ]
    for relative_path in top_level_agents:
        frontmatter = read_repo_file(relative_path).split("---", 2)[1]
        assert "model:" not in frontmatter, f"{relative_path} should inherit the session model"

    for path in sorted((ROOT / "agents" / "subagents").glob("scope-*.md")):
        if path.name == "scope-verify.md":
            continue
        frontmatter = path.read_text().split("---", 2)[1]
        assert "model: reasoning" in frontmatter, f"{path.relative_to(ROOT)} should use the reasoning tier"


def test_gemini_subagent_install_preserves_max_turns(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scope.install",
            "--gemini",
            "--local",
            "--no-splunk-mcp",
        ],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    attack_agent = tmp_path / ".gemini" / "agents" / "scope-attack-analyze.md"
    body = attack_agent.read_text()
    assert "model: pro" in body
    assert "max_turns: 60" in body
    assert "tools:\n  - run_shell_command\n  - read_file\n  - grep_search\n  - write_file" in body


def test_all_platform_install_writes_expected_files_and_respects_mcp_opt_out(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scope.install",
            "--all",
            "--local",
            "--no-splunk-mcp",
        ],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    expected_files = [
        ".claude/skills/scope-audit/SKILL.md",
        ".claude/agents/scope-attack-analyze.md",
        ".claude/agents/scope-awscli-replay.md",
        ".claude/agents/scope-controls-dashboards.md",
        ".claude/settings.json",
        ".agents/skills/scope-audit/SKILL.md",
        ".agents/hooks.json",
        ".agents/hooks/scope-safety-guard.sh",
        ".agents/plugins/scope/plugin.json",
        ".agents/plugins/scope/agents/scope-attack-analyze.md",
        ".agents/plugins/scope/agents/scope-awscli-replay.md",
        ".agents/plugins/scope/agents/scope-controls-dashboards.md",
        ".gemini/agents/scope-attack-analyze.md",
        ".gemini/agents/scope-awscli-replay.md",
        ".gemini/agents/scope-controls-dashboards.md",
        ".gemini/settings.json",
        ".codex/agents/scope-attack-analyze.md",
        ".codex/agents/scope-awscli-replay.md",
        ".codex/agents/scope-controls-dashboards.md",
        ".codex/agents/scope-awscli-replay.toml",
        ".codex/agents/scope-attack-analyze.toml",
        ".codex/agents/scope-controls-dashboards.toml",
        ".codex/config.toml",
        ".codex/hooks.json",
        "CLAUDE.md",
        "GEMINI.md",
        "AGENTS.md",
    ]
    for relative_path in expected_files:
        assert (tmp_path / relative_path).exists(), f"{relative_path} should be installed"
    assert not (tmp_path / ".gemini" / "skills" / "scope-audit" / "SKILL.md").exists()

    assert not (tmp_path / ".mcp.json").exists()
    assert not (tmp_path / ".agents" / "mcp_config.json").exists()
    gemini_settings = json.loads((tmp_path / ".gemini" / "settings.json").read_text())
    assert "mcpServers" not in gemini_settings

    codex_config = tomllib.loads((tmp_path / ".codex" / "config.toml").read_text())
    assert codex_config["features"]["multi_agent"] is True
    assert "mcp_servers" not in codex_config
    assert "scope-attack-analyze" in codex_config["agents"]

    codex_agent = tomllib.loads((tmp_path / ".codex" / "agents" / "scope-attack-analyze.toml").read_text())
    assert codex_agent["model"] == "gpt-5.5"
    assert codex_agent["model_reasoning_effort"] == "high"
    assert codex_agent["sandbox_mode"] == "workspace-write"
    assert codex_agent["developer_instructions"]
    dashboard_agent = tomllib.loads((tmp_path / ".codex" / "agents" / "scope-controls-dashboards.toml").read_text())
    assert dashboard_agent["model"] == "gpt-5.5"
    assert dashboard_agent["model_reasoning_effort"] == "high"
    assert not (tmp_path / ".codex" / "agents" / "scope-verify.toml").exists()


def test_scripted_install_skips_splunk_mcp_by_default(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scope.install",
            "--all",
            "--local",
        ],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    assert (tmp_path / ".claude" / "skills" / "scope-audit" / "SKILL.md").exists()
    assert (tmp_path / ".agents" / "skills" / "scope-audit" / "SKILL.md").exists()
    assert (tmp_path / ".gemini" / "agents" / "scope-attack-analyze.md").exists()
    assert (tmp_path / ".codex" / "agents" / "scope-attack-analyze.toml").exists()

    assert not (tmp_path / ".mcp.json").exists()
    assert not (tmp_path / ".agents" / "mcp_config.json").exists()
    gemini_settings = json.loads((tmp_path / ".gemini" / "settings.json").read_text())
    assert "mcpServers" not in gemini_settings
    codex_config = tomllib.loads((tmp_path / ".codex" / "config.toml").read_text())
    assert "mcp_servers" not in codex_config


def test_gemini_uses_shared_agents_skills_path_and_warns_on_legacy_path(tmp_path: Path) -> None:
    legacy_skill = tmp_path / ".gemini" / "skills" / "scope-audit"
    legacy_skill.mkdir(parents=True)
    (legacy_skill / "SKILL.md").write_text("---\nname: scope-audit\n---\n")

    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scope.install",
            "--gemini",
            "--local",
            "--no-splunk-mcp",
        ],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    assert (tmp_path / ".agents" / "skills" / "scope-audit" / "SKILL.md").exists()
    assert not (tmp_path / ".gemini" / "skills" / "scope-controls" / "SKILL.md").exists()
    assert "legacy SCOPE skill" in result.stderr
    assert ".agents/skills/" in result.stderr


def test_antigravity_local_install_writes_workspace_customizations(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scope.install",
            "--antigravity",
            "--local",
            "--with-splunk-mcp",
        ],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    expected_files = [
        ".agents/skills/scope-audit/SKILL.md",
        ".agents/hooks.json",
        ".agents/hooks/scope-safety-guard.sh",
        ".agents/mcp_config.json",
        ".agents/plugins/scope/plugin.json",
        ".agents/plugins/scope/agents/scope-attack-analyze.md",
        "AGENTS.md",
    ]
    for relative_path in expected_files:
        assert (tmp_path / relative_path).exists(), f"{relative_path} should be installed"

    hooks = json.loads((tmp_path / ".agents" / "hooks.json").read_text())
    assert "scope-safety-guard" in hooks
    assert "PreToolUse" in hooks["scope-safety-guard"]
    assert "run_command" in hooks["scope-safety-guard"]["PreToolUse"][0]["matcher"]
    assert "scope-aws-output-inject.sh" not in json.dumps(hooks)

    mcp_config = json.loads((tmp_path / ".agents" / "mcp_config.json").read_text())
    assert "splunk-mcp-server" in mcp_config["mcpServers"]
    plugin = json.loads((tmp_path / ".agents" / "plugins" / "scope" / "plugin.json").read_text())
    assert plugin["name"] == "scope"
    antigravity_agent = (tmp_path / ".agents" / "plugins" / "scope" / "agents" / "scope-attack-analyze.md").read_text()
    assert "model:" not in antigravity_agent


def test_antigravity_global_install_uses_cli_global_paths_without_subagent_plugin(tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()

    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["HOME"] = str(fake_home)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scope.install",
            "--antigravity",
            "--global",
            "--no-splunk-mcp",
        ],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    assert (fake_home / ".gemini" / "antigravity-cli" / "skills" / "scope-audit" / "SKILL.md").exists()
    assert (fake_home / ".gemini" / "config" / "hooks.json").exists()
    assert (fake_home / ".gemini" / "config" / "hooks" / "scope-safety-guard.sh").exists()
    assert not (fake_home / ".gemini" / "antigravity-cli" / "mcp_config.json").exists()
    assert not (fake_home / ".gemini" / "antigravity-cli" / "plugins" / "scope").exists()


def test_all_platform_install_writes_splunk_mcp_defaults_when_enabled(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scope.install",
            "--all",
            "--local",
            "--with-splunk-mcp",
        ],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    assert (tmp_path / ".mcp.json").exists()
    antigravity_mcp = json.loads((tmp_path / ".agents" / "mcp_config.json").read_text())
    assert "splunk-mcp-server" in antigravity_mcp["mcpServers"]
    gemini_settings = json.loads((tmp_path / ".gemini" / "settings.json").read_text())
    assert "splunk-mcp-server" in gemini_settings["mcpServers"]

    codex_config = tomllib.loads((tmp_path / ".codex" / "config.toml").read_text())
    assert codex_config["mcp_servers"]["splunk-mcp-server"]["url"] == "${SPLUNK_URL}"


def test_settings_templates_match_splunk_mcp_contract() -> None:
    claude_mcp = json.loads((ROOT / "config" / "settings" / "mcp.json").read_text())
    gemini_settings = json.loads((ROOT / "config" / "settings" / "gemini.settings.json").read_text())
    antigravity_mcp = json.loads((ROOT / "config" / "settings" / "antigravity.mcp_config.json").read_text())

    claude_server = claude_mcp["mcpServers"]["splunk-mcp-server"]
    assert claude_server["command"] == "npx"
    assert claude_server["args"] == [
        "-y",
        "mcp-remote",
        "${SPLUNK_URL}",
        "--header",
        "Authorization: Bearer ${SPLUNK_TOKEN}",
    ]

    gemini_server = gemini_settings["mcpServers"]["splunk-mcp-server"]
    assert gemini_server["command"] == "sh"
    assert gemini_server["args"] == [
        "-c",
        'npx -y mcp-remote "$SPLUNK_URL" --header "Authorization: Bearer $SPLUNK_TOKEN"',
    ]
    assert gemini_server["env"] == {
        "SPLUNK_URL": "$SPLUNK_URL",
        "SPLUNK_TOKEN": "$SPLUNK_TOKEN",
    }

    antigravity_server = antigravity_mcp["mcpServers"]["splunk-mcp-server"]
    assert antigravity_server["command"] == "sh"
    assert antigravity_server["args"] == [
        "-c",
        'npx -y mcp-remote "$SPLUNK_URL" --header "Authorization: Bearer $SPLUNK_TOKEN"',
    ]
    assert antigravity_server["env"] == {
        "SPLUNK_URL": "$SPLUNK_URL",
        "SPLUNK_TOKEN": "$SPLUNK_TOKEN",
    }


def test_hook_settings_templates_use_installer_placeholder() -> None:
    for relative_path in [
        "config/settings/claude.settings.json",
        "config/settings/gemini.settings.json",
        "config/settings/codex.hooks.json",
        "config/settings/antigravity.hooks.json",
    ]:
        body = (ROOT / relative_path).read_text()
        parsed = json.loads(body)
        assert "__HOOKS_DIR__/" in body
        assert "scope-safety-guard.sh" in body
        assert "scope-schema-validate.sh" in body
        assert "scope-artifact-check.sh" in body
        assert parsed["hooks"] if relative_path != "config/settings/antigravity.hooks.json" else parsed
