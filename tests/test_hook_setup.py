"""`skilltotal hook install|uninstall|status`: a merge into someone else's config."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal import __version__, cli, hook_setup
from skilltotal.hook_setup import AGENTS, BY_NAME, SetupError, install, uninstall

NAMES = [agent.name for agent in AGENTS]
OTHERS = {
    "cursor": {"version": 1, "hooks": {"beforeShellExecution": [{"command": "./audit.sh"}],
                                       "afterFileEdit": [{"command": "./fmt.sh"}]}},
    "windsurf": {"hooks": {"pre_run_command": [{"command": "audit", "show_output": False}]}},
    "devin": {"theme": "dark", "hooks": {"PreToolUse": [
        {"matcher": "exec", "hooks": [{"type": "command", "command": "audit"}]}]}},
    "codex": {"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "audit"}]}]}},
    "gemini": {"theme": "dark", "mcpServers": {"x": {"command": "y"}}, "hooks": {"BeforeTool": [
        {"matcher": "write_file", "hooks": [{"type": "command", "command": "audit"}]}]}},
    "copilot": {"version": 1, "hooks": {"preToolUse": [{"type": "command", "command": "audit"}]}},
}


def config(tmp_path: Path, name: str, content: dict | None = None) -> Path:
    path = tmp_path / "cfg" / name / "hooks.json"
    if content is not None:
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(content), encoding="utf-8")
    return path


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def commands(value: object) -> list[str]:
    """Every hook command in a config, however it nests."""
    if isinstance(value, dict):
        own = [value["command"]] if isinstance(value.get("command"), str) else []
        return own + [c for item in value.values() for c in commands(item)]
    if isinstance(value, list):
        return [c for item in value for c in commands(item)]
    return []


@pytest.mark.parametrize("name", NAMES)
def test_install_keeps_every_other_entry(tmp_path, name):
    path = config(tmp_path, name, OTHERS[name])
    change = install(BY_NAME[name], path, "user", f"skilltotal hook {name}")
    assert change.action == "installed"
    data = read(path)
    assert {c for c in commands(OTHERS[name])} <= set(commands(data))
    assert f"skilltotal hook {name}" in commands(data)
    if name == "gemini":
        assert data["theme"] == "dark" and data["mcpServers"] == OTHERS[name]["mcpServers"]


@pytest.mark.parametrize("name", NAMES)
def test_install_twice_changes_nothing(tmp_path, name):
    path = config(tmp_path, name, OTHERS[name])
    agent = BY_NAME[name]
    install(agent, path, "user", f"skilltotal hook {name}")
    first = path.read_bytes()
    assert install(agent, path, "user", f"skilltotal hook {name}").action == "unchanged"
    assert path.read_bytes() == first


@pytest.mark.parametrize("name", NAMES)
def test_a_new_cli_path_replaces_ours_in_place(tmp_path, name):
    path = config(tmp_path, name, OTHERS[name])
    agent = BY_NAME[name]
    install(agent, path, "user", f"skilltotal hook {name}")
    before = len(commands(read(path)))
    change = install(agent, path, "user", f'"/new/skilltotal" hook {name}')
    assert change.action == "updated"
    assert len(commands(read(path))) == before
    assert not any(c == f"skilltotal hook {name}" for c in commands(read(path)))


@pytest.mark.parametrize("name", NAMES)
def test_uninstall_restores_what_was_there(tmp_path, name):
    path = config(tmp_path, name, OTHERS[name])
    agent = BY_NAME[name]
    install(agent, path, "user", f"skilltotal hook {name}")
    assert uninstall(agent, path, "user").action == "removed"
    assert read(path) == OTHERS[name]


@pytest.mark.parametrize("name", NAMES)
def test_a_file_only_we_filled_goes_with_uninstall(tmp_path, name):
    path = config(tmp_path, name)
    agent = BY_NAME[name]
    install(agent, path, "user", f"skilltotal hook {name}")
    uninstall(agent, path, "user")
    assert not path.exists()


@pytest.mark.parametrize("name", NAMES)
def test_uninstall_with_nothing_of_ours_touches_nothing(tmp_path, name):
    path = config(tmp_path, name, OTHERS[name])
    before = path.read_bytes()
    assert uninstall(BY_NAME[name], path, "user").action == "absent"
    assert path.read_bytes() == before


@pytest.mark.parametrize("name", NAMES)
def test_dry_run_writes_nothing_and_shows_the_diff(tmp_path, name):
    path = config(tmp_path, name, OTHERS[name])
    before = path.read_bytes()
    agent = BY_NAME[name]
    change = install(agent, path, "user", f"skilltotal hook {name}", dry_run=True)
    assert "+" in change.diff and f"skilltotal hook {name}" in change.diff
    assert path.read_bytes() == before
    assert sorted(p.name for p in path.parent.iterdir()) == ["hooks.json"]


def test_dry_run_of_uninstall_writes_nothing(tmp_path):
    path = config(tmp_path, "cursor", OTHERS["cursor"])
    agent = BY_NAME["cursor"]
    install(agent, path, "user", "skilltotal hook cursor")
    before = path.read_bytes()
    change = uninstall(agent, path, "user", dry_run=True)
    assert change.action == "removed" and "skilltotal hook cursor" in change.diff
    assert path.read_bytes() == before


def test_the_file_as_it_was_is_backed_up_once(tmp_path):
    path = config(tmp_path, "cursor", OTHERS["cursor"])
    original = path.read_bytes()
    agent = BY_NAME["cursor"]
    install(agent, path, "user", "skilltotal hook cursor")
    install(agent, path, "user", '"/other/skilltotal" hook cursor')
    backup = path.with_name("hooks.json" + hook_setup.BACKUP_SUFFIX)
    assert backup.read_bytes() == original


@pytest.mark.parametrize("text", ["{ // comment\n}", "[1]", "{broken"])
def test_a_file_that_is_not_a_plain_object_is_refused_and_left_alone(tmp_path, text):
    path = tmp_path / "settings.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(SetupError):
        install(BY_NAME["gemini"], path, "user", "skilltotal hook gemini")
    assert path.read_text(encoding="utf-8") == text


@pytest.mark.parametrize("data", [{"hooks": []}, {"hooks": {"BeforeTool": {}}}])
def test_a_config_of_an_odd_shape_is_refused(tmp_path, data):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(SetupError):
        install(BY_NAME["gemini"], path, "user", "skilltotal hook gemini")


def test_a_link_is_refused(tmp_path):
    target = tmp_path / "real.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "hooks.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("no symlinks here")
    with pytest.raises(SetupError):
        install(BY_NAME["cursor"], link, "user", "skilltotal hook cursor")


def test_a_hook_that_only_mentions_us_is_not_ours(tmp_path):
    content = {"version": 1, "hooks": {"beforeShellExecution": [
        {"command": "./wrapper.sh skilltotal-hook cursor"}]}}
    path = config(tmp_path, "cursor", content)
    assert uninstall(BY_NAME["cursor"], path, "user").action == "absent"


def test_a_group_that_also_holds_someone_elses_hook_is_kept(tmp_path):
    content = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
        {"type": "command", "command": "audit"},
        {"type": "command", "command": "skilltotal hook codex"}]}]}}
    path = config(tmp_path, "codex", content)
    assert uninstall(BY_NAME["codex"], path, "user").action == "absent"
    assert read(path) == content


def test_each_agents_documented_shape(tmp_path):
    path = config(tmp_path, "shapes")
    install(BY_NAME["cursor"], path, "user", "skilltotal hook cursor")
    data = read(path)
    assert data["version"] == 1
    assert data["hooks"]["beforeShellExecution"] == [
        {"command": "skilltotal hook cursor", "timeout": 900}]
    assert set(data["hooks"]) == {"beforeShellExecution", "beforeMCPExecution", "sessionStart"}
    path.unlink()
    install(BY_NAME["gemini"], path, "user", "skilltotal hook gemini")
    group = read(path)["hooks"]["BeforeTool"][0]
    assert group["matcher"] == "run_shell_command"
    assert group["hooks"][0]["timeout"] == 900_000  # milliseconds
    path.unlink()
    install(BY_NAME["windsurf"], path, "user", "skilltotal hook windsurf")
    assert read(path)["hooks"]["pre_mcp_tool_use"] == [
        {"command": "skilltotal hook windsurf", "show_output": True}]
    path.unlink()
    install(BY_NAME["copilot"], path, "user", "skilltotal hook copilot")
    assert read(path) == {"version": 1, "hooks": {"preToolUse": [
        {"type": "command", "command": "skilltotal hook copilot", "timeoutSec": 900}]}}


def test_devins_project_file_is_the_hooks_object_itself(tmp_path):
    path = config(tmp_path, "devin")
    agent = BY_NAME["devin"]
    install(agent, path, "project", "skilltotal hook devin")
    assert set(read(path)) == {"PreToolUse"}
    uninstall(agent, path, "project")
    assert not path.exists()


def test_the_hook_outlasts_the_longest_budget():
    from skilltotal.agent_hook import STRICT_MAX_BUDGET_S
    from skilltotal.hook_scan import GRACE_S

    assert hook_setup.TIMEOUT_S > STRICT_MAX_BUDGET_S + GRACE_S


def test_the_person_gets_the_full_path_and_a_project_the_bare_name():
    agent = BY_NAME["cursor"]
    which = lambda _: "/home/me/.local/bin/skilltotal"  # noqa: E731
    assert hook_setup.hook_command(agent, "user", which) == (
        '"/home/me/.local/bin/skilltotal" hook cursor')
    assert hook_setup.hook_command(agent, "project", which) == "skilltotal hook cursor"
    assert hook_setup.hook_command(agent, "user", lambda _: None) == "skilltotal hook cursor"


def test_only_agents_found_here_are_changed(tmp_path):
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".gemini").mkdir()
    assert [a.name for a in hook_setup.selected("all", tmp_path)] == ["cursor", "gemini"]
    assert [a.name for a in hook_setup.selected("codex", tmp_path)] == ["codex"]


# --- Through the CLI --------------------------------------------------------------------------


@pytest.fixture
def home(tmp_path, monkeypatch):
    folder = tmp_path / "home"
    folder.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr(cli, "_home", lambda: folder)
    monkeypatch.chdir(project)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delenv("COPILOT_HOME", raising=False)
    return folder


def test_install_and_status_through_the_cli(home, capsys):
    (home / ".cursor").mkdir()
    assert cli.main(["hook", "install"]) == 0
    out = capsys.readouterr().out
    assert "claude plugin install skilltotal@skilltotal" in out
    assert "Cursor: installed" in out
    assert cli.main(["hook", "status", "--json"]) == 0
    rows = {row["agent"]: row for row in json.loads(capsys.readouterr().out)}
    assert rows["cursor"]["protected"] and not rows["gemini"]["found"]
    assert not rows["claude-code"]["protected"]


def test_dry_run_through_the_cli_writes_nothing(home, capsys):
    (home / ".cursor").mkdir()
    assert cli.main(["hook", "install", "--dry-run"]) == 0
    assert "would be installed" in capsys.readouterr().out
    assert list((home / ".cursor").iterdir()) == []


def test_project_scope_writes_into_the_project(home, capsys):
    assert cli.main(["hook", "install", "--agent", "cursor", "--scope", "project"]) == 0
    assert read(Path.cwd() / ".cursor" / "hooks.json")["hooks"]["sessionStart"] == [
        {"command": "skilltotal hook cursor", "timeout": 900}]


def test_claude_code_is_only_told_about_the_plugin(home, capsys):
    (home / ".claude").mkdir()
    assert cli.main(["hook", "install", "--agent", "claude-code"]) == 0
    assert "use the plugin" in capsys.readouterr().out
    assert list((home / ".claude").iterdir()) == []


def test_a_refused_config_fails_the_command_and_names_it(home, capsys):
    (home / ".gemini").mkdir()
    (home / ".gemini" / "settings.json").write_text("{ // comment\n}", encoding="utf-8")
    assert cli.main(["hook", "install"]) == 1
    assert "not plain JSON" in capsys.readouterr().err


def test_status_says_when_plugin_and_cli_differ(home):
    plugins = home / ".claude" / "plugins"
    plugins.mkdir(parents=True)
    (plugins / "installed_plugins.json").write_text(json.dumps({"plugins": {
        "skilltotal@skilltotal": [{"version": "0.1.0"}]}}), encoding="utf-8")
    rows = hook_setup.status(home, Path.cwd(), {}, __version__, home / ".claude")
    assert rows[0]["protected"] and "differ" in rows[0]["problem"]


def test_status_finds_a_hook_whose_cli_is_gone(home, tmp_path):
    path = home / ".cursor" / "hooks.json"
    install(BY_NAME["cursor"], path, "user", f'"{tmp_path / "gone" / "skilltotal"}" hook cursor')
    rows = {r["agent"]: r for r in hook_setup.status(home, Path.cwd(), {}, __version__,
                                                     home / ".claude")}
    assert "no longer there" in rows["cursor"]["problem"]
    assert not rows["cursor"]["protected"]
