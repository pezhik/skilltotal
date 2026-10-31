"""Register the hook in each agent's own config: ``skilltotal hook install|uninstall|status``.

An agent's hook file can hold other people's hooks and, for Gemini CLI and Devin, the rest of its
settings, so the change is a merge: only entries whose command runs ``skilltotal hook <agent>`` are
ours, added or replaced in place, and nothing else in the file moves. A file that is not plain
JSON (a settings file with comments) or is a link is refused rather than rewritten, and the file as
it was is copied beside it before the first change. Installing twice changes nothing.

Claude Code is not written to: the plugin brings the hook, the sentinel and the MCP server, and
updates with the marketplace. ``install`` says how to get it.

Pure library: the CLI prints what these return.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skilltotal import bounded_json
from skilltotal.hook_scan import write_atomic

# The longest a hook may take: the budget in CI strict mode (agent_hook.STRICT_MAX_BUDGET_S) and a
# margin, as in the plugin's hooks.json. An agent that outlives its hook's timeout lets the
# command run, so a shorter one would turn every slow check into a pass.
TIMEOUT_S = 900
BACKUP_SUFFIX = ".skilltotal-backup"
PLUGIN_ID = "skilltotal@skilltotal"
PLUGIN_ADVICE = ("Claude Code: use the plugin, which brings the hook and the sentinel and updates "
                 "with its marketplace: run `claude plugin marketplace add pezhik/skilltotal`, "
                 "then `claude plugin install skilltotal@skilltotal`.")
# A hook of ours, wherever the CLI was when it was installed, in any quoting.
_OURS = re.compile(r"""skilltotal(?:\.exe|\.cmd)?["']?\s+hook\s+(?P<agent>[a-z-]+)""",
                   re.IGNORECASE)


# What has been run in the agent itself, not only built to its documentation. A line here is added
# by running the agent, with the version and the date.
VERIFIED = {
    "claude-code": "verified against Claude Code 2.1.316 on 2026-10-31",
    "gemini": "verified against Gemini CLI 0.45.2 on 2026-10-31, with its real hook runner and a "
              "stand-in model",
}
PREVIEW = "preview: built to the agent's documented hook format, not yet run in the agent"


def tier(name: str) -> str:
    """How far an agent's hook has been proven: said wherever support is claimed."""
    return VERIFIED.get(name, PREVIEW)


class SetupError(ValueError):
    """A config file that cannot be changed safely."""


@dataclass(frozen=True)
class Agent:
    name: str
    label: str
    markers: tuple[str, ...]  # folders under the home folder that say it is installed
    user_file: str            # relative to the home folder
    project_file: str         # relative to the project
    events: tuple[tuple[str, str], ...]  # (event, matcher; "" for an event with no groups)
    note: str = ""            # what the person must still do
    version: bool = False     # the file carries `"version": 1`
    whole_file: bool = False  # in the project file, the object itself is the hooks map

    def entry(self, command: str) -> dict[str, Any]:
        """One hook, in this agent's fields."""
        if self.name == "cursor":
            return {"command": command, "timeout": TIMEOUT_S}
        if self.name == "windsurf":
            return {"command": command, "show_output": True}
        if self.name == "copilot":
            return {"type": "command", "command": command, "timeoutSec": TIMEOUT_S}
        if self.name == "gemini":  # milliseconds
            return {"type": "command", "command": command, "name": "skilltotal",
                    "timeout": TIMEOUT_S * 1000}
        return {"type": "command", "command": command, "timeout": TIMEOUT_S}

    def grouped(self, matcher: str, command: str) -> dict[str, Any]:
        """What goes into an event's list."""
        if matcher:
            return {"matcher": matcher, "hooks": [self.entry(command)]}
        return self.entry(command)


AGENTS = (
    Agent("cursor", "Cursor", (".cursor",), ".cursor/hooks.json", ".cursor/hooks.json",
          (("beforeShellExecution", ""), ("beforeMCPExecution", ""), ("sessionStart", "")),
          version=True),
    Agent("windsurf", "Windsurf", (".codeium/windsurf",), ".codeium/windsurf/hooks.json",
          ".windsurf/hooks.json", (("pre_run_command", ""), ("pre_mcp_tool_use", ""))),
    Agent("devin", "Devin", (".config/devin", "AppData/Roaming/devin"), ".config/devin/config.json",
          ".devin/hooks.v1.json", (("PreToolUse", "exec"),), whole_file=True),
    Agent("codex", "Codex", (".codex",), ".codex/hooks.json", ".codex/hooks.json",
          (("PreToolUse", "Bash"),),
          note="Codex runs a new hook only after you trust it: open /hooks in Codex."),
    Agent("gemini", "Gemini CLI", (".gemini",), ".gemini/settings.json", ".gemini/settings.json",
          (("BeforeTool", "run_shell_command"),)),
    Agent("copilot", "VS Code Copilot", (".copilot", ".vscode"), ".copilot/hooks/skilltotal.json",
          ".github/hooks/skilltotal.json", (("preToolUse", ""),), version=True),
)
BY_NAME = {agent.name: agent for agent in AGENTS}


def installed_agents(home: Path) -> list[Agent]:
    return [a for a in AGENTS if any((home / marker).is_dir() for marker in a.markers)]


def config_path(agent: Agent, scope: str, home: Path, project: Path,
                environ: Mapping[str, str]) -> Path:
    if scope == "project":
        return project / agent.project_file
    if agent.name == "devin" and environ.get("APPDATA"):
        return Path(environ["APPDATA"]) / "devin" / "config.json"
    if agent.name == "copilot" and environ.get("COPILOT_HOME"):
        return Path(environ["COPILOT_HOME"]) / "hooks" / "skilltotal.json"
    return home / agent.user_file


def hook_command(agent: Agent, scope: str, which=shutil.which, os_name: str = os.name) -> str:
    """The command that runs the hook. In the person's own config, the CLI's full path: an editor
    started from a dock does not see a shell's PATH, and a hook that cannot start lets the command
    run. A project's config is shared, so there it is the bare name. So it is on Windows, where a
    program inherits the person's PATH, and a quoted path is no command to PowerShell, which runs
    Cursor's hooks."""
    found = which("skilltotal") if scope == "user" and os_name != "nt" else None
    if not found or '"' in found:
        return f"skilltotal hook {agent.name}"
    return f'"{found}" hook {agent.name}'


def _load(path: Path) -> tuple[dict[str, Any], str]:
    """The config's object and text ({} and "" for no file). Raises SetupError for what must not
    be rewritten."""
    if path.is_symlink():
        raise SetupError(f"{path} is a link; change it by hand")
    if not path.exists():
        return {}, ""
    try:
        text = path.read_text(encoding="utf-8-sig")
        data = bounded_json.loads(text) if text.strip() else {}
    except (OSError, UnicodeDecodeError) as exc:
        raise SetupError(f"{path} cannot be read: {exc}") from None
    except ValueError:
        raise SetupError(f"{path} is not plain JSON (comments?); add the hook by hand: see "
                         f"docs/agent-hooks.md") from None
    if not isinstance(data, dict):
        raise SetupError(f"{path} does not hold a JSON object")
    return data, text


def _is_ours(item: object, name: str) -> bool:
    """Whether an event's entry, or a group's only content, is this agent's hook of ours."""
    if not isinstance(item, dict):
        return False
    inner = item.get("hooks")
    entries = inner if isinstance(inner, list) else [item]
    return bool(entries) and all(_is_our_entry(entry, name) for entry in entries)


def _is_our_entry(entry: object, name: str) -> bool:
    if not isinstance(entry, dict):
        return False
    match = _OURS.search(str(entry.get("command", "")))
    return match is not None and match.group("agent") == name


def _hooks_map(agent: Agent, data: dict[str, Any], scope: str) -> dict[str, Any]:
    if agent.whole_file and scope == "project":
        return data
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise SetupError(f'the "hooks" of the {agent.label} config is not an object')
    return hooks


def _merged(agent: Agent, data: dict[str, Any], scope: str, command: str) -> dict[str, Any]:
    data = json.loads(json.dumps(data))
    if agent.version:
        data.setdefault("version", 1)
    hooks = _hooks_map(agent, data, scope)
    for event, matcher in agent.events:
        entries = hooks.setdefault(event, [])
        if not isinstance(entries, list):
            raise SetupError(f'"{event}" in the {agent.label} config is not a list')
        wanted = agent.grouped(matcher, command)
        for i, item in enumerate(entries):
            if _is_ours(item, agent.name):
                entries[i] = wanted
                break
        else:
            entries.append(wanted)
    return data


def _without(agent: Agent, data: dict[str, Any], scope: str) -> dict[str, Any]:
    data = json.loads(json.dumps(data))
    hooks = data if agent.whole_file and scope == "project" else data.get("hooks")
    if not isinstance(hooks, dict):
        return data
    for event, _ in agent.events:
        entries = hooks.get(event)
        if not isinstance(entries, list):
            continue
        kept = [item for item in entries if not _is_ours(item, agent.name)]
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]
    if not agent.whole_file or scope != "project":
        if not hooks:
            del data["hooks"]
    if agent.version and set(data) == {"version"}:
        return {}
    return data


def _dump(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _diff(path: Path, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(before.splitlines(keepends=True),
                                        after.splitlines(keepends=True), str(path), str(path)))


def _store(path: Path, before: str, after: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if before:
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        if not backup.exists():  # the file as it was before SkillTotal ever touched it
            shutil.copy2(path, backup)
    write_atomic(path, after)


@dataclass
class Change:
    agent: str
    path: str
    action: str   # "installed", "updated", "unchanged", "removed", "absent", "failed"
    diff: str = ""
    note: str = ""


def install(agent: Agent, path: Path, scope: str, command: str, *, dry_run: bool = False) -> Change:
    """Merge the hook into ``path``. Raises SetupError when the file must not be rewritten."""
    data, text = _load(path)
    merged = _merged(agent, data, scope, command)
    if merged == data:
        return Change(agent.name, str(path), "unchanged", note=agent.note)
    after = _dump(merged)
    had_ours = any(_is_ours(item, agent.name) for item in _event_items(agent, data, scope))
    action = "updated" if had_ours else "installed"
    change = Change(agent.name, str(path), action, _diff(path, _dump(data) if text else "", after),
                    agent.note)
    if not dry_run:
        _store(path, text, after)
    return change


def uninstall(agent: Agent, path: Path, scope: str, *, dry_run: bool = False) -> Change:
    """Take the hook out of ``path``; a file left with nothing in it goes too."""
    data, text = _load(path)
    if not any(_is_ours(item, agent.name) for item in _event_items(agent, data, scope)):
        return Change(agent.name, str(path), "absent")
    remaining = _without(agent, data, scope)
    after = _dump(remaining) if remaining else ""
    change = Change(agent.name, str(path), "removed", _diff(path, _dump(data), after))
    if not dry_run:
        if remaining:
            _store(path, text, after)
        else:
            path.unlink()
    return change


def _event_items(agent: Agent, data: dict[str, Any], scope: str) -> list[object]:
    hooks = data if agent.whole_file and scope == "project" else data.get("hooks")
    if not isinstance(hooks, dict):
        return []
    items: list[object] = []
    for event, _ in agent.events:
        entries = hooks.get(event)
        if isinstance(entries, list):
            items.extend(entries)
    return items


def _commands(agent: Agent, data: dict[str, Any], scope: str) -> list[str]:
    """The commands of our hooks in a config."""
    found: list[str] = []
    for item in _event_items(agent, data, scope):
        if _is_ours(item, agent.name) and isinstance(item, dict):
            inner = item.get("hooks")
            found.extend(str(e.get("command", "")) for e in (inner if isinstance(inner, list)
                                                             else [item]))
    return found


def _missing_program(command: str) -> bool:
    """Whether a hook names a full path to a CLI that is no longer there."""
    match = re.match(r'"([^"]+)"', command)
    return match is not None and not Path(match.group(1)).exists()


def claude_plugin(claude_dir: Path) -> str:
    """The version of the SkillTotal plugin Claude Code has installed; "" when it has none, and
    "installed" when the list does not say which."""
    from skilltotal.inventory import _load as load_config

    data = load_config(claude_dir / "plugins" / "installed_plugins.json")
    entries = data.get("plugins") if isinstance(data, dict) else None
    installs = entries.get(PLUGIN_ID) if isinstance(entries, dict) else None
    if not installs:
        return ""
    first = installs[0] if isinstance(installs, list) else installs
    version = first.get("version") if isinstance(first, dict) else None
    return version if isinstance(version, str) and version else "installed"


def status(home: Path, project: Path, environ: Mapping[str, str], cli_version: str,
           claude_dir: Path) -> list[dict[str, Any]]:
    """One row per agent: found on this machine or not, where the hook is, what is wrong."""
    rows: list[dict[str, Any]] = []
    plugin = claude_plugin(claude_dir)
    problem = ""
    if plugin not in ("", "installed", cli_version):
        problem = f"plugin {plugin} and CLI {cli_version} differ; update both together"
    rows.append({"agent": "claude-code", "label": "Claude Code", "found": claude_dir.is_dir(),
                 "protected": bool(plugin), "where": [f"plugin {plugin}"] if plugin else [],
                 "problem": problem, "tier": tier("claude-code")})
    found = installed_agents(home)
    for agent in AGENTS:
        where: list[str] = []
        problems: list[str] = []
        for scope in ("user", "project"):
            path = config_path(agent, scope, home, project, environ)
            try:
                data, _ = _load(path)
            except SetupError as exc:
                problems.append(str(exc))
                continue
            commands = _commands(agent, data, scope)
            if commands:
                where.append(str(path))
            if any(_missing_program(c) for c in commands):
                problems.append(f"{path} runs a skilltotal that is no longer there; run "
                                f"`skilltotal hook install` again")
        rows.append({"agent": agent.name, "label": agent.label, "found": agent in found,
                     "protected": bool(where) and not problems, "where": where,
                     "problem": "; ".join(problems), "tier": tier(agent.name)})
    return rows


def selected(target: str, home: Path) -> list[Agent]:
    """The agents ``--agent`` names: one, or for ``all`` those found on this machine."""
    return installed_agents(home) if target == "all" else [BY_NAME[target]]
