"""Discover AI agent components already installed on this machine.

Reads the configuration files of common agent hosts (Claude Desktop, Claude Code with its plugins
and an organization's managed-mcp.json, Cursor, Windsurf, VS Code, Gemini CLI) and the local
skills directories, enumerates the MCP servers, plugins and skills they reference, and derives a
*scannable source* (an ``npm:`` / ``pypi:`` spec, a git URL or a local path) for each, which the
CLI then runs through the normal engine. This is pure discovery: it only reads config files,
never launches anything.

What a server's launch command installs is read by the same parser the Claude Code hook uses
(``agent_hook.parse_installs``), so ``cmd /c npx -y pkg``, a pinned ``pkg@1.2.3`` and ``uvx --from
git+https://...`` mean here what they mean there. A config entry's inline secrets (``env`` values,
an ``Authorization`` header, a key in a URL) are run through the secrets scanner and reported
redacted.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from skilltotal import bounded_json

# MCP server command launchers -> package ecosystem.
_NPM_LAUNCHERS = {"npx", "npm", "pnpm", "pnpx", "bunx", "yarn"}
_PYPI_LAUNCHERS = {"uvx", "uv", "pipx"}
_SCRIPT_RUNNERS = {"node", "deno", "bun", "python", "python3", "py", "ts-node", "tsx"}
# argv tokens that are flags / sub-commands, not a script path.
_SKIP_ARG_TOKENS = {"-y", "--yes", "-q", "run", "tool", "exec", "--", "-m", "x", "dlx"}
# Claude Code's ~/.claude/settings.json is not read: it holds permissions, hooks and which project
# servers to enable, not server definitions (those live in ~/.claude.json and .mcp.json).


@dataclass
class DiscoveredComponent:
    host: str          # which agent app declared it (e.g. "Claude Desktop")
    name: str          # server/skill/plugin name as configured
    kind: str          # "mcp_server" | "skill" | "plugin"
    source: str | None  # scannable source (npm:/pypi:/git URL/local path) or None
    scannable: bool
    note: str = ""     # why not scannable, or extra context
    config: str = ""   # the config file it came from
    risky: bool = False  # its launch command itself is risky (runs a downloaded script)
    # Inline secrets in its config entry, redacted (the secrets scanner's evidence snippets).
    secrets: list[str] = field(default_factory=list)
    remote: bool = False  # served from a URL: no code on this machine to scan
    this_tool: bool = False  # SkillTotal's own MCP server (`skilltotal mcp`)


# The notes for a remote server and for SkillTotal's own MCP server (see DiscoveredComponent).
REMOTE_NOTE = "remote server (not scannable)"
THIS_TOOL_NOTE = "this scanner (skilltotal mcp)"
# How SkillTotal's own MCP server is started: the console script, `python -m`, or the published
# package run by a launcher (`uvx skilltotal mcp`, `npx -y skilltotal@1.2.3 mcp`).
_OWN_PACKAGE = re.compile(r"(?:npm|pypi):skilltotal(?:@[\w.+-]+)?", re.IGNORECASE)
_PYTHONS = {"python", "python3", "py"}


def _is_this_tool(command: str, args: list[str]) -> bool:
    """Whether a server entry starts SkillTotal's own MCP server. A program named by a path (a
    `./skilltotal` committed to a repository) is not this tool, nor is a package from another index
    or a git URL: the parser names those differently, and they are scanned or reported as usual."""
    if "/" in command or "\\" in command:
        name = ""  # a launcher by path (`C:\\...\\npx.cmd`) still goes through the parser below
    else:
        name = command.lower()
        name = name[:-4] if name.endswith(".exe") else name
    if name == "skilltotal" and args[:1] == ["mcp"]:
        return True
    if name in _PYTHONS and args[:3] == ["-m", "skilltotal", "mcp"]:
        return True
    if "mcp" not in args:
        return False
    from skilltotal.agent_hook import parse_installs

    installs = parse_installs(" ".join(_quote(w) for w in [command, *args]), "bash")
    return len(installs) == 1 and bool(installs[0].source) and bool(
        _OWN_PACKAGE.fullmatch(installs[0].source or ""))


@dataclass(frozen=True)
class _Location:
    host: str
    path: Path
    keys: tuple[str, ...] = ("mcpServers",)  # where servers sit in the file; dots go deeper


def _config_locations(home: Path, project: Path | None,
                      env: Mapping[str, str]) -> list[_Location]:
    """Config files that can define MCP servers, across platforms. Existence checked by caller."""
    appdata = Path(env["APPDATA"]) if env.get("APPDATA") else home / "AppData" / "Roaming"
    mac = home / "Library" / "Application Support"
    vscode = ("servers", "mcpServers")
    locs = [
        _Location("Claude Desktop", appdata / "Claude" / "claude_desktop_config.json"),
        _Location("Claude Desktop", mac / "Claude" / "claude_desktop_config.json"),
        _Location("Claude Desktop", home / ".config" / "Claude" / "claude_desktop_config.json"),
        _Location("Cursor", home / ".cursor" / "mcp.json"),
        _Location("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        _Location("Gemini CLI", home / ".gemini" / "settings.json"),
    ]
    for edition in ("Code", "Code - Insiders"):
        for base in (appdata, mac, home / ".config"):
            user = base / edition / "User"
            locs.append(_Location("VS Code", user / "mcp.json", vscode))
            locs.append(_Location("VS Code", user / "settings.json", ("mcp.servers",)))
    if project is not None:
        locs += [
            _Location("Claude Code (project)", project / ".mcp.json"),
            _Location("Cursor (project)", project / ".cursor" / "mcp.json"),
            _Location("VS Code (project)", project / ".vscode" / "mcp.json", vscode),
        ]
    return locs


def _managed_mcp_files(env: Mapping[str, str]) -> list[Path]:
    """Claude Code's organization-wide ``managed-mcp.json`` (same format as ``.mcp.json``), which
    an administrator deploys to a system path; its servers load for every user of the machine."""
    program_files = Path(env.get("ProgramFiles") or env.get("PROGRAMFILES")
                         or r"C:\Program Files")
    return [
        Path("/Library/Application Support/ClaudeCode/managed-mcp.json"),
        Path("/etc/claude-code/managed-mcp.json"),
        program_files / "ClaudeCode" / "managed-mcp.json",
    ]


def _claude_dir(home: Path, env: Mapping[str, str]) -> Path:
    """Claude Code's configuration folder: ``~/.claude``, or CLAUDE_CONFIG_DIR."""
    return Path(env["CLAUDE_CONFIG_DIR"]) if env.get("CLAUDE_CONFIG_DIR") else home / ".claude"


def _claude_json_files(home: Path, env: Mapping[str, str]) -> list[Path]:
    """Claude Code's user config (user and local-scope MCP servers)."""
    files = [home / ".claude.json"]
    if env.get("CLAUDE_CONFIG_DIR"):
        files.insert(0, _claude_dir(home, env) / ".claude.json")
    return files


def _skill_dirs(home: Path, project: Path | None,
                env: Mapping[str, str]) -> list[tuple[str, Path]]:
    dirs = [("Claude skills", _claude_dir(home, env) / "skills")]
    if project is not None:
        dirs.append(("Claude skills (project)", project / ".claude" / "skills"))
    return dirs


def _quote(word: str) -> str:
    """``word`` as one bash word (POSIX single quotes)."""
    return "'" + word.replace("'", "'\\''") + "'"


def _from_parser(command: str, args: list[str]) -> tuple[str | None, str, bool] | None:
    """What the hook's parser says this command installs: (source, note, risky), or None when it
    finds nothing to install (a local script, an unknown program)."""
    from skilltotal.agent_hook import GIT_CLONE, SCRIPT, parse_installs

    installs = parse_installs(" ".join(_quote(w) for w in [command, *args]), "bash")
    scripts = [i for i in installs if i.unchecked == SCRIPT]
    if scripts:
        does = "; ".join(dict.fromkeys(i.does or "" for i in scripts))
        return None, f"risky: {does} each time it starts (not scanned)", True
    sources = [i.source for i in installs if i.source]
    if sources:
        more = f"; it also installs {', '.join(sources[1:])}" if len(sources) > 1 else ""
        return sources[0], more.lstrip("; "), False
    unverifiable = [i.unverifiable for i in installs if i.unverifiable]
    if unverifiable:
        return None, f"not scanned: {unverifiable[0]}", False
    others = [i.does for i in installs if i.unchecked and i.unchecked != GIT_CLONE and i.does]
    if others:
        return None, f"not scanned: it {others[0]}", False
    return None


def derive_source(server: dict, config_dir: Path, plugin_root: Path | None = None
                  ) -> tuple[str | None, str]:
    """Map an mcpServers entry to a scannable source. Returns (source, note)."""
    source, note, _ = _derive(server, config_dir, plugin_root)
    return source, note


def _derive(server: object, config_dir: Path, plugin_root: Path | None = None
            ) -> tuple[str | None, str, bool]:
    """(source, note, risky) for one server entry."""
    if not isinstance(server, dict):
        return None, "unrecognized entry", False
    # Remote transports (SSE/HTTP) — nothing local to scan.
    url = server.get("url") or server.get("httpUrl") or server.get("serverUrl")
    if url:
        return None, REMOTE_NOTE, False

    def expand(text: str) -> str:
        return text.replace("${CLAUDE_PLUGIN_ROOT}", str(plugin_root)) if plugin_root else text

    command = expand(str(server.get("command", "")).strip())
    raw_args = server.get("args", [])
    args = [expand(str(a)) for a in raw_args if isinstance(a, (str, int))] if isinstance(
        raw_args, list) else []
    if not command:
        return None, "no command", False
    if _is_this_tool(command, args):
        return None, THIS_TOOL_NOTE, False

    parsed = _from_parser(command, args)
    if parsed is not None:
        return parsed

    base = Path(command).name.lower()
    base = base[:-4] if base.endswith(".exe") else base
    if base in _NPM_LAUNCHERS:
        return None, "no npm package in args", False
    if base in _PYPI_LAUNCHERS:
        return None, "no pypi package in args", False
    if base in _SCRIPT_RUNNERS:
        script = _first_local_path(args, config_dir)
        return (str(script.parent), "", False) if script else (
            None, "no local script in args", False)

    # A direct path to an executable/script.
    p = _resolve(command, config_dir)
    if p is not None and p.exists():
        return str(p if p.is_dir() else p.parent), "", False
    return None, f"unsupported launcher '{command}'", False


def _resolve(token: str, config_dir: Path) -> Path | None:
    try:
        p = Path(os.path.expanduser(token))
    except (ValueError, OSError):
        return None
    return p if p.is_absolute() else (config_dir / p)


def _first_local_path(args: list[str], config_dir: Path) -> Path | None:
    for tok in args:
        if tok.startswith("-") or tok in _SKIP_ARG_TOKENS:
            continue
        if any(sep in tok for sep in ("/", "\\")) or tok.endswith((".js", ".py", ".ts", ".mjs")):
            p = _resolve(tok, config_dir)
            if p is not None and p.exists():
                return p
    return None


# --- Inline secrets ------------------------------------------------------------------------------

# `Authorization: Bearer <token>` and its kin: the token is the secret.
_AUTH_VALUE = re.compile(r"^\s*(?:bearer|basic|token|apikey)\s+(\S{8,})\s*$", re.IGNORECASE)
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]")


def _secret_lines(server: dict) -> list[str]:
    """The entry's values as ``NAME="value"`` lines, the shape the secrets scanner reads: env
    values, headers (a bearer token as ``authorization_token``), URL query values and arguments."""
    lines: list[str] = []

    def add(name: object, value: object) -> None:
        if isinstance(value, (str, int)) and str(value):
            text = str(value).replace("\n", " ").replace('"', " ")
            lines.append(f'{_SAFE_NAME.sub("_", str(name))[:80]}="{text[:2000]}"')

    for key in ("env", "headers", "requestInit"):
        values = server.get(key)
        if key == "requestInit" and isinstance(values, dict):
            values = values.get("headers")
        if isinstance(values, dict):
            for name, value in values.items():
                auth = _AUTH_VALUE.match(str(value)) if isinstance(value, str) else None
                add(f"{name}_token" if auth else name, auth.group(1) if auth else value)
    for key in ("url", "httpUrl", "serverUrl"):
        url = server.get(key)
        if isinstance(url, str):
            try:
                pairs = parse_qsl(urlsplit(url).query)
            except ValueError:
                pairs = []
            for name, value in pairs:
                add(name, value)
    args = server.get("args")
    if isinstance(args, list):
        for i, arg in enumerate(args):
            if isinstance(arg, str) and "=" in arg and arg.startswith("-"):
                name, _, value = arg.lstrip("-").partition("=")
                add(name, value)
            else:
                previous = args[i - 1] if i else ""
                add(str(previous).lstrip("-") if isinstance(previous, str) and str(
                    previous).startswith("-") else "arg", arg)
    return lines


def _inline_secrets(server: object, config: Path) -> list[str]:
    """The secrets scanner's redacted evidence for what the entry holds inline."""
    if not isinstance(server, dict):
        return []
    lines = _secret_lines(server)
    if not lines:
        return []
    from skilltotal.file_index import FileIndex, IndexedFile
    from skilltotal.scanners.secrets import SecretsScanner

    text = "\n".join(lines) + "\n"
    entry = IndexedFile(path=config, relpath="mcp-server-entry.conf", text=text,
                        _line_starts=FileIndex._compute_line_starts(text))
    result = SecretsScanner().scan(FileIndex(root=config.parent, files=[entry], stats={}))
    return [ev.snippet.strip() for finding in result.findings for ev in finding.evidence]


# --- Reading configs -----------------------------------------------------------------------------


def _strip_jsonc(text: str) -> str:
    """VS Code's JSON with comments and trailing commas, as plain JSON (strings left intact)."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _load(path: Path) -> object:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return None
    for candidate in (text, None):
        try:
            return bounded_json.loads(candidate if candidate is not None else _strip_jsonc(text))
        except (json.JSONDecodeError, ValueError, RecursionError):
            continue
    return None


def _servers_at(data: object, key: str) -> dict | None:
    """``data[key]`` (``mcp.servers`` goes one level deeper) when it is a mapping."""
    for part in key.split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data if isinstance(data, dict) else None


def _servers(host: str, servers: dict, config: Path, *, label: str = "",
             plugin_root: Path | None = None) -> list[DiscoveredComponent]:
    out: list[DiscoveredComponent] = []
    for name, server in servers.items():
        source, note, risky = _derive(server, config.parent, plugin_root)
        out.append(DiscoveredComponent(
            host=host, name=str(name), kind="mcp_server", source=source,
            scannable=source is not None, note=note, config=label or str(config), risky=risky,
            secrets=_inline_secrets(server, config),
            remote=source is None and note == REMOTE_NOTE,
            this_tool=source is None and note == THIS_TOOL_NOTE,
        ))
    return out


def _parse_config(location: _Location) -> list[DiscoveredComponent]:
    data = _load(location.path)
    found: list[DiscoveredComponent] = []
    for key in location.keys:
        servers = _servers_at(data, key)
        if servers is not None:
            found.extend(_servers(location.host, servers, location.path))
            break
    return found


def _parse_claude_json(path: Path) -> list[DiscoveredComponent]:
    """``~/.claude.json``: user-scope servers at the top, local-scope ones per project."""
    data = _load(path)
    if not isinstance(data, dict):
        return []
    found: list[DiscoveredComponent] = []
    servers = _servers_at(data, "mcpServers")
    if servers is not None:
        found.extend(_servers("Claude Code", servers, path))
    projects = data.get("projects")
    if isinstance(projects, dict):
        for where, settings in projects.items():
            local = _servers_at(settings, "mcpServers")
            if local:
                found.extend(_servers(f"Claude Code (local: {where})", local, path,
                                      label=f"{path} (projects.{where})"))
    return found


# --- Claude Code plugins -------------------------------------------------------------------------


def _installed_plugins(plugins: Path) -> list[tuple[str, Path]] | None:
    """(name, folder) of every installed plugin from Claude Code's install list, or None when
    there is no readable list."""
    data = _load(plugins / "installed_plugins.json")
    entries = data.get("plugins") if isinstance(data, dict) else None
    if not isinstance(entries, dict):
        return None
    found: list[tuple[str, Path]] = []
    for name, installs in entries.items():
        for install in installs if isinstance(installs, list) else [installs]:
            where = install.get("installPath") if isinstance(install, dict) else None
            if isinstance(where, str) and where and Path(where).is_dir():
                found.append((str(name), Path(where)))
    return found


def _cached_plugins(plugins: Path) -> list[tuple[str, Path]]:
    """Without the install list: every plugin version in the cache that is not marked orphaned
    (``cache/<marketplace>/<plugin>/<version>/``)."""
    found: list[tuple[str, Path]] = []
    cache = plugins / "cache"
    if not cache.is_dir():
        return found
    for market in sorted(p for p in cache.iterdir() if p.is_dir()):
        for plugin in sorted(p for p in market.iterdir() if p.is_dir()):
            for version in sorted(p for p in plugin.iterdir() if p.is_dir()):
                if (version / ".claude-plugin" / "plugin.json").is_file() and not (
                        version / ".orphaned_at").exists():
                    found.append((f"{plugin.name}@{market.name}", version))
    return found


def _plugin_servers(name: str, root: Path) -> list[DiscoveredComponent]:
    """The MCP servers a plugin starts: its ``.mcp.json`` and its manifest's ``mcpServers``."""
    host = f"Claude Code plugin {name}"
    found: list[DiscoveredComponent] = []
    configs: list[tuple[Path, object]] = []
    mcp_json = root / ".mcp.json"
    if mcp_json.is_file():
        configs.append((mcp_json, _load(mcp_json)))
    manifest = root / ".claude-plugin" / "plugin.json"
    declared = _servers_at(_load(manifest), "mcpServers") if manifest.is_file() else None
    if declared is not None:
        configs.append((manifest, {"mcpServers": declared}))
    elif manifest.is_file():
        data = _load(manifest)
        named = data.get("mcpServers") if isinstance(data, dict) else None
        if isinstance(named, str):  # a path to a servers file, relative to the plugin
            path = (root / named.replace("${CLAUDE_PLUGIN_ROOT}", ".")).resolve()
            if path.is_file() and path.is_relative_to(root.resolve()):
                configs.append((path, _load(path)))
    for path, data in configs:
        servers = _servers_at(data, "mcpServers")
        if servers is None and isinstance(data, dict) and all(
                isinstance(v, dict) for v in data.values()):
            servers = data  # a bare mapping of names to servers
        if servers:
            found.extend(_servers(host, servers, path, plugin_root=root))
    return found


def _plugins(claude_dir: Path) -> list[DiscoveredComponent]:
    plugins = claude_dir / "plugins"
    installed = _installed_plugins(plugins)
    if installed is None:
        installed = _cached_plugins(plugins)
    found: list[DiscoveredComponent] = []
    for name, root in installed:
        found.append(DiscoveredComponent(
            host="Claude Code plugins", name=name, kind="plugin", source=str(root),
            scannable=True, config=str(plugins),
            note="its hooks, skills, commands and MCP server code are scanned together",
        ))
        found.extend(_plugin_servers(name, root))
    return found


def discover(
    home: Path | None = None,
    project: Path | None = None,
    extra_configs: list[Path] | None = None,
    environ: Mapping[str, str] | None = None,
    managed_configs: list[Path] | None = None,
) -> list[DiscoveredComponent]:
    """Find installed MCP servers, plugins and skills. Parameters override defaults for testing.

    ``environ`` supplies APPDATA and CLAUDE_CONFIG_DIR. It defaults to the process environment
    only when ``home`` is not given either: a home passed in (a test's fake one) means every
    location comes from it, never from the machine running the code. For the same reason the
    system-wide ``managed-mcp.json`` paths are read only when ``home`` is not given;
    ``managed_configs`` names them explicitly.
    """
    env: Mapping[str, str] = environ if environ is not None else (
        os.environ if home is None else {})
    if managed_configs is None:
        managed_configs = _managed_mcp_files(env) if home is None else []
    home = home or Path.home()
    found: list[DiscoveredComponent] = []
    seen_cfg: set[Path] = set()

    for path in _claude_json_files(home, env):
        if path not in seen_cfg and path.is_file():
            seen_cfg.add(path)
            found.extend(_parse_claude_json(path))
    candidates = [_Location("Claude Code (managed)", p) for p in managed_configs]
    candidates += _config_locations(home, project, env)
    candidates += [_Location("config", p) for p in (extra_configs or [])]
    for location in candidates:
        if location.path in seen_cfg or not location.path.is_file():
            continue
        seen_cfg.add(location.path)
        found.extend(_parse_config(location))

    found.extend(_plugins(_claude_dir(home, env)))

    for host, sdir in _skill_dirs(home, project, env):
        if not sdir.is_dir():
            continue
        for child in sorted(sdir.iterdir()):
            if child.is_dir():
                found.append(
                    DiscoveredComponent(
                        host=host, name=child.name, kind="skill",
                        source=str(child), scannable=True, config=str(sdir),
                    )
                )
    return found
