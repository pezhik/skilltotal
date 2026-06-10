"""Discover AI agent components already installed on this machine.

Reads the configuration files of common agent hosts (Claude Desktop/Code, Cursor, Windsurf,
VS Code, Gemini CLI) and the local skills directories, enumerates the MCP servers and skills
they reference, and derives a *scannable source* (an ``npm:`` / ``pypi:`` spec or a local
path) for each — which the CLI then runs through the normal engine. This is pure discovery:
it only reads config files, never launches anything.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

# MCP server command launchers -> package ecosystem.
_NPM_LAUNCHERS = {"npx", "npm", "pnpm", "pnpx", "bunx", "yarn"}
_PYPI_LAUNCHERS = {"uvx", "uv", "pipx"}
_SCRIPT_RUNNERS = {"node", "deno", "bun", "python", "python3", "py", "ts-node", "tsx"}
# argv tokens that are flags / sub-commands, not the package name.
_SKIP_ARG_TOKENS = {"-y", "--yes", "-q", "run", "tool", "exec", "--", "-m", "x", "dlx"}


@dataclass
class DiscoveredComponent:
    host: str          # which agent app declared it (e.g. "Claude Desktop")
    name: str          # server/skill name as configured
    kind: str          # "mcp_server" | "skill"
    source: str | None  # scannable source (npm:/pypi:/local path) or None
    scannable: bool
    note: str = ""     # why not scannable, or extra context
    config: str = ""   # the config file it came from


def _config_locations(home: Path, project: Path | None) -> list[tuple[str, Path]]:
    """(host, config-path) candidates across platforms. Existence checked by caller."""
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    mac_claude = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    locs: list[tuple[str, Path]] = [
        ("Claude Desktop", appdata / "Claude" / "claude_desktop_config.json"),
        ("Claude Desktop", mac_claude),
        ("Claude Desktop", home / ".config" / "Claude" / "claude_desktop_config.json"),
        ("Claude Code", home / ".claude.json"),
        ("Claude Code", home / ".claude" / "settings.json"),
        ("Cursor", home / ".cursor" / "mcp.json"),
        ("Windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("Gemini CLI", home / ".gemini" / "settings.json"),
    ]
    if project is not None:
        locs += [
            ("Claude Code (project)", project / ".mcp.json"),
            ("Cursor (project)", project / ".cursor" / "mcp.json"),
            ("VS Code (project)", project / ".vscode" / "mcp.json"),
        ]
    return locs


def _skill_dirs(home: Path, project: Path | None) -> list[tuple[str, Path]]:
    dirs = [("Claude skills", home / ".claude" / "skills")]
    if project is not None:
        dirs.append(("Claude skills (project)", project / ".claude" / "skills"))
    return dirs


def _first_package_token(args: list[str]) -> str | None:
    """The first argv token that looks like a package name (not a flag/sub-command)."""
    for tok in args:
        t = tok.strip()
        if not t or t.startswith("-") or t in _SKIP_ARG_TOKENS:
            continue
        return t
    return None


def _strip_version(pkg: str) -> str:
    """lodash@4.1 -> lodash ; @scope/x@1 -> @scope/x ; keep scope's leading @."""
    if pkg.startswith("@"):
        scope, _, rest = pkg.partition("/")
        return f"{scope}/{rest.split('@', 1)[0]}" if rest else pkg
    return pkg.split("@", 1)[0]


def derive_source(server: dict, config_dir: Path) -> tuple[str | None, str]:
    """Map an mcpServers entry to a scannable source. Returns (source, note)."""
    if not isinstance(server, dict):
        return None, "unrecognized entry"
    # Remote transports (SSE/HTTP) — nothing local to scan.
    url = server.get("url") or server.get("httpUrl") or server.get("serverUrl")
    if url:
        return None, "remote server (not scanned)"

    command = str(server.get("command", "")).strip()
    args = [str(a) for a in server.get("args", []) if isinstance(a, (str, int))]
    if not command:
        return None, "no command"

    base = Path(command).name.lower()
    base = base[:-4] if base.endswith(".exe") else base

    if base in _NPM_LAUNCHERS:
        pkg = _first_package_token(args)
        return (f"npm:{_strip_version(pkg)}", "") if pkg else (None, "no npm package in args")
    if base in _PYPI_LAUNCHERS:
        pkg = _first_package_token(args)
        return (f"pypi:{_strip_version(pkg)}", "") if pkg else (None, "no pypi package in args")
    if base in _SCRIPT_RUNNERS:
        script = _first_local_path(args, config_dir)
        return (str(script.parent), "") if script else (None, "no local script in args")

    # A direct path to an executable/script.
    p = _resolve(command, config_dir)
    if p is not None and p.exists():
        return (str(p if p.is_dir() else p.parent), "")
    return None, f"unsupported launcher '{command}'"


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


def _parse_config(host: str, path: Path) -> list[DiscoveredComponent]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return []
    out: list[DiscoveredComponent] = []
    for name, server in servers.items():
        source, note = derive_source(server, path.parent)
        out.append(
            DiscoveredComponent(
                host=host, name=str(name), kind="mcp_server",
                source=source, scannable=source is not None, note=note,
                config=str(path),
            )
        )
    return out


def discover(
    home: Path | None = None,
    project: Path | None = None,
    extra_configs: list[Path] | None = None,
) -> list[DiscoveredComponent]:
    """Find installed MCP servers and skills. Parameters override defaults for testing."""
    home = home or Path.home()
    found: list[DiscoveredComponent] = []
    seen_cfg: set[Path] = set()

    candidates = _config_locations(home, project)
    candidates += [("config", p) for p in (extra_configs or [])]
    for host, path in candidates:
        if path in seen_cfg or not path.is_file():
            continue
        seen_cfg.add(path)
        found.extend(_parse_config(host, path))

    for host, sdir in _skill_dirs(home, project):
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
