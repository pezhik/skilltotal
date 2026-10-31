"""Where a Claude Code plugin comes from: ``claude plugin install name@marketplace`` names a catalog
entry, not code. ``plugins/known_marketplaces.json`` says where Claude Code keeps each marketplace,
the ``marketplace.json`` there lists the plugin, and the entry's ``source`` says what gets fetched
(github, url, git-subdir, npm, archive, command, or a path inside the marketplace). That is what is
checked. What cannot be resolved is asked about, by name.

A marketplace's file is written by its publisher, so nothing in it is trusted: a path stays inside
the marketplace folder, a URL goes through the same parsers as a command line, and a reason quotes
only fixed words, a validated name and a host. A catalog entry can also add hooks or MCP servers of
its own, which no scan of the plugin's source reads, and those are asked about too.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from skilltotal import bounded_json
from skilltotal.agent_hook import (
    _NPM_NAME,
    Install,
    _github,
    _npm_spec,
    _public,
    _read_config,
    _shown_host,
)

_MAX_FILE = 2 * 1024 * 1024
_RELATIVE = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
_DEFAULT_CATALOG = ".claude-plugin/marketplace.json"
# Fields of a catalog entry that add code to the plugin, whatever its source holds.
_INLINE = ("hooks", "mcpServers", "lspServers", "commands", "agents", "skills")


def _ask(spec: str, why: str) -> Install:
    return Install(None, f"{spec} (a Claude Code plugin: {why})")


def _load(path: Path) -> Any:
    text = _read_config(path, _MAX_FILE)
    if not text:
        return None
    try:
        return bounded_json.loads(text)
    except ValueError:
        return None


def _inside(root: Path, relative: str) -> Path | None:
    """``root/relative`` when that stays in ``root``, links resolved; else None."""
    parts = relative.split("/")
    if not _RELATIVE.fullmatch(relative) or ".." in parts:
        return None
    try:
        base = root.resolve()
        target = (base / relative).resolve()
    except (OSError, ValueError, RuntimeError):
        return None
    return target if target.is_relative_to(base) else None


def _marketplaces(claude_dir: Path) -> dict[str, Any]:
    data = _load(claude_dir / "plugins" / "known_marketplaces.json")
    return data if isinstance(data, dict) else {}


def _catalog(market: dict[str, Any]) -> tuple[dict[str, Any], Path] | None:
    """The marketplace's file and its root folder, or None when they cannot be found."""
    source = market.get("source")
    source = source if isinstance(source, dict) else {}
    kind = source.get("source")
    where = source.get("path")
    if kind == "file" and isinstance(where, str):
        file = Path(where)
        root = file.parent.parent
    else:
        location = where if kind == "directory" else market.get("installLocation")
        if not isinstance(location, str) or not location:
            return None
        root = Path(location)
        if root.is_file():
            data = _load(root)
            return (data, root.parent) if isinstance(data, dict) else None
        inner = where if isinstance(where, str) and where and kind != "directory" \
            else _DEFAULT_CATALOG
        found = _inside(root, inner)
        if found is None:
            return None
        file = found
    data = _load(file)
    return (data, root) if isinstance(data, dict) else None


def _relative(spec: str, value: str, root: Path, catalog: dict[str, Any]) -> list[Install]:
    relative = value
    if relative in (".", "./"):
        return [Install(str(root))]
    if relative.startswith("./"):
        relative = relative[2:]
    else:
        meta = catalog.get("metadata")
        base = meta.get("pluginRoot") if isinstance(meta, dict) else None
        if "/" in value or not isinstance(base, str):
            return [_ask(spec, "its marketplace gives a path SkillTotal could not read")]
        relative = f"{base.removeprefix('./').rstrip('/')}/{value}"
    target = _inside(root, relative.rstrip("/"))
    if target is None or not target.is_dir():
        return [_ask(spec, "its marketplace gives a path outside the marketplace, or none")]
    return [Install(str(target))]


def _ref(source: dict[str, Any]) -> str:
    for key in ("sha", "ref"):
        value = source.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _repository(spec: str, url: object, ref: str, subdir: object = None) -> list[Install]:
    if not isinstance(url, str) or not url:
        return [_ask(spec, "its marketplace names no repository")]
    found = _github(f"{url}#{ref}" if ref else url)
    if found is None:
        host = _shown_host(url)
        where = f"a repository on {host}" if host else "a repository SkillTotal could not read"
        return [_ask(spec, f"it comes from {where}")]
    if found.source is None:
        return [_ask(spec, "its marketplace pins a ref SkillTotal could not reproduce")]
    if subdir is None:
        return [found]
    if not isinstance(subdir, str) or not _RELATIVE.fullmatch(subdir) or ".." in subdir.split("/"):
        return [_ask(spec, "its marketplace gives a path SkillTotal could not read")]
    # With no ref the branch is not known here: the whole repository holds the folder.
    return [Install(f"{found.source}/{subdir}")] if ref else [found]


def _npm(spec: str, source: dict[str, Any]) -> list[Install]:
    package = source.get("package")
    version = source.get("version")
    registry = source.get("registry")
    if isinstance(registry, str) and registry and not _public(registry):
        return [Install(None, f"{spec} from {_shown_host(registry) or 'a custom registry'}",
                        registry=True)]
    if not isinstance(package, str):
        return [_ask(spec, "its marketplace names no npm package")]
    name = package[:package.rfind("@")] if package.rfind("@") > 0 else package
    if not _NPM_NAME.fullmatch(name):
        return [_ask(spec, "its marketplace names an npm package SkillTotal could not read")]
    pinned = package.rfind("@") > 0
    wanted = package if pinned or not isinstance(version, str) or not version \
        else f"{package}@{version}"
    return _npm_spec(wanted, None)


def _from_entry(spec: str, entry: dict[str, Any], root: Path,
                catalog: dict[str, Any]) -> list[Install]:
    source = entry.get("source")
    if isinstance(source, str):
        return _relative(spec, source, root, catalog)
    if not isinstance(source, dict):
        return [_ask(spec, "its marketplace gives no source")]
    kind = source.get("source")
    if kind == "github":
        repo = source.get("repo")
        if not isinstance(repo, str) or "://" in repo or repo.count("/") != 1:
            return [_ask(spec, "its marketplace names no repository")]
        return _repository(spec, repo, _ref(source))
    if kind == "url":
        return _repository(spec, source.get("url"), _ref(source))
    if kind == "git-subdir":
        return _repository(spec, source.get("url"), _ref(source), source.get("path"))
    if kind == "npm":
        return _npm(spec, source)
    if kind == "archive":
        return [_ask(spec, "it comes from a zip archive")]
    if kind == "command":
        return [_ask(spec, "a command on this machine produces it")]
    return [_ask(spec, "its marketplace gives a source of a kind SkillTotal does not know")]


def _extras(spec: str, entry: dict[str, Any]) -> list[Install]:
    """What the catalog entry brings besides its source."""
    extras: list[Install] = []
    if any(entry.get(key) for key in _INLINE):
        extras.append(_ask(spec, "its marketplace entry adds code the scan does not read"))
    if entry.get("dependencies"):
        extras.append(_ask(spec, "it installs other plugins as dependencies"))
    return extras


def resolve(spec: str, claude_dir: Path) -> list[Install]:
    """What installing ``spec`` (``name@marketplace``, or a name) brings in."""
    name, _, wanted = spec.partition("@")
    markets = _marketplaces(claude_dir)
    if wanted:
        chosen = {wanted: markets[wanted]} if isinstance(markets.get(wanted), dict) else {}
    else:
        chosen = {key: value for key, value in markets.items() if isinstance(value, dict)}
    matches: list[tuple[dict[str, Any], Path, dict[str, Any]]] = []
    for market in chosen.values():
        found = _catalog(market)
        plugins = found[0].get("plugins") if found else None
        if not found or not isinstance(plugins, list):
            continue
        matches.extend((entry, found[1], found[0]) for entry in plugins
                       if isinstance(entry, dict) and entry.get("name") == name)
    if not matches:
        return [_ask(spec, "SkillTotal could not find it in a known marketplace")]
    if len(matches) > 1:
        return [_ask(spec, "more than one marketplace lists it")]
    entry, root, catalog = matches[0]
    return [*_from_entry(spec, entry, root, catalog), *_extras(spec, entry)]
