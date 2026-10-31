"""Lockfile installs: is an exact version on OSV's list of known malicious packages?

``npm ci`` or ``uv sync`` names no package for the hook to scan, but its lockfile names every one,
down to the transitive ones, at an exact version. OSV (api.osv.dev, operated by Google) publishes
known malicious releases under ``MAL-`` ids, so the hook can ask in one batch. This is a lookup of a
public list, not a scan of the code: it knows nothing about a package nobody has reported.

It is the only part of SkillTotal that sends anything about a project to a third party. A package
is sent only when the install itself would fetch it from the public registry:

* an entry whose lockfile records a public URL (``registry.npmjs.org`` or ``registry.yarnpkg.com``
  for npm, ``pypi.org`` or ``files.pythonhosted.org`` for Python) is sent, scoped names included,
  unless an ``.npmrc`` maps that scope elsewhere or holds a token that could reach a private scope;
* an entry that records no URL (pnpm, yarn berry, a pinned requirements line, poetry's default
  source) is sent only when no custom registry is configured anywhere the installer would read
  (:func:`_settings`). With one present it may be private, so it is not sent;
* a git, file, link or path dependency and an entry from any other host are never sent. What is
  not sent is counted, and the line says how many;
* what goes out is ``{"package": {"name", "ecosystem"}, "version"}`` per entry and nothing else: no
  path, project name, identifier or hash, and a fixed ``User-Agent`` with no version.

The answer is worded for what it is. A clean answer is "no known-malicious version in OSV", and
never "safe": see :meth:`Lookup.line`. A lookup that failed is "not checked", never a pass.

``SKILLTOTAL_OSV=0`` turns it off. It lives in the hook layer: ``engine.analyze`` looks only at the
component, and ``scan``, ``guard`` and ``inventory`` make no such request.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from skilltotal import bounded_json
from skilltotal.agent_hook import (
    _env_get,
    _npm_configured,
    _npm_prefixes,
    _npm_stacks,
    _public,
    _py_configured,
    _read_config,
    _tool_config_files,
    _tool_configured,
)
from skilltotal.hook_scan import file_lock, write_atomic

OSV_ENV = "SKILLTOTAL_OSV"
OSV_URL = "https://api.osv.dev/v1/querybatch"
TIMEOUT_S = 5.0        # the whole lookup, however slowly the answer trickles in
MAX_QUERIES = 1000     # what OSV takes in one batch
CACHE_TTL_S = 3600     # short: a release can be reported at any time
_MAX_CACHE = 20_000
_MAX_LOCKFILE = 32 * 1024 * 1024
_MAX_ANSWER = 16 * 1024 * 1024
_OFF = frozenset({"0", "false", "no", "off"})
_NPM_HOSTS = frozenset({"registry.npmjs.org", "registry.yarnpkg.com"})
_PYPI_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})
_PLAIN_NPM = re.compile(r"(?:@[a-z0-9][a-z0-9._-]{0,100}/)?[a-z0-9][a-z0-9._-]{0,213}",
                        re.IGNORECASE)
_PLAIN_PYPI = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_PLAIN_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+!_-]{0,63}")
_MAL_ID = re.compile(r"MAL-[0-9A-Za-z-]{1,40}")
# npm's placeholder for a package it took down: nothing to install, and every one is on the list.
_NPM_HELD = "0.0.1-security"
NPM, PYPI = "npm", "PyPI"
_LOCKFILES_OF = {
    "package.json": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"),
    "pyproject.toml": ("uv.lock", "poetry.lock"),
}
_NO_LOCKFILE = frozenset({"package.json", "pyproject.toml"})


def enabled(environ: Mapping[str, str]) -> bool:
    """On unless ``SKILLTOTAL_OSV`` turns it off; a value that is neither stays on."""
    return environ.get(OSV_ENV, "").strip().lower() not in _OFF


@dataclass(frozen=True, order=True)
class Package:
    ecosystem: str
    name: str
    version: str

    def key(self) -> str:
        return f"{self.ecosystem}|{self.name}|{self.version}"


@dataclass
class Entries:
    """A lockfile, sorted by what proves where each entry comes from."""

    public: set[Package] = field(default_factory=set)    # the lockfile records a public URL
    unproven: set[Package] = field(default_factory=set)  # it records no URL at all
    withheld: int = 0    # it records something else: a private host, git, a path. Never sent
    unparsed: int = 0    # read as an entry, but no name and version came of it
    indexes: bool = False  # the file itself names an index (a requirements file's --index-url)

    def add(self, other: Entries) -> None:
        self.public |= other.public
        self.unproven |= other.unproven
        self.withheld += other.withheld
        self.unparsed += other.unparsed
        self.indexes = self.indexes or other.indexes


def _no_url(found: Entries, ecosystem: str, name: str, version: str) -> None:
    """An entry whose lockfile records no registry."""
    plain = _PLAIN_NPM if ecosystem == NPM else _PLAIN_PYPI
    if not plain.fullmatch(name) or not _PLAIN_VERSION.fullmatch(version):
        found.unparsed += 1
    elif not (ecosystem == NPM and version == _NPM_HELD):
        found.unproven.add(Package(ecosystem, name, version))


def _npm_entry(found: Entries, name: object, version: object, resolved: object) -> None:
    """One npm entry. The public registry's URL proves it, and also names it:
    ``https://registry.npmjs.org/<name>/-/<base>-<version>.tgz``. An alias, or a name that does not
    match its URL, is not what it says it is."""
    if not isinstance(resolved, str) or not resolved:
        found.withheld += 1
        return
    try:
        url = urlsplit(resolved)
        host = url.hostname
    except ValueError:
        found.withheld += 1
        return
    if url.scheme != "https" or host not in _NPM_HOSTS or url.username or url.port:
        found.withheld += 1
        return
    if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
        found.unparsed += 1
        return
    if unquote(url.path) != f"/{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz":
        found.withheld += 1
        return
    if not _PLAIN_NPM.fullmatch(name) or not _PLAIN_VERSION.fullmatch(version):
        found.unparsed += 1
        return
    if version != _NPM_HELD:
        found.public.add(Package(NPM, name, version))


def _npm_tree(found: Entries, dependencies: dict[str, Any]) -> None:
    """A version 1 lockfile: entries nest."""
    for name, entry in dependencies.items():
        if isinstance(entry, dict):
            _npm_entry(found, name, entry.get("version"), entry.get("resolved"))
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                _npm_tree(found, nested)
        else:
            found.unparsed += 1


def _npm_lock(text: str) -> Entries | None:
    data = bounded_json.loads(text)
    if not isinstance(data, dict):
        return None
    found = Entries()
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, entry in packages.items():
            if not path:
                continue  # the project itself
            if not isinstance(entry, dict):
                found.unparsed += 1
                continue
            name = path.rsplit("node_modules/", 1)[-1]
            _npm_entry(found, name, entry.get("version"), entry.get("resolved"))
        return found
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        _npm_tree(found, dependencies)
        return found
    return None


_YARN_BLOCK = re.compile(r'^("?)(.+?)\1(?:, .*)?:\r?$')
_YARN_FIELD = re.compile(r'^  (version|resolved) "([^"]*)"')
_BERRY_RESOLUTION = re.compile(r'^\s+resolution: "([^"\n]*)"', re.MULTILINE)
_BERRY_NPM = re.compile(r"(@?[^@]+)@npm:([^:@]+)")


def _yarn_lock(text: str) -> Entries | None:
    found = Entries()
    if re.search(r"^__metadata:", text, re.MULTILINE):
        # Yarn berry records `resolution: "x@npm:1.2.3"`, with no URL. Anything else there is a
        # workspace, a patch, a git or file source; `::` marks an archive URL of its own.
        for resolution in _BERRY_RESOLUTION.finditer(text):
            parts = _BERRY_NPM.fullmatch(resolution.group(1))
            if parts:
                _no_url(found, NPM, parts.group(1), parts.group(2))
            elif "@workspace:" not in resolution.group(1):
                found.withheld += 1
        return found
    name: str | None = None
    fields: dict[str, str] = {}

    def finish() -> None:
        if name is not None:
            _npm_entry(found, name, fields.get("version"), fields.get("resolved", "").split("#")[0])

    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if not line.startswith(" "):
            finish()
            header = _YARN_BLOCK.match(line)
            name, fields = (header.group(2).rsplit("@", 1)[0] if header else ""), {}
            continue
        field_line = _YARN_FIELD.match(line)
        if field_line:
            fields[field_line.group(1)] = field_line.group(2)
    finish()
    return found


# Any key of the section, whatever its version holds: a key this misses would hand its body to the
# entry before it. A version that is a URL or a path fails the plain test further on.
_PNPM_KEY = re.compile(r"""^  ['"]?/?(@?[^@\s'"(/]+(?:/[^@\s'"(/]+)?)[@/]([^\s'"(]+)[^\s'"]*['"]?:"""
                       r"""\s*(?:\{.*\})?\s*$""")
_PNPM_TARBALL = re.compile(r"tarball:\s*([^\s,}]+)")


def _pnpm_lock(text: str) -> Entries | None:
    """pnpm records an integrity hash and no URL for a package from the default registry, and a
    ``tarball`` or a ``type`` (git, directory) in its ``resolution`` for anything else."""
    section = re.search(r"^packages:[ \t]*\r?\n(.*?)(?=^\S|\Z)", text, re.MULTILINE | re.DOTALL)
    found = Entries()
    if section is None:
        return found
    lines = section.group(1).splitlines()
    keys = [(i, match) for i, line in enumerate(lines) if (match := _PNPM_KEY.match(line))]
    for position, (i, match) in enumerate(keys):
        end = keys[position + 1][0] if position + 1 < len(keys) else len(lines)
        body = "\n".join(lines[i + 1:end])
        name, version = match.group(1), match.group(2)
        tarball = _PNPM_TARBALL.search(body)
        if tarball:
            _npm_entry(found, name, version, tarball.group(1))
        elif "type:" in body:
            found.withheld += 1
        else:
            _no_url(found, NPM, name, version)
    return found


_TOML_NAME = re.compile(r'^name = "([^"\n]*)"', re.MULTILINE)
_TOML_VERSION = re.compile(r'^version = "([^"\n]*)"', re.MULTILINE)
_UV_SOURCE = re.compile(r"^source = \{\s*(\w+)\s*=\s*\"([^\"\n]*)\"", re.MULTILINE)
_POETRY_SOURCE_URL = re.compile(r'^\[package\.source\]\s(?:.*\n)*?url = "([^"\n]*)"', re.MULTILINE)


def _pypi_index(url: str) -> bool:
    try:
        parts = urlsplit(url)
        return (parts.scheme == "https" and parts.hostname in _PYPI_HOSTS and not parts.username
                and not parts.port and (parts.hostname != "pypi.org"
                                        or parts.path.rstrip("/") == "/simple"))
    except ValueError:
        return False


def _pypi_entry(found: Entries, block: str, proven: bool) -> None:
    name, version = _TOML_NAME.search(block), _TOML_VERSION.search(block)
    if not proven:
        found.withheld += 1
    elif name is None or version is None or not _PLAIN_PYPI.fullmatch(name.group(1)) or (
            not _PLAIN_VERSION.fullmatch(version.group(1))):
        found.unparsed += 1
    else:
        found.public.add(Package(PYPI, name.group(1), version.group(1)))


def _pypi_no_url(found: Entries, block: str) -> None:
    name, version = _TOML_NAME.search(block), _TOML_VERSION.search(block)
    if name is None or version is None:
        found.unparsed += 1
    else:
        _no_url(found, PYPI, name.group(1), version.group(1))


def _uv_lock(text: str) -> Entries | None:
    found = Entries()
    for block in text.split("[[package]]")[1:]:
        source = _UV_SOURCE.search(block)
        if source is not None and source.group(1) in ("virtual", "editable"):
            continue  # the project itself
        _pypi_entry(found, block, source is not None and source.group(1) == "registry"
                    and _pypi_index(source.group(2)))
    return found


def _poetry_lock(text: str) -> Entries | None:
    """Poetry writes ``[package.source]`` only for a source other than its default, so an entry
    without one records no URL."""
    found = Entries()
    for block in text.split("[[package]]")[1:]:
        if "[package.source]" not in block:
            _pypi_no_url(found, block)
            continue
        url = _POETRY_SOURCE_URL.search(block)
        _pypi_entry(found, block, url is not None and _pypi_index(url.group(1)))
    return found


_REQUIREMENT = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;#\\,]+)\s*"
                          r"(?:[;#\\].*)?$")
_INDEX_LINE = re.compile(r"(?:--index-url|--extra-index-url|--find-links|-i|-f)(?:[\s=]|$)")


def _requirements(text: str) -> Entries | None:
    """A requirements file records no URL for a pin. A line that pins nothing is resolved by pip
    when it runs, so it cannot be looked up. An index it names counts as configured."""
    found = Entries()
    for raw in text.splitlines():
        line = raw.strip()
        if _INDEX_LINE.match(line):
            found.indexes = True
        elif line.startswith(("-r", "--requirement", "-c", "--constraint")):
            found.unparsed += 1  # another file, which is not followed
        elif not line or line.startswith(("#", "-")):
            continue
        else:
            pin = _REQUIREMENT.match(line)
            if pin:
                _no_url(found, PYPI, pin.group(1), pin.group(2))
            else:
                found.unparsed += 1
    return found


_READERS: dict[str, Callable[[str], Entries | None]] = {
    "package-lock.json": _npm_lock, "npm-shrinkwrap.json": _npm_lock, "yarn.lock": _yarn_lock,
    "pnpm-lock.yaml": _pnpm_lock, "uv.lock": _uv_lock, "poetry.lock": _poetry_lock,
}


def _reader(name: str) -> Callable[[str], Entries | None] | None:
    if name in _READERS:
        return _READERS[name]
    return _requirements if name.lower().endswith((".txt", ".in")) else None


# --- What the machine says about registries -------------------------------------------------------

_NPMRC_SCOPE = re.compile(r"^\s*(@[^:=\s]+):registry\s*=\s*(\S*)", re.MULTILINE)
_NPMRC_TOKEN = re.compile(
    r"^\s*(?://registry\.npmjs\.org/:)?(?:_authToken|_auth|_password)\s*=", re.MULTILINE)
_NPMRC_SCOPED_TOKEN = re.compile(r"^\s*(@[^:=\s]+):_auth(?:Token)?\s*=", re.MULTILINE)
_ENV_SCOPE = re.compile(r"npm_config_(@[^:]+):registry", re.IGNORECASE)
_PYPROJECT_SOURCE = re.compile(r"^\s*\[\[tool\.(?:poetry|pdm)\.source\]\]", re.MULTILINE)
_COMMAND_INDEX = re.compile(r"(?:^|\s)(?:--ind|--ext|--fin|--reg|-i(?=\s)|-f(?=\s))")


@dataclass
class Registries:
    """What installers on this machine are configured to read, for what a lockfile cannot prove."""

    npm: bool = False    # a custom registry for npm, pnpm, yarn or bun is configured somewhere
    pypi: bool = False   # a custom index is
    scopes: set[str] = field(default_factory=set)  # npm scopes mapped or holding a token
    all_scopes: bool = False  # a token for the public registry can reach any private scope

    def scoped_private(self, package: Package) -> bool:
        if package.ecosystem != NPM or not package.name.startswith("@"):
            return False
        return self.all_scopes or package.name.split("/", 1)[0].lower() in self.scopes


def _npmrc_texts(folder: Path, environ: Mapping[str, str], home: Path | None) -> list[str | None]:
    """The project's and the person's ``.npmrc``, as text; None for one too large to read."""
    paths = [prefix / ".npmrc" for prefix in _npm_prefixes(folder)]
    moved = _env_get(environ, "NPM_CONFIG_USERCONFIG")
    if moved:
        paths.append(Path(moved))
    elif home is not None:
        paths.append(home / ".npmrc")
    return [_read_config(path) for path in paths]


def _npm_settings(found: Registries, folder: Path, environ: Mapping[str, str],
                  home: Path | None, tools: list[Path]) -> None:
    if _npm_configured("", _npm_stacks(folder, environ, home), environ) is not None:
        found.npm = True
    if any(_tool_configured(tool, tools, environ) for tool in ("yarn", "bun", "pnpm")):
        found.npm = True
    for name in environ:
        scope = _ENV_SCOPE.fullmatch(name)
        if scope:
            found.npm = True
            found.scopes.add(scope.group(1).lower())
    for text in _npmrc_texts(folder, environ, home):
        if text is None:
            found.npm = found.all_scopes = True
            continue
        for scope, value in _NPMRC_SCOPE.findall(text):
            if not _public(value):
                found.npm = True
                found.scopes.add(scope.lower())
        found.scopes.update(scope.lower() for scope in _NPMRC_SCOPED_TOKEN.findall(text))
        found.all_scopes = found.all_scopes or bool(_NPMRC_TOKEN.search(text))
    for base in tools:
        text = _read_config(base / ".yarnrc.yml")
        if text is None or (text and re.search(r"^npmScopes:", text, re.MULTILINE)):
            found.npm = found.all_scopes = True


def _pypi_settings(found: Registries, environ: Mapping[str, str], home: Path | None,
                   tools: list[Path]) -> None:
    if _py_configured(environ, home, "", tools) is not None or _tool_configured(
            "uv", tools, environ) is not None:
        found.pypi = True
    for base in tools:
        text = _read_config(base / "pyproject.toml", 256 * 1024)
        if text is None or (text and _PYPROJECT_SOURCE.search(text)):
            found.pypi = True


def _settings(folder: Path, environ: Mapping[str, str], home: Path | None,
              command: str) -> Registries:
    """Every place an installer on this machine may be told to read something other than the
    public registry: project and user ``.npmrc``, yarn, pnpm and bun configuration, ``pip.conf``,
    the environment, uv's and poetry's sources in ``pyproject.toml``, and the command itself. A
    home folder that cannot be found, or a file too large to read, counts as configured."""
    found = Registries()
    if home is None:
        return Registries(npm=True, pypi=True, all_scopes=True)
    tools = _tool_config_files(folder, environ, home)
    _npm_settings(found, folder, environ, home, tools)
    _pypi_settings(found, environ, home, tools)
    if _COMMAND_INDEX.search(command):
        found.npm = found.pypi = True
    return found


def read_lockfile(path: Path) -> Entries | None:
    """The file's entries; None when it cannot be read as the lockfile it is named after."""
    reader = _reader(path.name)
    text = _read_config(path, _MAX_LOCKFILE)
    if reader is None or not text:
        return None
    try:
        return reader(text)
    except (ValueError, RecursionError):
        return None


@dataclass
class Lookup:
    """What one lookup found, and what it did not cover."""

    known: list[tuple[Package, list[str]]] = field(default_factory=list)  # malicious, with ids
    asked: int = 0            # packages OSV answered for (this run or within the cache's life)
    withheld: int = 0         # not sent: they may come from somewhere private
    not_checked: int = 0      # could not be parsed, or the batch failed or was too long
    failed: bool = False      # OSV did not answer
    no_lockfile: bool = False # `npm install` with nothing to read
    unread: list[str] = field(default_factory=list)  # lockfiles it could not read

    @property
    def incomplete(self) -> bool:
        """Something that should have been looked up was not: "not checked", never a pass."""
        return self.failed or self.not_checked > 0 or bool(self.unread)

    def hit_lines(self) -> list[str]:
        return [f"{pkg.name} {pkg.version} ({', '.join(ids)})" for pkg, ids in self.known]

    def line(self) -> str:
        """The console line. A clean answer says what it is and no more."""
        parts: list[str] = []
        if self.no_lockfile:
            parts.append("OSV was not asked: there is no lockfile, so which packages this brings "
                         "in is not known until the installer resolves them.")
        if self.failed:
            parts.append(f"OSV could not be reached: {self.not_checked} package(s) not checked.")
        elif self.asked and not self.known:
            parts.append(f"No known-malicious version in OSV for the {self.asked} package(s) "
                         f"looked up; a lookup is not a scan of their code.")
        elif self.asked:
            parts.append(f"{self.asked} package(s) looked up in OSV.")
        if self.not_checked and not self.failed:
            parts.append(f"{self.not_checked} lockfile entries were not checked in OSV.")
        if self.withheld:
            parts.append(f"{self.withheld} lockfile entries were not sent to OSV: they may come "
                         f"from a private registry.")
        if self.unread:
            parts.append(f"Not checked in OSV: {', '.join(self.unread)} could not be read.")
        return " ".join(parts)


def _read_cache(path: Path) -> dict[str, Any]:
    try:
        data = bounded_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_cache(path: Path, entries: dict[str, list[str]], now: float) -> None:
    """Best effort: a package that could not be remembered is only asked about again."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with file_lock(path.with_suffix(".lock"), wait_s=1.0):
            cache = {key: value for key, value in _read_cache(path).items()
                     if isinstance(value, dict) and _fresh(value, now)}
            cache.update({key: {"at": now, "ids": ids} for key, ids in entries.items()})
            newest = sorted(cache.items(), key=lambda item: item[1]["at"])[-_MAX_CACHE:]
            write_atomic(path, json.dumps(dict(newest)))
    except (OSError, TimeoutError):
        pass


def _fresh(entry: object, now: float) -> bool:
    if not isinstance(entry, dict):
        return False
    at = entry.get("at")
    return (isinstance(at, (int, float)) and not isinstance(at, bool)
            and 0 <= now - at < CACHE_TTL_S and isinstance(entry.get("ids"), list))


def _ids(result: object) -> tuple[list[str], bool] | None:
    """The MAL ids of one answer, and whether more pages hold ids it does not list; None when it
    is not an answer."""
    if not isinstance(result, dict):
        return None
    vulns = result.get("vulns", [])
    if not isinstance(vulns, list):
        return None
    ids = [v["id"] for v in vulns if isinstance(v, dict) and isinstance(v.get("id"), str)
           and _MAL_ID.fullmatch(v["id"])]
    return ids, bool(result.get("next_page_token"))


Transport = Callable[[bytes], bytes]


def _ask(packages: list[Package], transport: Transport) -> list[object] | None:
    """One batch: OSV's answers in the order asked, or None when there is no usable answer."""
    body = json.dumps({"queries": [
        {"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}
        for p in packages]}).encode("utf-8")
    try:
        answer = bounded_json.loads(transport(body).decode("utf-8"))
    except Exception:  # noqa: BLE001 - any failure of the lookup is "not checked"
        return None
    results = answer.get("results") if isinstance(answer, dict) else None
    return results if isinstance(results, list) and len(results) == len(packages) else None


def _sendable(entries: Entries, settings: Registries) -> tuple[set[Package], int]:
    """What may leave the machine, and how many entries may not, by the rule at the top."""
    send: set[Package] = set()
    held = 0
    for package in entries.public:
        if settings.scoped_private(package):
            held += 1
        else:
            send.add(package)
    for package in entries.unproven - entries.public:
        custom = settings.npm if package.ecosystem == NPM else (settings.pypi or entries.indexes)
        if custom or settings.scoped_private(package):
            held += 1
        else:
            send.add(package)
    return send, held


def lookup(files: list[str], cwd: str | None, transport: Transport, cache: Path,
           now: float | None = None, *, environ: Mapping[str, str] | None = None,
           home: Path | None = None, command: str = "") -> Lookup:
    """Look up what the lockfiles ``files`` name (as the command names them, under ``cwd``).
    ``environ``, ``home`` and ``command`` say what the machine is configured to read."""
    now = time.time() if now is None else now
    result = Lookup()
    entries = Entries()
    folder = Path(cwd) if cwd and Path(cwd).is_absolute() else None
    if folder is None:
        result.unread = list(dict.fromkeys(files))
        return result
    for file in dict.fromkeys(files):
        target = folder / file
        candidates = [folder / name for name in _LOCKFILES_OF.get(file, ())] or [target]
        present = [path for path in candidates if path.is_file()]
        if not present:
            if file in _NO_LOCKFILE:
                result.no_lockfile = True
            else:
                result.unread.append(file)
            continue
        for path in present[:1]:
            read = read_lockfile(path)
            if read is None:
                result.unread.append(path.name)
            else:
                entries.add(read)
    send, held = _sendable(entries, _settings(folder, environ or {}, home, command))
    result.withheld = entries.withheld + held
    result.not_checked = entries.unparsed
    known: dict[Package, list[str]] = {}
    fresh = _read_cache(cache)
    unseen: list[Package] = []
    for package in sorted(send):
        hit = fresh.get(package.key())
        if _fresh(hit, now):
            known[package] = [i for i in hit["ids"] if isinstance(i, str) and _MAL_ID.fullmatch(i)]
            result.asked += 1
        else:
            unseen.append(package)
    sent, left = unseen[:MAX_QUERIES], unseen[MAX_QUERIES:]
    result.not_checked += len(left)
    if sent:
        answers = _ask(sent, transport)
        if answers is None:
            result.failed = True
            result.not_checked += len(sent)
        else:
            store: dict[str, list[str]] = {}
            for package, answer in zip(sent, answers, strict=True):
                read_ids = _ids(answer)
                if read_ids is None or (read_ids[1] and not read_ids[0]):
                    result.not_checked += 1  # not read, or the ids may be on a further page
                    continue
                known[package] = read_ids[0]
                store[package.key()] = read_ids[0]
                result.asked += 1
            _write_cache(cache, store, now)
    result.known = [(package, ids) for package, ids in sorted(known.items()) if ids]
    return result


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # the body goes to OSV and nowhere else


def post(body: bytes, timeout: float = TIMEOUT_S) -> bytes:
    """One POST to OSV, for ``timeout`` seconds in all. urllib's own timeout covers each network
    step, not a slow name lookup or a trickle of data, so it runs in a thread this process does
    not wait for past the limit. No retry: a lookup that fails is "not checked". Only the content
    type and a fixed name go along."""
    request = urllib.request.Request(  # noqa: S310
        OSV_URL, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "skilltotal"})
    opener = urllib.request.build_opener(_NoRedirects)
    got: list[bytes] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            with opener.open(request, timeout=timeout) as response:  # nosec B310 - fixed https URL
                data = response.read(_MAX_ANSWER + 1)
            if len(data) > _MAX_ANSWER:
                raise ValueError("answer too long")
            got.append(data)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            errors.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout)
    if not got:
        raise TimeoutError("no answer from OSV")
    return got[0]
