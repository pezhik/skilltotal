"""Lockfile installs: is an exact version on OSV's list of known malicious packages?

``npm ci`` or ``uv sync`` names no package for the hook to scan, but its lockfile names every one,
down to the transitive ones, at an exact version. OSV (api.osv.dev, operated by Google) publishes
known malicious releases under ``MAL-`` ids, so the hook can ask in one batch. This is a lookup of a
public list, not a scan of the code: it knows nothing about a package nobody has reported.

It is the only part of SkillTotal that sends anything about a project to a third party, so what it
may send is decided here, by proof and not by inference:

* an entry goes out only when the lockfile itself records that it resolved from the public
  registry (``registry.npmjs.org`` or ``registry.yarnpkg.com`` for npm, ``pypi.org`` for Python).
  The name and version are read from that same record;
* a scoped npm entry, a git, file, link or path dependency, an entry from any other host and an
  entry that records no registry (pnpm, yarn berry, a requirements file, poetry's default source)
  are never sent, whatever the machine's configuration says. They are counted, and the line says
  how many;
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
from skilltotal.agent_hook import _read_config
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
_PLAIN_NPM = re.compile(r"[a-z0-9][a-z0-9._-]{0,213}", re.IGNORECASE)
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
    """A lockfile, sorted by what may leave the machine."""

    public: set[Package] = field(default_factory=set)
    withheld: int = 0    # its registry is not proven public: never sent
    unparsed: int = 0    # read as an entry, but no name and version came of it

    def add(self, other: Entries) -> None:
        self.public |= other.public
        self.withheld += other.withheld
        self.unparsed += other.unparsed


def _npm_entry(found: Entries, name: object, version: object, resolved: object) -> None:
    """One npm entry. The public registry's URL proves it, and also names it:
    ``https://registry.npmjs.org/<name>/-/<name>-<version>.tgz``. An alias, or a name that does not
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
    if name.startswith("@") or "/" in name or "%2f" in resolved.lower():
        found.withheld += 1
        return
    if unquote(url.path) != f"/{name}/-/{name}-{version}.tgz":
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


def _yarn_lock(text: str) -> Entries | None:
    found = Entries()
    if re.search(r"^__metadata:", text, re.MULTILINE):
        # Yarn berry records `resolution: "x@npm:1.2.3"`, with no URL: the registry is not proven.
        found.withheld = len(re.findall(r"^\s+resolution: ", text, re.MULTILINE))
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


def _pnpm_lock(text: str) -> Entries | None:
    """pnpm records an integrity hash and no registry, so nothing here is proven public."""
    section = re.search(r"^packages:[ \t]*\r?\n(.*?)(?=^\S|\Z)", text, re.MULTILINE | re.DOTALL)
    if section is None:
        return Entries()
    return Entries(withheld=len(re.findall(r"^  \S.*:\s*(?:\{.*\})?\s*$", section.group(1),
                                           re.MULTILINE)))


_TOML_NAME = re.compile(r'^name = "([^"\n]*)"', re.MULTILINE)
_TOML_VERSION = re.compile(r'^version = "([^"\n]*)"', re.MULTILINE)
_UV_SOURCE = re.compile(r"^source = \{\s*(\w+)\s*=\s*\"([^\"\n]*)\"", re.MULTILINE)
_POETRY_SOURCE_URL = re.compile(r'^\[package\.source\]\s(?:.*\n)*?url = "([^"\n]*)"', re.MULTILINE)


def _pypi_index(url: str) -> bool:
    try:
        parts = urlsplit(url)
        return (parts.scheme == "https" and parts.hostname == "pypi.org" and not parts.username
                and not parts.port and parts.path.rstrip("/") == "/simple")
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
    """Poetry writes ``[package.source]`` only for a source other than its default, so most entries
    record no registry, and a default index can be replaced in configuration: not proven."""
    found = Entries()
    for block in text.split("[[package]]")[1:]:
        url = _POETRY_SOURCE_URL.search(block)
        _pypi_entry(found, block, url is not None and _pypi_index(url.group(1)))
    return found


_REQUIREMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?\s*==\s*[^\s;#\\]+")


def _requirements(text: str) -> Entries | None:
    """A requirements file records no registry, so a pin here is not proven public. A line that
    pins nothing is resolved by pip when it runs: nothing could be looked up."""
    found = Entries()
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            found.unparsed += 1  # another file, which is not followed
        elif not line or line.startswith(("#", "-")):
            continue
        elif _REQUIREMENT.match(line):
            found.withheld += 1
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
    withheld: int = 0         # never sent: the lockfile does not prove them public
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
            parts.append(f"{self.withheld} lockfile entries were not sent to OSV: the lockfile "
                         f"does not prove they come from the public registry.")
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


def lookup(files: list[str], cwd: str | None, transport: Transport, cache: Path,
           now: float | None = None) -> Lookup:
    """Look up what the lockfiles ``files`` name (as the command names them, under ``cwd``)."""
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
    result.withheld = entries.withheld
    result.not_checked = entries.unparsed
    known: dict[Package, list[str]] = {}
    fresh = _read_cache(cache)
    unseen: list[Package] = []
    for package in sorted(entries.public):
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
