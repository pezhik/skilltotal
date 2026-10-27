"""Source collection: resolve a path or URL into a local directory + component identity.

Supported sources: a local directory, or a remote git URL (cloned shallowly into a temp
directory). Component identity (name/type/version) is derived **only** from the component
itself — never from the user's environment.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import stat
import subprocess  # nosec B404
import tarfile
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import NamedTuple
from urllib.parse import quote, urljoin, urlparse, urlsplit

from skilltotal import bounded_json
from skilltotal.file_index import MAX_FILE_BYTES

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

from skilltotal.file_index import is_regular_file, neutralize_hidden, walk_files
from skilltotal.models import Component

_GIT_URL_RE = re.compile(r"^(?:https?://|git@|ssh://|git://).+", re.IGNORECASE)
_NPMJS_URL_RE = re.compile(r"^https?://(?:www\.)?npmjs\.com/package/(@?[\w.-]+(?:/[\w.-]+)?)", re.I)
_PYPI_URL_RE = re.compile(r"^https?://pypi\.org/project/([\w.-]+)", re.I)
# Conservative package-name shapes (also block path traversal in specs). ASCII-only on purpose
# (npm/PyPI names are ASCII by spec): `\w` would be Unicode and let e.g. cyrillic pass validation
# and reach the registry, whose 404 then reflected the raw input back to the user.
_NPM_NAME_RE = re.compile(r"^@?[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)?$", re.I)
_PYPI_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$", re.I)

_HTTP_TIMEOUT = 60  # seconds for a registry/download request
# Every temporary folder a scan downloads, clones or extracts into starts with this, in
# tempfile.gettempdir(); a killed scan leaves its folder behind (see mcp_server's sweep).
TEMP_DIR_PREFIX = "skilltotal_"
# Archive caps (env-overridable so a hosted upload path can tighten them on a small box):
#   SKILLTOTAL_MAX_ARCHIVE_MB   — max size of the archive itself (downloaded or uploaded)
#   SKILLTOTAL_MAX_EXTRACT_MB   — max total uncompressed size (decompression-bomb guard)
#   SKILLTOTAL_MAX_ARCHIVE_MEMBERS — max number of entries (anti "millions of tiny files" DoS)
# The whole-number settings below, with their defaults. A value that is not a positive whole
# number keeps the default here (a library import never crashes on its environment); the CLI
# refuses it with an error first (cli.invalid_settings).
INT_SETTINGS = {
    "SKILLTOTAL_MAX_ARCHIVE_MB": 150, "SKILLTOTAL_MAX_EXTRACT_MB": 400,
    "SKILLTOTAL_MAX_ARCHIVE_MEMBERS": 30000, "SKILLTOTAL_CLONE_TIMEOUT": 300,
    "SKILLTOTAL_MAX_CLONE_MB": 200, "SKILLTOTAL_MAX_READABLE_MB": None,
}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else default


_MAX_ARCHIVE_BYTES = _env_int("SKILLTOTAL_MAX_ARCHIVE_MB", 150) * 1024 * 1024
_MAX_EXTRACT_BYTES = _env_int("SKILLTOTAL_MAX_EXTRACT_MB", 400) * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = _env_int("SKILLTOTAL_MAX_ARCHIVE_MEMBERS", 30000)
# Local archive sources accepted by `scan <path>` (besides a directory and a single file). Zip is
# also the container of formats that carry their own extension: Claude Desktop extensions (.mcpb,
# formerly .dxt), Python wheels and VS Code extensions. Any other local file that starts with the
# zip signature is extracted as one too.
_TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz")
_ZIP_SUFFIXES = (".zip", ".mcpb", ".dxt", ".whl", ".vsix")
_ZIP_MAGIC = b"PK\x03\x04"
# PEP 706 extraction filters: Python 3.12+, and the security releases that backported them to
# 3.8-3.11 (where `tarfile.data_filter` exists, so does the `filter=` argument). "data" refuses
# absolute paths, paths out of the destination and special files, and makes files owner-readable.
_TAR_FILTER: dict[str, str] = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
# Inflated bytes a tar may hold beyond its members' data: one header block, padding and pax
# records per member. Past _MAX_EXTRACT_BYTES plus this much, inflating stops (see _BoundedReader).
_TAR_OVERHEAD_PER_MEMBER = 4096
# Bound a git clone so a slow/huge remote can't hang the caller (a long-lived server holds a
# request the whole time); overridable via env. noninteractive_git_env() keeps a clone from
# blocking forever on a credential prompt for a private/typo'd URL.
_CLONE_TIMEOUT = _env_int("SKILLTOTAL_CLONE_TIMEOUT", 300)
# Reject repositories larger than this (MB). Checked before cloning (GitHub API) and again
# during the clone (a watchdog kills git if the working tree blows past the cap) so a huge repo
# can neither hang nor fill the disk / OOM the box. Overridable via env.
_MAX_CLONE_MB = _env_int("SKILLTOTAL_MAX_CLONE_MB", 200)
# The second limit bounds WORK rather than bytes: the readable text an index will actually open.
# The two are not the same constraint and a single number cannot serve both -- a repository of
# video is enormous to clone and trivial to scan, while one of pure source is the reverse, and
# scan time tracks the readable part alone. It defaults to the clone limit, where it can never
# fire on its own (readable bytes are a subset of the tree), so the offline CLI is unchanged. A
# deployment that kills a scan at a wall clock sets it to whatever fits inside that wall; without
# it, such a host accepts a repository it cannot finish and times out instead of saying no.
_MAX_READABLE_MB = _env_int("SKILLTOTAL_MAX_READABLE_MB", _MAX_CLONE_MB)
# The index refuses any single file this big, whatever it holds, so a pre-clone estimate of the
# work ahead must not count those bytes either. Imported rather than repeated: one number.
_MAX_INDEXED_FILE_BYTES = MAX_FILE_BYTES
_CLONE_POLL_SECONDS = 1.5
# Web hosts whose browser URLs we understand (branch / subfolder / file / commit links).
_WEB_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "huggingface.co")
# Hosts known to serve partial clones (`--filter=blob:none`): a subfolder link then downloads
# only that folder's files. Elsewhere the checkout is still sparse, but the pack is whole.
_PARTIAL_CLONE_HOSTS = {"github.com", "gitlab.com"}
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)
# A branch/tag name that can go into a GitHub API path as-is (no traversal, no query).
_SAFE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
# Hugging Face repo-type prefixes: a model is `hf.co/<org>/<name>`, but datasets and spaces nest
# under `hf.co/datasets/<org>/<name>` and `hf.co/spaces/<org>/<name>`.
_HF_REPO_PREFIXES = ("datasets", "spaces")
# HF browser ref kinds: tree (dir), blob (file), resolve (raw file).
_HF_REF_KINDS = ("tree", "blob", "resolve")


class CollectionError(Exception):
    """Raised when a source cannot be resolved into an analyzable directory."""


# Every setting a SizeLimitError can name. A hook reads the name back from a file its check
# wrote, and takes only one of these.
LIMIT_VARIABLES = frozenset({
    "SKILLTOTAL_MAX_ARCHIVE_MB", "SKILLTOTAL_MAX_EXTRACT_MB", "SKILLTOTAL_MAX_ARCHIVE_MEMBERS",
    "SKILLTOTAL_MAX_CLONE_MB", "SKILLTOTAL_MAX_READABLE_MB",
})


def _raise_hint(variable: str) -> str:
    return f"To scan it anyway, set {variable} to a higher value."


def _mb(n_bytes: int) -> int:
    return n_bytes // (1024 * 1024)


class SizeLimitError(CollectionError):
    """A source over one of the size limits a person can raise.

    ``variable`` names the setting that raises it, so the CLI and the hook can say which one.
    "archive is too large" alone left people guessing which of five limits had refused them.
    The start of each message stays as it was: callers file these refusals by it.
    """

    def __init__(self, message: str, *, variable: str) -> None:
        super().__init__(f"{message} {_raise_hint(variable)}")
        self.variable = variable


class SourceTooLargeError(SizeLimitError):
    """Raised when a repository exceeds the configured size cap (pre-clone or mid-clone).

    ``measured_mb`` and ``limit_mb`` carry the numbers as data, not only inside the message, so a
    caller can tell someone how far over they are. "Too large" alone is a dead end: a visitor
    whose repository came to 202 MB against a 200 MB limit has no way to know it was two
    megabytes and that a subfolder would work. ``measured_mb`` is None when the clone was aborted
    mid-transfer, where the total is genuinely unknown.
    """

    def __init__(self, message: str, *, measured_mb: int | None = None,
                 limit_mb: int | None = None,
                 variable: str = "SKILLTOTAL_MAX_CLONE_MB") -> None:
        super().__init__(message, variable=variable)
        self.measured_mb = measured_mb
        self.limit_mb = limit_mb if limit_mb is not None else _MAX_CLONE_MB


@dataclass
class SourceContext:
    """A resolved, analyzable component on local disk."""

    root: Path
    component: Component
    _tempdir: tempfile.TemporaryDirectory | None = None
    # Set when a browser URL was normalized to scan something other than what was pasted
    # (e.g. a /issues link reduced to the repo's default branch); surfaced in the report.
    note: str | None = None
    # Archive entries that were deliberately not extracted (links, FIFOs, devices).
    skipped_entries: int = 0
    # A PyPI release is several files (wheels, an sdist), one of which is scanned: which one,
    # and how many were not read.
    distribution_note: str | None = None
    # Set when a registry package was fetched through a configured mirror, not the public registry.
    mirror_note: str | None = None

    def __enter__(self) -> SourceContext:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        if self._tempdir is not None:
            self._tempdir.cleanup()
            self._tempdir = None


def find_program(name: str, environ=None, os_name: str = os.name) -> str | None:
    """The absolute path of program ``name`` from the absolute directories on PATH, or None.

    ``shutil.which`` on Windows before Python 3.12 looks in the current directory first, whatever
    PATH says: a scan run inside a checkout (the pre-commit hook, CI) would start a ``git.bat``
    committed to it. Here '.', empty and relative PATH entries are skipped, and the current
    directory is never searched.
    """
    environ = os.environ if environ is None else environ
    if os_name == "nt":
        exts = [e for e in environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if e]
        if any(name.lower().endswith(e.lower()) for e in exts):
            exts = [""]
    else:
        exts = [""]
    for entry in environ.get("PATH", "").split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or not os.path.isabs(entry):
            continue
        for ext in exts:
            candidate = os.path.join(entry, name + ext)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None


def _git_program() -> str:
    git = find_program("git")
    if git is None:
        raise CollectionError("git is required to analyze remote URLs but was not found on PATH.")
    return git


def is_url(source: str) -> bool:
    return bool(_GIT_URL_RE.match(source.strip()))


def classify_source(source: str) -> str:
    """Classify a source string into 'npm', 'pypi', 'git', or 'local'."""
    s = source.strip()
    if s.lower().startswith("npm:") or _NPMJS_URL_RE.match(s):
        return "npm"
    if s.lower().startswith("pypi:") or _PYPI_URL_RE.match(s):
        return "pypi"
    if is_url(s):
        return "git"
    return "local"


def npm_package_spec(source: str) -> tuple[str | None, str | None]:
    """Parse `npm:<name>[@<version>]` (or an npmjs.com URL) into (name, version).

    Scoped names keep their leading ``@`` (``@scope/pkg``); only a trailing ``@version``
    after the name is treated as a pin. Returns ``(None, None)`` for an invalid name.
    """
    s = source.strip()
    if s.lower().startswith("npm:"):
        spec = s[4:].strip()
    else:
        m = _NPMJS_URL_RE.match(s)
        spec = m.group(1) if m else ""
    version: str | None = None
    # Split a trailing @version, but not the leading scope '@'. Look for '@' after index 0.
    at = spec.find("@", 1)
    if at > 0:
        spec, version = spec[:at], spec[at + 1:].strip() or None
    if not (spec and _NPM_NAME_RE.match(spec)):
        return None, None
    return spec, version


def pypi_package_spec(source: str) -> tuple[str | None, str | None]:
    """Parse `pypi:<name>[==<version>]` / `pypi:<name>[@<version>]` into (name, version)."""
    s = source.strip()
    if s.lower().startswith("pypi:"):
        spec = s[5:].strip()
    else:
        m = _PYPI_URL_RE.match(s)
        spec = m.group(1) if m else ""
    version: str | None = None
    for sep in ("==", "@"):
        if sep in spec:
            spec, _, ver = spec.partition(sep)
            spec, version = spec.strip(), ver.strip() or None
            break
    if not (spec and _PYPI_NAME_RE.match(spec)):
        return None, None
    return spec, version


def npm_package_name(source: str) -> str | None:
    """Extract the npm package name from an `npm:<name>` spec or an npmjs.com URL."""
    return npm_package_spec(source)[0]


def pypi_package_name(source: str) -> str | None:
    """Extract the PyPI project name from a `pypi:<name>` spec or a pypi.org URL."""
    return pypi_package_spec(source)[0]


def collect(source: str, *, on_size: Callable[[TreeSize], None] | None = None) -> SourceContext:
    """Resolve ``source`` into a :class:`SourceContext`.

    Supports a local directory, a git URL (shallow clone), and npm / PyPI packages
    (`npm:<name>` / `pypi:<name>` specs or npmjs.com / pypi.org URLs — the latest published
    release is downloaded from the registry and extracted).

    ``on_size`` is called once, before the clone starts, with the :class:`TreeSize` of a GitHub
    repository whose tree the API could list. It exists so a caller running this as a job can
    tell someone waiting how much work is ahead; the library itself neither prints nor blocks on
    it. It is not called for a local directory, for a registry package, for a non-GitHub host, or
    when the API is unavailable — a caller must treat its absence as normal, not as an error.
    """
    kind = classify_source(source)
    if kind == "npm":
        return _collect_npm(source)
    if kind == "pypi":
        return _collect_pypi(source)
    if kind == "git":
        return _collect_remote(source, on_size=on_size)
    return _collect_local(source)


def _local_archive_kind(path: Path) -> str | None:
    """``"zip"`` or ``"tar"`` for a local archive, None for any other file.

    A zip is recognized by its signature as well as by its name: read as a single file, a Claude
    Desktop extension (.mcpb) was one opaque binary, and a malicious server inside it was reported
    as "No significant risks found" with nothing indexed.
    """
    name = path.name.lower()
    if name.endswith(_ZIP_SUFFIXES):
        return "zip"
    try:
        with path.open("rb") as fh:
            head = fh.read(len(_ZIP_MAGIC))
    except OSError as exc:
        raise _unreadable_source(path, exc) from exc
    if head == _ZIP_MAGIC:
        return "zip"
    if name.endswith(_TAR_SUFFIXES):
        return "tar"
    return None


def _unreadable_source(path: Path, exc: OSError) -> CollectionError:
    return CollectionError(
        f"could not read {neutralize_hidden(path.name)}: {exc.strerror or type(exc).__name__}"
    )


def _archive_identity(filename: str) -> tuple[str, str]:
    """(name, version) a local archive's own file name gives, for when nothing inside names it.

    A wheel's file name is standardized (``name-version[-build]-python-abi-platform.whl``); any
    other archive is named after its file without the archive extension, with no version.
    """
    lower = filename.lower()
    suffix = next((s for s in (*_TAR_SUFFIXES, *_ZIP_SUFFIXES) if lower.endswith(s)), None)
    stem = filename[: -len(suffix)] if suffix else Path(filename).stem
    if lower.endswith(".whl"):
        parts = stem.split("-")
        if len(parts) >= 5:
            return parts[0], parts[1]
    return stem or filename, ""


def registry_suggestion(name: str) -> str:
    """``npm:<name> or pypi:<name>`` for a bare name that could be a package, naming only the
    registries whose names allow it (a scoped ``@scope/x`` is npm only); empty otherwise."""
    return " or ".join(
        f"{registry}:{name}"
        for registry, pattern in (("npm", _NPM_NAME_RE), ("pypi", _PYPI_NAME_RE))
        if pattern.match(name)
    )


def _collect_local(source: str) -> SourceContext:
    root = Path(source).expanduser().resolve()
    if not root.exists():
        name = source.strip()
        # An archive name or a path is a file that is missing, not a package name.
        looks_like_path = name.lower().endswith((*_TAR_SUFFIXES, *_ZIP_SUFFIXES)) or (
            "/" in name and not name.startswith("@"))
        suggestion = "" if looks_like_path else registry_suggestion(name)
        if suggestion:
            # `skilltotal scan lodash` most often means the package, not a folder named lodash.
            raise CollectionError(
                f"Path does not exist: {source}. To scan a package, name its registry: "
                f"{suggestion}"
            )
        raise CollectionError(f"Path does not exist: {source}")
    if root.is_dir():
        component = detect_component(root, source=str(root))
        return SourceContext(root=root, component=component)
    if root.is_file():
        # A project archive (zip/tar.gz/…) or a single code file: extract/stage to a temp dir and
        # scan it with the same engine. The display source is the file name (neutralized), never the
        # temp path.
        kind = _local_archive_kind(root)
        if kind is not None:
            return _collect_local_archive(root, kind)
        return _collect_local_file(root)
    raise CollectionError(f"Path is not a file or directory: {source}")


def _collect_local_archive(path: Path, kind: str) -> SourceContext:
    try:
        size = path.stat().st_size
        if size > _MAX_ARCHIVE_BYTES:
            raise SizeLimitError(
                f"archive is too large: {_mb(size)} MB, over the {_mb(_MAX_ARCHIVE_BYTES)} MB "
                "limit.", variable="SKILLTOTAL_MAX_ARCHIVE_MB")
        data = path.read_bytes()
    except OSError as exc:
        raise _unreadable_source(path, exc) from exc
    display = neutralize_hidden(path.name)
    tmp = tempfile.TemporaryDirectory(prefix=TEMP_DIR_PREFIX)
    try:
        extract_dir = Path(tmp.name) / "x"
        extract_dir.mkdir()
        if kind == "zip":
            skipped = _safe_extract_zip(data, extract_dir)
        else:  # .tar.gz / .tgz / .tar / .tar.bz2 / .tar.xz
            skipped = _safe_extract_tar(data, extract_dir)
        root = _single_root(extract_dir)
        # Files at the top of the archive (a wheel, an extension bundle) have no folder to be named
        # after: the archive's own file name stands in, never the temporary directory.
        name, version = _archive_identity(path.name) if root == extract_dir else (None, "")
        component = detect_component(root, source=display, default_name=name)
        if component.type == "directory":
            component = replace(component, type="project")
        if version and not component.version:
            component = replace(component, version=neutralize_hidden(version))
        return SourceContext(root=root, component=component, _tempdir=tmp,
                             skipped_entries=skipped)
    except Exception:
        tmp.cleanup()
        raise


def _collect_local_file(path: Path) -> SourceContext:
    display = neutralize_hidden(path.name)
    tmp = tempfile.TemporaryDirectory(prefix=TEMP_DIR_PREFIX)
    try:
        size = path.stat().st_size
        if size > _MAX_ARCHIVE_BYTES:
            raise SizeLimitError(
                f"file is too large: {_mb(size)} MB, over the {_mb(_MAX_ARCHIVE_BYTES)} MB "
                "limit.", variable="SKILLTOTAL_MAX_ARCHIVE_MB")
        root = Path(tmp.name)
        # path.name is a bare filename; we control `root`, so the destination stays inside it.
        shutil.copy2(path, root / path.name)
        component = detect_component(root, source=display, default_name=path.name)
        if component.type == "directory":
            component = replace(component, type="project")
        return SourceContext(root=root, component=component, _tempdir=tmp)
    except OSError as exc:
        tmp.cleanup()
        raise _unreadable_source(path, exc) from exc
    except Exception:
        tmp.cleanup()
        raise


def _parse_hf_url(host: str, parts: list[str]) -> tuple[str, str | None, str | None, str | None]:
    """Resolve a Hugging Face browser/clone URL into ``(clone_url, ref, subpath, note)``.

    Models clone from ``hf.co/<org>/<name>``; datasets/spaces nest under a type prefix
    (``hf.co/datasets/<org>/<name>``). Browser deep-links use ``/tree`` (dir), ``/blob`` and
    ``/resolve`` (file). The clone URL has no ``.git`` suffix (HF serves git at the bare path).
    """
    if parts[0] in _HF_REPO_PREFIXES:
        if len(parts) < 3:
            return f"https://{host}/{'/'.join(parts)}", None, None, None  # incomplete -> as-is
        repo_id, rest = "/".join(parts[:3]), parts[3:]
    else:
        repo_id, rest = "/".join(parts[:2]), parts[2:]
    clone_url = f"https://{host}/{repo_id}"
    if not rest:
        return clone_url, None, None, None
    kind = rest[0]
    if kind in _HF_REF_KINDS and len(rest) >= 2:
        ref, sub = rest[1], "/".join(rest[2:])
        if kind in ("blob", "resolve") and sub:  # a file link -> scan the file's folder
            sub = sub.rsplit("/", 1)[0] if "/" in sub else ""
        return clone_url, ref, (sub or None), None
    note = (
        f"The link pointed to '/{kind}', which is not source code; "
        f"scanned the default branch of {repo_id} instead."
    )
    return clone_url, None, None, note


def parse_git_url(url: str) -> tuple[str, str | None, str | None, str | None]:
    """Resolve a browser/clone URL into ``(clone_url, ref, subpath, note)``.

    Understands github/gitlab/bitbucket/Hugging-Face web URLs — a branch/tag/commit and an
    optional subfolder or file (``/tree/<ref>/<path>``, ``/blob/<ref>/<file>``, ``/commit/<sha>``;
    HF also ``/resolve/<ref>/<file>`` and the ``datasets/``/``spaces/`` repo prefixes). A
    non-code page (``/issues``, ``/pull``, ``/wiki`` …) is reduced to the repo root and a human
    ``note`` is returned. Bare git URLs (``*.git``, ``git@``, ssh, or any unrecognized host)
    pass through unchanged.
    """
    s = url.strip()
    if not s.lower().startswith(("http://", "https://")):
        return s, None, None, None  # scp/ssh/git: nothing to parse
    parsed = urlparse(s)
    host = (parsed.hostname or "").lower()
    parts = [p for p in parsed.path.split("/") if p]
    if host not in _WEB_HOSTS or len(parts) < 2:
        return s, None, None, None  # unknown shape -> let git try the URL as-is
    if host == "huggingface.co":
        return _parse_hf_url(host, parts)
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    clone_url = f"https://{host}/{owner}/{repo}.git"
    rest = parts[2:]
    if host == "gitlab.com" and rest and rest[0] == "-":  # gitlab nests under /-/
        rest = rest[1:]
    if not rest:
        return clone_url, None, None, None
    kind = rest[0]
    if kind in ("tree", "blob", "src") and len(rest) >= 2:
        ref = rest[1]
        sub = "/".join(rest[2:])
        if kind == "blob" and sub:  # a file link -> scan the file's folder
            sub = sub.rsplit("/", 1)[0] if "/" in sub else ""
        return clone_url, ref, (sub or None), None
    if kind in ("commit", "commits") and len(rest) >= 2:
        return clone_url, rest[1], None, None
    # Anything else (issues, pull, wiki, actions, releases, …) is not source code.
    note = (
        f"The link pointed to '/{kind}', which is not source code; "
        f"scanned the default branch of {owner}/{repo} instead."
    )
    return clone_url, None, None, note


def _dir_size_bytes(root: Path, *, skip_git: bool = False) -> int:
    """Total size of regular files under ``root`` (best-effort; races during a clone are fine).

    ``skip_git`` leaves out ``.git/``: the scan reads the working tree, and a shallow clone's
    pack is roughly a compressed second copy of it, so counting both made a 168 MB checkout
    read as 234 MB and fail the 200 MB limit.

    Links are not followed (a junction could lead anywhere), and the walk keeps its own stack: a
    repository nested deeper than the recursion limit must not kill the watchdog thread.
    """
    total = 0
    skip = (lambda name: name == ".git") if skip_git else None
    for p in walk_files(root, skip=skip):
        try:
            total += p.stat().st_size
        except OSError:
            continue
    return total


def _github_api(url: str) -> dict | None:
    """One GitHub REST call; ``None`` when rate-limited, private, offline or not JSON.

    With ``SKILLTOTAL_GITHUB_TOKEN`` set the call is authenticated: 5000 an hour instead of the 60
    an address gets, after which the size check before a clone is skipped. The token goes to
    api.github.com only, and never along a redirect.
    """
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "skilltotal-scanner", "Accept": "application/vnd.github+json"},
        )
        token = os.environ.get("SKILLTOTAL_GITHUB_TOKEN", "").strip()
        if token and urlparse(url).hostname == "api.github.com":
            req.add_unredirected_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # nosec B310 - https
            data = bounded_json.loads(resp.read(_MAX_ARCHIVE_BYTES + 1))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# Suffixes a pre-clone estimate treats as unreadable. The index itself decides by sniffing for
# NUL bytes rather than trusting a name, but before the clone there are only paths. Since the
# work limit reads this number, being wrong is no longer free, so the list stays conservative:
# it holds only suffixes that are binary by definition. Anything unrecognised counts as readable,
# which can refuse a scan that would have run but never admits one that cannot finish.
_NON_TEXT_SUFFIXES: frozenset[str] = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tiff", ".psd",
        ".mp4", ".mov", ".avi", ".mkv", ".webm", ".mp3", ".wav", ".flac", ".ogg", ".m4a",
        ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar", ".pdf",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".bin", ".so", ".dll", ".dylib", ".exe", ".o", ".a", ".pyc", ".pyd", ".class", ".jar",
        ".wasm", ".safetensors", ".pt", ".pth", ".onnx", ".ckpt", ".h5", ".npy", ".npz",
        ".parquet", ".db", ".sqlite",
    }
)


class TreeSize(NamedTuple):
    """Bytes on a ref: everything in the checkout, and the part an index would actually read.

    The two differ by more than an order of magnitude on real components, and it is ``readable``
    that predicts how long a scan takes. A 202 MB repository of video and fonts holds 3.8 MB of
    readable text and scans in 28 seconds; a 104 MB repository that is almost all source holds
    100 MB and takes five minutes. Each bounds a different thing: ``total`` the clone (disk,
    bandwidth, the mid-clone watchdog), ``readable`` the scan itself.
    """

    total: int
    readable: int


def _readable_bytes(entry_path: str, size: int) -> int:
    """``size`` if an index would read this file, else 0.

    Two reasons it would not: a suffix that is never text, and a file over ``MAX_FILE_BYTES``,
    which the index skips whatever it contains.
    """
    name = entry_path.rsplit("/", 1)[-1].lower()
    suffix = name[name.rfind(".") :] if "." in name else ""
    if suffix in _NON_TEXT_SUFFIXES or size > _MAX_INDEXED_FILE_BYTES:
        return 0
    return size


def _github_tree_bytes(path: str, ref: str, subpath: str | None) -> TreeSize | None:
    """Bytes the checkout will hold: blob sizes on ``ref``, under ``subpath`` when one is linked.

    ``None`` when the answer cannot be trusted (API error, or a tree so large the API truncated
    it) — the caller then falls back to the history size, which can only over-reject.
    """
    if not _SAFE_REF_RE.match(ref) or ".." in ref:
        return None
    data = _github_api(f"https://api.github.com/repos/{path}/git/trees/{ref}?recursive=1")
    if not data or data.get("truncated") or not isinstance(data.get("tree"), list):
        return None
    prefix = subpath.strip("/") + "/" if subpath else ""
    total = 0
    readable = 0
    for entry in data["tree"]:
        if not isinstance(entry, dict) or entry.get("type") != "blob":
            continue
        entry_path = str(entry.get("path", ""))
        if prefix and not entry_path.startswith(prefix):
            continue
        size = entry.get("size")
        if isinstance(size, (int, float)):
            total += int(size)
            readable += _readable_bytes(entry_path, int(size))
    return TreeSize(total=total, readable=readable)


def _reject_if_too_large(
    clone_url: str,
    ref: str | None = None,
    subpath: str | None = None,
    on_size: Callable[[TreeSize], None] | None = None,
) -> None:
    """Pre-clone size check via the GitHub API; no-op for other hosts or on any API error.

    What is measured is what will be scanned: the working tree of ``ref`` (the default branch
    when none is linked), narrowed to ``subpath`` for a subfolder link. The repository's ``size``
    — its whole history — is only the fallback when the tree cannot be listed: a 24 MB checkout
    behind a 202 MB history used to be refused.
    """
    parsed = urlparse(clone_url)
    if (parsed.hostname or "").lower() != "github.com":
        return
    path = parsed.path.removesuffix(".git").strip("/")
    if path.count("/") != 1:
        return
    meta = _github_api(f"https://api.github.com/repos/{path}")
    if meta is None:
        return  # rate-limited / private / offline -> rely on the mid-clone watchdog
    cap = _MAX_CLONE_MB * 1024 * 1024
    tree_ref = ref or str(meta.get("default_branch") or "HEAD")
    tree = _github_tree_bytes(path, tree_ref, subpath)
    if tree is not None:
        where = f"{path}/{subpath.strip('/')}" if subpath else path
        if tree.total > cap:
            raise SourceTooLargeError(
                f"working tree is ~{round(tree.total / 1024 / 1024)} MB, which exceeds the "
                f"{_MAX_CLONE_MB} MB scan limit ({where}).",
                measured_mb=round(tree.total / 1024 / 1024),
            )
        if tree.readable > _MAX_READABLE_MB * 1024 * 1024:
            raise SourceTooLargeError(
                f"working tree holds ~{round(tree.readable / 1024 / 1024)} MB of readable text, "
                f"which exceeds the {_MAX_READABLE_MB} MB scan limit ({where}).",
                measured_mb=round(tree.readable / 1024 / 1024),
                limit_mb=_MAX_READABLE_MB, variable="SKILLTOTAL_MAX_READABLE_MB",
            )
        # Reported only once the size is accepted: a caller wanting to show progress has no use
        # for the measurement of a scan that is about to be refused.
        if on_size is not None:
            on_size(tree)
        return
    size_kb = meta.get("size")
    if isinstance(size_kb, (int, float)) and size_kb / 1024 > _MAX_CLONE_MB:
        raise SourceTooLargeError(
            f"repository is ~{round(size_kb / 1024)} MB, which exceeds the "
            f"{_MAX_CLONE_MB} MB scan limit ({path}).",
            measured_mb=round(size_kb / 1024),
        )


def _run_git(args: list[str], dest: Path, env: dict, url: str) -> None:
    """Run a git clone/fetch, bounded in time AND in size (watchdog kills it past the cap).

    Security: git is resolved to an absolute path from PATH's absolute entries (never the current
    directory, see find_program), arguments are passed as a list (never a shell), and the URL was
    validated upstream. Reviewed exception for the static security scan.
    """
    cap = _MAX_CLONE_MB * 1024 * 1024
    if args and args[0] == "git":
        args = [_git_program(), *args[1:]]
    proc = subprocess.Popen(  # nosec B603
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
        creationflags=_NO_WINDOW,
    )
    exceeded = {"hit": False}

    def _watch() -> None:
        # The limit is on the working tree (what gets scanned). The pack under .git is bounded
        # too, at twice the limit, so an unlisted giant cannot fill the disk during the fetch.
        while proc.poll() is None:
            if dest.exists() and (
                _dir_size_bytes(dest, skip_git=True) > cap or _dir_size_bytes(dest) > 2 * cap
            ):
                exceeded["hit"] = True
                proc.kill()
                return
            time.sleep(_CLONE_POLL_SECONDS)

    watcher = threading.Thread(target=_watch, daemon=True)
    watcher.start()
    try:
        _, stderr = proc.communicate(timeout=_CLONE_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        _kill_and_drain(proc)
        raise CollectionError(f"git clone timed out after {_CLONE_TIMEOUT}s for {url}") from exc
    finally:
        watcher.join(timeout=2)
    if exceeded["hit"]:
        raise SourceTooLargeError(
            f"repository exceeds the {_MAX_CLONE_MB} MB scan limit (aborted mid-clone): {url}"
        )
    if proc.returncode != 0:
        raise CollectionError(f"git clone failed for {url}: {(stderr or '').strip()}")


# Windows refuses to create a path much over 260 characters, and real repositories contain them:
# a machine-learning project with one result file per model combination reaches that in a single
# name. Without this, cloning such a repository dies with "unable to create file", which reads as
# a broken tool rather than a platform limit — the same scan succeeds on Linux and macOS. Passed
# per command instead of being written to the user's git configuration, because a scanner should
# not change the settings of the machine it runs on. The option is Windows-only in effect and is
# accepted and ignored elsewhere, so there is no platform branch to get wrong.
_GIT_LONG_PATHS = ["-c", "core.longpaths=true"]
# git is a console program: started from a process without a console (a background job), Windows
# gives it a console window of its own, which flashes on the screen. Its output is captured and it
# never prompts, so it needs no window. Zero (no flags) elsewhere.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _git(dest: Path, args: list[str], env: dict, *, timeout: int) -> None:
    """A bounded, non-interactive git command inside ``dest`` (errors surface to the caller)."""
    argv = [_git_program(), *_GIT_LONG_PATHS, "-C", str(dest), *args]
    done = run_bounded(argv, env=env, timeout=timeout)
    if done.returncode != 0:
        raise subprocess.CalledProcessError(done.returncode, argv, done.stdout, done.stderr)


def noninteractive_git_env() -> dict[str, str]:
    """The environment for every git command run on a scanned URL: no credential prompt, neither
    in the terminal nor from Git Credential Manager's own window (a private or deleted repository
    would otherwise wait for a login nobody gives), and no LFS download."""
    return {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never",
            "GIT_LFS_SKIP_SMUDGE": "1"}


# How long the output of a killed program is still read. Git for Windows' git.exe is a launcher:
# killing it leaves the real git, git-remote-https and a credential helper running with the same
# output pipes, and a read to the end of them waits as long as they live.
_DRAIN_AFTER_KILL_SECONDS = 5


def _kill_and_drain(proc: subprocess.Popen) -> None:
    proc.kill()
    try:
        proc.communicate(timeout=_DRAIN_AFTER_KILL_SECONDS)
    except subprocess.TimeoutExpired:
        pass  # the readers are daemon threads; what is left of the output is dropped


def run_bounded(argv: list[str], *, env: dict, timeout: float) -> subprocess.CompletedProcess:
    """``subprocess.run(argv, capture_output=True, text=True, timeout=timeout)`` that returns or
    raises ``TimeoutExpired`` within about ``timeout`` seconds. On Windows ``subprocess.run`` kills
    the program on timeout and then reads its output to the end with no limit, which on
    2026-10-27 held a calibration run for four hours on a credential prompt (see _kill_and_drain).
    """
    proc = subprocess.Popen(  # nosec B603 - argv list, no shell; callers pass fixed git arguments
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
        creationflags=_NO_WINDOW,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_and_drain(proc)
        raise
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)


def _clone(clone_url: str, ref: str | None, subpath: str | None, dest: Path, env: dict,
           url: str) -> None:
    """Shallow-clone ``ref`` of ``clone_url`` into ``dest``; a linked ``subpath`` is checked out
    sparsely (and, on hosts that serve partial clones, its files are the only ones fetched), so
    "scan this folder" costs that folder, not the repository around it."""
    is_sha = bool(ref and _SHA_RE.match(ref))
    args = ["git", *_GIT_LONG_PATHS, "clone", "--depth", "1"]
    if subpath:
        args.append("--sparse")
        if (urlparse(clone_url).hostname or "").lower() in _PARTIAL_CLONE_HOSTS:
            args.append("--filter=blob:none")
    if ref and not is_sha:  # branch or tag
        args += ["--branch", ref]
    _run_git([*args, clone_url, str(dest)], dest, env, url)
    if subpath:
        try:
            # The folder comes from the URL: after --end-of-options a name such as "-x" or
            # "--output=…" is a path to git, never a switch.
            _git(dest, ["sparse-checkout", "set", "--end-of-options", subpath.strip("/")], env,
                 timeout=60)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise CollectionError(f"could not narrow the checkout to '{subpath}'") from exc
    if is_sha:  # fetch + check out the requested commit (GitHub allows reachable SHAs)
        try:
            _git(dest, ["fetch", "--depth", "1", "origin", ref], env, timeout=_CLONE_TIMEOUT)
            _git(dest, ["checkout", "--force", ref], env, timeout=60)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise CollectionError(f"commit '{ref}' not found in {clone_url}") from exc


def _collect_remote(
    url: str, *, on_size: Callable[[TreeSize], None] | None = None
) -> SourceContext:
    """Resolve a git/browser URL into a local checkout (shallow, size-bounded).

    Parses branch/tag/commit/subfolder links, rejects oversized repositories, and clones only
    what is needed.
    """
    _git_program()  # git missing is said before anything is fetched
    clone_url, ref, subpath, note = parse_git_url(url)
    _reject_if_too_large(clone_url, ref, subpath, on_size=on_size)

    tmp = tempfile.TemporaryDirectory(prefix=TEMP_DIR_PREFIX)
    dest = Path(tmp.name) / "repo"
    # Non-interactive (no credential prompt that could block) and bounded in time + size. LFS
    # objects are left as pointer files: fetching them would download from wherever the scanned
    # repository's own .lfsconfig points, and the scan reads source, not large binaries.
    try:
        _clone(clone_url, ref, subpath, dest, noninteractive_git_env(), url)
    except CollectionError:
        tmp.cleanup()
        raise

    root = dest
    if subpath:
        candidate = (dest / subpath).resolve()
        try:
            candidate.relative_to(dest.resolve())
        except ValueError:
            tmp.cleanup()
            raise CollectionError(f"unsafe subpath in URL: {subpath}") from None
        if not candidate.is_dir():
            tmp.cleanup()
            raise CollectionError(f"path '{subpath}' not found in repository {clone_url}")
        root = candidate

    # A whole repository is checked out into a temp folder named "repo": with no manifest to
    # name it, the repository's own name stands in for that folder name.
    default_name = None if subpath else _repo_name(clone_url)
    component = detect_component(root, source=url, default_name=default_name)
    return SourceContext(root=root, component=component, _tempdir=tmp, note=note)


def _repo_name(clone_url: str) -> str | None:
    """The repository name a clone URL ends in (``owner/name.git`` -> ``name``), if any."""
    tail = re.split(r"[/:]", clone_url.strip().rstrip("/"))[-1]
    tail = tail[:-4] if tail.lower().endswith(".git") else tail
    return tail or None


# --------------------------------------------------------------- package registries

# A company registry mirror (Artifactory, Nexus, Verdaccio, devpi) to fetch `npm:` / `pypi:`
# sources from instead of the public registries. Read only from the scanning process's own
# environment, never from a scanned component's files. Unset, nothing changes.
NPM_REGISTRY_ENV = "SKILLTOTAL_NPM_REGISTRY"  # npm protocol: <base>/<name>[/<version|tag>]
PYPI_INDEX_ENV = "SKILLTOTAL_PYPI_INDEX"  # PyPI JSON API: <base>/pypi/<name>[/<version>]/json
# Sent as `Authorization: Bearer` to the mirror's own scheme and host only.
REGISTRY_TOKEN_ENV = "SKILLTOTAL_REGISTRY_TOKEN"  # nosec B105 - a variable name, not a secret
_PUBLIC_NPM = "https://registry.npmjs.org"
_PUBLIC_PYPI = "https://pypi.org"
# Where the public registries serve their files: a mirror may hand out these download URLs too.
_PUBLIC_DOWNLOAD_HOSTS = {"npm": frozenset({"registry.npmjs.org"}),
                          "pypi": frozenset({"files.pythonhosted.org"})}
# Public hosts the token is never sent to, whatever a mirror setting names.
_PUBLIC_HOSTS = frozenset({"registry.npmjs.org", "registry.yarnpkg.com", "www.npmjs.com",
                           "pypi.org", "pypi.python.org", "files.pythonhosted.org"})
# The only hosts a mirror may be reached over plain http.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# What a mirror URL may hold: no whitespace, quotes, backslashes or control characters (a query
# or fragment is refused by name after this).
_MIRROR_URL_CHARS = re.compile(r"[A-Za-z0-9._~:/?#\[\]%@!$&'()*+,;=-]+")


def normalize_registry_url(value: str, variable: str) -> str:
    """``value`` as a mirror base URL (``scheme://host[:port]/path``, lowercase scheme and host,
    no trailing slash), or a CollectionError naming ``variable``.

    https only, except http to this machine (localhost, 127.0.0.1, ::1); no user name or password
    (the token goes in SKILLTOTAL_REGISTRY_TOKEN), no query, no fragment. The value is not quoted
    back: it may hold a credential the person pasted by mistake.
    """
    def bad(why: str) -> CollectionError:
        return CollectionError(f"{variable} is not a usable registry URL: {why}")

    value = value.strip()
    if not _MIRROR_URL_CHARS.fullmatch(value):
        raise bad("it holds spaces, quotes, backslashes or other characters a URL cannot")
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http"):
        raise bad("it must start with https://")
    if "@" in parts.netloc:
        raise bad("it must not hold a user name or password; set "
                  f"{REGISTRY_TOKEN_ENV} for a token")
    if "?" in value or "#" in value:
        raise bad("it must not hold a query (?) or a fragment (#)")
    try:
        host, _port = parts.hostname, parts.port
    except ValueError:
        raise bad("its port is not a number from 0 to 65535") from None
    if not host:
        raise bad("it names no host")
    if scheme == "http" and host not in _LOOPBACK_HOSTS:
        raise bad("plain http is allowed only for localhost; use https")
    path = parts.path.rstrip("/")
    if any(segment in (".", "..") for segment in path.split("/")):
        raise bad("its path must not hold . or .. segments")
    return f"{scheme}://{parts.netloc.lower()}{path}"


def registry_mirror(kind: str, environ=None) -> str | None:
    """The mirror base URL configured for ``kind`` ("npm" or "pypi"), normalized; None when unset.
    An unusable value raises a CollectionError naming the variable."""
    variable = NPM_REGISTRY_ENV if kind == "npm" else PYPI_INDEX_ENV
    raw = (os.environ if environ is None else environ).get(variable, "").strip()
    return normalize_registry_url(raw, variable) if raw else None


def _origin(url: str) -> str:
    """``scheme://host[:port]`` of a URL, lowercase; "" when it has none."""
    parts = urlsplit(url)
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}" if parts.netloc else ""


def _mirror_origins() -> set[str]:
    """The origins of the mirrors this process is configured with (an unusable setting, none)."""
    origins: set[str] = set()
    for kind in ("npm", "pypi"):
        try:
            base = registry_mirror(kind)
        except CollectionError:
            continue
        if base:
            origins.add(_origin(base))
    return origins


def _token_for(url: str, origins: set[str]) -> str:
    """The registry token, when ``url`` is on a configured mirror's own scheme and host (and
    that host is not a public registry); else ""."""
    token = os.environ.get(REGISTRY_TOKEN_ENV, "").strip()
    if not token or _origin(url) not in origins:
        return ""
    return "" if (urlsplit(url).hostname or "") in _PUBLIC_HOSTS else token


def _fetchable(url: str, origins: set[str]) -> bool:
    """https, or plain http to a configured mirror on this machine."""
    lowered = url.lower()
    return lowered.startswith("https://") or (lowered.startswith("http://")
                                              and _origin(url) in origins)


class _MirrorRedirects(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to an https URL (or a configured http mirror on this machine), and
    carries the token only to a configured mirror's own scheme and host: a mirror that sends a
    download on to cloud storage does not hand that storage the token."""

    def __init__(self, origins: set[str]) -> None:
        super().__init__()
        self._origins = origins

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        if not _fetchable(newurl, self._origins):
            raise CollectionError("refusing to follow a redirect to a non-https URL")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        token = _token_for(newurl, self._origins)
        if new is not None and token:
            new.add_unredirected_header("Authorization", f"Bearer {token}")
        return new


def _open(url: str, *, timeout: float = _HTTP_TIMEOUT):
    """Open an https URL (scheme enforced) with a timeout.

    With no mirror configured this is a plain https request, as it always was. A URL on a
    configured mirror may also be http to this machine, and gets the registry token; the token
    is an unredirected header, so it never follows a redirect to another host.
    """
    origins = _mirror_origins()
    if not _fetchable(url, origins):
        raise CollectionError(f"refusing to fetch non-https URL: {url}")
    if not origins:
        return urllib.request.urlopen(url, timeout=timeout)  # nosec B310 - https enforced above
    request = urllib.request.Request(url)
    token = _token_for(url, origins)
    if token:
        request.add_unredirected_header("Authorization", f"Bearer {token}")
    opener = urllib.request.build_opener(_MirrorRedirects(origins))
    return opener.open(request, timeout=timeout)  # nosec B310 - scheme checked above


def _http_get(url: str) -> bytes:
    """Fetch a URL, capping the response size (guards against oversized payloads)."""
    try:
        with _open(url) as resp:
            data = resp.read(_MAX_ARCHIVE_BYTES + 1)
    except (OSError, ValueError) as exc:  # URLError/HTTPError are OSError subclasses
        raise CollectionError(f"failed to fetch {url}: {exc}") from exc
    if len(data) > _MAX_ARCHIVE_BYTES:
        raise SizeLimitError(
            f"response from {url} exceeds the size limit of {_mb(_MAX_ARCHIVE_BYTES)} MB.",
            variable="SKILLTOTAL_MAX_ARCHIVE_MB")
    return data


def _single_root(extract_dir: Path) -> Path:
    """If the archive extracted to a single top-level directory, return it; else the dir."""
    entries = list(extract_dir.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return extract_dir


def _within(dest_resolved: Path, name: str, dest: Path) -> bool:
    """True if extracting ``name`` stays inside ``dest`` (boundary-correct, not prefix-based)."""
    try:
        (dest / name).resolve().relative_to(dest_resolved)
        return True
    except ValueError:
        return False


# Names Windows opens as a device whatever the extension (`NUL.py` is NUL), so the file is never
# written there. The superscript digits are devices too.
_WINDOWS_DEVICES = frozenset({
    "con", "prn", "aux", "nul", "conin$", "conout$",
    *(f"{port}{n}" for port in ("com", "lpt")
      for n in [*"0123456789", chr(0xB9), chr(0xB2), chr(0xB3)]),
})
# Characters a Windows file name cannot hold. In a tar name, `a.txt:x.py` writes an alternate data
# stream of `a.txt`; zipfile replaces them with `_` on Windows instead.
_WINDOWS_ILLEGAL = frozenset('<>:"|?*')
_ZIP_WINDOWS_NAME = str.maketrans({c: "_" for c in _WINDOWS_ILLEGAL})


class _PortableNames:
    """The member names of an archive, held to what extracts to the same files on every system.

    Windows folds case, drops trailing dots and spaces, reads `::$DATA` as the file itself, opens
    device names as devices and writes `a:b` to a hidden stream; macOS folds case and Unicode
    composition. An archive that holds `setup.py` and `SETUP.py` (or `setup.py.`) extracts both on
    Linux but one over the other on Windows, so a harmless file could replace the one that runs
    and the report would depend on the system that made it. Such an archive is refused
    everywhere. Only the system's rule is named in the error, never a member name (a member name
    is its author's text).
    """

    def __init__(self, *, zip_names: bool) -> None:
        self._zip_names = zip_names
        self._seen: dict[tuple[str, ...], tuple[tuple[str, ...], bool]] = {}
        self._files: set[tuple[str, ...]] = set()
        self._folders: set[tuple[str, ...]] = set()

    def add(self, name: str, is_dir: bool) -> None:
        exact = tuple(p for p in name.split("/") if p not in ("", "."))
        parts = [p for p in re.split(r"[\\/]", name) if p not in ("", ".")]
        if not parts:
            return
        if not self._zip_names and any(c in _WINDOWS_ILLEGAL or ord(c) < 32 for c in name):
            raise CollectionError(
                "archive contains a file name with a character Windows cannot store "
                "(one of < > : \" | ? * or a control character)")
        key_parts = []
        for part in parts:
            if part.casefold().endswith("::$data"):
                part = part[: -len("::$data")]
            if self._zip_names:
                part = part.translate(_ZIP_WINDOWS_NAME)
            part = part.rstrip(". ")
            if part.split(".", 1)[0].rstrip(" ").casefold() in _WINDOWS_DEVICES:
                raise CollectionError(
                    "archive contains a file named after a Windows device (CON, PRN, AUX, NUL, "
                    "COM1, LPT1, ...), which Windows cannot store")
            # macOS stores names composed (NFC), so `café` spelled two ways is one file there.
            key_parts.append(unicodedata.normalize("NFC", part).casefold())
        key = tuple(key_parts)
        prior = self._seen.get(key)
        if prior is not None and prior[0] != exact and not (prior[1] and is_dir):
            raise _windows_collision()
        self._seen[key] = (exact, is_dir)
        folders = {key[:i] for i in range(1, len(key))}
        if is_dir:
            folders.add(key)
        else:
            if key in self._folders:
                raise _windows_collision()
            self._files.add(key)
        if folders & self._files:
            raise _windows_collision()
        self._folders |= folders


def _windows_collision() -> CollectionError:
    return CollectionError(
        "archive contains entries that are the same file on Windows or macOS (their names differ "
        "only in case, Unicode composition, trailing dots or spaces, or a ::$DATA suffix), so "
        "what it holds would depend on the system it is extracted on")


def _unextractable(kind: str, exc: Exception) -> CollectionError:
    """The error for an archive that cannot be extracted. Nothing from inside the archive is
    quoted (a member name is its author's text): only the system's reason or the error type."""
    if isinstance(exc, OSError) and exc.strerror:
        return CollectionError(f"archive could not be extracted: {exc.strerror}")
    return CollectionError(
        f"archive could not be read: it is damaged, truncated or not a {kind} archive "
        f"({type(exc).__name__})"
    )


class _BoundedReader:
    """A decompressed tar stream that refuses to inflate past ``limit`` bytes.

    The archive itself is size-capped, but gzip inflates about a thousand to one, and tarfile
    inflates some data before any member can be checked: it reads a pax or GNU long-name record
    whole into memory, and it skips the data of an entry of unknown type by decompressing it. A
    read or a seek past ``limit`` raises instead, so reading an archive costs at most that much.
    """

    def __init__(self, stream: io.IOBase, limit: int) -> None:
        self._stream = stream
        self._limit = limit

    def _refuse_past(self, end: int) -> None:
        if end > self._limit:
            raise SizeLimitError(
                "archive too large when extracted: more than "
                f"{_mb(_MAX_EXTRACT_BYTES)} MB.", variable="SKILLTOTAL_MAX_EXTRACT_MB")

    def read(self, size: int | None = -1) -> bytes:
        room = self._limit - self._stream.tell()
        if size is None or size < 0:
            data = self._stream.read(room + 1)
            self._refuse_past(self._limit - room + len(data))
            return data
        self._refuse_past(self._limit - room + size)
        return self._stream.read(size)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        target = offset + (self._stream.tell() if whence == io.SEEK_CUR else 0)
        if whence in (io.SEEK_SET, io.SEEK_CUR):
            self._refuse_past(target)
        return self._stream.seek(offset, whence)

    def tell(self) -> int:
        return self._stream.tell()


def _tar_stream(data: bytes) -> io.IOBase:
    """The tar bytes inside ``data``: gzip, bzip2 and xz are recognized by their signatures (as
    tarfile's own "r:*" does), anything else is read as a plain tar."""
    raw = io.BytesIO(data)
    if data[:2] == b"\x1f\x8b":
        import gzip

        return gzip.GzipFile(fileobj=raw, mode="rb")
    if data[:3] == b"BZh":
        import bz2  # imported here: a Python built without it can still read other archives

        return bz2.BZ2File(raw, mode="rb")
    if data[:6] == b"\xfd7zXZ\x00":
        import lzma

        return lzma.LZMAFile(raw, mode="rb")
    return raw


def _safe_extract_tar(data: bytes, dest: Path) -> int:
    """Extract the files and directories of a tar archive into ``dest``.

    Returns how many entries were left out: symbolic and hard links (a link can point anywhere,
    and a later entry could write through it), FIFOs and devices (never component content, and
    opening a FIFO blocks). Every limit applies to a header as it is read, before the data behind
    it is inflated, and the inflated stream is capped as a whole (see _BoundedReader). Stored
    permissions are never applied: a file archived as mode 000 stays readable for the scan. A
    damaged or truncated archive is a CollectionError.
    """
    dest_resolved = dest.resolve()
    limit = _MAX_EXTRACT_BYTES + _MAX_ARCHIVE_MEMBERS * _TAR_OVERHEAD_PER_MEMBER
    skipped = entries = total = 0
    names = _PortableNames(zip_names=False)
    try:
        with _tar_stream(data) as stream, tarfile.open(
            fileobj=_BoundedReader(stream, limit), mode="r:"
        ) as tf:
            for member in tf:
                entries += 1
                if entries > _MAX_ARCHIVE_MEMBERS:
                    raise SizeLimitError(
                        f"archive has too many entries: more than {_MAX_ARCHIVE_MEMBERS:,}.",
                        variable="SKILLTOTAL_MAX_ARCHIVE_MEMBERS")
                if member.issym() or member.islnk() or member.isdev():
                    skipped += 1
                    continue
                if not _within(dest_resolved, member.name, dest):
                    raise CollectionError("archive contains an unsafe path")
                names.add(member.name, member.isdir())
                if member.type not in tarfile.SUPPORTED_TYPES:
                    # tarfile (and pip with it) writes an entry of unknown type as a regular file,
                    # so its content is installed; the data filter would refuse it instead.
                    member.type = tarfile.REGTYPE
                if not member.isdir():
                    total += member.size
                    if total > _MAX_EXTRACT_BYTES:
                        raise SizeLimitError(
                            "archive too large when extracted: more than "
                            f"{_mb(_MAX_EXTRACT_BYTES)} MB.", variable="SKILLTOTAL_MAX_EXTRACT_MB")
                tf.extract(member, dest, set_attrs=False, **_TAR_FILTER)
    except CollectionError:
        raise
    except ImportError as exc:
        raise CollectionError(f"this Python cannot decompress the archive ({exc.name})") from exc
    except Exception as exc:  # whatever tarfile or a decompressor raises on bytes it cannot read
        if isinstance(exc, getattr(tarfile, "FilterError", ())):
            raise CollectionError("archive contains an unsafe path") from exc
        raise _unextractable("tar", exc) from exc
    return skipped


def _safe_extract_zip(data: bytes, dest: Path) -> int:
    """Extract a zip archive into ``dest``; return how many entries were left out (symlinks).

    Every check runs on the central directory before anything is written. Declared sizes bound
    the work, since an entry never inflates past its declared size. A damaged, truncated,
    password-protected or unsupported archive is a CollectionError.
    """
    dest_resolved = dest.resolve()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > _MAX_ARCHIVE_MEMBERS:
                raise SizeLimitError(
                    f"archive has too many entries: more than {_MAX_ARCHIVE_MEMBERS:,}.",
                    variable="SKILLTOTAL_MAX_ARCHIVE_MEMBERS")
            safe, total, skipped = [], 0, 0
            names = _PortableNames(zip_names=True)
            for info in infos:
                # zipfile.extractall can create symlinks from the stored unix mode on some
                # platforms.
                if stat.S_ISLNK(info.external_attr >> 16):
                    skipped += 1
                    continue  # never extract symlinks (path-escape risk)
                if info.flag_bits & 0x1:
                    raise CollectionError(
                        "archive is password-protected, so its contents cannot be read")
                if not _within(dest_resolved, info.filename, dest):
                    raise CollectionError("archive contains an unsafe path")
                # The name as stored: on Windows zipfile has already turned `\` into `/`.
                names.add(info.orig_filename, info.is_dir())
                total += info.file_size
                if total > _MAX_EXTRACT_BYTES:
                    raise SizeLimitError(
                        "archive too large when extracted: more than "
                        f"{_mb(_MAX_EXTRACT_BYTES)} MB.", variable="SKILLTOTAL_MAX_EXTRACT_MB")
                safe.append(info)
            zf.extractall(dest, members=safe)  # nosec B202 - members validated above
    except CollectionError:
        raise
    except Exception as exc:  # whatever zipfile or a decompressor raises on bytes it cannot read
        raise _unextractable("zip", exc) from exc
    return skipped


def _collect_archive(
    source: str, ctype: str, version: str, archive_url: str, filename: str,
    *, name: str | None = None,
) -> SourceContext:
    """Download and extract a registry artifact. ``name`` is the registry's own name for the
    project, when the artifact may not carry a manifest that says it (a wheel has none at its
    root, and an sdist folder is named ``project-1.2.3``)."""
    data = _http_get(archive_url)
    tmp = tempfile.TemporaryDirectory(prefix=TEMP_DIR_PREFIX)
    try:
        extract_dir = Path(tmp.name) / "x"
        extract_dir.mkdir()
        if filename.lower().endswith((".whl", ".zip")) or data.startswith(_ZIP_MAGIC):
            skipped = _safe_extract_zip(data, extract_dir)
        else:  # .tgz / .tar.gz / .tar.*
            skipped = _safe_extract_tar(data, extract_dir)
        root = _single_root(extract_dir)
        component = detect_component(root, source=source)
        component = replace(
            component,
            name=neutralize_hidden(name) if name else component.name,
            type=ctype,
            version=component.version or version,
            download_url=archive_url,
        )
        return SourceContext(root=root, component=component, _tempdir=tmp,
                             skipped_entries=skipped)
    except Exception:
        tmp.cleanup()
        raise


# An exact release, as opposed to a dist-tag (`latest`) or a range the installer resolves.
_NPM_RANGE_RE = re.compile(r"[\^~<>=*| ]|(?:^|\.)[xX](?:\.|$)")
_EXACT_NPM_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_EXACT_PYPI_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+!-]*$")


class Release(NamedTuple):
    """One exact registry artifact. ``source`` scans it (``npm:x@1.2.3`` / ``pypi:x==1.2.3``).

    A PyPI release can gain files after it is published (a wheel added to a version first shipped
    as an sdist), so its version alone does not say what gets installed: ``artifact`` is the file
    the scan reads and ``files`` a digest of every file in the release, so a verdict stays tied to
    the set pip could choose from. An npm version is one immutable tarball: neither is needed.
    """

    source: str
    artifact: str = ""
    files: str = ""

    @property
    def key(self) -> str:
        """What a verdict about this release may be remembered under."""
        return " ".join(part for part in (self.source, self.artifact, self.files) if part)


def resolve_release(source: str, *, timeout: float = _HTTP_TIMEOUT,
                    use_mirror: bool = True) -> Release | None:
    """The exact artifact a registry source names right now.

    ``npm:x`` / ``npm:x@latest`` -> ``npm:x@1.2.3``; ``pypi:x`` -> ``pypi:x==1.2.3`` plus the file
    pip would install. An exact npm pin comes back without a request. Anything that is not an npm
    or PyPI package (a git URL, a local path) returns None, as does a registry that does not
    answer: the caller then knows only the name, not what it would get.

    One small request (npm's per-tag manifest, PyPI's release JSON), so a caller that keeps a
    verdict per package can tell a new release from the one it checked. It goes to the configured
    mirror (see ``registry_mirror``) unless ``use_mirror`` is False.
    """
    kind = classify_source(source)
    try:
        if kind == "npm":
            name, pin = npm_package_spec(source)
            if not name:
                return None
            if pin and _EXACT_NPM_VERSION_RE.match(pin):
                return Release(f"npm:{name}@{pin}")
            base = _registry_base("npm", use_mirror)[0]
            url = f"{base}/{quote(name, safe='@')}/{quote(pin or 'latest')}"
            with _open(url, timeout=timeout) as resp:
                version = str(bounded_json.loads(resp.read(8 * 1024 * 1024)).get("version")
                              or "")
            if not _EXACT_NPM_VERSION_RE.match(version):
                return None
            return Release(f"npm:{name}@{version}")
        if kind == "pypi":
            name, pin = pypi_package_spec(source)
            if not name or (pin and not _EXACT_PYPI_VERSION_RE.match(pin)):
                return None
            base = _registry_base("pypi", use_mirror)[0]
            url = f"{base}/pypi/{name}/{quote(pin)}/json" if pin else (
                f"{base}/pypi/{name}/json")
            with _open(url, timeout=timeout) as resp:
                meta = bounded_json.loads(resp.read(_MAX_ARCHIVE_BYTES))
            version = str((meta.get("info") or {}).get("version") or "")
            urls = meta.get("urls") or []
            chosen = _pick_distribution(urls)
            artifact = str((chosen or {}).get("filename") or "")
            if not (_EXACT_PYPI_VERSION_RE.match(version) and artifact):
                return None
            names = sorted(str(u.get("filename") or "") for u in urls)
            files = hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()[:16]
            return Release(f"pypi:{name}=={version}", artifact, files)
    except (OSError, ValueError, CollectionError):
        return None
    return None


# Why a source could not be fetched, as a fixed category: what the hook and the CLI say instead
# of a raw error (git's "could not read Username" for a repository that does not exist). Only
# these words cross to the person; the error text, which can quote the source, never does.
FAILURE_CATEGORIES = {
    "git-missing": "git is not installed, and checking a git source needs it",
    "not-found": "the registry has no such package or version",
    "repo-not-found": "the repository was not found, or it is private",
    "offline": "the registry could not be reached (no network connection, or a proxy or "
               "firewall blocks it)",
    "timeout": "the registry did not answer in time",
    "registry-error": "the registry answered with an error; try again later",
}
# What a fetch error says when the network, not the package, is the reason.
_OFFLINE_MARKERS = (
    "getaddrinfo failed", "Name or service not known", "nodename nor servname",
    "Temporary failure in name resolution", "No address associated with hostname",
    "Network is unreachable", "Connection refused", "No route to host", "actively refused",
    "[WinError 10051]", "[WinError 10060]", "[WinError 10065]", "Could not resolve host",
    "Could not resolve proxy", "Failed to connect to",
)
_REGISTRY_ERROR = re.compile(r"HTTP Error (?:5\d\d|429)")


def failure_category(exc: BaseException) -> str | None:
    """The FAILURE_CATEGORIES key for a CollectionError, or None when it is none of them."""
    message = str(exc)
    if "git is required" in message:
        return "git-missing"
    if any(m in message for m in ("HTTP Error 404", "was not found on", "has no version",
                                  "has no resolvable release",
                                  "has no downloadable distribution")):
        return "not-found"
    if "git clone failed" in message and any(
            m in message for m in ("Repository not found", "could not read Username",
                                   "not found", "Authentication failed")):
        return "repo-not-found"
    if not message.startswith(("failed to fetch", "git clone failed")):
        return None
    if any(m in message for m in _OFFLINE_MARKERS):
        return "offline"
    if "timed out" in message:
        return "timeout"
    if _REGISTRY_ERROR.search(message):
        return "registry-error"
    return None


def _registry_json(url: str, not_found: str = "") -> dict:
    """A registry document as a JSON object; anything else is a CollectionError, not a traceback.
    A 404 is reported as ``not_found`` when given: "HTTP Error 404" says nothing to a person."""
    try:
        data = _http_get(url)
    except CollectionError as exc:
        cause = exc.__cause__
        if not_found and isinstance(cause, urllib.error.HTTPError) and cause.code == 404:
            raise CollectionError(not_found) from exc
        raise
    try:
        doc = bounded_json.loads(data)
    except ValueError as exc:
        raise CollectionError(f"unexpected response from {url}") from exc
    if not isinstance(doc, dict):
        raise CollectionError(f"unexpected response from {url}")
    return doc


def _registry_base(kind: str, use_mirror: bool = True) -> tuple[str, bool]:
    """The base URL ``kind``'s packages are fetched from, and whether it is a configured mirror."""
    mirror = registry_mirror(kind) if use_mirror else None
    if mirror:
        return mirror, True
    return (_PUBLIC_NPM if kind == "npm" else _PUBLIC_PYPI), False


def _mirror_download(kind: str, url: str, metadata_url: str) -> str:
    """The file URL a mirror's metadata gives, checked: on the mirror's own scheme and host, or on
    the public registry's file host over https. A relative URL is read against the metadata's.
    Anything else is refused: the mirror's answer must not send the scan, or the token, elsewhere.
    """
    variable = NPM_REGISTRY_ENV if kind == "npm" else PYPI_INDEX_ENV
    resolved = urljoin(metadata_url, url)
    parts = urlsplit(resolved)
    host = (parts.hostname or "").lower() if parts.netloc else ""
    if _origin(resolved) == _origin(metadata_url) or (
            parts.scheme.lower() == "https" and host in _PUBLIC_DOWNLOAD_HOSTS[kind]):
        return resolved
    shown = host if re.fullmatch(r"[a-z0-9.:\[\]-]{1,200}", host) else "another host"
    raise CollectionError(
        f"the mirror set by {variable} points the download at {shown}, which is neither the "
        f"mirror nor the public registry; refusing to fetch it")


def _mirror_note(kind: str, base: str) -> str:
    variable = NPM_REGISTRY_ENV if kind == "npm" else PYPI_INDEX_ENV
    public = "the public npm registry" if kind == "npm" else "PyPI"
    return (f"Fetched from the registry mirror at {_origin(base)} ({variable}), not from "
            f"{public}: the report describes the mirror's copy of the package.")


def _npm_release(name: str, pin: str | None, base: str = _PUBLIC_NPM) -> tuple[str, str] | None:
    """``(version, tarball)`` of one version or dist-tag of ``name``, from the registry's
    per-version document (a few KB) instead of the packument, which lists every version ever
    published (31 MB for ``next``). The registry resolves a dist-tag there the same way, and
    answers 404 for anything else (a missing version, a range).

    None when the registry answered without a usable release: the caller then reads the
    packument, so every outcome, error messages included, stays what it was. A registry that
    cannot be reached raises: asking it a second time would only double the wait.
    """
    url = f"{base}/{quote(name, safe='@')}/{quote(pin or 'latest', safe='')}"
    try:
        data = _http_get(url)
    except CollectionError as exc:
        if isinstance(exc.__cause__, urllib.error.HTTPError):
            return None  # the registry answered: no such version or tag here
        raise
    try:
        manifest = bounded_json.loads(data)
    except ValueError:
        return None
    if not isinstance(manifest, dict):
        return None
    version, dist = manifest.get("version"), manifest.get("dist")
    tarball = dist.get("tarball") if isinstance(dist, dict) else None
    if not (isinstance(version, str) and version and isinstance(tarball, str) and tarball):
        return None
    if pin and _EXACT_NPM_VERSION_RE.match(pin) and version != pin:
        return None
    return version, tarball


def _collect_npm(source: str) -> SourceContext:
    name, pin = npm_package_spec(source)
    if not name:
        raise CollectionError(f"invalid npm package name in: {source}")
    if pin and _NPM_RANGE_RE.search(pin):
        # npm refuses a dist-tag that reads as a range, so these characters never name a tag.
        raise CollectionError(
            f"npm version ranges are not supported ('{pin}'): pin an exact version, "
            f"e.g. npm:{name}@1.2.3")
    base, mirrored = _registry_base("npm")
    release = _npm_release(name, pin, base)
    if release is not None:
        chosen, tarball = release
        return _npm_archive(source, chosen, tarball, base if mirrored else None,
                            f"{base}/{quote(name, safe='@')}/{quote(pin or 'latest', safe='')}")
    where = "the npm registry mirror" if mirrored else "npm"
    packument = f"{base}/{quote(name, safe='@')}"
    meta = _registry_json(packument, not_found=f"package '{name}' was not found on {where}")
    versions = meta.get("versions") or {}
    tags = meta.get("dist-tags") or {}
    if pin:
        # `x@latest` / `x@next` name a dist-tag, which npm resolves to a version the same way.
        # npm refuses a tag that parses as a version, so a tag never shadows a real version.
        pin = str(tags.get(pin, pin))
        if pin not in versions:
            raise CollectionError(f"npm package '{name}' has no version '{pin}'")
        chosen = pin
    else:
        chosen = tags.get("latest")
    dist = (versions.get(chosen) or {}).get("dist") if chosen else None
    tarball = (dist or {}).get("tarball")
    if not (chosen and tarball):
        raise CollectionError(f"npm package '{name}' has no resolvable release")
    return _npm_archive(source, str(chosen), tarball, base if mirrored else None, packument)


def _npm_archive(source: str, version: str, tarball: str, mirror: str | None,
                 metadata_url: str) -> SourceContext:
    """Fetch and extract an npm tarball; from a mirror, only once its URL is checked."""
    if mirror is None:
        return _collect_archive(source, "npm_package", version, tarball, tarball)
    tarball = _mirror_download("npm", tarball, metadata_url)
    ctx = _collect_archive(source, "npm_package", version, tarball, tarball)
    ctx.mirror_note = _mirror_note("npm", mirror)
    return ctx


def _pick_distribution(urls: list[dict]) -> dict | None:
    """The file to scan for a PyPI release: a wheel whenever the release has one, since pip
    installs a wheel over building the sdist wherever one matches.

    The choice depends on the release alone, never on the machine running the scan, so the same
    `pypi:x` gives the same report on a laptop, in CI and on the hosted scanner (analysis is
    component-only). A pure-Python wheel (``*-none-any.whl``) first: pip installs it wherever no
    platform wheel matches, and its code is exactly what gets imported. Else a platform wheel in a
    fixed order: Linux x86-64 (where CI and servers run), then Windows x64, then macOS, then the
    rest, newest CPython first within each. The sdist only when the release has no wheel. The
    other files are not read: the report says so (``distribution_note``), since a platform wheel
    can carry code the scanned one does not.
    """
    wheels = [u for u in urls if u.get("packagetype") == "bdist_wheel"]
    if not wheels:
        return next((u for u in urls if u.get("packagetype") == "sdist"), None)
    return min(wheels, key=lambda u: _wheel_rank(str(u.get("filename") or "").lower()))


# Platform families in the order a platform wheel is picked; anything else comes after them.
_PLATFORM_ORDER = (
    ("manylinux", "x86_64"), ("musllinux", "x86_64"), ("linux", "x86_64"),
    ("win", "amd64"),
    ("macosx", "universal2"), ("macosx", "x86_64"), ("macosx", "arm64"),
)


def _wheel_rank(filename: str) -> tuple[int, int, int, str]:
    """Sort key for a wheel: pure first, then by platform family (``_PLATFORM_ORDER``), then the
    newest CPython tag, then the name (so ties never depend on the order PyPI lists files)."""
    parts = filename[: -len(".whl")].split("-") if filename.endswith(".whl") else []
    if len(parts) not in (5, 6):
        return (2, len(_PLATFORM_ORDER), 0, filename)
    pythons, _abis, platforms = (part.split(".") for part in parts[-3:])
    if "any" in platforms:
        return (0, 0, 0, filename)
    family = min(
        (i for i, (os_name, arch) in enumerate(_PLATFORM_ORDER)
         for tag in platforms if tag.startswith(os_name) and tag.endswith(arch)),
        default=len(_PLATFORM_ORDER),
    )
    newest = max((int(t[3:]) for t in pythons if t.startswith("cp3") and t[3:].isdigit()),
                 default=0)
    return (1, family, -newest, filename)


def _distribution_note(urls: list[dict], chosen: dict) -> str | None:
    """What the report says about the files of a release that were not scanned, if any."""
    others = sum(1 for u in urls if u is not chosen and u.get("filename"))
    if not others:
        return None
    files = "distribution of this release was" if others == 1 else (
        "distributions of this release were")
    return (f"Scanned {neutralize_hidden(str(chosen.get('filename') or ''))}; {others} other "
            f"{files} not read (other platform wheels or the sdist can carry different code).")


def _collect_pypi(source: str) -> SourceContext:
    name, pin = pypi_package_spec(source)
    if not name:
        raise CollectionError(f"invalid PyPI package name in: {source}")
    base, mirrored = _registry_base("pypi")
    where = "the PyPI mirror" if mirrored else "PyPI"
    if pin:
        if not _EXACT_PYPI_VERSION_RE.match(pin):
            raise CollectionError(f"invalid PyPI version in: {source}")
        # Per-version metadata endpoint lists that release's distributions directly.
        metadata_url = f"{base}/pypi/{name}/{quote(pin)}/json"
        meta = _registry_json(metadata_url,
                              not_found=f"package '{name}' {pin} was not found on {where}")
        version = str((meta.get("info") or {}).get("version") or pin)
    else:
        metadata_url = f"{base}/pypi/{name}/json"
        meta = _registry_json(metadata_url, not_found=f"package '{name}' was not found on {where}")
        version = str((meta.get("info") or {}).get("version") or "")
    urls = meta.get("urls") or []
    chosen = _pick_distribution(urls)
    if not (version and chosen and chosen.get("url")):
        raise CollectionError(f"PyPI project '{name}' has no downloadable distribution")
    project = str((meta.get("info") or {}).get("name") or name)
    download = str(chosen["url"])
    if mirrored:
        download = _mirror_download("pypi", download, metadata_url)
    ctx = _collect_archive(
        source, "python_package", version, download, chosen.get("filename", ""),
        name=project,
    )
    ctx.distribution_note = _distribution_note(urls, chosen)
    if mirrored:
        ctx.mirror_note = _mirror_note("pypi", base)
    return ctx


def detect_component(root: Path, source: str, default_name: str | None = None) -> Component:
    """Derive component name/type/version solely from files inside ``root``.

    The name falls back to ``default_name``, else the folder name, when no manifest gives one.
    Manifests are read only when they are regular files: one that is a link is not followed.
    """
    name = default_name or root.name
    version = ""
    ctype = "directory"

    pkg = root / "package.json"
    pyproject = root / "pyproject.toml"
    setup_py = root / "setup.py"

    if is_regular_file(pkg):
        ctype = "npm_package"
        meta = _read_package_json(pkg)
        name = meta.get("name") or name
        version = meta.get("version") or ""
    elif is_regular_file(pyproject) or is_regular_file(setup_py):
        ctype = "python_package"
        meta = _read_pyproject(pyproject) if is_regular_file(pyproject) else {}
        name = meta.get("name") or name
        version = meta.get("version") or ""

    # Label common non-Python/Node project shapes so an uploaded project reads better than a bare
    # "directory" (detection itself is language-agnostic for the cross-cutting rules).
    elif is_regular_file(root / "go.mod"):
        ctype = "go_project"
    elif any(is_regular_file(root / f) for f in ("pom.xml", "build.gradle", "build.gradle.kts")):
        ctype = "java_project"

    # MCP / AI-component overrides take precedence when their artifacts are present.
    if _has_mcp_manifest(root):
        ctype = "mcp_server"
    elif ctype == "directory" and _has_skill_manifest(root):
        ctype = "agent_skill"  # an Anthropic-style Agent Skill (SKILL.md + bundled scripts)
    elif ctype == "directory" and _has_ai_artifacts(root):
        ctype = "ai_component"

    # Name/version come from attacker-controlled manifests; neutralize hidden/bidi chars so a
    # spoofed name can't deceive in the report header. (source is the user's own input.)
    return Component(
        name=neutralize_hidden(name), type=ctype, source=source, version=neutralize_hidden(version)
    )


def _read_package_json(path: Path) -> dict[str, str]:
    try:
        data = bounded_json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        "name": str(data.get("name", "")),
        "version": str(data.get("version", "")),
    }


# tomllib takes time quadratic in some crafted inputs (a 200 KB run of dotted keys parsed for
# 46 s), so it reads at most this much: the whole file when it is small, else only the
# `[project]` table, which is all the identity needs.
_MAX_TOML_PARSE = 16 * 1024


def _project_table(text: str) -> str:
    """The `[project]` table of a TOML document, found by a line scan: from its header to the
    next table header. Empty when there is none."""
    lines: list[str] = []
    inside = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            if inside:
                break
            inside = stripped.split("#", 1)[0].strip() == "[project]"
        if inside:
            lines.append(line)
    return "\n".join(lines)


def _read_pyproject(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    toml_text = text if len(text) <= _MAX_TOML_PARSE else _project_table(text)
    if tomllib is not None and len(toml_text) <= _MAX_TOML_PARSE:
        try:
            data = tomllib.loads(toml_text)
            project = data.get("project", {}) if isinstance(data, dict) else {}
            return {
                "name": str(project.get("name", "")),
                "version": str(project.get("version", "")),
            }
        # tomllib recurses: a value nested a few hundred levels deep exhausts the stack.
        except (tomllib.TOMLDecodeError, ValueError, RecursionError):
            pass
    # Fallback: best-effort regex for name/version.
    name = _toml_value(text, "name")
    version = _toml_value(text, "version")
    return {"name": name, "version": version}


def _toml_value(text: str, key: str) -> str:
    # `[^\S\n]*`, not `\s*`: from each of many blank lines `^\s*` ran over all the rest
    # (quadratic).
    m = re.search(rf'^[^\S\n]*{key}\s*=\s*"([^"]*)"', text, re.MULTILINE)
    return m.group(1) if m else ""


def _has_mcp_manifest(root: Path) -> bool:
    for name in ("mcp.json", ".mcp.json", "mcp.config.json"):
        if is_regular_file(root / name):
            return True
    # A package.json / manifest that declares mcpServers also counts.
    for candidate in ("package.json", "manifest.json", "server.json"):
        p = root / candidate
        if is_regular_file(p):
            try:
                if "mcpServers" in p.read_text(encoding="utf-8", errors="replace"):
                    return True
            except OSError:
                pass
    return False


def _has_skill_manifest(root: Path) -> bool:
    return is_regular_file(root / "SKILL.md") or is_regular_file(root / "skill.md")


def _has_ai_artifacts(root: Path) -> bool:
    for name in ("SKILL.md", "AGENTS.md", "skill.md", "agents.md", "CLAUDE.md"):
        if is_regular_file(root / name):
            return True
    return False
