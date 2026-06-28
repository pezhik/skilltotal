"""Source collection: resolve a path or URL into a local directory + component identity.

Supported sources: a local directory, or a remote git URL (cloned shallowly into a temp
directory). Component identity (name/type/version) is derived **only** from the component
itself — never from the user's environment.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import stat
import subprocess  # nosec B404
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import quote, urlparse

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

from skilltotal.file_index import neutralize_hidden
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
# Archive caps (env-overridable so a hosted upload path can tighten them on a small box):
#   SKILLTOTAL_MAX_ARCHIVE_MB   — max size of the archive itself (downloaded or uploaded)
#   SKILLTOTAL_MAX_EXTRACT_MB   — max total uncompressed size (decompression-bomb guard)
#   SKILLTOTAL_MAX_ARCHIVE_MEMBERS — max number of entries (anti "millions of tiny files" DoS)
_MAX_ARCHIVE_BYTES = int(os.environ.get("SKILLTOTAL_MAX_ARCHIVE_MB", "150")) * 1024 * 1024
_MAX_EXTRACT_BYTES = int(os.environ.get("SKILLTOTAL_MAX_EXTRACT_MB", "400")) * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = int(os.environ.get("SKILLTOTAL_MAX_ARCHIVE_MEMBERS", "30000"))
# Local archive / single-file sources accepted by `scan <path>` (besides a directory).
_LOCAL_ARCHIVE_EXTS = (".zip", ".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz")
# Bound a git clone so a slow/huge remote can't hang the caller (a long-lived server holds a
# request the whole time); overridable via env. GIT_TERMINAL_PROMPT=0 prevents a clone from
# blocking forever on an interactive credential prompt for a private/typo'd URL.
_CLONE_TIMEOUT = int(os.environ.get("SKILLTOTAL_CLONE_TIMEOUT", "300"))
# Reject repositories larger than this (MB). Checked before cloning (GitHub API) and again
# during the clone (a watchdog kills git if the working tree blows past the cap) so a huge repo
# can neither hang nor fill the disk / OOM the box. Overridable via env.
_MAX_CLONE_MB = int(os.environ.get("SKILLTOTAL_MAX_CLONE_MB", "200"))
_CLONE_POLL_SECONDS = 1.5
# Web hosts whose browser URLs we understand (branch / subfolder / file / commit links).
_WEB_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "huggingface.co")
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)
# Hugging Face repo-type prefixes: a model is `hf.co/<org>/<name>`, but datasets and spaces nest
# under `hf.co/datasets/<org>/<name>` and `hf.co/spaces/<org>/<name>`.
_HF_REPO_PREFIXES = ("datasets", "spaces")
# HF browser ref kinds: tree (dir), blob (file), resolve (raw file).
_HF_REF_KINDS = ("tree", "blob", "resolve")


class CollectionError(Exception):
    """Raised when a source cannot be resolved into an analyzable directory."""


class SourceTooLargeError(CollectionError):
    """Raised when a repository exceeds the configured size cap (pre-clone or mid-clone)."""


@dataclass
class SourceContext:
    """A resolved, analyzable component on local disk."""

    root: Path
    component: Component
    _tempdir: tempfile.TemporaryDirectory | None = None
    # Set when a browser URL was normalized to scan something other than what was pasted
    # (e.g. a /issues link reduced to the repo's default branch); surfaced in the report.
    note: str | None = None

    def __enter__(self) -> SourceContext:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        if self._tempdir is not None:
            self._tempdir.cleanup()
            self._tempdir = None


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


def collect(source: str) -> SourceContext:
    """Resolve ``source`` into a :class:`SourceContext`.

    Supports a local directory, a git URL (shallow clone), and npm / PyPI packages
    (`npm:<name>` / `pypi:<name>` specs or npmjs.com / pypi.org URLs — the latest published
    release is downloaded from the registry and extracted).
    """
    kind = classify_source(source)
    if kind == "npm":
        return _collect_npm(source)
    if kind == "pypi":
        return _collect_pypi(source)
    if kind == "git":
        return _collect_remote(source)
    return _collect_local(source)


def _is_archive_name(name: str) -> bool:
    n = name.lower()
    return any(n.endswith(ext) for ext in _LOCAL_ARCHIVE_EXTS)


def _collect_local(source: str) -> SourceContext:
    root = Path(source).expanduser().resolve()
    if not root.exists():
        raise CollectionError(f"Path does not exist: {source}")
    if root.is_dir():
        component = detect_component(root, source=str(root))
        return SourceContext(root=root, component=component)
    if root.is_file():
        # A project archive (zip/tar.gz/…) or a single code file: extract/stage to a temp dir and
        # scan it with the same engine. The display source is the file name (neutralized), never the
        # temp path.
        if _is_archive_name(root.name):
            return _collect_local_archive(root)
        return _collect_local_file(root)
    raise CollectionError(f"Path is not a file or directory: {source}")


def _collect_local_archive(path: Path) -> SourceContext:
    if path.stat().st_size > _MAX_ARCHIVE_BYTES:
        raise CollectionError("archive is too large")
    data = path.read_bytes()
    display = neutralize_hidden(path.name)
    tmp = tempfile.TemporaryDirectory(prefix="skilltotal_")
    try:
        extract_dir = Path(tmp.name) / "x"
        extract_dir.mkdir()
        if path.name.lower().endswith(".zip"):
            _safe_extract_zip(data, extract_dir)
        else:  # .tar.gz / .tgz / .tar / .tar.bz2 / .tar.xz
            _safe_extract_tar(data, extract_dir)
        root = _single_root(extract_dir)
        component = detect_component(root, source=display)
        if component.type == "directory":
            component = replace(component, type="project")
        return SourceContext(root=root, component=component, _tempdir=tmp)
    except Exception:
        tmp.cleanup()
        raise


def _collect_local_file(path: Path) -> SourceContext:
    if path.stat().st_size > _MAX_ARCHIVE_BYTES:
        raise CollectionError("file is too large")
    display = neutralize_hidden(path.name)
    tmp = tempfile.TemporaryDirectory(prefix="skilltotal_")
    try:
        root = Path(tmp.name)
        # path.name is a bare filename; we control `root`, so the destination stays inside it.
        shutil.copy2(path, root / path.name)
        component = detect_component(root, source=display)
        if component.type == "directory":
            component = replace(component, type="project")
        return SourceContext(root=root, component=component, _tempdir=tmp)
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


def _dir_size_bytes(root: Path) -> int:
    """Total size of regular files under ``root`` (best-effort; races during a clone are fine)."""
    total = 0
    for p in root.rglob("*"):
        try:
            if p.is_file() and not p.is_symlink():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def _reject_if_too_large(clone_url: str) -> None:
    """Fast pre-clone size check via the GitHub API; no-op for other hosts or on any API error."""
    parsed = urlparse(clone_url)
    if (parsed.hostname or "").lower() != "github.com":
        return
    path = parsed.path.removesuffix(".git").strip("/")
    if path.count("/") != 1:
        return
    api = f"https://api.github.com/repos/{path}"
    try:
        req = urllib.request.Request(
            api,
            headers={"User-Agent": "skilltotal-scanner", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # nosec B310 - https
            meta = json.loads(resp.read(_MAX_ARCHIVE_BYTES + 1))
    except (OSError, ValueError):
        return  # rate-limited / private / offline -> rely on the mid-clone watchdog
    size_kb = meta.get("size")
    if isinstance(size_kb, (int, float)) and size_kb / 1024 > _MAX_CLONE_MB:
        raise SourceTooLargeError(
            f"repository is ~{round(size_kb / 1024)} MB, which exceeds the "
            f"{_MAX_CLONE_MB} MB scan limit ({path})."
        )


def _run_git(args: list[str], dest: Path, env: dict, url: str) -> None:
    """Run a git clone/fetch, bounded in time AND in size (watchdog kills it past the cap).

    Security: git is resolved from PATH, arguments are passed as a list (never a shell), and the
    URL was validated upstream. Reviewed exception for the static security scan.
    """
    cap = _MAX_CLONE_MB * 1024 * 1024
    proc = subprocess.Popen(  # nosec B603 B607
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env
    )
    exceeded = {"hit": False}

    def _watch() -> None:
        while proc.poll() is None:
            if dest.exists() and _dir_size_bytes(dest) > cap:
                exceeded["hit"] = True
                proc.kill()
                return
            time.sleep(_CLONE_POLL_SECONDS)

    watcher = threading.Thread(target=_watch, daemon=True)
    watcher.start()
    try:
        _, stderr = proc.communicate(timeout=_CLONE_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        proc.communicate()
        raise CollectionError(f"git clone timed out after {_CLONE_TIMEOUT}s for {url}") from exc
    finally:
        watcher.join(timeout=2)
    if exceeded["hit"]:
        raise SourceTooLargeError(
            f"repository exceeds the {_MAX_CLONE_MB} MB scan limit (aborted mid-clone): {url}"
        )
    if proc.returncode != 0:
        raise CollectionError(f"git clone failed for {url}: {(stderr or '').strip()}")


def _collect_remote(url: str) -> SourceContext:
    """Resolve a git/browser URL into a local checkout (shallow, size-bounded).

    Parses branch/tag/commit/subfolder links, rejects oversized repositories, and clones only
    what is needed.
    """
    if shutil.which("git") is None:
        raise CollectionError("git is required to analyze remote URLs but was not found on PATH.")
    clone_url, ref, subpath, note = parse_git_url(url)
    _reject_if_too_large(clone_url)

    tmp = tempfile.TemporaryDirectory(prefix="skilltotal_")
    dest = Path(tmp.name) / "repo"
    # Non-interactive (no credential prompt that could block) and bounded in time + size.
    clone_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}
    is_sha = bool(ref and _SHA_RE.match(ref))
    try:
        if ref and not is_sha:  # branch or tag
            _run_git(["git", "clone", "--depth", "1", "--branch", ref, clone_url, str(dest)],
                     dest, clone_env, url)
        else:
            _run_git(["git", "clone", "--depth", "1", clone_url, str(dest)], dest, clone_env, url)
            if is_sha:  # fetch + check out the requested commit (GitHub allows reachable SHAs)
                try:
                    subprocess.run(  # nosec B603 B607
                        ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", ref],
                        check=True, capture_output=True, text=True,
                        timeout=_CLONE_TIMEOUT, env=clone_env,
                    )
                    subprocess.run(  # nosec B603 B607
                        ["git", "-C", str(dest), "checkout", "--force", ref],
                        check=True, capture_output=True, text=True, timeout=60, env=clone_env,
                    )
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                    tmp.cleanup()
                    raise CollectionError(f"commit '{ref}' not found in {clone_url}") from exc
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

    component = detect_component(root, source=url)
    return SourceContext(root=root, component=component, _tempdir=tmp, note=note)


# --------------------------------------------------------------- package registries

def _open(url: str):
    """Open an https URL (scheme enforced) with a timeout."""
    if not url.lower().startswith("https://"):
        raise CollectionError(f"refusing to fetch non-https URL: {url}")
    return urllib.request.urlopen(url, timeout=_HTTP_TIMEOUT)  # nosec B310 - https enforced above


def _http_get(url: str) -> bytes:
    """Fetch a URL, capping the response size (guards against oversized payloads)."""
    try:
        with _open(url) as resp:
            data = resp.read(_MAX_ARCHIVE_BYTES + 1)
    except (OSError, ValueError) as exc:  # URLError/HTTPError are OSError subclasses
        raise CollectionError(f"failed to fetch {url}: {exc}") from exc
    if len(data) > _MAX_ARCHIVE_BYTES:
        raise CollectionError(f"response from {url} exceeds the size limit")
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


def _safe_extract_tar(data: bytes, dest: Path) -> None:
    dest_resolved = dest.resolve()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        safe, total = [], 0
        for m in tf.getmembers():
            if len(safe) >= _MAX_ARCHIVE_MEMBERS:
                raise CollectionError("archive has too many entries")
            if m.issym() or m.islnk():
                continue  # never extract links (path-escape risk)
            if not _within(dest_resolved, m.name, dest):
                raise CollectionError("archive contains an unsafe path")
            if m.isfile():
                total += m.size
                if total > _MAX_EXTRACT_BYTES:
                    raise CollectionError("archive too large when extracted")
            safe.append(m)
        tf.extractall(dest, members=safe)  # nosec B202 - members validated above


def _safe_extract_zip(data: bytes, dest: Path) -> None:
    dest_resolved = dest.resolve()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        safe, total = [], 0
        for info in zf.infolist():
            if len(safe) >= _MAX_ARCHIVE_MEMBERS:
                raise CollectionError("archive has too many entries")
            # zipfile.extractall can create symlinks from the stored unix mode on some platforms.
            if stat.S_ISLNK(info.external_attr >> 16):
                continue  # never extract symlinks (path-escape risk)
            if not _within(dest_resolved, info.filename, dest):
                raise CollectionError("archive contains an unsafe path")
            total += info.file_size
            if total > _MAX_EXTRACT_BYTES:
                raise CollectionError("archive too large when extracted")
            safe.append(info)
        zf.extractall(dest, members=safe)  # nosec B202 - members validated above


def _collect_archive(
    source: str, ctype: str, version: str, archive_url: str, filename: str
) -> SourceContext:
    data = _http_get(archive_url)
    tmp = tempfile.TemporaryDirectory(prefix="skilltotal_")
    try:
        extract_dir = Path(tmp.name) / "x"
        extract_dir.mkdir()
        if filename.lower().endswith(".whl") or filename.lower().endswith(".zip"):
            _safe_extract_zip(data, extract_dir)
        else:  # .tgz / .tar.gz / .tar.*
            _safe_extract_tar(data, extract_dir)
        root = _single_root(extract_dir)
        component = detect_component(root, source=source)
        component = replace(
            component,
            type=ctype,
            version=component.version or version,
            download_url=archive_url,
        )
        return SourceContext(root=root, component=component, _tempdir=tmp)
    except Exception:
        tmp.cleanup()
        raise


def _collect_npm(source: str) -> SourceContext:
    name, pin = npm_package_spec(source)
    if not name:
        raise CollectionError(f"invalid npm package name in: {source}")
    meta = json.loads(_http_get(f"https://registry.npmjs.org/{quote(name, safe='@')}"))
    versions = meta.get("versions") or {}
    if pin:
        if pin not in versions:
            raise CollectionError(f"npm package '{name}' has no version '{pin}'")
        chosen = pin
    else:
        chosen = (meta.get("dist-tags") or {}).get("latest")
    dist = (versions.get(chosen) or {}).get("dist") if chosen else None
    tarball = (dist or {}).get("tarball")
    if not (chosen and tarball):
        raise CollectionError(f"npm package '{name}' has no resolvable release")
    return _collect_archive(source, "npm_package", str(chosen), tarball, tarball)


def _collect_pypi(source: str) -> SourceContext:
    name, pin = pypi_package_spec(source)
    if not name:
        raise CollectionError(f"invalid PyPI package name in: {source}")
    if pin:
        # Per-version metadata endpoint lists that release's distributions directly.
        meta = json.loads(_http_get(f"https://pypi.org/pypi/{name}/{pin}/json"))
        version = str((meta.get("info") or {}).get("version") or pin)
    else:
        meta = json.loads(_http_get(f"https://pypi.org/pypi/{name}/json"))
        version = str((meta.get("info") or {}).get("version") or "")
    urls = meta.get("urls") or []
    chosen = next((u for u in urls if u.get("packagetype") == "sdist"), None)
    chosen = chosen or next((u for u in urls if u.get("packagetype") == "bdist_wheel"), None)
    if not (version and chosen and chosen.get("url")):
        raise CollectionError(f"PyPI project '{name}' has no downloadable distribution")
    return _collect_archive(
        source, "python_package", version, chosen["url"], chosen.get("filename", "")
    )


def detect_component(root: Path, source: str) -> Component:
    """Derive component name/type/version solely from files inside ``root``."""
    name = root.name
    version = ""
    ctype = "directory"

    pkg = root / "package.json"
    pyproject = root / "pyproject.toml"
    setup_py = root / "setup.py"

    if pkg.exists():
        ctype = "npm_package"
        meta = _read_package_json(pkg)
        name = meta.get("name") or name
        version = meta.get("version") or ""
    elif pyproject.exists() or setup_py.exists():
        ctype = "python_package"
        meta = _read_pyproject(pyproject) if pyproject.exists() else {}
        name = meta.get("name") or name
        version = meta.get("version") or ""

    # Label common non-Python/Node project shapes so an uploaded project reads better than a bare
    # "directory" (detection itself is language-agnostic for the cross-cutting rules).
    elif (root / "go.mod").exists():
        ctype = "go_project"
    elif any((root / f).exists() for f in ("pom.xml", "build.gradle", "build.gradle.kts")):
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
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        "name": str(data.get("name", "")),
        "version": str(data.get("version", "")),
    }


def _read_pyproject(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if tomllib is not None:
        try:
            data = tomllib.loads(text)
            project = data.get("project", {}) if isinstance(data, dict) else {}
            return {
                "name": str(project.get("name", "")),
                "version": str(project.get("version", "")),
            }
        except (tomllib.TOMLDecodeError, ValueError):
            pass
    # Fallback: best-effort regex for name/version.
    name = _toml_value(text, "name")
    version = _toml_value(text, "version")
    return {"name": name, "version": version}


def _toml_value(text: str, key: str) -> str:
    m = re.search(rf'^\s*{key}\s*=\s*"([^"]*)"', text, re.MULTILINE)
    return m.group(1) if m else ""


def _has_mcp_manifest(root: Path) -> bool:
    for name in ("mcp.json", ".mcp.json", "mcp.config.json"):
        if (root / name).exists():
            return True
    # A package.json / manifest that declares mcpServers also counts.
    for candidate in ("package.json", "manifest.json", "server.json"):
        p = root / candidate
        if p.exists():
            try:
                if "mcpServers" in p.read_text(encoding="utf-8", errors="replace"):
                    return True
            except OSError:
                pass
    return False


def _has_skill_manifest(root: Path) -> bool:
    return (root / "SKILL.md").exists() or (root / "skill.md").exists()


def _has_ai_artifacts(root: Path) -> bool:
    for name in ("SKILL.md", "AGENTS.md", "skill.md", "agents.md", "CLAUDE.md"):
        if (root / name).exists():
            return True
    return False
