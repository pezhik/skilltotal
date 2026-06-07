"""Source collection: resolve a path or URL into a local directory + component identity.

Supported sources: a local directory, or a remote git URL (cloned shallowly into a temp
directory). Component identity (name/type/version) is derived **only** from the component
itself — never from the user's environment.
"""

from __future__ import annotations

import io
import json
import re
import shutil
import subprocess  # nosec B404
import tarfile
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import quote

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

from skilltotal.models import Component

_GIT_URL_RE = re.compile(r"^(?:https?://|git@|ssh://|git://).+", re.IGNORECASE)
_NPMJS_URL_RE = re.compile(r"^https?://(?:www\.)?npmjs\.com/package/(@?[\w.-]+(?:/[\w.-]+)?)", re.I)
_PYPI_URL_RE = re.compile(r"^https?://pypi\.org/project/([\w.-]+)", re.I)
# Conservative package-name shapes (also block path traversal in specs).
_NPM_NAME_RE = re.compile(r"^@?[a-z0-9][\w.-]*(?:/[a-z0-9][\w.-]*)?$", re.I)
_PYPI_NAME_RE = re.compile(r"^[a-z0-9][\w.-]*$", re.I)

_HTTP_TIMEOUT = 60  # seconds for a registry/download request
_MAX_ARCHIVE_BYTES = 150 * 1024 * 1024  # cap the downloaded archive
_MAX_EXTRACT_BYTES = 400 * 1024 * 1024  # cap total uncompressed size (decompression-bomb guard)


class CollectionError(Exception):
    """Raised when a source cannot be resolved into an analyzable directory."""


@dataclass
class SourceContext:
    """A resolved, analyzable component on local disk."""

    root: Path
    component: Component
    _tempdir: tempfile.TemporaryDirectory | None = None

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


def npm_package_name(source: str) -> str | None:
    """Extract the npm package name from an `npm:<name>` spec or an npmjs.com URL."""
    s = source.strip()
    if s.lower().startswith("npm:"):
        name = s[4:].strip()
    else:
        m = _NPMJS_URL_RE.match(s)
        name = m.group(1) if m else ""
    return name if name and _NPM_NAME_RE.match(name) else None


def pypi_package_name(source: str) -> str | None:
    """Extract the PyPI project name from a `pypi:<name>` spec or a pypi.org URL."""
    s = source.strip()
    if s.lower().startswith("pypi:"):
        name = s[5:].strip()
    else:
        m = _PYPI_URL_RE.match(s)
        name = m.group(1) if m else ""
    return name if name and _PYPI_NAME_RE.match(name) else None


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


def _collect_local(source: str) -> SourceContext:
    root = Path(source).expanduser().resolve()
    if not root.exists():
        raise CollectionError(f"Path does not exist: {source}")
    if not root.is_dir():
        raise CollectionError(f"Path is not a directory: {source}")
    component = detect_component(root, source=str(root))
    return SourceContext(root=root, component=component)


def _collect_remote(url: str) -> SourceContext:
    """Shallow-clone a remote git URL into a temp dir.

    Security: the subprocess call is intentional and reviewed — git is resolved from PATH
    (cross-platform), arguments are passed as a list (never with a shell), and the URL has
    already been validated by :func:`is_url`. The call below is annotated as a reviewed
    exception for the static security scan.
    """
    if shutil.which("git") is None:
        raise CollectionError(
            "git is required to analyze remote URLs but was not found on PATH."
        )
    tmp = tempfile.TemporaryDirectory(prefix="skilltotal_")
    dest = Path(tmp.name) / "repo"
    try:
        subprocess.run(  # nosec B603 B607
            ["git", "clone", "--depth", "1", url, str(dest)],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        tmp.cleanup()
        raise CollectionError(
            f"git clone failed for {url}: {exc.stderr.strip() or exc}"
        ) from exc
    component = detect_component(dest, source=url)
    return SourceContext(root=dest, component=component, _tempdir=tmp)


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


def _safe_extract_tar(data: bytes, dest: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        safe, total = [], 0
        for m in tf.getmembers():
            if m.issym() or m.islnk():
                continue  # never extract links (path-escape risk)
            target = (dest / m.name).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise CollectionError("archive contains an unsafe path")
            if m.isfile():
                total += m.size
                if total > _MAX_EXTRACT_BYTES:
                    raise CollectionError("archive too large when extracted")
            safe.append(m)
        tf.extractall(dest, members=safe)  # nosec B202 - members validated above


def _safe_extract_zip(data: bytes, dest: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        total = 0
        for info in zf.infolist():
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise CollectionError("archive contains an unsafe path")
            total += info.file_size
            if total > _MAX_EXTRACT_BYTES:
                raise CollectionError("archive too large when extracted")
        zf.extractall(dest)  # nosec B202 - paths validated above


def _collect_archive(source: str, ctype: str, version: str, archive_url: str, filename: str) -> SourceContext:
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
        component = replace(component, type=ctype, version=component.version or version)
        return SourceContext(root=root, component=component, _tempdir=tmp)
    except Exception:
        tmp.cleanup()
        raise


def _collect_npm(source: str) -> SourceContext:
    name = npm_package_name(source)
    if not name:
        raise CollectionError(f"invalid npm package name in: {source}")
    meta = json.loads(_http_get(f"https://registry.npmjs.org/{quote(name, safe='@')}"))
    latest = (meta.get("dist-tags") or {}).get("latest")
    versions = meta.get("versions") or {}
    dist = (versions.get(latest) or {}).get("dist") if latest else None
    tarball = (dist or {}).get("tarball")
    if not (latest and tarball):
        raise CollectionError(f"npm package '{name}' has no resolvable latest release")
    return _collect_archive(source, "npm_package", str(latest), tarball, tarball)


def _collect_pypi(source: str) -> SourceContext:
    name = pypi_package_name(source)
    if not name:
        raise CollectionError(f"invalid PyPI package name in: {source}")
    meta = json.loads(_http_get(f"https://pypi.org/pypi/{name}/json"))
    version = str((meta.get("info") or {}).get("version") or "")
    urls = meta.get("urls") or []
    chosen = next((u for u in urls if u.get("packagetype") == "sdist"), None)
    chosen = chosen or next((u for u in urls if u.get("packagetype") == "bdist_wheel"), None)
    if not (version and chosen and chosen.get("url")):
        raise CollectionError(f"PyPI project '{name}' has no downloadable distribution")
    return _collect_archive(source, "python_package", version, chosen["url"], chosen.get("filename", ""))


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

    # MCP / AI-component overrides take precedence when their artifacts are present.
    if _has_mcp_manifest(root):
        ctype = "mcp_server"
    elif ctype == "directory" and _has_ai_artifacts(root):
        ctype = "ai_component"

    return Component(name=name, type=ctype, source=source, version=version)


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


def _has_ai_artifacts(root: Path) -> bool:
    for name in ("SKILL.md", "AGENTS.md", "skill.md", "agents.md", "CLAUDE.md"):
        if (root / name).exists():
            return True
    return False
