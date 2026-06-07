"""Source collection: resolve a path or URL into a local directory + component identity.

Supported sources: a local directory, or a remote git URL (cloned shallowly into a temp
directory). Component identity (name/type/version) is derived **only** from the component
itself — never from the user's environment.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404
import tempfile
from dataclasses import dataclass
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

from skilltotal.models import Component

_GIT_URL_RE = re.compile(r"^(?:https?://|git@|ssh://|git://).+", re.IGNORECASE)


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


def collect(source: str) -> SourceContext:
    """Resolve ``source`` (local path or git URL) into a :class:`SourceContext`."""
    if is_url(source):
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
