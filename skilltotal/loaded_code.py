"""Code a component loads from a folder the index walk passes over, and how Node finds a module.

The walk sets aside dependency trees (``node_modules``, ``vendor/``), virtual environments and, in a
repository, build output (``skilltotal.file_index.skipped_dir_kind``): they hold code someone else
wrote, or a copy of the component's own. A component can file its *own* code there too. An entry
point that requires ``./lib/env/loader.js`` or ``./src/vendor/run.js`` ran that code while the scan
read none of it and reported the package clean. So the files a component loads by a literal path
are read wherever they sit: the targets of relative ``require``/``import`` in its JavaScript and
TypeScript, of its Python imports, and of its ``package.json`` / ``pyproject.toml`` entry points,
transitively. Only what lies in a skipped folder is added (everything else is read already), and a
loaded file that could not be read is reported, so a report never vouches for code it did not see.

Node's lookup (``module_file``) is shared with the install-script reader in ``skilltotal.engine``.
Parsing only: nothing is run.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path, PureWindowsPath

from skilltotal import bounded_json
from skilltotal.file_index import (
    SKIP_BUILD_OUTPUT,
    SKIP_VCS,
    FileIndex,
    IndexedFile,
    is_regular_file,
)

# A relative module a script loads with a literal specifier: require('./x'), import('./x'),
# `import x from './x'`, `export * from './x'`.
RELATIVE_MODULE = re.compile(
    r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s*|\bimport\s+)(["'])(\.{1,2}(?:/[^"'\n]{0,200})?)\1"""
)
# The same shapes with a bare name (`require("helper")`, `import x from "@s/pkg/sub"`): a
# dependency, read only when the package bundles it in its own node_modules.
BARE_MODULE = re.compile(
    r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s*|\bimport\s+)(["'])([A-Za-z0-9@_][^"'\s:]{0,200})\1"""
)
LOADING_SUFFIXES = frozenset({".js", ".cjs", ".mjs", ""})
MODULE_SUFFIXES = (".js", ".cjs", ".mjs", ".json")
# TypeScript sources resolve the same specifiers to `.ts` files (and `./x.js` written in a `.ts`
# file names the `x.ts` it is compiled from).
_TS_MODULE_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".cjs", ".mjs", ".json")
_JS_LIKE = frozenset({".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"})
_PY = frozenset({".py", ".pyw"})
# What a component loads is a handful of files; this only bounds a pathological import graph.
MAX_LOADED_FILES = 300


def _inside_by_name(base: Path, start: Path, spec: str) -> bool:
    """True when ``spec`` from ``start`` names a path inside ``base`` by its text alone.

    Checked before anything touches the file system: on Windows resolving `//host/share/x.js` (or
    the same with backslashes, a drive, a device path) opens a network connection to that host,
    so a command in a scanned package.json could make the scanner send the user's NTLM
    credentials to a host of the package author's choosing (security review, 2026-10-15).
    """
    if not spec or "\x00" in spec:
        return False
    if spec.startswith(("/", "\\")) or PureWindowsPath(spec).anchor or ":" in spec:
        return False
    joined = posixpath.normpath(posixpath.join(start.as_posix(), spec.replace("\\", "/")))
    root = posixpath.normpath(base.as_posix())
    return joined == root or joined.startswith(root.rstrip("/") + "/")


def module_file(
    base: Path, start: Path, spec: str, suffixes: tuple[str, ...] = MODULE_SUFFIXES
) -> Path | None:
    """The file ``spec`` names from ``start``, looked up as Node does (the path itself, then with
    each of ``suffixes``, then a folder's ``package.json`` main or ``index``), and only when it
    lies inside the component ``base``."""
    if not _inside_by_name(base, start, spec):
        return None
    try:
        path = (start / spec).resolve()
        # Outside the component (`../x`, or a link out of it) nothing is read, not even the
        # `package.json` of a linked folder.
        path.relative_to(base)
    except (OSError, ValueError):
        return None
    candidates = [path, *(path.with_name(path.name + s) for s in suffixes)]
    if path.suffix in (".js", ".mjs", ".cjs") and ".ts" in suffixes:
        stem = path.with_suffix("")
        candidates += [stem.with_name(stem.name + s) for s in (".ts", ".tsx", ".mts", ".cts")]
    if path.is_dir():
        manifest = path / "package.json"
        try:
            main = (bounded_json.loads(manifest.read_text(encoding="utf-8")).get("main")
                    if is_regular_file(manifest) else None)
        except (OSError, ValueError, AttributeError):
            main = None
        if isinstance(main, str) and main and _inside_by_name(base, path, main):
            entry = path / main
            candidates += [entry, *(entry.with_name(entry.name + s) for s in suffixes)]
            candidates += [entry / f"index{s}" for s in suffixes]
        candidates += [path / f"index{s}" for s in suffixes]
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            resolved.relative_to(base)
        except (OSError, ValueError):
            continue  # outside the component, or not a path at all
        if resolved.is_file():
            return resolved
    return None


def bundled_module_file(base: Path, start: Path, spec: str) -> Path | None:
    """The file a bare ``require("x")`` loads when ``x`` ships inside the package itself.

    Node looks for ``node_modules/x`` in the requiring file's folder and each parent. Only the
    folders inside the component count: a bundled dependency is in the tarball and runs with the
    install script, while one npm installs separately is not this package's code.
    """
    folder = start
    while True:
        loaded = module_file(base, folder / "node_modules", spec)
        if loaded is not None:
            return loaded
        if folder == base or base not in folder.parents:
            return None
        folder = folder.parent


# --- Python imports -------------------------------------------------------------------------------
_PY_FROM = re.compile(
    r"^[ \t]*from[ \t]+(\.*)([\w.]*)[ \t]+import[ \t]+(\([^)]{0,2000}\)|[^\n#;]{1,500})",
    re.MULTILINE,
)
_PY_IMPORT = re.compile(r"^[ \t]*import[ \t]+([\w.]+(?:[ \t]*,[ \t]*[\w.]+)*)", re.MULTILINE)
# Console scripts in pyproject (`name = "pkg.mod:func"`) and setup.py / setup.cfg. Unquoted, the
# name starts where its run of name characters does: tried from each character of a long run, the
# same failing match was repeated (quadratic).
_PY_ENTRY_POINT = re.compile(
    r"""(?:["']|(?<![\w.-]))[\w.-]+["']?[ \t]*=[ \t]*["']?([A-Za-z_][\w.]*):[\w.]+"""
)


def _module_paths(prefix: str, parts: list[str]) -> list[str]:
    """``prefix/a/b.py`` and ``prefix/a/b/__init__.py`` for module parts ``[a, b]``."""
    if not parts or not all(p.isidentifier() for p in parts):
        return []
    joined = "/".join(parts)
    base = f"{prefix}/{joined}" if prefix else joined
    return [f"{base}.py", f"{base}/__init__.py"]


def _import_names(raw: str) -> list[str]:
    names = []
    for item in raw.strip().strip("()").split(","):
        name = item.strip().split()[0] if item.strip() else ""
        if name and name != "*" and name.isidentifier():
            names.append(name)
    return names


def _python_targets(f: IndexedFile, roots: list[str]) -> list[str]:
    """Relative paths a Python file's imports may load (existence is checked by the caller)."""
    package = posixpath.dirname(f.relpath)
    out: list[str] = []
    for m in _PY_FROM.finditer(f.text):
        dots, module, names = m.group(1), m.group(2), _import_names(m.group(3))
        parts = [p for p in module.split(".") if p] if module else []
        if dots:
            base = package
            for _ in range(len(dots) - 1):
                base = posixpath.dirname(base)
            out += _module_paths(base, parts)
            for name in names:
                out += _module_paths(base, [*parts, name])
        else:
            for root in roots:
                out += _module_paths(root, parts)
                for name in names:
                    out += _module_paths(root, [*parts, name])
    for m in _PY_IMPORT.finditer(f.text):
        for dotted in m.group(1).split(","):
            parts = [p for p in dotted.strip().split(".") if p]
            for root in roots:
                for k in range(1, len(parts) + 1):
                    out += _module_paths(root, parts[:k])
    return out


# --- the follower ---------------------------------------------------------------------------------
def follow_skipped_references(index: FileIndex) -> tuple[FileIndex, list[str]]:
    """``index`` with the files the component loads from skipped folders added, and the loaded
    files in skipped folders that could not be read (too large, unreadable, or past
    ``MAX_LOADED_FILES``).

    A loaded file that is minified joins the index's minified list (it is reported as a bundle not
    analyzed); a binary one (a native addon) cannot be analyzed and is not reported.
    """
    # Build output a repository sets aside is a copy of its own source, read where it is written;
    # following `main: dist/index.js` there would count every finding twice.
    prefixes = tuple(
        rel + "/" for rel, kind in index.skipped_dirs if kind not in (SKIP_VCS, SKIP_BUILD_OUTPUT)
    )
    if not prefixes:
        return index, []
    base = index.root.resolve()
    known = {f.relpath for f in index.files} | set(index.minified)
    extra: list[IndexedFile] = []
    minified: list[str] = []
    unread: list[str] = []
    queue: list[IndexedFile] = []

    def skipped(rel: str) -> bool:
        return rel.startswith(prefixes)

    def consider(target: Path | None) -> None:
        if target is None:
            return
        try:
            rel = target.relative_to(base).as_posix()
        except ValueError:
            return
        if rel in known or not skipped(rel):
            return
        known.add(rel)
        if len(extra) >= MAX_LOADED_FILES:
            # Past the bound the code is still loaded; the report must say it was not read.
            unread.append(rel)
            return
        f, why = FileIndex.read_file(base, rel)
        if f is not None:
            extra.append(f)
            queue.append(f)
        elif why == "minified":
            minified.append(rel)
        elif why in ("large", "unreadable"):
            unread.append(rel)

    def consider_relpath(rel: str) -> None:
        rel = posixpath.normpath(rel)
        if rel.startswith("..") or not skipped(rel) or rel in known:
            return
        path = base / rel
        if path.is_file():
            consider(path.resolve())

    py_roots = [""] + [r for r in ("src", "lib") if (base / r).is_dir()]
    for target in _entry_points(base, py_roots):
        if isinstance(target, Path):
            consider(target)
        else:
            consider_relpath(target)
    queue.extend(f for f in index.files if f.suffix in _JS_LIKE or f.suffix in _PY)
    while queue:
        f = queue.pop()
        if f.suffix in _JS_LIKE:
            folder = posixpath.dirname(f.relpath)
            suffixes = MODULE_SUFFIXES if f.suffix in LOADING_SUFFIXES else _TS_MODULE_SUFFIXES
            for m in RELATIVE_MODULE.finditer(f.text):
                spec = m.group(2)
                joined = posixpath.normpath(posixpath.join(folder, spec)) if folder else (
                    posixpath.normpath(spec)
                )
                # Cheap test first: only a specifier pointing into a skipped folder is resolved.
                if not skipped(joined + "/") and not skipped(joined):
                    continue
                consider(module_file(base, f.path.parent, spec, suffixes))
        elif f.suffix in _PY:
            for rel in _python_targets(f, py_roots):
                consider_relpath(rel)
    if not extra and not minified:
        return index, sorted(unread)
    return index.with_files(extra, minified), sorted(unread)


def _entry_points(base: Path, py_roots: list[str]) -> list[Path | str]:
    """What the package itself starts: ``package.json`` main/module/browser/bin/exports and the
    Python console scripts. Paths (resolved) or relative paths to check."""
    found: list[Path | str] = []
    manifest = base / "package.json"
    if is_regular_file(manifest):
        try:
            data = bounded_json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            data = None
        if isinstance(data, dict):
            values: list[object] = [data.get(k) for k in ("main", "module", "browser")]
            bins = data.get("bin")
            values += list(bins.values()) if isinstance(bins, dict) else [bins]
            stack: list[object] = [data.get("exports")]
            while stack:
                item = stack.pop()
                if isinstance(item, str):
                    values.append(item)
                elif isinstance(item, dict):
                    stack.extend(item.values())
                elif isinstance(item, list):
                    stack.extend(item)
            for value in values:
                if isinstance(value, str) and value and "*" not in value:
                    spec = value if value.startswith(".") else f"./{value}"
                    found.append(module_file(base, base, spec, _TS_MODULE_SUFFIXES))
    for name in ("pyproject.toml", "setup.cfg", "setup.py"):
        path = base / name
        if not is_regular_file(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _PY_ENTRY_POINT.finditer(text):
            parts = m.group(1).split(".")
            for root in py_roots:
                found += _module_paths(root, parts)
    return [f for f in found if f is not None]
