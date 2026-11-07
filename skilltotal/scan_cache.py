"""Replay a scanner's result on a file index it has already scanned with the same code.

A scanner is a function of the file index alone (see :mod:`skilltotal.parallel`), so its result
is decided by two things: what the index holds, and the code the scanner runs. ``ScanCache`` keys
each stored result on both. The index side is a digest of its content: every file's relative path
and text and the walk's other lists, never the folder the files sit in. The code side is a digest
of the scanner's module together with every engine module it imports, directly or through others,
plus the Python version and the platform. Change a scanner, or anything it imports, and that
scanner scans again while the others replay. Everything after the scanners (demotion, scoring, the
synthesized findings) always runs, so a change there needs no rescan at all.

It is opt-in, for a caller that scans the same components again and again with an engine that
changes a little at a time (the calibration harness). An entry that does not parse or has the
wrong shape is a miss. A scanner that reads files outside the index sets
``reads_outside_index`` and is never replayed. ``audit_every=N`` scans one index in N anyway, by
its digest, and counts every replay that would have differed, so a dependency the digest missed
shows up as a number instead of a quietly wrong report.
"""

from __future__ import annotations

import ast
import functools
import hashlib
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from skilltotal.models import Evidence, Finding, NeedsReview, Severity, ThreatClass

if TYPE_CHECKING:
    from skilltotal.file_index import FileIndex
    from skilltotal.scanners.base import Scanner, ScanResult

# Bumped when the entry layout or what a digest covers changes: old entries then miss.
FORMAT = 1
_PACKAGE = "skilltotal"
_PACKAGE_ROOT = Path(__file__).resolve().parent


# --- the code a scanner runs ---------------------------------------------------------------------


def _module_file(name: str, root: Path = _PACKAGE_ROOT) -> Path | None:
    """The source file of engine module ``name`` (``skilltotal.a.b``), or None."""
    parts = name.split(".")
    if parts[0] != _PACKAGE:
        return None
    base = root.joinpath(*parts[1:])
    for candidate in (base.with_suffix(".py"), base / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


@functools.cache  # each module is parsed once per process, not once per scanner importing it
def _imported(name: str, path: Path, root: Path) -> frozenset[str]:
    """The engine modules ``path`` (module ``name``) imports anywhere in its body."""
    try:
        tree = ast.parse(path.read_bytes())
    except (SyntaxError, ValueError):
        return frozenset({_PACKAGE})  # unknowable: depend on the package as a whole
    package = name if path.name == "__init__.py" else name.rpartition(".")[0]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names if a.name.split(".")[0] == _PACKAGE)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                anchor = package.split(".")
                anchor = anchor[: len(anchor) - (node.level - 1)]
                base = ".".join([*anchor, *([node.module] if node.module else [])])
            else:
                base = node.module or ""
            if base.split(".")[0] != _PACKAGE:
                continue
            for alias in node.names:
                # `from skilltotal import bounded_json` names a module, not the package's own code.
                sub = f"{base}.{alias.name}"
                found.add(sub if _module_file(sub, root) is not None else base)
    return frozenset(found)


def code_files(module: str, root: Path = _PACKAGE_ROOT) -> list[Path]:
    """The source files module ``module`` runs: its own and every engine module it imports,
    directly or through others, in a stable order."""
    seen: dict[str, Path] = {}
    todo = [module]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        path = _module_file(name, root)
        if path is None:
            continue
        seen[name] = path
        todo.extend(_imported(name, path, root) - seen.keys())
    return sorted(seen.values())


@functools.cache
def _data_files(root: Path) -> tuple[Path, ...]:
    return tuple(sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.suffix not in (".py", ".pyc") and "__pycache__" not in p.parts
    ))


def code_digest(scanner: Scanner, root: Path = _PACKAGE_ROOT) -> str:
    """A digest of the code ``scanner`` runs (computed once per process: it cannot change)."""
    return _code_digest(type(scanner).__module__, type(scanner).__qualname__, scanner.name, root)


@functools.cache
def _code_digest(module: str, qualname: str, name: str, root: Path) -> str:
    h = hashlib.sha256(f"{FORMAT}\0{sys.version_info[0]}.{sys.version_info[1]}\0{sys.platform}"
                       f"\0{qualname}\0{name}".encode())
    for path in [*code_files(module, root), *_data_files(root)]:
        h.update(b"\0" + path.relative_to(root).as_posix().encode() + b"\0")
        h.update(path.read_bytes())
    return h.hexdigest()[:24]


# --- what the index holds ------------------------------------------------------------------------

# Index attributes outside the digest: where the files sit (no scanner's result depends on it) and
# the files themselves, hashed one by one below.
_NOT_CONTENT = frozenset({"root", "files", "git_config"})


def _canonical(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    raise TypeError(f"no stable form for {type(value).__name__}")


def index_digest(index: FileIndex) -> str | None:
    """A digest of everything in ``index`` a scanner can read, or None when some part of it has
    no stable form (then nothing is replayed)."""
    h = hashlib.sha256()
    extra = [index.git_config] if index.git_config is not None else []
    for marker, files in ((b"F", index.files), (b"G", extra)):
        for f in files:
            h.update(marker + f.relpath.encode("utf-8", "surrogatepass") + b"\0")
            h.update(f.text.encode("utf-8", "surrogatepass") + b"\0")
    rest = {k: v for k, v in vars(index).items() if k not in _NOT_CONTENT}
    try:
        h.update(json.dumps(rest, sort_keys=True, default=_canonical).encode())
    except (TypeError, ValueError):
        return None
    return h.hexdigest()[:32]


# --- entries -------------------------------------------------------------------------------------


def _encode(result: ScanResult) -> dict[str, Any]:
    return {
        "findings": [
            {
                "id": f.id, "severity": f.severity.value, "category": f.category,
                "title": f.title, "description": f.description,
                "evidence": [[e.file, e.line_start, e.line_end, e.snippet, e.match_offset]
                             for e in f.evidence],
                "recommendation": f.recommendation, "threat_class": f.threat_class.value,
                "owasp": list(f.owasp),
            }
            for f in result.findings
        ],
        "needs_review": [n.to_dict() for n in result.needs_review],
        "regex_only_files": list(result.regex_only_files),
    }


def _decode(data: dict[str, Any]) -> ScanResult:
    from skilltotal.scanners.base import ScanResult

    return ScanResult(
        findings=[
            Finding(
                id=f["id"], severity=Severity(f["severity"]), category=f["category"],
                title=f["title"], description=f["description"],
                evidence=[Evidence(file=e[0], line_start=e[1], line_end=e[2], snippet=e[3],
                                   match_offset=e[4]) for e in f["evidence"]],
                recommendation=f["recommendation"], threat_class=ThreatClass(f["threat_class"]),
                owasp=tuple(f["owasp"]),
            )
            for f in data["findings"]
        ],
        needs_review=[NeedsReview(**n) for n in data["needs_review"]],
        regex_only_files=list(data["regex_only_files"]),
    )


@dataclass
class ScanCache:
    """Stored scanner results under ``directory``; see the module docstring."""

    directory: Path
    audit_every: int = 0
    replayed: int = 0
    scanned: int = 0
    mismatches: list[str] = field(default_factory=list)

    def _entry(self, scanner: Scanner, digest: str) -> Path:
        return Path(self.directory) / scanner.name / code_digest(scanner) / f"{digest}.json"

    def _load(self, entry: Path) -> ScanResult | None:
        try:
            data = json.loads(entry.read_text(encoding="utf-8"))
            return _decode(data["result"]) if data.get("format") == FORMAT else None
        except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError):
            return None

    def _store(self, entry: Path, result: ScanResult) -> None:
        try:
            entry.parent.mkdir(parents=True, exist_ok=True)
            tmp = entry.with_name(f"{entry.name}.{os.getpid()}.tmp")
            tmp.write_text(json.dumps({"format": FORMAT, "result": _encode(result)}),
                           encoding="utf-8")
            os.replace(tmp, entry)
        except OSError:
            pass  # a cache that cannot be written only costs the next scan its replay

    def run(self, index: FileIndex, scanners: Sequence[Scanner], scan) -> list[ScanResult]:
        """Each scanner's result for ``index``, in ``scanners`` order: replayed where an entry
        exists, otherwise from ``scan(index, scanners_to_run)`` and stored."""
        digest = index_digest(index)
        entries = [
            None if digest is None or getattr(s, "reads_outside_index", False)
            else self._entry(s, digest)
            for s in scanners
        ]
        audit = bool(digest and self.audit_every > 0
                     and int(digest[:8], 16) % self.audit_every == 0)
        stored = [None if e is None else self._load(e) for e in entries]
        todo = [i for i, r in enumerate(stored) if r is None or audit]
        fresh = dict(zip(todo, scan(index, [scanners[i] for i in todo]), strict=True))
        results = []
        for i, scanner in enumerate(scanners):
            replay = stored[i]
            if i in fresh:
                self.scanned += 1
                if replay is not None and _encode(replay) != _encode(fresh[i]):
                    self.mismatches.append(scanner.name)
                if entries[i] is not None and (replay is None or audit):
                    self._store(entries[i], fresh[i])
                results.append(fresh[i])
            else:
                self.replayed += 1
                results.append(replay)
        return results
