"""File indexing and evidence extraction.

The :class:`FileIndex` walks a component directory once, caches the text of each analyzable
file, and provides precise *offset -> line* mapping so scanners can produce exact
:class:`~skilltotal.models.Evidence` (file, line_start, line_end, snippet) for every regex
match. Centralizing traversal here means every scanner inherits identical, safe filtering
(skipping VCS dirs, dependency trees, and binaries).
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from skilltotal.models import Evidence

# Directories that never contain the component's own first-party source.
SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".idea",
        ".vscode",
        "site-packages",
    }
)

# Directory segments and filename patterns that indicate non-shipped test code.
_TEST_DIR_SEGMENTS: frozenset[str] = frozenset(
    {"test", "tests", "__tests__", "__mocks__", "spec", "specs", "e2e"}
)
_TEST_FILE_RE = re.compile(r"\.test\.|\.spec\.|^test_|_test\.|^conftest\.py$")


def is_test_path(relpath: str) -> bool:
    """True if ``relpath`` looks like test code (not executed by consumers)."""
    parts = relpath.lower().split("/")
    if any(part in _TEST_DIR_SEGMENTS for part in parts[:-1]):
        return True
    return bool(_TEST_FILE_RE.search(parts[-1]))


# Files larger than this are not loaded as text (still recorded in stats).
MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB

# Maximum characters kept in an evidence snippet (protects against minified one-liners).
MAX_SNIPPET_CHARS = 240


@dataclass
class IndexedFile:
    """A single analyzable text file with cached content and line offsets."""

    path: Path
    relpath: str
    text: str
    _line_starts: list[int]

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()

    def line_of_offset(self, offset: int) -> int:
        """Return the 1-based line number containing ``offset``."""
        # _line_starts[i] is the offset at which line (i+1) begins.
        return bisect.bisect_right(self._line_starts, offset)

    def _line_text(self, line_no: int) -> str:
        start = self._line_starts[line_no - 1]
        end = (
            self._line_starts[line_no]
            if line_no < len(self._line_starts)
            else len(self.text)
        )
        return self.text[start:end].rstrip("\n").rstrip("\r")

    def evidence_for_span(self, start_offset: int, end_offset: int) -> Evidence:
        """Build Evidence covering the source span [start_offset, end_offset)."""
        line_start = self.line_of_offset(start_offset)
        # end_offset is exclusive; subtract 1 so a match ending at a newline does not
        # spill onto the next line.
        line_end = self.line_of_offset(max(start_offset, end_offset - 1))
        lines = [self._line_text(n) for n in range(line_start, line_end + 1)]
        snippet = "\n".join(lines).strip()
        if len(snippet) > MAX_SNIPPET_CHARS:
            snippet = snippet[:MAX_SNIPPET_CHARS].rstrip() + " …"
        return Evidence(
            file=self.relpath,
            line_start=line_start,
            line_end=line_end,
            snippet=snippet,
        )

    def evidence_for_lines(self, line_start: int, line_end: int) -> Evidence:
        """Build Evidence from 1-based line numbers (used by AST-based scanners)."""
        line_start = max(1, line_start)
        line_end = max(line_start, line_end)
        # Cap the span so a call spanning many lines does not produce a huge snippet.
        line_end = min(line_end, line_start + 10, len(self._line_starts))
        lines = [self._line_text(n) for n in range(line_start, line_end + 1)]
        snippet = "\n".join(lines).strip()
        if len(snippet) > MAX_SNIPPET_CHARS:
            snippet = snippet[:MAX_SNIPPET_CHARS].rstrip() + " …"
        return Evidence(
            file=self.relpath,
            line_start=line_start,
            line_end=line_end,
            snippet=snippet,
        )

    def finditer(self, pattern: re.Pattern[str]) -> Iterator[tuple[re.Match[str], Evidence]]:
        """Yield each match in this file together with its Evidence."""
        for m in pattern.finditer(self.text):
            yield m, self.evidence_for_span(m.start(), m.end())


class FileIndex:
    """An immutable, pre-walked view of a component directory."""

    def __init__(self, root: Path, files: list[IndexedFile], stats: dict[str, int]):
        self.root = root
        self.files = files
        self.stats = stats

    # ------------------------------------------------------------------ build
    @classmethod
    def build(cls, root: Path) -> FileIndex:
        root = Path(root).resolve()
        files: list[IndexedFile] = []
        stats = {"indexed": 0, "skipped_binary": 0, "skipped_large": 0, "total_seen": 0}

        for path in cls._walk(root):
            stats["total_seen"] += 1
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_BYTES:
                stats["skipped_large"] += 1
                continue
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            if b"\x00" in raw:  # crude but effective binary check
                stats["skipped_binary"] += 1
                continue
            text = raw.decode("utf-8", errors="replace")
            files.append(
                IndexedFile(
                    path=path,
                    relpath=path.relative_to(root).as_posix(),
                    text=text,
                    _line_starts=cls._compute_line_starts(text),
                )
            )
            stats["indexed"] += 1

        files.sort(key=lambda f: f.relpath)
        return cls(root, files, stats)

    @staticmethod
    def _walk(root: Path) -> Iterator[Path]:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
                continue
            yield path

    @staticmethod
    def _compute_line_starts(text: str) -> list[int]:
        starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                starts.append(i + 1)
        return starts

    # --------------------------------------------------------------- selection
    def select(
        self,
        *,
        suffixes: Iterable[str] | None = None,
        names: Iterable[str] | None = None,
    ) -> list[IndexedFile]:
        """Return files filtered by suffix and/or exact filename (case-insensitive)."""
        suffix_set = {s.lower() for s in suffixes} if suffixes else None
        name_set = {n.lower() for n in names} if names else None
        out: list[IndexedFile] = []
        for f in self.files:
            if suffix_set is not None and f.suffix in suffix_set:
                out.append(f)
            elif name_set is not None and f.name.lower() in name_set:
                out.append(f)
            elif suffix_set is None and name_set is None:
                out.append(f)
        return out

    def search(
        self,
        pattern: re.Pattern[str],
        *,
        suffixes: Iterable[str] | None = None,
        names: Iterable[str] | None = None,
    ) -> Iterator[tuple[IndexedFile, re.Match[str], Evidence]]:
        """Yield (file, match, evidence) for ``pattern`` across the selected files."""
        for f in self.select(suffixes=suffixes, names=names):
            for m, ev in f.finditer(pattern):
                yield f, m, ev
