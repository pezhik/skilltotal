"""File indexing and evidence extraction.

The :class:`FileIndex` walks a component directory once, caches the text of each analyzable
file, and provides precise *offset -> line* mapping so scanners can produce exact
:class:`~skilltotal.models.Evidence` (file, line_start, line_end, snippet) for every regex
match. Centralizing traversal here means every scanner inherits identical, safe filtering
(skipping VCS dirs, dependency trees, and binaries).
"""

from __future__ import annotations

import bisect
import io
import re
import tokenize
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
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


# Human-facing documentation / metadata: prose and ignore-files that are never executed and
# are not an agent-instruction surface. A pattern that appears only here is descriptive (a
# README showing an example attack, a CHANGELOG entry, a `.gitignore` listing `.env`), not the
# behavior itself, so its evidence is demoted to NeedsReview and never drives the score/verdict.
_DOC_DIR_SEGMENTS: frozenset[str] = frozenset({"docs", "doc"})
# Doc keywords matched as whole words (split on _ / -) in a prose-suffixed filename's stem,
# so README.md / CHANGELOG.rst / RULES_CHANGELOG.md count, but license.py / security.py (code)
# do not.
_DOC_KEYWORDS: frozenset[str] = frozenset(
    {
        "readme", "changelog", "changes", "history", "contributing", "security",
        "license", "licence", "notice", "authors", "maintainers",
    }
)
_PROSE_SUFFIXES: frozenset[str] = frozenset({".md", ".mdx", ".rst", ".txt", ".adoc", ""})
# Exact filenames that are always documentation/metadata or ignore-files.
_DOC_EXACT_NAMES: frozenset[str] = frozenset(
    {"pkg-info", "code_of_conduct.md", ".gitignore", ".dockerignore", ".npmignore",
     ".gcloudignore"}
)
# AI-instruction surfaces that ARE an attack target even though they are markdown/text: a
# real injection lives here, so these are explicitly NOT treated as documentation.
_INSTRUCTION_NAMES: frozenset[str] = frozenset(
    {
        "claude.md", "agents.md", "agent.md", "gemini.md", "skill.md", "cursor.md",
        ".cursorrules", ".windsurfrules", "system_prompt.md", "system-prompt.md",
    }
)
_INSTRUCTION_SUFFIXES: tuple[str, ...] = (".mdc",)


def is_doc_path(relpath: str) -> bool:
    """True if ``relpath`` is human-facing documentation/metadata (not an instruction surface)."""
    parts = relpath.lower().split("/")
    name = parts[-1]
    if name in _INSTRUCTION_NAMES or name.endswith(_INSTRUCTION_SUFFIXES):
        return False
    if name in _DOC_EXACT_NAMES:
        return True
    if any(part in _DOC_DIR_SEGMENTS or part.endswith(".egg-info") for part in parts[:-1]):
        return True
    suffix = name[name.rindex("."):] if "." in name[1:] else ""
    if suffix not in _PROSE_SUFFIXES:
        return False
    stem = name[: name.rindex(".")] if suffix else name
    return any(word in _DOC_KEYWORDS for word in re.split(r"[_-]", stem))


# Token types that count as "inside a string" for code-context demotion (f-string parts are
# only separate token types on Python 3.12+).
_STRING_TOKEN_TYPES: set[int] = {tokenize.STRING}
for _fstr_name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"):
    _fstr_type = getattr(tokenize, _fstr_name, None)
    if _fstr_type is not None:
        _STRING_TOKEN_TYPES.add(_fstr_type)


def _offset_in_spans(spans: list[tuple[int, int]] | None, offset: int) -> bool:
    for start, end in spans or ():
        if start <= offset < end:
            return True
    return False


# Hidden / deceptive code points neutralized in DISPLAYED snippets (Trojan-Source defense): a
# scanned repo is untrusted, so bidi overrides/isolates, LRM/RLM, zero-width & format chars,
# Unicode tag chars (ASCII smuggling), and other control chars are rendered as a visible
# <U+XXXX> token instead of silently reordering/hiding the shown code. Detection is unaffected
# (scanners read the raw text); only the evidence snippet shown to a human is neutralized.
_BIDI_MARKS = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F}
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x00AD, 0xFEFF}


def _is_hidden_codepoint(cp: int) -> bool:
    if 0xE0000 <= cp <= 0xE007F:  # Unicode tag chars
        return True
    if cp in _BIDI_MARKS or cp in _ZERO_WIDTH:
        return True
    if cp == 0x7F or 0x80 <= cp <= 0x9F:  # DEL + C1 controls
        return True
    return cp < 0x20 and cp not in (0x09, 0x0A)  # C0 controls except tab/newline


def neutralize_hidden(text: str) -> str:
    """Render hidden/deceptive code points as a visible ``<U+XXXX>`` token (display safety)."""
    if not any(_is_hidden_codepoint(ord(c)) for c in text):
        return text  # fast path: the vast majority of snippets are clean
    return "".join(
        f"<U+{ord(c):04X}>" if _is_hidden_codepoint(ord(c)) else c for c in text
    )


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
    # Lazily-computed char-spans of Python string literals / comments (None = not yet computed).
    _str_spans: list[tuple[int, int]] | None = field(default=None, repr=False, compare=False)
    _comment_spans: list[tuple[int, int]] | None = field(default=None, repr=False, compare=False)

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()

    def _ensure_code_spans(self) -> None:
        """Tokenize Python source once to record string-literal and comment char-spans.

        Used by the engine's code-context demotion. A file that fails to tokenize (syntax
        error, partial source) falls back to empty spans — i.e. today's behavior, where every
        match counts. Non-Python files have no spans.
        """
        if self._str_spans is not None:
            return
        str_spans: list[tuple[int, int]] = []
        com_spans: list[tuple[int, int]] = []
        if self.suffix in (".py", ".pyw"):
            try:
                for tok in tokenize.generate_tokens(io.StringIO(self.text).readline):
                    if tok.type in _STRING_TOKEN_TYPES:
                        str_spans.append(
                            (self._rowcol_to_offset(*tok.start), self._rowcol_to_offset(*tok.end))
                        )
                    elif tok.type == tokenize.COMMENT:
                        com_spans.append(
                            (self._rowcol_to_offset(*tok.start), self._rowcol_to_offset(*tok.end))
                        )
            except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
                pass  # malformed source: behave as before (no demotion)
        self._str_spans = str_spans
        self._comment_spans = com_spans

    def _rowcol_to_offset(self, row: int, col: int) -> int:
        if 1 <= row <= len(self._line_starts):
            return self._line_starts[row - 1] + col
        return len(self.text)

    def in_string(self, offset: int) -> bool:
        """True if ``offset`` falls inside a Python string literal (Python files only)."""
        self._ensure_code_spans()
        return _offset_in_spans(self._str_spans, offset)

    def in_comment(self, offset: int) -> bool:
        """True if ``offset`` falls inside a Python comment (Python files only)."""
        self._ensure_code_spans()
        return _offset_in_spans(self._comment_spans, offset)

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
        snippet = neutralize_hidden("\n".join(lines).strip())
        if len(snippet) > MAX_SNIPPET_CHARS:
            snippet = snippet[:MAX_SNIPPET_CHARS].rstrip() + " …"
        return Evidence(
            file=self.relpath,
            line_start=line_start,
            line_end=line_end,
            snippet=snippet,
            match_offset=start_offset,
        )

    def evidence_for_lines(self, line_start: int, line_end: int) -> Evidence:
        """Build Evidence from 1-based line numbers (used by AST-based scanners)."""
        line_start = max(1, line_start)
        line_end = max(line_start, line_end)
        # Cap the span so a call spanning many lines does not produce a huge snippet.
        line_end = min(line_end, line_start + 10, len(self._line_starts))
        lines = [self._line_text(n) for n in range(line_start, line_end + 1)]
        snippet = neutralize_hidden("\n".join(lines).strip())
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
            # Strip a leading UTF-8 BOM (common in Windows-authored configs). Left in, it breaks
            # JSON parsing of manifests (e.g. an MCP config → missed ST-MCP-* findings) and is
            # mis-flagged as hidden zero-width Unicode. It precedes line 1, so line offsets are
            # unaffected.
            if text.startswith("\ufeff"):
                text = text[1:]
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
