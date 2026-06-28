"""File indexing and evidence extraction.

The :class:`FileIndex` walks a component directory once, caches the text of each analyzable
file, and provides precise *offset -> line* mapping so scanners can produce exact
:class:`~skilltotal.models.Evidence` (file, line_start, line_end, snippet) for every regex
match. Centralizing traversal here means every scanner inherits identical, safe filtering
(skipping VCS dirs, dependency trees, and binaries).
"""

from __future__ import annotations

import bisect
import fnmatch
import io
import re
import tokenize
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from skilltotal.models import Evidence


def _matches_any(relpath: str, patterns: tuple[str, ...]) -> bool:
    """True if a posix relpath matches any glob (matched against the full path and basename)."""
    name = relpath.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(relpath, p) or fnmatch.fnmatch(name, p) for p in patterns)

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
# A compound segment that still names a test tree: cli-e2e-tests, integration-tests, unit_test,
# api-spec. The `[-_]` boundary keeps ordinary words out (e.g. "latest" is not a test dir).
_TEST_SEGMENT_RE = re.compile(r"(?:.*[-_])?(?:tests?|specs?|e2e)")
_TEST_FILE_RE = re.compile(r"\.test\.|\.spec\.|^test_|_test\.|^conftest\.py$")


def is_test_path(relpath: str) -> bool:
    """True if ``relpath`` looks like test code (not executed by consumers)."""
    parts = relpath.lower().split("/")
    for part in parts[:-1]:
        if part in _TEST_DIR_SEGMENTS or _TEST_SEGMENT_RE.fullmatch(part):
            return True
    return bool(_TEST_FILE_RE.search(parts[-1]))


# Data / evaluation / benchmark corpora: reference data, not the component's executed behavior
# or its agent-instruction surface. A prompt-injection string in eval_datasets/poisoning.yaml is
# a *test vector for a detector*, not behavior — analogous to test code, so its evidence is
# demoted to NeedsReview. Restricted to non-code data files so a real payload dropped as code in
# such a directory is still scanned and scored (see ``is_data_corpus_path``).
_DATA_CORPUS_SEGMENTS: frozenset[str] = frozenset(
    {
        "fixtures", "fixture", "testdata", "test-data", "test_data",
        "eval", "evals", "eval_datasets", "eval-datasets", "evaluation", "evaluations",
        "benchmark", "benchmarks", "datasets", "dataset",
        "golden", "goldens", "snapshots", "__snapshots__", "corpus", "corpora",
    }
)
# Executable code suffixes. Evidence in these is NEVER treated as inert corpus data, even inside
# a corpus directory — a real payload must not hide under fixtures/ or eval_datasets/.
_CODE_SUFFIXES: frozenset[str] = frozenset(
    {
        ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh",
        ".rb", ".go", ".rs", ".java", ".php", ".pl", ".lua", ".ps1", ".bat", ".cmd",
        ".c", ".cpp", ".cc", ".h", ".hpp",
    }
)


def is_data_corpus_path(relpath: str) -> bool:
    """True if ``relpath`` is an inert data/eval/benchmark corpus file (not executed code).

    Requires BOTH a corpus directory segment AND a non-code file suffix, so reference data
    (``.yaml``/``.json``/``.jsonl``/``.csv``/``.md`` …) is demoted while any executable code in
    the same tree is still scanned and scored.
    """
    parts = relpath.lower().split("/")
    if not any(part in _DATA_CORPUS_SEGMENTS for part in parts[:-1]):
        return False
    name = parts[-1]
    dot = name.rfind(".")
    suffix = name[dot:] if dot > 0 else ""
    return suffix not in _CODE_SUFFIXES


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
    # Split on `.` too so a localized/variant doc keeps its keyword: README.zh-CN.md ->
    # ["readme","zh","cn"], CHANGELOG.fr.md -> ["changelog","fr"].
    return any(word in _DOC_KEYWORDS for word in re.split(r"[._-]", stem))


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


# C-family languages whose `//` and `/* */` comments are demotable code-context (a pattern that
# only appears in a comment is a doc/description, not executed behavior). String literals are NOT
# demoted for these (unlike Python) — a credential path passed as a string argument is real access.
_C_FAMILY_SUFFIXES: frozenset[str] = frozenset(
    {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".rs", ".java", ".c", ".cc", ".cpp",
     ".h", ".hpp"}
)


def _c_comment_spans(text: str) -> list[tuple[int, int]]:
    """Char-spans of ``//`` line and ``/* */`` block comments in C-family source.

    String-aware (skips ``'…'``/``"…"``/`` `…` `` with backslash escapes) so a ``//`` or ``/*``
    inside a string literal is not mistaken for a comment. Best-effort and stdlib-only; template
    ``${…}`` interpolation is treated as opaque string content (worst case: no demotion).
    """
    spans: list[tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in ("'", '"', "`"):
            quote = c
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                start = i
                i += 2
                while i < n and text[i] != "\n":
                    i += 1
                spans.append((start, i))
                continue
            if nxt == "*":
                start = i
                i += 2
                while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                    i += 1
                i = min(n, i + 2)
                spans.append((start, i))
                continue
        i += 1
    return spans


# Rust unit tests live INLINE in the same .rs file as production code (gated by `#[cfg(test)]`
# on a module or `#[test]` on a function), unlike the separate test directories is_test_path
# recognizes. That gated code is compiled only for `cargo test` and never shipped to consumers,
# so a credential-looking string there is a test fixture, not behavior. We locate those spans so
# the engine can demote evidence inside them exactly as it demotes path-based test code.
# `#[cfg(not(test))]` (code compiled when NOT testing) is deliberately NOT matched.
_RUST_TEST_FN_ATTR = r"#\[\s*(?:[A-Za-z_]\w*\s*::\s*)*test\s*\]"
_RUST_CFG_TEST_ATTR = r"#!?\[\s*cfg\s*\(\s*(?:all\s*\(|any\s*\()?\s*test\b"
_RUST_TEST_MARKER = re.compile(f"{_RUST_TEST_FN_ATTR}|{_RUST_CFG_TEST_ATTR}")
_RUST_BLOCK_ITEM = re.compile(r"\b(?:fn|mod)\b")
_RUST_MARKER_LOOKAHEAD = 400  # max chars from a test attribute to its block body `{`


def _rust_code_mask(text: str) -> str:
    """Return ``text`` with comment / string / char-literal regions blanked to spaces.

    Length and newlines are preserved so offsets stay identical to the original. Blanking the
    non-code regions lets :func:`_rust_test_spans` count ``{``/``}`` and find attribute markers
    without being fooled by braces — or the word ``test`` — inside strings or comments. Handles
    ``//`` and (nesting) ``/* */`` comments, ``"…"`` and raw ``r#"…"#`` strings, and char/byte
    literals, while leaving Rust lifetimes (``'a``) untouched. Best-effort, stdlib-only.
    """
    out = list(text)
    i, n = 0, len(text)

    def blank(a: int, b: int) -> None:
        for p in range(a, b):
            if out[p] != "\n":
                out[p] = " "

    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":  # line comment
            j = i
            while j < n and text[j] != "\n":
                j += 1
            blank(i, j)
            i = j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":  # block comment (Rust nests)
            depth, j = 1, i + 2
            while j < n and depth > 0:
                if text[j] == "/" and j + 1 < n and text[j + 1] == "*":
                    depth += 1
                    j += 2
                    continue
                if text[j] == "*" and j + 1 < n and text[j + 1] == "/":
                    depth -= 1
                    j += 2
                    continue
                j += 1
            blank(i, j)
            i = j
            continue
        if c == "r" and i + 1 < n and text[i + 1] in ('"', "#"):  # raw string r#"…"#
            j, hashes = i + 1, 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                close = '"' + "#" * hashes
                end = text.find(close, j + 1)
                end = n if end == -1 else end + len(close)
                blank(i, end)
                i = end
                continue
        if c == '"':  # normal / byte string
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
            continue
        if c == "'":  # char literal ('x', '\n', '\u{..}') -> blank; lifetime ('a) -> keep
            if i + 1 < n and text[i + 1] == "\\":
                j = i + 2
                while j < n and text[j] not in ("'", "\n"):
                    j += 1
                if j < n and text[j] == "'":
                    j += 1
                blank(i, j)
                i = j
                continue
            if i + 2 < n and text[i + 2] == "'":
                blank(i, i + 3)
                i += 3
                continue
            i += 1
            continue
        i += 1
    return "".join(out)


def _match_brace(masked: str, open_pos: int) -> int:
    """Index just past the ``}`` matching the ``{`` at ``masked[open_pos]`` (len on imbalance)."""
    depth, i, n = 0, open_pos, len(masked)
    while i < n:
        ch = masked[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _rust_test_spans(text: str) -> list[tuple[int, int]]:
    """Char-spans of inline Rust test code (``#[cfg(test)] mod`` / ``#[test] fn`` blocks)."""
    masked = _rust_code_mask(text)
    spans: list[tuple[int, int]] = []
    for m in _RUST_TEST_MARKER.finditer(masked):
        brace = masked.find("{", m.end(), m.end() + _RUST_MARKER_LOOKAHEAD)
        if brace == -1:
            continue
        if not _RUST_BLOCK_ITEM.search(masked, m.end(), brace):
            continue  # attribute on a non-block item (use/const) -> no body to demote
        spans.append((m.start(), _match_brace(masked, brace)))
    return spans


def _unquoted_hash_index(line: str) -> int | None:
    """Index of the first shell comment ``#`` in ``line``, or None.

    A ``#`` starts a comment only when it is unquoted and at the start of the line or preceded by
    whitespace (``echo "a # b"`` and ``x=a#b`` are not comments). Single-line tracking is enough
    for evidence demotion; heredocs/line-continuations are out of scope (worst case: no demotion).
    """
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double and (i == 0 or line[i - 1] in " \t"):
            return i
    return None


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
    # Lazily-computed char-spans of shell (#) comments, for non-Python code-context demotion.
    _sh_comment_spans: list[tuple[int, int]] | None = field(
        default=None, repr=False, compare=False
    )
    # Lazily-computed char-spans of C-family (// and /* */) comments.
    _c_comment_spans_cache: list[tuple[int, int]] | None = field(
        default=None, repr=False, compare=False
    )
    # Lazily-computed char-spans of inline Rust test code (#[cfg(test)] / #[test] blocks).
    _rust_test_spans_cache: list[tuple[int, int]] | None = field(
        default=None, repr=False, compare=False
    )

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

    def _ensure_sh_comment_spans(self) -> None:
        """Record shell (#) comment char-spans once, for ``.sh``/``.bash``/``.zsh`` files."""
        if self._sh_comment_spans is not None:
            return
        spans: list[tuple[int, int]] = []
        if self.suffix in (".sh", ".bash", ".zsh"):
            offset = 0
            for line in self.text.splitlines(keepends=True):
                hash_idx = _unquoted_hash_index(line)
                if hash_idx is not None:
                    spans.append((offset + hash_idx, offset + len(line)))
                offset += len(line)
        self._sh_comment_spans = spans

    def in_shell_comment(self, offset: int) -> bool:
        """True if ``offset`` falls inside a shell ``#`` comment (shell files only)."""
        self._ensure_sh_comment_spans()
        return _offset_in_spans(self._sh_comment_spans, offset)

    def _ensure_c_comment_spans(self) -> None:
        """Record C-family (// and /* */) comment char-spans once, for C-family files only."""
        if self._c_comment_spans_cache is not None:
            return
        self._c_comment_spans_cache = (
            _c_comment_spans(self.text) if self.suffix in _C_FAMILY_SUFFIXES else []
        )

    def in_c_comment(self, offset: int) -> bool:
        """True if ``offset`` falls inside a C-family ``//`` or ``/* */`` comment.

        Returns False for non-C-family files, so callers can invoke it unconditionally.
        """
        self._ensure_c_comment_spans()
        return _offset_in_spans(self._c_comment_spans_cache, offset)

    def _ensure_rust_test_spans(self) -> None:
        """Record inline Rust test-block char-spans once, for ``.rs`` files only."""
        if self._rust_test_spans_cache is not None:
            return
        self._rust_test_spans_cache = (
            _rust_test_spans(self.text) if self.suffix == ".rs" else []
        )

    def in_rust_test(self, offset: int) -> bool:
        """True if ``offset`` falls inside inline Rust test code (#[cfg(test)] / #[test]).

        Returns False for non-Rust files, so callers can invoke it unconditionally.
        """
        self._ensure_rust_test_spans()
        return _offset_in_spans(self._rust_test_spans_cache, offset)

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

    def line_text(self, line_no: int) -> str:
        """Return the text of 1-based ``line_no`` (empty string if out of range)."""
        if 1 <= line_no <= len(self._line_starts):
            return self._line_text(line_no)
        return ""

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
    def build(cls, root: Path, *, exclude: Iterable[str] | None = None) -> FileIndex:
        root = Path(root).resolve()
        files: list[IndexedFile] = []
        stats = {"indexed": 0, "skipped_binary": 0, "skipped_large": 0, "total_seen": 0}
        excludes = tuple(exclude or ())

        for path in cls._walk(root, excludes):
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
    def _walk(root: Path, exclude: tuple[str, ...] = ()) -> Iterator[Path]:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(root)
            if any(part in SKIP_DIRS for part in rel.parts):
                continue
            if exclude and _matches_any(rel.as_posix(), exclude):
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
