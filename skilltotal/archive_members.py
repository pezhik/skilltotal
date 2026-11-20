"""Files inside an archive the component unpacks, imports from or hands to the agent.

The walk reads text files and passes over archives. A component that ships ``assets/tools.zip``
and tells the agent to ``unzip assets/tools.zip && sh tools/setup.sh`` runs a script no rule ever
saw, and so does ``sys.path.insert(0, "lib.zip")``, ``python app.pyz`` or a postinstall that
untars a bundled tarball. A Word document the instructions tell the agent to read is a zip of XML
whose text the agent receives, including text formatted not to show.

Two steps, both parsing only:

* ``referenced_archives`` finds the archives of the component that its own files name: anywhere
  in an instruction file, or on a line of a script, code file or auto-run command that unpacks,
  imports or runs one (``unzip``, ``tar -x``, ``extractall``, ``zipimport``, ``sys.path``,
  ``java -jar``, ``pip install``, ...). An archive nothing names is left alone, as before.
* ``read_archive`` reads the text members of one such archive **in memory** and returns them as
  indexed files named ``<archive>!/<member>``, so every rule judges them like any other file of
  the component. Nothing is written to disk and nothing is run.

Limits, so a crafted archive costs a bounded amount of memory and time: the archive, each member,
the members read from one archive and their total size are capped; a compressed tarball is
inflated up to a cap before it is opened; an archive inside an archive is opened one level deep.
Whatever was not read (past a limit, encrypted, nested deeper, compiled code, a format that is
not read) is returned in words, and the engine reports it: a report must not read as covering it.
"""

from __future__ import annotations

import bz2
import html
import io
import lzma
import posixpath
import re
import tarfile
import zipfile
import zlib
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from skilltotal.autorun import autorun_commands
from skilltotal.file_index import (
    FileIndex,
    IndexedFile,
    _is_minified,
    _sniffed_text,
    is_instruction_file,
)
from skilltotal.scanners.skill_fetch_exec import _INSTRUCTION_FILE

# Separates the archive's path from the member's in the name of a file read from an archive.
MEMBER_SEPARATOR = "!/"

_OOXML_SUFFIXES = (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".odt", ".ods", ".odp")
_ZIP_SUFFIXES = (
    ".zip", ".whl", ".egg", ".jar", ".war", ".pyz", ".pex", ".vsix", ".nupkg", ".xpi",
    *_OOXML_SUFFIXES,
)
_TAR_SUFFIXES = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2", ".txz", ".tar")
# Named like an archive, in a format that is not read: reported as not analyzed.
_UNREAD_FORMATS = (".7z", ".rar")
ARCHIVE_SUFFIXES = (*_TAR_SUFFIXES, *_ZIP_SUFFIXES, *_UNREAD_FORMATS)

MAX_ARCHIVES = 8
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_INFLATED_TAR_BYTES = 32 * 1024 * 1024
MAX_NESTED_ARCHIVE_BYTES = 4 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024
MAX_MEMBERS_READ = 200
MAX_MEMBERS_LISTED = 5000
MAX_TOTAL_BYTES = 4 * 1024 * 1024
# Bytes inflated from the members of one archive, kept or not: a member that turns out to be an
# image or a nested archive is inflated before it is passed over, and thousands of them must not
# cost minutes.
MAX_INFLATED_MEMBER_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 2
# One entry object is loaded per member of a zip: a directory larger than this is not opened.
_MAX_ZIP_DIRECTORY_BYTES = 1024 * 1024

_SUFFIX_ALTERNATION = "|".join(
    re.escape(s[1:]) for s in sorted(ARCHIVE_SUFFIXES, key=len, reverse=True)
)
_ARCHIVE_HINT = re.compile(rf"(?i)\.(?:{_SUFFIX_ALTERNATION})(?![\w-])")
_ARCHIVE_PATH = re.compile(
    r"(?i)(?<![\w/:.@\\$-])((?:\$\{?[A-Za-z_][\w:.-]{0,60}\}?[\"']?[/\\])?[\w./@+\\-]{0,200}?"
    rf"\.(?:{_SUFFIX_ALTERNATION}))(?![\w-])"
)
_ROOT_VARIABLE = re.compile(r"^\$\{?[A-Za-z_][\w:.-]*\}?[\"']?[/\\]")
# A line of a script, code file or command that unpacks an archive, imports from it or runs it.
# A tool counts only as a command with its arguments (`pip install x.whl`, `["python", "app.pyz"]`,
# `tar -xf`), never as a word on the line: a table such as `"pip": "pip-26.3-py3-none-any.whl"`
# names a bundled wheel and uses nothing, and `tar` or `jar` is also the end of every such name.
_ARG = r"""(?:\.exe)?["']?[ \t,]+["']?"""
_USES_ARCHIVE = re.compile(
    r"(?i)unzip|untar|bsdtar|unrar|(?<![\w.])7z[ar]?" + _ARG
    + r"|(?<![\w.])jar" + _ARG + r"-?[a-z]*x"
    + r"|(?<![\w.-])java" + _ARG + r"-(?:jar|cp|classpath)\b"
    + r"|(?<![\w.-])(?:python|pypy)[\d.]*" + _ARG
    + r"|(?<![\w.-])pip3?" + _ARG + r"(?:install|download|wheel)\b|-m[ \t\"',]+pip\b"
    + r"|(?<![\w.-])uvx?" + _ARG + r"(?:pip|run|tool|add)\b"
    + r"|Expand-Archive|extract|unpack|zipimport|zipfile|tarfile|sys\.path|PYTHONPATH|NODE_PATH"
    + r"|CLASSPATH|adm-?zip|unzipper|decompress|yauzl|jszip|(?<!\w)-(?:cp|jar)\b"
    + r"|(?<![\w.])tar" + _ARG
)
# The same line when it writes the archive instead (a build or backup step): an archive opened
# for writing, `zip -r`, or `tar` whose first option word has `c` and no `x` (`tar czf`).
_WRITES_ARCHIVE = re.compile(
    r"""(?i:make_archive|writestr|\.write\(|,[ \t]*["'][wax]b?["']|(?<![\w./\\-])zip[ \t]+-"""
    r"""|Compress-Archive)"""
    r"""|\btar(?:\.exe)?[ \t]+(?:-?(?![a-zA-Z]*x)[a-zA-Z]*c[a-zA-Z]*\b|--create\b)"""
)
_CODE_SUFFIXES = frozenset({
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".sh", ".bash", ".zsh", ".ps1",
    ".psm1", ".bat", ".cmd",
})
_CODE_NAMES = frozenset({"package.json", "makefile", "dockerfile", "justfile"})
_MAX_LINE_CHARS = 2000
_MAX_HITS_PER_FILE = 200

# The parts of an office document that hold what a reader (or an agent) is given as its text.
_DOCUMENT_PART = re.compile(
    r"(?i)^(?:word/(?:document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml"
    r"|xl/sharedStrings\.xml|ppt/(?:slides|notesSlides)/[\w-]+\.xml|content\.xml)$"
)
_PARAGRAPH_END = re.compile(r"</(?:w:p|a:p|text:p|text:h|si|row)>|<(?:w:br|w:cr|text:line-break)\b")
# No `<` inside a tag: a run of `<` with no `>` then fails at once instead of rescanning.
_XML_TAG = re.compile(r"<[^<>]{0,4000}>")
_COMPILED_SUFFIXES = (
    ".pyc", ".pyo", ".class", ".so", ".dll", ".dylib", ".node", ".wasm", ".exe", ".bin",
)
_PROGRAM_MAGIC = (
    b"\x7fELF", b"MZ", b"\x00asm", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def is_member_path(relpath: str) -> bool:
    """Whether ``relpath`` names a file read from inside an archive."""
    return MEMBER_SEPARATOR in relpath


def _archive_kind(name: str) -> str:
    lower = name.lower()
    if lower.endswith(_TAR_SUFFIXES):
        return "tar"
    if lower.endswith(_ZIP_SUFFIXES):
        return "zip"
    return "unread" if lower.endswith(_UNREAD_FORMATS) else ""


# ------------------------------------------------------------------------------- references

def _candidates(word: str, near: str) -> list[str]:
    """Relative paths ``word`` may name: from the folder of ``near``, each folder above it, and
    the component root."""
    word = _ROOT_VARIABLE.sub("", word.strip("\"'")).replace("\\", "/")
    if not word or word.startswith(("/", "~")) or ":" in word:
        return []
    parts = near.split("/")[:-1]
    out: list[str] = []
    for k in range(len(parts), -1, -1):
        rel = posixpath.normpath("/".join([*parts[:k], word]))
        if rel != "." and rel != ".." and not rel.startswith("../") and rel not in out:
            out.append(rel)
    return out


def _named_on_lines(text: str, *, any_line: bool) -> Iterator[str]:
    """Archive paths written in ``text``: every one (``any_line``), or those on a line that
    unpacks, imports or runs an archive and does not write one."""
    pos = 0
    for _ in range(_MAX_HITS_PER_FILE):
        hint = _ARCHIVE_HINT.search(text, pos)
        if hint is None:
            return
        start = text.rfind("\n", 0, hint.start()) + 1
        end = text.find("\n", hint.end())
        end = len(text) if end < 0 else end
        pos = end + 1
        line = text[start:end]
        if len(line) > _MAX_LINE_CHARS:
            # A minified or generated line: read the part around the name.
            at = hint.start() - start
            line = line[max(0, at - _MAX_LINE_CHARS // 2):at + _MAX_LINE_CHARS // 2]
        if not any_line and (not _USES_ARCHIVE.search(line) or _WRITES_ARCHIVE.search(line)):
            continue
        for m in _ARCHIVE_PATH.finditer(line):
            yield m.group(1)


def referenced_archives(
    index: FileIndex,
    exists: Callable[[str], bool],
    is_fixture: Callable[[str], bool] = lambda _rel: False,
) -> dict[str, bool]:
    """``{relative path: handed to the agent}`` for the archives of the component that its own
    files name: in an instruction file (then an office document among them is text the agent is
    given, hence the flag), or on a line of a script, code file, ``package.json`` or auto-run
    command that unpacks, imports from or runs an archive.

    ``exists(relpath)`` says whether a relative path is a regular file inside the component;
    ``is_fixture(relpath)`` whether a file is a test, an example or a document, whose commands
    run for nobody who installs the component. At most ``MAX_ARCHIVES`` are returned.
    """
    found: dict[str, bool] = {}

    def consider(words: Iterable[str], near: str, handed: bool) -> None:
        for word in words:
            for rel in _candidates(word, near):
                if rel in found:
                    found[rel] = found[rel] or handed
                    break
                if len(found) < MAX_ARCHIVES and exists(rel):
                    found[rel] = handed
                    break

    for f in index.files:
        if is_member_path(f.relpath) or is_fixture(f.relpath):
            continue
        instruction = is_instruction_file(f) or bool(_INSTRUCTION_FILE.search(f.relpath))
        if not instruction and f.suffix not in _CODE_SUFFIXES and f.name.lower() not in _CODE_NAMES:
            continue
        if not _ARCHIVE_HINT.search(f.text):
            continue
        consider(_named_on_lines(f.text, any_line=instruction), f.relpath, instruction)
    for command in autorun_commands(index).commands:
        if command.is_http or is_fixture(command.file.relpath):
            continue
        text = command.text
        if _ARCHIVE_HINT.search(text) and _USES_ARCHIVE.search(text):
            consider((m.group(1) for m in _ARCHIVE_PATH.finditer(text[:_MAX_LINE_CHARS])),
                     command.file.relpath, False)
    return found


# ---------------------------------------------------------------------------------- reading

class _Reader:
    """Reads the members of one archive of the component, within the limits above."""

    def __init__(self, root: Path, handed_to_agent: bool):
        self.root = root
        self.handed_to_agent = handed_to_agent
        self.files: list[IndexedFile] = []
        self.unread: dict[str, int] = {}
        self.total = 0
        self.inflated = 0
        self.listed = 0
        self.names: set[str] = set()

    def skip(self, why: str) -> None:
        self.unread[why] = self.unread.get(why, 0) + 1

    def full(self) -> bool:
        return (
            len(self.files) >= MAX_MEMBERS_READ
            or self.total >= MAX_TOTAL_BYTES
            or self.inflated >= MAX_INFLATED_MEMBER_BYTES
        )

    def archive(self, raw: bytes, name: str, depth: int) -> None:
        kind = _archive_kind(name)
        try:
            if kind == "zip":
                self._zip(raw, name, depth)
            elif kind == "tar":
                self._tar(raw, name, depth)
            else:
                self.skip("in a format that is not read (7z, rar)")
        except Exception:  # noqa: BLE001 - a crafted archive must not stop the scan
            self.skip("in an archive that could not be opened")

    def _zip(self, raw: bytes, name: str, depth: int) -> None:
        if _zip_directory_bytes(raw) > _MAX_ZIP_DIRECTORY_BYTES:
            self.skip("in an archive with too many entries to list")
            return
        office = depth == 1 and name.lower().endswith(_OOXML_SUFFIXES)
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if not self._listing():
                    return
                if info.flag_bits & 0x1:
                    self.skip("encrypted")
                    continue
                cap = self._cap(info.filename, depth)
                if cap is None:
                    continue
                try:
                    with zf.open(info) as member:
                        data = member.read(cap + 1)
                except Exception:  # noqa: BLE001 - a damaged or unsupported entry
                    self.skip("that could not be read")
                    continue
                self.member(name, info.filename, data, cap, depth, office)

    def _tar(self, raw: bytes, name: str, depth: int) -> None:
        plain = _inflated(raw)
        if plain is None:
            self.skip("in a tarball that inflates past the size limit")
            return
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as tf:
            for info in tf:
                if not info.isreg():
                    continue  # links and devices are never followed or created
                if not self._listing():
                    return
                cap = self._cap(info.name, depth)
                if cap is None:
                    continue
                member = tf.extractfile(info)
                data = member.read(cap + 1) if member is not None else b""
                self.member(name, info.name, data, cap, depth, False)

    def _listing(self) -> bool:
        self.listed += 1
        if self.listed > MAX_MEMBERS_LISTED or self.full():
            self.skip(f"past the limits on one archive ({MAX_MEMBERS_READ} files or "
                      f"{MAX_TOTAL_BYTES // (1024 * 1024)} MiB of text read, "
                      f"{MAX_INFLATED_MEMBER_BYTES // (1024 * 1024)} MiB inflated)")
            return False
        return True

    def _cap(self, member: str, depth: int) -> int | None:
        """How many bytes of ``member`` are read; None when it is not read at all."""
        if not _archive_kind(member):
            return MAX_MEMBER_BYTES
        if depth >= MAX_DEPTH:
            self.skip(f"in an archive nested more than {MAX_DEPTH} levels deep")
            return None
        return MAX_NESTED_ARCHIVE_BYTES

    def member(
        self, archive: str, member: str, data: bytes, cap: int, depth: int, office: bool
    ) -> None:
        self.inflated += len(data)
        clean = _member_name(member)
        if not clean:
            return
        relpath = f"{archive}{MEMBER_SEPARATOR}{clean}"
        if len(data) > cap:
            if _archive_kind(clean) or _sniffed_text(clean, data[:8000]) is not None:
                self.skip(f"larger than {cap // 1024} KiB")
            return
        if _archive_kind(clean):
            self.archive(data, relpath, depth + 1)
            return
        lower = clean.lower()
        if office and lower.endswith(".xml"):
            if not _DOCUMENT_PART.match(clean):
                return  # styles, relationships, settings: no text of the document
            text = _document_text(data.decode("utf-8", errors="replace"))
            if text.strip():
                self._add(relpath, text, agent_read=self.handed_to_agent)
            return
        text = _sniffed_text(clean, data)
        if text is None:
            if lower.endswith("vbaproject.bin"):
                self.skip("a macro project (vbaProject.bin)")
            elif lower.endswith(_COMPILED_SUFFIXES) or data.startswith(_PROGRAM_MAGIC):
                self.skip("compiled or native code")
            return  # any other binary (an image, a font) is passed over, as on disk
        text = text.removeprefix("\N{ZERO WIDTH NO-BREAK SPACE}")  # a byte-order mark
        if _is_minified(clean, text):
            self.skip("minified")
            return
        self._add(relpath, text)

    def _add(self, relpath: str, text: str, *, agent_read: bool = False) -> None:
        if relpath in self.names:
            return  # a second entry of the same name: the first one read stands
        self.names.add(relpath)
        self.total += len(text)
        self.files.append(IndexedFile(
            path=self.root / relpath, relpath=relpath, text=text,
            _line_starts=FileIndex._compute_line_starts(text), agent_read=agent_read,
        ))


def read_archive(
    root: Path, relpath: str, *, handed_to_agent: bool = False
) -> tuple[list[IndexedFile], dict[str, int]]:
    """The text members of the archive ``relpath`` of the component at ``root`` as indexed files
    named ``<relpath>!/<member>``, and what was not read as ``{reason: number of members}``
    (an empty dict: everything that is text was read).

    The text of an office document's parts is read with its markup removed; with
    ``handed_to_agent`` it is marked as text the instructions hand to the agent.
    """
    reader = _Reader(root, handed_to_agent)
    path = root / relpath
    try:
        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            return [], {f"in an archive larger than {MAX_ARCHIVE_BYTES // (1024 * 1024)} MiB": 1}
        raw = path.read_bytes()
    except OSError:
        return [], {"in an archive that could not be opened": 1}
    reader.archive(raw, relpath, 1)
    return sorted(reader.files, key=lambda f: f.relpath), reader.unread


def _member_name(name: str) -> str:
    """``name`` as a relative path with no ``..``, no leading slash and no control characters:
    nothing is written to disk, so the name only labels the evidence."""
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return _CONTROL.sub("?", "/".join(parts))[:300]


def _zip_directory_bytes(raw: bytes) -> int:
    """The size of the central directory the zip's end record declares (0 when there is none)."""
    tail = raw[-65_557:]  # the end record and the longest comment it may carry
    at = tail.rfind(b"PK\x05\x06")
    if at < 0 or len(tail) < at + 22:
        return 0
    return int.from_bytes(tail[at + 12:at + 16], "little")


def _inflated(raw: bytes) -> bytes | None:
    """The tar stream inside ``raw`` (gzip, bzip2, xz or none), or None when it inflates past
    ``MAX_INFLATED_TAR_BYTES``: decompressed here, with a bound, so that a small file cannot make
    ``tarfile`` read gigabytes."""
    limit = MAX_INFLATED_TAR_BYTES + 1
    if raw.startswith(b"\x1f\x8b"):
        plain = zlib.decompressobj(wbits=31).decompress(raw, limit)
    elif raw.startswith(b"BZh"):
        plain = bz2.BZ2Decompressor().decompress(raw, limit)
    elif raw.startswith(b"\xfd7zXZ\x00"):
        plain = lzma.LZMADecompressor(memlimit=64 * 1024 * 1024).decompress(raw, limit)
    else:
        plain = raw
    return plain if len(plain) < limit else None


def _document_text(xml: str) -> str:
    """The text of one part of an office document: paragraph ends become line breaks, markup is
    removed, character references are decoded. No XML parser is involved."""
    return html.unescape(_XML_TAG.sub("", _PARAGRAPH_END.sub("\n\\g<0>", xml)))
