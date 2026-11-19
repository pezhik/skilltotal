"""A name in code written to read as another name.

``check_token`` and the same name with a Cyrillic ``e`` in it are two different identifiers to
Python and JavaScript and one identifier to a reader. A file that holds both can define a second
function, flag or variable beside the one a review looks at, and call the second.

What is reported, in Python and JavaScript/TypeScript code (never in a string or a comment):

* ``ST-LOOKALIKE-IDENTIFIER``: an identifier in which one word mixes Latin letters with letters of
  another alphabet that each look like a Latin letter, or a JavaScript identifier with a
  zero-width joiner inside it, **and** the name it reads as is also an identifier in the same
  file. Both names exist and look the same.
* a review note for a mixed-script identifier with no such twin: a keyboard-layout slip produces
  the same spelling, and nothing shows which other name it would pass for.

A name wholly in one script (code written by a Russian or Greek speaker, a Greek letter in a
formula) is never reported, and neither is a Latin word joined to a word of another script by an
underscore or a capital letter (``get_<Cyrillic word>``): each word is in one script. Parsing only.
"""

from __future__ import annotations

import re
from dataclasses import replace

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Evidence, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    aggregated_review,
)
from skilltotal.scanners.lookalike_host import _script_of
from skilltotal.text_normalize import _fold_char

R_LOOKALIKE_IDENTIFIER = "ST-LOOKALIKE-IDENTIFIER"

_PY_SUFFIXES = frozenset({".py", ".pyw"})
_JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"})
# U+200C and U+200D are identifier characters in JavaScript (not in Python).
_JOINERS = "\N{ZERO WIDTH NON-JOINER}\N{ZERO WIDTH JOINER}"
# An identifier with a non-ASCII character in it, matched from its first character only (so a
# long ASCII name is passed over once, not once per character).
_IDENTIFIER = re.compile(
    rf"(?<![\w{_JOINERS}])(?=[A-Za-z0-9_]*(?:[^\x00-\x7f\W]|[{_JOINERS}]))[^\W\d][\w{_JOINERS}]*"
)
# The words of an identifier: split at underscores and digits, before a capital that follows a
# small letter (`getName`), and before the last capital of a run (`HTTPServer`).
_WORD = re.compile(r"[^\W\d_]+")
_ASCII_LETTER = re.compile(r"[A-Za-z]")
# A file or a component holds a handful of these at most; the caps only bound a crafted one.
_MAX_SUSPECTS_PER_FILE = 16
_MAX_SUSPECTS = 48


def _words(run: str) -> list[str]:
    """The camel-case words of a run of letters."""
    words: list[str] = []
    start = 0
    for i in range(1, len(run)):
        prev, ch = run[i - 1], run[i]
        after = run[i + 1] if i + 1 < len(run) else ""
        if ch.isupper() and (prev.islower() or (prev.isupper() and after.islower())):
            words.append(run[start:i])
            start = i
    words.append(run[start:])
    return words


def _mixed_word(word: str) -> bool:
    """Whether ``word`` mixes Latin letters with letters of one more script that each pass for a
    Latin letter. A letter of any other script (an accented Latin one, CJK) makes it honest."""
    if word.isascii():
        return False
    scripts = {_script_of(c) for c in word}
    if "LATIN" not in scripts or "" in scripts or len(scripts) < 2:
        return False
    return all(c.isascii() or (_fold_char(c).isascii() and _fold_char(c).isalpha()) for c in word)


def identifier_reading(name: str, *, joiners: bool = False) -> str | None:
    """The ASCII name ``name`` reads as when it is spelled to pass for one, else None: one of its
    words mixes Latin with look-alike letters, or (``joiners``, JavaScript) it is an ASCII name
    with a zero-width joiner inside."""
    if name.isascii():
        return None
    bare = name.translate({0x200C: None, 0x200D: None})
    if bare != name:
        return bare if joiners and bare.isascii() and bare else None
    mixed = any(
        _mixed_word(word) for run in _WORD.findall(name) for word in _words(run)
    )
    if not mixed:
        return None
    reading = "".join(c if c.isascii() else _fold_char(c) for c in name)
    return reading if reading.isascii() else None


def _in_code(f: IndexedFile, offset: int) -> bool:
    if f.suffix in _PY_SUFFIXES:
        return not (f.in_string(offset) or f.in_comment(offset))
    return not (f.in_c_comment(offset) or f.string_span_at(offset) is not None)


def _first_use(f: IndexedFile, name: str) -> int | None:
    """The offset of the first use of the ASCII identifier ``name`` in the code of ``f``."""
    if name not in f.text:
        return None
    pattern = re.compile(rf"(?<![\w$]){re.escape(name)}(?![\w$])")
    for k, m in enumerate(pattern.finditer(f.text)):
        if k >= 200:
            break
        if _in_code(f, m.start()):
            return m.start()
    return None


class LookalikeIdentifierScanner(Scanner):
    name = "lookalike_identifier"
    rules = [
        RuleSpec(
            id=R_LOOKALIKE_IDENTIFIER,
            category="obfuscation",
            severity=Severity.HIGH,
            title="Two names in the code that look the same",
            description=(
                "An identifier in Python or JavaScript code is spelled with letters of another "
                "alphabet that look like Latin letters (or with a zero-width joiner inside it), "
                "and the name it reads as is also an identifier in the same file. The two are "
                "different names to the interpreter and the same name to a reader, so the code "
                "can define and use one where a review sees the other. A keyboard-layout slip "
                "can produce the same spelling."
            ),
            recommendation=(
                "Compare the two names character by character (the evidence shows the "
                "non-Latin letters) and read what each one is bound to. Rename the look-alike."
            ),
            capability=None,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        suspects: list[tuple[IndexedFile, int, str, str]] = []
        for f in index.files:
            if f.suffix not in _PY_SUFFIXES and f.suffix not in _JS_SUFFIXES:
                continue
            if f.text.isascii():
                continue
            suspects.extend(_file_suspects(f))
            if len(suspects) >= _MAX_SUSPECTS:
                break
        evidence: list[Evidence] = []
        alone: list[tuple[str, int | None]] = []
        for f, start, name, reading in suspects[:_MAX_SUSPECTS]:
            ev = f.evidence_for_span(start, start + len(name))
            twin = _twin(f, reading)
            if twin is None:
                if name.translate({0x200C: None, 0x200D: None}) == name:
                    alone.append((f.relpath, ev.line_start))
                continue
            note = f"  [{ascii(name)} reads as {reading!r}, also a name at {twin}]"
            evidence.append(replace(ev, snippet=ev.snippet[:180] + note))
        findings = []
        if evidence:
            findings.append(_finding_from_rule(self.rules[0], evidence[:MAX_EVIDENCE_SCANNED]))
        needs_review: list[NeedsReview] = []
        if alone:
            needs_review.append(aggregated_review(
                category="obfuscation",
                title="Identifier mixes Latin with look-alike letters",
                places=alone,
                what="identifier(s) in code mix Latin letters with letters of another alphabet "
                     "that look like Latin ones",
                advice="No other name in the same file reads the same, so this is most often a "
                       "keyboard-layout slip. Retype the name in one alphabet.",
            ))
        return ScanResult(findings=findings, needs_review=needs_review)


def _file_suspects(f: IndexedFile) -> list[tuple[IndexedFile, int, str, str]]:
    """``(file, offset, name, the ASCII name it reads as)`` for each distinct identifier in the
    code of ``f`` that is spelled to pass for an ASCII name."""
    joiners = f.suffix in _JS_SUFFIXES
    found: list[tuple[IndexedFile, int, str, str]] = []
    seen: set[str] = set()
    for m in _IDENTIFIER.finditer(f.text):
        name = m.group()
        if name.isascii() or name in seen or not _ASCII_LETTER.search(name):
            continue  # a name with no Latin letter is in one script, whatever script that is
        reading = identifier_reading(name, joiners=joiners)
        if reading is None:
            seen.add(name)
            continue
        if not _in_code(f, m.start()):
            continue  # in a string or a comment here; a later use may be code
        seen.add(name)
        found.append((f, m.start(), name, reading))
        if len(found) >= _MAX_SUSPECTS_PER_FILE:
            break
    return found


def _twin(f: IndexedFile, reading: str) -> str | None:
    """Where the ASCII identifier ``reading`` is used in the code of the same file (``line N``),
    or None. Another file is not searched: a common name is used somewhere in most components,
    so a slip of the keyboard would always find one."""
    at = _first_use(f, reading)
    if at is None:
        return None
    return f"line {f.evidence_for_span(at, at + len(reading)).line_start}"
