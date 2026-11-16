"""Deterministic text de-obfuscation for instruction-surface matching.

Attackers hide instruction-override / tool-poisoning phrases from a naive regex by swapping
Latin letters for look-alikes (Cyrillic, Greek, small capitals, enclosed letters), adding
combining marks, using full-width forms, or splicing invisible characters mid-word. None of that
changes what a language model reads, but it defeats byte-for-byte matching.

One pipeline, three views of a text, each with an index map back to the ORIGINAL offsets so a
match is still anchored to real file/line/snippet evidence:

* :func:`normalize_with_map` (strict): invisible and format characters removed, compatibility
  forms and accents folded (NFKD first, then marks dropped), look-alike letters mapped to ASCII.
* ``normalize_with_map(text, gaps=True)`` (gap): the same, but a run of invisible or
  blank-drawn characters standing between two word characters becomes one space, for a phrase
  whose spaces were replaced by them.
* :func:`loose_fold` (loose): on top of the strict view, leetspeak digits and symbols mapped to
  letters, letters spaced out by one repeated separator joined, fully doubled words halved,
  markup inside a word removed. This view can create matches honest text does not hold, so only
  the injection-phrase rules read it, only in files an agent takes instructions from, and only
  for a multi-word phrase the other views did not match.

:func:`js_unescaped` is the same idea for JavaScript source: ``\\xHH`` / ``\\uHHHH`` /
``\\u{H}`` escapes written out, with offsets.

This is deterministic and dependency-free (stdlib ``unicodedata`` + curated tables). It does NOT
attempt semantic understanding, translation, or paraphrase detection.
"""

from __future__ import annotations

import re
import unicodedata
from array import array
from collections.abc import Sequence
from functools import lru_cache

# What the character loop has to look at: everything but printable ASCII and ASCII whitespace.
_FOLD_RUN = re.compile(r"[^\x09-\x0d\x20-\x7e]+")
_PLAIN_BYTES = bytes((*range(0x09, 0x0E), *range(0x20, 0x7F)))

# Code points removed entirely before matching: they draw nothing (or a blank) and are used to
# splice or reorder text. The Unicode Default_Ignorable_Code_Point set (soft hyphen, combining
# grapheme joiner, Arabic letter mark, Hangul fillers, Khmer inherent vowels, Mongolian
# selectors, zero-width and bidi controls, invisible operators, deprecated format characters,
# variation selectors, BOM, interlinear annotation, shorthand / musical / Egyptian format
# controls, the tag block and the supplementary variation selectors), plus the Braille blank,
# the object replacement character and the C0/C1 controls that are not whitespace.
# ``scanners/invisible_unicode.py`` builds its own classes from this table, so what the fold
# sees through and what that scanner reports cannot drift apart.
IGNORABLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x0000, 0x0008), (0x000E, 0x001F), (0x007F, 0x0084), (0x0086, 0x009F),
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x2800, 0x2800), (0x3164, 0x3164), (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFFC), (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)
# Ignorable characters that are drawn as a blank of some width: in the gap view they read as a
# space even at the edge of a word.
BLANK_DRAWN: frozenset[int] = frozenset({0x115F, 0x1160, 0x180E, 0x2800, 0x3164, 0xFFA0})


def is_ignorable(cp: int) -> bool:
    """True for a code point the fold removes (see ``IGNORABLE_RANGES``)."""
    return any(lo <= cp <= hi for lo, hi in IGNORABLE_RANGES)


def ignorable_class(*, exclude: Sequence[tuple[int, int]] = ((0x0000, 0x007F),)) -> str:
    """The ignorable set as the inside of a regex character class, without the code points in
    ``exclude`` (inclusive ranges; by default the ASCII controls)."""
    parts: list[str] = []
    for lo, hi in IGNORABLE_RANGES:
        cps = [cp for cp in range(lo, hi + 1) if not any(a <= cp <= b for a, b in exclude)]
        start = None
        for cp in cps:
            if start is None:
                start = prev = cp
            elif cp == prev + 1:
                prev = cp
            else:
                parts.append(_class_range(start, prev))
                start = prev = cp
        if start is not None:
            parts.append(_class_range(start, prev))
    return "".join(parts)


def _class_range(lo: int, hi: int) -> str:
    def esc(cp: int) -> str:
        return f"\\U{cp:08x}"
    return esc(lo) if lo == hi else f"{esc(lo)}-{esc(hi)}"


# Any ignorable code point: a text without one has no gap view of its own.
HAS_IGNORABLE = re.compile("[" + ignorable_class(exclude=()) + "]")


def _letters(first: int, target: str) -> dict[int, str]:
    """A run of 26 consecutive code points mapped to ``target``'s alphabet."""
    return {first + i: chr(ord(target) + i) for i in range(26)}


# Characters whose compatibility decomposition is not the letter itself (``(a)``), or that have
# none: enclosed and regional-indicator letters. Looked up before NFKD.
_ENCLOSED: dict[int, str] = {
    **_letters(0x249C, "a"),   # parenthesized small letters
    **_letters(0x1F110, "A"),  # parenthesized capitals
    **_letters(0x1F130, "A"),  # squared capitals
    **_letters(0x1F150, "A"),  # negative circled capitals
    **_letters(0x1F170, "A"),  # negative squared capitals
    **_letters(0x1F1E6, "A"),  # regional indicators
    0x03F2: "c", 0x03F9: "C",  # Greek lunate sigma (decomposes to a sigma, which is no look-alike)
}


def _table(*groups: tuple[str, str]) -> dict[str, str]:
    """``(code points in hex separated by blanks, the ASCII letters they look like)`` pairs."""
    out: dict[str, str] = {}
    for sources, targets in groups:
        cps = sources.split()
        if len(cps) != len(targets):  # pragma: no cover - a typo in the table below
            raise ValueError(f"confusable group size mismatch: {targets!r}")
        for cp, target in zip(cps, targets, strict=True):
            out[chr(int(cp, 16))] = target
    return out


# Curated look-alike fold: letters of other scripts and of the Latin extensions that read as an
# ASCII letter. Applied AFTER NFKD and mark removal, so an accented look-alike (Greek omicron
# with tonos) folds too. NFKD itself handles full-width, mathematical, circled, superscript and
# subscript forms. Folding only affects these code points; real Cyrillic / Greek / Armenian
# words do not turn into English phrases, and the readers of the fold look for multi-word
# English phrases or a shell command, so genuine non-Latin text does not match.
_CONFUSABLES: dict[str, str] = _table(
    # Cyrillic lowercase
    ("0430 0432 0435 043A 043C 043D 043E 0440 0441 0442 0443 0445 0455 0456 0458 0501 0433 "
     "04CF 04BB 04AF 044C 051B 051D 04BD 0475 0473",
     "abekmhopctyxsijdrlhybqwevo"),
    # Cyrillic uppercase
    ("0410 0412 0415 041A 041C 041D 041E 0420 0421 0422 0423 0425 0406 0408 0405 051A 051C "
     "04AE 04C0 0474",
     "ABEKMHOPCTYXIJSQWYIV"),
    # Greek lowercase
    ("03B1 03B5 03B9 03BA 03BD 03BF 03C1 03C4 03C5 03C7 03F2 03F3 03C9 03B3 03B7 03B2 03BC",
     "aeikvoptuxcjwynbu"),
    # Greek uppercase
    ("0391 0392 0395 0397 0399 039A 039C 039D 039F 03A1 03A4 03A5 03A7 0396 03F9 037F",
     "ABEHIKMNOPTYXZCJ"),
    # Armenian
    ("0585 057D 0578 0570 0566 0575 057C 0555 054D 054F 053C",
     "ounhqjnOUSL"),
    # Latin extensions and IPA: dotless and stroked letters, hooks, tails
    ("0131 0269 0268 01C0 0261 0260 0251 025B 014B 0167 00F8 00D8 0142 0141 0111 0110 0127 "
     "0126 026B 019A 0257 0253 0199 01AD 027E 0237 0192 0282 0290 024B 024D 0247 01B6 0266 "
     "0271 0272 0273 0275 0288 0289 2C65 023C",
     "iiilggaentoOlLdDhHlldbktrjfszqrezhmnnotuac"),
    # Small capitals
    ("1D00 0299 1D04 1D05 1D07 A730 0262 029C 026A 1D0A 1D0B 029F 1D0D 0274 1D0F 1D18 A7AF "
     "0280 A731 1D1B 1D1C 1D20 1D21 028F 1D22",
     "abcdefghijklmnopqrstuvwyz"),
    # Cherokee capitals
    ("13AA 13A0 13AC 13C0 13BB 13AB 13E6 13DE 13B7 13E2 13A1 13DA 13A2 13D9 13B3 13C3 13DF",
     "ADEGHJKLMPRSTVWZC"),
    # Thai digit zero; punctuation a command line is written with
    ("0E50 2010 2011 2012 2013 2212 2044 2215 2223 2236",
     "o-----//|:"),
)

_DROPPED_CATEGORIES = frozenset({"Mn", "Me", "Cf"})


@lru_cache(maxsize=8192)
def _fold_char(ch: str) -> str:
    """What one non-ASCII (or control) character becomes in the strict view; "" when removed."""
    cp = ord(ch)
    enclosed = _ENCLOSED.get(cp)
    if enclosed is not None:
        return enclosed
    if is_ignorable(cp):
        return ""
    out: list[str] = []
    # NFKD: full-width/compatibility forms -> ASCII, precomposed accents -> base + mark.
    for d in unicodedata.normalize("NFKD", ch):
        # Marks go whatever their combining class: U+0489 and the enclosing circle / keycap
        # (class 0) are stacked on letters like any accent.
        if unicodedata.category(d) in _DROPPED_CATEGORIES or unicodedata.combining(d):
            continue
        out.append(_CONFUSABLES.get(d, d))
    return "".join(out)


def normalize_with_map(text: str, *, gaps: bool = False) -> tuple[str, array[int]]:
    """Return ``(normalized_text, index_map)``.

    ``index_map[i]`` is the offset in ``text`` of the character that produced
    ``normalized_text[i]``. Removed characters contribute nothing; a character that expands
    (e.g. the ``ﬁ`` ligature -> ``fi``) maps every produced character to its single origin.

    With ``gaps``, a run of removed invisible characters between two word characters yields one
    space (mapped to the first of them), and a blank-drawn one yields a space wherever it sits.

    Text that is printable ASCII and ASCII whitespace only is returned unchanged with an EMPTY
    map: nothing in it folds, so normalization is the identity — and every caller treats
    ``normalized == text`` as "nothing to fold" without touching the map. The fast path matters:
    the per-character loop below is orders of magnitude slower than one C scan, and scanning a
    large ordinary repo used to burn minutes normalizing plain-ASCII sources.

    The map is an ``array('I')``, not a list. It holds one entry per character and is cached for
    every non-ASCII file of a scan, so as a list of ints it cost ~36 bytes per character: a 22 MB
    repository peaked at 338 MB, 180 MB of it these maps, and the hosted scan died at its 400 MB
    cap with "may be too large". Packed, an entry is 4 bytes.
    """
    idx: array[int] = array("I")
    # Two C-speed passes decide the common case (a regex search over a large plain file is far
    # slower): ASCII only, and nothing left once the plain bytes are deleted.
    if text.isascii() and not text.encode("ascii").translate(None, _PLAIN_BYTES):
        return text, idx
    # Plain runs are copied in one piece (a C slice + a range), so the per-character work is
    # spent only on the other runs: a CJK document is still mostly ASCII markup, and the
    # character loop over a 16 MB repository cost a minute of a hosted scan.
    out: list[str] = []
    pos = 0
    gap_at = -1  # offset of the first removed character of a pending gap, or -1
    last = ""    # the last character written
    for run in _FOLD_RUN.finditer(text):
        start, end = run.span()
        if start > pos:
            if gap_at >= 0:
                if last.isalnum() and text[pos].isalnum():
                    out.append(" ")
                    idx.append(gap_at)
                gap_at = -1
            out.append(text[pos:start])
            idx.extend(range(pos, start))
            last = text[start - 1]
        for j in range(start, end):
            ch = text[j]
            folded = _fold_char(ch)
            if not folded:
                if gaps and is_ignorable(ord(ch)):
                    if ord(ch) in BLANK_DRAWN:
                        if last != " ":
                            out.append(" ")
                            idx.append(j)
                            last = " "
                        gap_at = -1
                    elif gap_at < 0:
                        gap_at = j
                continue
            if gap_at >= 0:
                if last.isalnum() and folded[0].isalnum():
                    out.append(" ")
                    idx.append(gap_at)
                gap_at = -1
            out.append(folded)
            idx.extend([j] * len(folded))
            last = folded[-1]
        pos = end
    if pos < len(text):
        if gap_at >= 0 and last.isalnum() and text[pos].isalnum():
            out.append(" ")
            idx.append(gap_at)
        out.append(text[pos:])
        idx.extend(range(pos, len(text)))
    return "".join(out), idx


def original_span(index_map: Sequence[int], start: int, end: int) -> tuple[int, int]:
    """Map a ``[start, end)`` span on the normalized text to a span in the original text.

    ``end`` is exclusive; the original end is the origin of the last matched character + 1, so
    the returned span covers the full original substring the match came from.
    """
    if start >= end or not index_map:
        return (0, 0)
    return (index_map[start], index_map[end - 1] + 1)


# ----------------------------------------------------------------------------- loose view

# Markup that splits a word without showing in the rendered text: emphasis markers, a backtick,
# an empty HTML element or comment, between two letters.
_INWORD_MARKUP = re.compile(
    r"(?<=[A-Za-z])(?:\*\*|__|`|<([A-Za-z]{1,8})>\s{0,4}</\1>|<!--[^<>\n]{0,40}-->)(?=[A-Za-z])"
)
# Single letters joined by one repeated separator character ("i g n o r e", "i.g.n.o.r.e",
# "i-g-n-o-r-e"). A word of four or more letters is joined, and with it the shorter words written
# the same way right next to it ("a.l.l" beside "i.g.n.o.r.e"); on their own "e.g.", "U.S.A" and
# "P-D-F" stay as they are.
_SPACED_LETTERS = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z](?:([^A-Za-z0-9\n])[A-Za-z])(?:\1[A-Za-z])*(?![A-Za-z0-9])"
)
_SPACED_MIN_LETTERS = 4
# A word in which every letter is written twice ("iiggnnoorree").
_DOUBLED_WORD = re.compile(r"(?<![A-Za-z0-9])(?:([A-Za-z])\1){2,}(?![A-Za-z0-9])")
# Leetspeak: a token that mixes letters with these digits and symbols. A number, a price or a
# lone symbol has no letter in the token and is left alone.
# Matched from the token's first character, and only where letters meet a digit or symbol, so
# an ordinary word costs one failed attempt and no callback.
_LEET_TOKEN = re.compile(
    r"(?<![A-Za-z0-9@$!|+])(?:[A-Za-z]+(?=[0-9@$!|+])|[0-9@$!|+]+(?=[A-Za-z]))[A-Za-z0-9@$!|+]+"
)
_LEET_MAP = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "b", "7": "t", "8": "b",
             "9": "g", "@": "a", "$": "s", "!": "l", "|": "l", "+": "t"}
_LEET_CHAR = re.compile(r"[013-9@$!|+]")
_HAS_LETTER = re.compile(r"[A-Za-z]")
# These count as letters only in front of another token character: "prompt!" keeps its mark.
_LEET_SYMBOL_TAIL = re.compile(r"[!+]+$")


def _leet_token(m: re.Match[str]) -> str:
    token = m.group()
    if not _HAS_LETTER.search(token) or not _LEET_CHAR.search(token):
        return token
    tail = _LEET_SYMBOL_TAIL.search(token)
    body = token[: tail.start()] if tail else token
    return _LEET_CHAR.sub(lambda c: _LEET_MAP[c.group()], body) + token[len(body):]


def _spaced_words(text: str) -> list[re.Match[str]]:
    """The spaced-out words of ``text`` that are to be joined (see ``_SPACED_LETTERS``)."""
    found = list(_SPACED_LETTERS.finditer(text))
    keep: list[re.Match[str]] = []
    i = 0
    while i < len(found):
        j = i
        sep = found[i].group(1)
        # Neighbours: the next word uses the same separator and only blanks lie between them.
        while (j + 1 < len(found) and found[j + 1].group(1) == sep and not sep.isspace()
               and found[j + 1].start() - found[j].end() <= 3
               and text[found[j].end():found[j + 1].start()].isspace()):
            j += 1
        group = found[i:j + 1]
        if any((m.end() - m.start() + 1) // 2 >= _SPACED_MIN_LETTERS for m in group):
            keep.extend(group)
        i = j + 1
    return keep


def _delete(text: str, idx: Sequence[int], spans: list[tuple[int, int]]) -> tuple[str, array]:
    """``text`` without the given sorted, disjoint spans, and its index map."""
    out: list[str] = []
    new_idx: array[int] = array("I")
    pos = 0
    for start, end in spans:
        out.append(text[pos:start])
        new_idx.extend(idx[pos:start])
        pos = end
    out.append(text[pos:])
    new_idx.extend(idx[pos:])
    return "".join(out), new_idx


def loose_fold(
    text: str, index_map: Sequence[int] | None = None
) -> tuple[str, Sequence[int], list[tuple[int, int]]] | None:
    """The loose view of ``text`` (see the module docstring), or None when it changes nothing.

    ``index_map`` maps ``text`` to the original file when ``text`` is already a folded view.
    Returns ``(loose_text, index_map, joined)``: ``joined`` lists the spans of the loose text
    that were letters spaced out by blanks, where the word gaps are gone too ("i g n o r e a l
    l"), so a caller can match a phrase there without its spaces.
    """
    idx: Sequence[int] = index_map if index_map else array("I", range(len(text)))
    changed = False
    spans = [m.span() for m in _INWORD_MARKUP.finditer(text)]
    if spans:
        text, idx = _delete(text, idx, spans)
        changed = True
    joined: list[tuple[int, int]] = []
    spans = []
    removed = 0
    for m in _spaced_words(text):
        spans.extend((o, o + 1) for o in range(m.start() + 1, m.end(), 2))
        length = (m.end() - m.start() + 1) // 2
        if m.group(1).isspace():
            joined.append((m.start() - removed, m.start() - removed + length))
        removed += length - 1
    if spans:
        text, idx = _delete(text, idx, spans)
        changed = True
    spans = [(o, o + 1) for m in _DOUBLED_WORD.finditer(text)
             for o in range(m.start() + 1, m.end(), 2)]
    if spans:
        if joined:  # rare together; the joined spans would need shifting
            joined = []
        text, idx = _delete(text, idx, spans)
        changed = True
    leet = _LEET_TOKEN.sub(_leet_token, text)  # one character for one: the map is unchanged
    if leet != text:
        text = leet
        changed = True
    return (text, idx, joined) if changed else None


def loose_pattern(pattern: re.Pattern[str], *, spaceless: bool = False) -> re.Pattern[str]:
    """``pattern`` for matching the loose view: every literal ``i`` or ``l`` matches either.

    The loose view writes ``1``, ``!`` and ``|`` as ``l`` because it cannot know which of the two
    letters was meant; comparing in that skeleton also reads a capital I written as a small L.
    With ``spaceless``, a required run of blanks (``\\s+``) becomes optional, for text whose
    word gaps were removed together with the separators between its letters.
    """
    src = pattern.pattern
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        ch = src[i]
        if ch == "\\":
            out.append(src[i:i + 2])
            i += 2
        elif ch == "[":
            j = i + 1
            if j < n and src[j] == "^":
                j += 1
            if j < n and src[j] == "]":
                j += 1
            while j < n and src[j] != "]":
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        elif ch == "{":
            j = src.find("}", i)
            j = n - 1 if j < 0 else j
            out.append(src[i:j + 1])
            i = j + 1
        elif ch == "(" and src.startswith("(?", i):
            m = _GROUP_HEAD.match(src, i)
            j = m.end() if m else i + 2
            out.append(src[i:j])
            i = j
        elif ch in "ilIL":
            out.append("[il]" if ch in "il" else "[IL]")
            i += 1
        else:
            out.append(ch)
            i += 1
    folded = "".join(out)
    if spaceless:
        folded = folded.replace("\\s+", "\\s*")
    return re.compile(folded, pattern.flags)


# The head of a `(?...` group: a lookaround, a named group, or flags (`(?i)`, `(?-i:`).
_GROUP_HEAD = re.compile(r"\(\?(?:<?[=!]|P<\w+>|P=\w+\)|[aiLmsux-]*[:)]|:)")


# ----------------------------------------------------------------------------- JavaScript

# A backslash pair is a literal backslash, so what follows it is not an escape.
_JS_ESCAPE = re.compile(
    r"\\\\|\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})|\\u\{([0-9a-fA-F]{1,6})\}"
)
# An escape that spells a printable ASCII character: the only reason to write one in source is
# that the plain character was not wanted there.
JS_ASCII_ESCAPE = re.compile(
    r"\\(?:x[2-7][0-9a-fA-F]|u00[2-7][0-9a-fA-F]|u\{0{0,4}[2-7][0-9a-fA-F]\})"
)


def js_unescaped(
    text: str, origin: Sequence[int] | None = None
) -> tuple[str, Sequence[int]] | None:
    """``text`` with its ``\\xHH``, ``\\uHHHH`` and ``\\u{H}`` escapes written out, and for each
    character of the result its offset in the original file (``origin`` maps ``text`` itself when
    it is already a rewritten view); None when the text has no such escape.

    JavaScript resolves these in string literals and (``\\u`` forms) in identifiers, so
    ``cp.\\u0065xec`` and ``require("child_\\u0070rocess")`` run as ``cp.exec`` and
    ``require("child_process")``.
    """
    if "\\x" not in text and "\\u" not in text:
        return None
    out: list[str] = []
    offsets: array[int] = array("I")
    at = 0
    replaced = False
    for m in _JS_ESCAPE.finditer(text):
        digits = m.group(1) or m.group(2) or m.group(3)
        if digits is None:
            continue  # an escaped backslash
        value = int(digits, 16)
        if value > 0x10FFFF:
            continue
        out.append(text[at:m.start()])
        offsets.extend(range(at, m.start()))
        out.append(chr(value))
        offsets.append(m.start())
        at = m.end()
        replaced = True
    if not replaced:
        return None
    out.append(text[at:])
    offsets.extend(range(at, len(text)))
    if origin is not None:
        offsets = array("I", (origin[o] for o in offsets))
    return "".join(out), offsets
