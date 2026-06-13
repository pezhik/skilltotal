"""Deterministic text de-obfuscation for instruction-surface matching.

Attackers hide instruction-override / tool-poisoning phrases from a naive regex by swapping
Latin letters for look-alikes (Cyrillic ``а``, Greek ``ο``), adding combining accents, using
full-width forms, or splicing zero-width characters mid-word. None of that changes what a
language model reads, but it defeats byte-for-byte matching.

:func:`normalize_with_map` folds those tricks away *and* returns an index map so a match on the
normalized text can be anchored back to the exact span in the ORIGINAL file — preserving the
engine invariant that every finding carries real file/line/snippet evidence.

This is deterministic and dependency-free (stdlib ``unicodedata`` + a curated confusable table).
It does NOT attempt semantic understanding, translation, or paraphrase detection — those need an
LLM and live in the paid Deep Analysis layer, not here.
"""

from __future__ import annotations

import unicodedata

# Characters removed entirely before matching: zero-width, bidi controls, and other format
# characters used to splice or visually reorder text. Kept in sync with the smuggling set in
# invisible_unicode.py (that scanner still flags their *presence*; here we just see through them).
_REMOVABLE = {
    0x200B,  # zero-width space
    0x200C,  # zero-width non-joiner
    0x200D,  # zero-width joiner
    0x2060,  # word joiner
    0xFEFF,  # BOM / zero-width no-break space
    0x00AD,  # soft hyphen
    0x202A,  # LRE
    0x202B,  # RLE
    0x202C,  # PDF
    0x202D,  # LRO
    0x202E,  # RLO
    0x2066,  # LRI
    0x2067,  # RLI
    0x2068,  # FSI
    0x2069,  # PDI
}

# Curated homoglyph fold: Cyrillic / Greek look-alikes -> their Latin ASCII counterpart. NFKC
# does NOT do this (these are distinct letters, not compatibility forms), so we map the common
# attack set explicitly. Folding only affects these specific code points; legitimate Cyrillic/
# Greek words are not ASCII phrases, and the matchers only look for multi-word English phrases,
# so this does not create false matches on genuine non-Latin text.
_CONFUSABLES = {
    # Cyrillic lowercase -> Latin
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i",
    "ј": "j", "ԁ": "d", "ո": "n", "г": "r",
    # Cyrillic uppercase -> Latin
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "І": "I", "Ј": "J",
    # Greek lowercase -> Latin
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "ѵ": "v", "ѳ": "o",
    # Greek uppercase -> Latin
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "Ζ": "Z",
}


def normalize_with_map(text: str) -> tuple[str, list[int]]:
    """Return ``(normalized_text, index_map)``.

    ``index_map[i]`` is the offset in ``text`` of the character that produced
    ``normalized_text[i]``. Removable characters contribute nothing; a character that expands
    (e.g. the ``ﬁ`` ligature -> ``fi``) maps every produced character to its single origin.
    """
    out: list[str] = []
    idx: list[int] = []
    for j, ch in enumerate(text):
        if ord(ch) in _REMOVABLE:
            continue
        folded = _CONFUSABLES.get(ch, ch)
        # NFKD: full-width/compatibility forms -> ASCII, precomposed accents -> base + mark.
        for d in unicodedata.normalize("NFKD", folded):
            if unicodedata.combining(d):
                continue  # drop diacritics (café -> cafe)
            out.append(d)
            idx.append(j)
    return "".join(out), idx


def original_span(index_map: list[int], start: int, end: int) -> tuple[int, int]:
    """Map a ``[start, end)`` span on the normalized text to a span in the original text.

    ``end`` is exclusive; the original end is the origin of the last matched character + 1, so
    the returned span covers the full original substring the match came from.
    """
    if start >= end or not index_map:
        return (0, 0)
    return (index_map[start], index_map[end - 1] + 1)
