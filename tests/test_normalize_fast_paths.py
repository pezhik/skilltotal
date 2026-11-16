"""The run-based normalizer and the hidden-Unicode prefilter are pure speed-ups: on every input
they must produce exactly what the character-by-character versions did.

Profiled on a 24 MB, mostly-CJK repository (2026-09-20): the per-character loops in
``normalize_with_map`` and ``invisible_unicode.scan`` took 78 s and 128 s of a 500 s scan."""

from __future__ import annotations

import random
from array import array

from skilltotal import text_normalize
from skilltotal.scanners import invisible_unicode
from skilltotal.text_normalize import _fold_char, normalize_with_map

_REMOVABLE = (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x202A, 0x202E, 0x2066, 0x2069,
              0x200E, 0x034F, 0x3164, 0xFE0F, 0x2063, 0x0008)
_PLAIN = frozenset(map(chr, (*range(0x09, 0x0E), *range(0x20, 0x7F))))


def _reference_normalize(text: str) -> tuple[str, array[int]]:
    """The per-character implementation (the oracle): every character folded on its own."""
    idx: array[int] = array("I")
    if all(ch in _PLAIN for ch in text):
        return text, idx
    out: list[str] = []
    for j, ch in enumerate(text):
        for d in ch if ch in _PLAIN else _fold_char(ch):
            out.append(d)
            idx.append(j)
    return "".join(out), idx


_ALPHABET = (
    list("abc XYZ 0\n\t{}()")            # ASCII incl. whitespace and punctuation
    + list("ﬁ①Ａｂｃ")                    # NFKD expansions and full-width forms
    + list("éñü")                        # precomposed accents (a mark is dropped)
    + list("аеорсх")                     # Cyrillic confusables
    + [chr(cp) for cp in _REMOVABLE]
    + [chr(cp) for cp in (0x03CC, 0x0585, 0x1D00, 0x249C, 0x1F1E6, 0x0489)]  # look-alikes
    + list("中文字テスト")                # CJK: untouched, non-ASCII
    + ["\U000E0061", "\U000E007F", "‮", "​", "\U0001F3F4"]
)


def _random_text(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(_ALPHABET) for _ in range(n))


def test_run_based_normalizer_matches_the_character_loop():
    rng = random.Random(20260920)
    samples = ["", "plain ascii", "é", "中", "a中b", "​x", "ﬁx中‮ab"]
    samples += [_random_text(rng, rng.randint(1, 200)) for _ in range(400)]
    for text in samples:
        got_text, got_idx = normalize_with_map(text)
        ref_text, ref_idx = _reference_normalize(text)
        assert got_text == ref_text, repr(text)
        assert list(got_idx) == list(ref_idx), repr(text)
        assert got_idx.typecode == "I"


def test_ascii_runs_at_either_end_and_in_the_middle_keep_their_offsets():
    text = "abc" + "é" + "def" + "中中" + "ghi"
    norm, idx = normalize_with_map(text)
    assert norm == "abcedef中中ghi"
    # Every produced character maps back to the offset of its origin.
    assert [text[i] for i in idx] == list("abcédef中中ghi")


def test_prefilter_covers_exactly_the_code_points_the_scanner_acts_on():
    hunted = invisible_unicode._HUNTED
    for cp in range(0xE0000, 0xE0080):
        assert hunted.search(chr(cp))
    for cp in invisible_unicode._REVIEW:
        assert hunted.search(chr(cp))
    for ch in "a中é\U0001F3F4  ":  # ordinary, CJK, accent, flag base, nbsp, LS
        assert not hunted.search(ch)


def test_prefilter_changes_no_verdict(tmp_path):
    """A CJK file (non-ASCII, nothing hunted) is skipped; smuggling and bidi are still seen."""
    from skilltotal.file_index import FileIndex
    from skilltotal.scanners.invisible_unicode import InvisibleUnicodeScanner

    (tmp_path / "cjk.md").write_text("# 说明\n\n这是普通的中文文档。\n", encoding="utf-8")
    (tmp_path / "SKILL.md").write_text(
        "# Skill\n\n说明\nhello\U000E0069\U000E0067\U000E006E\U000E006F\U000E0072\U000E0065\n",
        encoding="utf-8",
    )
    (tmp_path / "code.py").write_text("x = 1  # abc ‮ def\n", encoding="utf-8")
    result = InvisibleUnicodeScanner().scan(FileIndex.build(tmp_path))
    assert {e.file for f in result.findings for e in f.evidence} == {"SKILL.md"}
    assert [e.line_start for f in result.findings for e in f.evidence] == [4]
    assert "ignore" in result.findings[0].evidence[0].snippet  # decoded hidden text
    assert [n.title for n in result.needs_review] == ["Bidi / zero-width Unicode"]
    assert text_normalize.normalize_with_map("这是普通的中文文档。")[0] == "这是普通的中文文档。"
