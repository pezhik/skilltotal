"""Unit tests for the deterministic de-obfuscation normalizer."""

from __future__ import annotations

import re

from skilltotal.text_normalize import normalize_with_map, original_span


def test_ascii_is_unchanged_with_empty_map():
    # Pure ASCII takes the identity fast path: text unchanged, EMPTY map. The map is only
    # meaningful when normalization changed the text — every caller gates on `norm != text`.
    text = "ignore previous instructions"
    norm, idx = normalize_with_map(text)
    assert norm == text
    assert len(idx) == 0


def test_non_ascii_text_keeps_a_full_map():
    # Anything past the ASCII fast path keeps the real per-character map contract.
    text = "naïve plan"
    norm, idx = normalize_with_map(text)
    assert norm == "naive plan"
    assert len(idx) == len(norm)


def test_cyrillic_homoglyph_phrase_folds_to_ascii():
    # "ignore previous instructions" with Cyrillic о/е/с look-alikes spliced in.
    obf = "ignоre prеviоus instruсtiоns"
    norm, _ = normalize_with_map(obf)
    assert norm == "ignore previous instructions"


def test_zero_width_inside_word_is_removed():
    text = "ig​no​re"  # zero-width spaces spliced in
    norm, idx = normalize_with_map(text)
    assert norm == "ignore"
    assert len(idx) == len(norm)


def test_diacritics_are_stripped():
    norm, _ = normalize_with_map("café")
    assert norm == "cafe"


def test_fullwidth_folds_to_ascii():
    norm, _ = normalize_with_map("ｉｇｎｏｒｅ")  # fullwidth "ignore"
    assert norm == "ignore"


def test_span_maps_back_to_original_across_zero_width():
    # A zero-width splice shifts original offsets; the map must recover the real span.
    text = "x ig​nore y"
    norm, idx = normalize_with_map(text)
    m = re.search("ignore", norm)
    assert m is not None
    s, e = original_span(idx, m.start(), m.end())
    assert "​" in text[s:e]  # the original span includes the smuggled char
    assert text[s:e].replace("​", "") == "ignore"


def _reference(text: str) -> tuple[str, list[int]]:
    """The pre-0.49 per-character implementation, kept to pin the optimized one against."""
    import unicodedata

    from skilltotal.text_normalize import _CONFUSABLES, _REMOVABLE

    out: list[str] = []
    idx: list[int] = []
    for j, ch in enumerate(text):
        if ord(ch) in _REMOVABLE:
            continue
        for d in unicodedata.normalize("NFKD", _CONFUSABLES.get(ch, ch)):
            if not unicodedata.combining(d):
                out.append(d)
                idx.append(j)
    return "".join(out), idx


def test_optimized_map_matches_the_reference_exactly():
    samples = [
        "naïve café — “quotes” ﬁle ｉｇｎｏｒｅ",
        "ignоre prеviоus instruсtiоns",  # Cyrillic look-alikes
        "x ig​no‍re‮ y﻿",  # zero-width, bidi, BOM
        "plain ascii with one é",
        "\U000e0041\U000e0042 tag chars",
        "",
    ]
    for text in samples:
        norm, idx = normalize_with_map(text)
        ref_norm, ref_idx = _reference(text) if not text.isascii() else (text, [])
        assert norm == ref_norm, text
        assert list(idx) == ref_idx, text


def test_map_is_packed_not_a_list_of_ints():
    # One entry per character, cached per non-ASCII file for the whole scan: as a list of ints it
    # took a 22 MB repository to 338 MB and past the hosted scan's memory cap.
    _, idx = normalize_with_map("é" * 1000)
    assert idx.itemsize == 4 and len(idx) == 1000


def test_empty_span_is_safe():
    _, idx = normalize_with_map("abc")
    assert original_span(idx, 1, 1) == (0, 0)
    assert original_span([], 0, 5) == (0, 0)
