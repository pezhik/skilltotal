"""The engine's own source holds no invisible or control characters.

A scanner that flags hidden Unicode in other people's code must not carry it in its own: a
zero-width or bidi character in a regex or a string literal reads differently from what runs (the
Trojan Source class). On 2026-10-11 an editing tool decoded ``\\u202a``-style escapes into the
characters themselves; the characters a pattern needs are now built from code point numbers.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {"\n", "\t", "\r"}


def test_no_hidden_or_control_characters_in_the_engine_source():
    found = []
    for path in sorted((ROOT / "skilltotal").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), 1):
            for ch in line:
                if ch not in ALLOWED and unicodedata.category(ch) in ("Cc", "Cf"):
                    found.append(f"{path.relative_to(ROOT)}:{line_no}: U+{ord(ch):04X}")
    assert found == []
