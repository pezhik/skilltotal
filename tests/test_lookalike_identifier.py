"""Two names in code that look the same (``ST-LOOKALIKE-IDENTIFIER``).

An identifier that mixes Latin letters with look-alike letters of another alphabet (or, in
JavaScript, carries a zero-width joiner) is reported when the name it reads as is also a name in
the same file; alone it is a review note. Names wholly in one script, two words in two scripts,
strings and comments stay clean.

Non-Latin letters are written as escapes so this file stays ASCII; nothing here is executed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.models import Component, ThreatClass
from skilltotal.rules import get_rules
from skilltotal.scanners.lookalike_identifier import identifier_reading

RULE = "ST-LOOKALIKE-IDENTIFIER"
NOTE = "Identifier mixes Latin with look-alike letters"
BANNER_PY = "# FIXTURE ONLY - synthetic detection test sample, not real malware\n"
BANNER_JS = "// FIXTURE ONLY - synthetic detection test sample, not real malware\n"
CYR_E, CYR_A, CYR_P, CYR_C = (chr(c) for c in (0x435, 0x430, 0x440, 0x441))
CYR_BIG_A, ZWNJ, ALPHA = chr(0x410), chr(0x200C), chr(0x3B1)
# Wholly Cyrillic and wholly Greek words.
SUMMA = "".join(chr(c) for c in (0x441, 0x443, 0x43C, 0x43C, 0x430))
THESI = "".join(chr(c) for c in (0x398, 0x3AD, 0x3C3, 0x3B7))


def _scan(root: Path, name: str, text: str):
    (root / name).write_text(text, encoding="utf-8")
    return analyze_directory(root, Component(name="x", type="directory", source=str(root)))


def _evidence(report):
    return [e for f in report.findings if f.id == RULE for e in f.evidence]


def _titles(report):
    return {n.title for n in report.needs_review}


def test_the_rule_is_a_registered_risky_construct():
    rule = next(r for r in get_rules() if r.id == RULE)
    assert rule.threat_class is ThreatClass.RISKY_CONSTRUCT
    assert rule.capability is None


@pytest.mark.parametrize(
    ("name", "reads_as"),
    [
        (f"ch{CYR_E}ck_token", "check_token"),
        (f"is{CYR_BIG_A}dmin", "isAdmin"),
        (f"{CYR_P}{CYR_A}yload", "payload"),
        (f"get_{CYR_C}ount", "get_count"),
    ],
)
def test_a_word_mixing_latin_and_lookalike_letters_reads_as_the_ascii_name(name, reads_as):
    assert identifier_reading(name) == reads_as


@pytest.mark.parametrize(
    "name",
    [
        "check_token",
        SUMMA,  # one script
        f"get_{SUMMA}",  # two words, each in one script
        f"get{THESI}",  # the same, joined by a capital letter
        f"HTTP{SUMMA.capitalize()}",  # an acronym and a word
        chr(0x394) + "t",  # a Greek letter that looks like no Latin one
        "caf" + chr(0xE9) + "_total",  # an accented Latin letter is Latin
        chr(0x5909) + chr(0x6570) + "x",  # CJK passes for nothing
    ],
)
def test_names_in_one_script_per_word_are_not_lookalikes(name):
    assert identifier_reading(name) is None


def test_a_zero_width_joiner_counts_in_javascript_only():
    assert identifier_reading(f"allow{ZWNJ}ed", joiners=True) == "allowed"
    assert identifier_reading(f"allow{ZWNJ}ed") is None
    # A joiner inside a word of another script is how that script is written.
    assert identifier_reading(f"{chr(0x645)}{chr(0x6CC)}{ZWNJ}{chr(0x62E)}", joiners=True) is None


def test_python_function_beside_its_lookalike_is_reported_with_exact_evidence(tmp_path):
    report = _scan(tmp_path, "tool.py", BANNER_PY + (
        "def check_token(t):\n    return t == 'expected'\n\n\n"
        f"def ch{CYR_E}ck_token(t):\n    return True\n\n\n"
        f"def login(t):\n    return ch{CYR_E}ck_token(t)\n"
    ))
    evidence = _evidence(report)
    assert len(evidence) == 1  # one per distinct name, at its first use
    assert (evidence[0].file, evidence[0].line_start) == ("tool.py", 6)
    assert "reads as 'check_token'" in evidence[0].snippet
    assert "line 2" in evidence[0].snippet
    assert "\\u0435" in evidence[0].snippet  # the foreign letter is spelled out
    assert report.verdict["has_malicious_indicators"] is False
    assert NOTE not in _titles(report)


def test_javascript_constant_beside_its_lookalike_is_reported(tmp_path):
    report = _scan(tmp_path, "index.js", BANNER_JS + (
        f"const isAdmin = false;\nconst is{CYR_BIG_A}dmin = true;\n"
        f"module.exports = () => is{CYR_BIG_A}dmin;\n"
    ))
    evidence = _evidence(report)
    assert [(e.file, e.line_start) for e in evidence] == [("index.js", 3)]


def test_javascript_name_with_a_zero_width_joiner_beside_the_plain_name_is_reported(tmp_path):
    report = _scan(tmp_path, "index.ts", BANNER_JS + (
        f"let allowed = false;\nlet allow{ZWNJ}ed = true;\nexport default () => allow{ZWNJ}ed;\n"
    ))
    assert [(e.file, e.line_start) for e in _evidence(report)] == [("index.ts", 3)]


def test_a_mixed_name_with_no_twin_in_the_file_is_a_note_not_a_finding(tmp_path):
    report = _scan(tmp_path, "tool.py", BANNER_PY + (
        f"def build(data):\n    {CYR_P}{CYR_A}yload = data.strip()\n"
        f"    return {CYR_P}{CYR_A}yload\n"
    ))
    assert not _evidence(report)
    note = next(n for n in report.needs_review if n.title == NOTE)
    assert (note.file, note.line) == ("tool.py", 3)
    assert report.risk_score == 0


def test_the_twin_in_another_file_does_not_make_a_finding(tmp_path):
    (tmp_path / "other.py").write_text(BANNER_PY + "payload = 1\n", encoding="utf-8")
    report = _scan(tmp_path, "tool.py", BANNER_PY + f"{CYR_P}{CYR_A}yload = 2\n")
    assert not _evidence(report)
    assert NOTE in _titles(report)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        # Code written in Russian, with a Latin twin of nothing.
        ("tool.py", BANNER_PY + f"def {SUMMA}(items):\n    return sum(items)\n\n\n"
                                f"def get_{SUMMA}(items):\n    return {SUMMA}(items)\n\n\n"
                                f"def get_sum(items):\n    return get_{SUMMA}(items)\n"),
        # The look-alike sits in a string and a comment only.
        ("tool.py", BANNER_PY + f"# ch{CYR_E}ck_token is a look-alike\n"
                                "def check_token(t):\n"
                                f"    return t == 'ch{CYR_E}ck_token'\n"),
        ("index.js", BANNER_JS + f"// is{CYR_BIG_A}dmin\nconst isAdmin = false;\n"
                                 f"const label = `is{CYR_BIG_A}dmin`;\n"
                                 "module.exports = { isAdmin, label };\n"),
        # Greek letters in a formula, a Greek word after a Latin one.
        ("index.js", BANNER_JS + f"const {ALPHA} = 0.5;\nconst alpha = {ALPHA};\n"
                                 f"const get{THESI} = (x) => x * {ALPHA};\n"
                                 f"module.exports = {{ alpha, get{THESI} }};\n"),
    ],
)
def test_honest_non_latin_code_stays_clean(tmp_path, name, text):
    report = _scan(tmp_path, name, text)
    assert not _evidence(report)
    assert NOTE not in _titles(report)
    assert report.risk_score == 0


def test_a_lookalike_in_a_markdown_or_data_file_is_not_read_as_an_identifier(tmp_path):
    text = f"check_token and ch{CYR_E}ck_token\n"
    (tmp_path / "notes.md").write_text(text, encoding="utf-8")
    report = _scan(tmp_path, "words.txt", text)
    assert not _evidence(report)
    assert NOTE not in _titles(report)


def test_many_lookalikes_in_one_file_are_bounded(tmp_path):
    lines = [f"name{i} = {i}\nn{CYR_A}me{i} = {i}\n" for i in range(300)]
    report = _scan(tmp_path, "tool.py", BANNER_PY + "".join(lines))
    assert 1 <= len(_evidence(report)) <= 16
