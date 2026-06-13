"""Trojan-Source defense: hidden/deceptive code points are neutralized in displayed snippets."""

from __future__ import annotations

from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.file_index import neutralize_hidden

_RLO = "‮"  # right-to-left override (Trojan-Source)
_ZWNJ = "‌"  # zero-width non-joiner


def test_neutralize_renders_hidden_codepoints():
    out = neutralize_hidden(f"a{_RLO}b{_ZWNJ}c\U000e0041d\x07e")
    for token in ("<U+202E>", "<U+200C>", "<U+E0041>", "<U+0007>"):
        assert token in out
    assert _RLO not in out and _ZWNJ not in out


def test_neutralize_keeps_clean_text_and_tabs():
    assert neutralize_hidden("clean\tline\nok") == "clean\tline\nok"
    # visible non-ASCII (cyrillic / CJK / emoji) is legitimate and preserved
    assert neutralize_hidden("обычный 中文") == (
        "обычный 中文"
    )


def test_evidence_snippet_is_neutralized(tmp_path: Path):
    # A bidi override hidden inside a real construct must show as <U+202E>, not reorder the line.
    (tmp_path / "m.py").write_text(
        f'import subprocess\nsubprocess.run("ls{_RLO}rm -rf")\n', encoding="utf-8"
    )
    report = analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))
    snippets = "\n".join(e.snippet for f in report.findings for e in f.evidence)
    assert "<U+202E>" in snippets
    assert _RLO not in snippets


def test_component_name_is_neutralized(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        f'{{"name": "evil{_RLO}ttt", "version": "1.0"}}', encoding="utf-8"
    )
    component = detect_component(tmp_path, source=str(tmp_path))
    assert _RLO not in component.name and "<U+202E>" in component.name
