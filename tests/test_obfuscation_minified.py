"""Minified-line note: build artifacts are expected long-line formats, rest aggregates."""

from __future__ import annotations

from skilltotal.file_index import FileIndex
from skilltotal.scanners.obfuscation import ObfuscationScanner

LONG = "x" * 2500  # over the 2000-char threshold


def _scan(tmp_path, files: dict[str, str]):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return ObfuscationScanner().scan(FileIndex.build(tmp_path))


def _minified_notes(result):
    return [n for n in result.needs_review if "minified" in n.title.lower()]


def test_build_artifacts_are_not_flagged(tmp_path):
    # Source maps, declaration files and lockfiles are single/long-line BY DESIGN.
    res = _scan(tmp_path, {
        "client.js.map": '{"mappings":"' + LONG + '"}',
        "client.d.ts": "export type T = " + LONG + ";",
        "client.d.mts": "export type T = " + LONG + ";",
        "bundle.min.js": "var a=1;" + LONG,
        "package-lock.json": '{"x":"' + LONG + '"}',
    })
    assert _minified_notes(res) == []


def test_real_minified_files_aggregate_into_one_note(tmp_path):
    res = _scan(tmp_path, {
        "a.js": "var a=1;" + LONG,
        "b.js": "var b=2;" + LONG,
        "sub/c.py": "x = '" + LONG + "'",
        "clean.js": "var ok = 1;\n",
    })
    notes = _minified_notes(res)
    assert len(notes) == 1  # one aggregated row, not one per file
    note = notes[0]
    assert "(3)" in note.title
    assert "a.js" in note.reason and "b.js" in note.reason and "sub/c.py" in note.reason
    assert note.file == "a.js"  # anchored to the first example


def test_many_minified_files_list_examples_plus_count(tmp_path):
    files = {f"f{i:02}.js": LONG for i in range(12)}
    res = _scan(tmp_path, files)
    notes = _minified_notes(res)
    assert len(notes) == 1
    assert "and 4 more" in notes[0].reason  # 12 files, 8 examples shown


def test_no_note_when_nothing_is_minified(tmp_path):
    res = _scan(tmp_path, {"a.js": "short line\n", "b.map": '{"mappings":"AAAA"}'})
    assert _minified_notes(res) == []
