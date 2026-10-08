"""Review-only heuristics write one needs_review note per heuristic, not one per file or line.

Before 0.57.0 each of these wrote a note for every file or line it matched, so one package could
carry hundreds of identical rows (a linter's deliberately broken test fixtures produced 352
"Unparseable Python file" notes). The findings and the score never depended on these notes;
only their shape changed.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.file_index import FileIndex
from skilltotal.scanners.base import REVIEW_PLACES_SHOWN, aggregated_review
from skilltotal.scanners.invisible_unicode import InvisibleUnicodeScanner
from skilltotal.scanners.obfuscation import ObfuscationScanner
from skilltotal.scanners.python_ast import PythonAstScanner


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _notes(result, title: str):
    return [n for n in result.needs_review if n.title == title]


def test_many_unparseable_files_make_one_note_that_counts_them(tmp_path: Path):
    for i in range(8):
        _write(tmp_path, f"src/broken_{i}.py", "def f(:\n")
    for i in range(3):
        _write(tmp_path, f"tests/fixtures/bad_{i}.py", "class (\n")
    result = PythonAstScanner().scan(FileIndex.build(tmp_path))
    (note,) = _notes(result, "Unparseable Python file")
    assert note.reason.startswith("11 Python file(s) could not be parsed")
    assert ", and 6 more" in note.reason
    assert "3 of the files are test code" in note.reason
    assert note.file and note.line == 1


def test_dynamic_imports_are_counted_in_one_note(tmp_path: Path):
    calls = "".join(f"importlib.import_module(name_{i})\n" for i in range(30))
    _write(tmp_path, "plugins.py", "import importlib\n" + calls)
    result = PythonAstScanner().scan(FileIndex.build(tmp_path))
    (note,) = _notes(result, "Dynamic module import")
    assert note.reason.startswith("30 dynamic import(s)")
    assert "plugins.py:2" in note.reason


def test_unparseable_files_no_longer_eat_the_dynamic_import_cap(tmp_path: Path):
    for i in range(30):
        _write(tmp_path, f"broken_{i}.py", "def f(:\n")
    _write(tmp_path, "loader.py", "import importlib\nimportlib.import_module(x)\n")
    result = PythonAstScanner().scan(FileIndex.build(tmp_path))
    assert len(_notes(result, "Unparseable Python file")) == 1
    assert len(_notes(result, "Dynamic module import")) == 1


def test_base64_blobs_on_many_lines_make_one_note(tmp_path: Path):
    blob = "QUJD" * 60
    _write(tmp_path, "data.js", "".join(f'const b{i} = "{blob}";\n' for i in range(40)))
    result = ObfuscationScanner().scan(FileIndex.build(tmp_path))
    (note,) = _notes(result, "Large base64 blob")
    assert note.reason.startswith("40 large base64-looking blob(s)")
    assert note.file == "data.js"


def test_bidi_in_many_files_makes_one_note(tmp_path: Path):
    for i in range(7):
        _write(tmp_path, f"docs/n{i}.md", f"note {i} ‮ reversed\n")
    result = InvisibleUnicodeScanner().scan(FileIndex.build(tmp_path))
    (note,) = _notes(result, "Bidi / zero-width Unicode")
    assert note.reason.startswith("7 file(s) with bidi/zero-width characters")
    assert result.findings == []


def test_the_note_names_the_first_places_and_says_how_many_more():
    places = [(f"f{i}.py", i + 1) for i in range(REVIEW_PLACES_SHOWN + 2)]
    note = aggregated_review(category="c", title="T", places=places, what="thing(s)",
                             advice="Look.")
    assert note.reason == (
        "7 thing(s): f0.py:1, f1.py:2, f2.py:3, f3.py:4, f4.py:5, and 2 more. Look."
    )
    assert (note.file, note.line) == ("f0.py", 1)


def test_a_capped_count_is_marked_as_a_lower_bound():
    places = [(f"f{i}.py", 1) for i in range(REVIEW_PLACES_SHOWN + 1)]
    note = aggregated_review(category="c", title="T", places=places, what="x", advice="A.",
                             capped=True)
    assert note.reason.startswith("6+ x:")
    assert "and 1+ more" in note.reason
