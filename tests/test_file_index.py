"""File indexing and evidence extraction correctness."""

from __future__ import annotations

import re
from pathlib import Path

from skilltotal.file_index import FileIndex


def _write(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    # newline="" disables platform newline translation so test content is byte-exact
    # (otherwise Windows would rewrite "\n" as "\r\n" and break multiline assertions).
    p.write_text(content, encoding="utf-8", newline="")


def test_line_mapping_and_snippet(tmp_path: Path):
    _write(tmp_path, "a.py", "line one\nimport os\nos.system('x')\nlast\n")
    index = FileIndex.build(tmp_path)
    pat = re.compile(r"os\.system\(")
    hits = list(index.search(pat, suffixes=(".py",)))
    assert len(hits) == 1
    _f, _m, ev = hits[0]
    assert ev.file == "a.py"
    assert ev.line_start == 3
    assert ev.line_end == 3
    assert ev.snippet == "os.system('x')"


def test_multiline_match_span(tmp_path: Path):
    _write(tmp_path, "b.py", "a = (\n    1\n)\n")
    index = FileIndex.build(tmp_path)
    pat = re.compile(r"\(\n\s+1\n\)", re.MULTILINE)
    hits = list(index.search(pat, suffixes=(".py",)))
    assert hits, "expected a multiline match"
    _f, _m, ev = hits[0]
    assert ev.line_start == 1
    assert ev.line_end == 3


def test_skips_dependency_and_vcs_dirs(tmp_path: Path):
    _write(tmp_path, "node_modules/dep/x.js", "fetch('http://x')\n")
    _write(tmp_path, ".git/config", "secret\n")
    _write(tmp_path, "src/app.js", "fetch('http://y')\n")
    index = FileIndex.build(tmp_path)
    rels = {f.relpath for f in index.files}
    assert rels == {"src/app.js"}


def test_skips_binary(tmp_path: Path):
    (tmp_path / "bin").write_bytes(b"\x00\x01\x02binary")
    _write(tmp_path, "ok.txt", "hello\n")
    index = FileIndex.build(tmp_path)
    rels = {f.relpath for f in index.files}
    assert "ok.txt" in rels
    assert "bin" not in rels
    assert index.stats["skipped_binary"] == 1


def test_snippet_truncation(tmp_path: Path):
    long_line = "x" * 1000 + "TARGET"
    _write(tmp_path, "c.txt", long_line)
    index = FileIndex.build(tmp_path)
    pat = re.compile("TARGET")
    _f, _m, ev = next(iter(index.search(pat)))
    assert ev.snippet.endswith("…")
    assert len(ev.snippet) <= 242
