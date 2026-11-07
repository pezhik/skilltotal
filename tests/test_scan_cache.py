"""The scanner result cache: a replay gives the report a scan gives, and misses when it must."""

from __future__ import annotations

import ast
import inspect
import json
import shutil
from pathlib import Path

import pytest

from skilltotal import engine, scan_cache
from skilltotal.collector import detect_component
from skilltotal.file_index import FileIndex
from skilltotal.scan_cache import ScanCache, code_files, index_digest
from skilltotal.scanners import SCANNERS

_CORPUS = Path(__file__).parent / "eval_corpus"
_PKG = Path(scan_cache.__file__).resolve().parent
_SAMPLES = sorted(p for kind in ("positive", "negative") for p in (_CORPUS / kind).glob("*/*")
                  if p.is_dir())
_DECODE_EXEC = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"


def _report(root: Path, cache: ScanCache | None = None) -> dict:
    data = engine.analyze_directory(root, detect_component(root, source="sample"),
                                    scan_cache=cache).to_dict()
    data["metadata"].pop("generated_at")
    return data


def _replayable() -> int:
    return sum(not s.reads_outside_index for s in SCANNERS)


def test_every_corpus_sample_gives_the_same_report_replayed(tmp_path):
    assert len(_SAMPLES) > 50
    for sample in _SAMPLES:
        cache = ScanCache(tmp_path / "cache")
        plain = _report(sample)
        assert _report(sample, cache) == plain, sample.name
        replay = ScanCache(tmp_path / "cache")
        assert _report(sample, replay) == plain, sample.name
        assert replay.replayed == _replayable(), sample.name
        assert replay.scanned == len(SCANNERS) - _replayable()


def test_the_same_files_in_another_folder_replay(tmp_path):
    a = tmp_path / "a" / "pkg"
    a.mkdir(parents=True)
    (a / "x.py").write_text(_DECODE_EXEC, encoding="utf-8")
    b = tmp_path / "b" / "elsewhere"
    shutil.copytree(a, b)
    assert index_digest(FileIndex.build(a)) == index_digest(FileIndex.build(b))
    _report(a, ScanCache(tmp_path / "cache"))
    replay = ScanCache(tmp_path / "cache")
    assert _report(b, replay) == _report(b)
    assert replay.replayed == _replayable()


def test_a_changed_or_added_file_misses(tmp_path):
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "x.py").write_text("x = 1\n", encoding="utf-8")
    before = index_digest(FileIndex.build(root))
    (root / "x.py").write_text(_DECODE_EXEC, encoding="utf-8")
    changed = index_digest(FileIndex.build(root))
    (root / "y.md").write_text("hello\n", encoding="utf-8")
    added = index_digest(FileIndex.build(root))
    assert len({before, changed, added}) == 3
    _report(root, ScanCache(tmp_path / "cache"))
    (root / "x.py").write_text("x = 1\n", encoding="utf-8")
    again = ScanCache(tmp_path / "cache")
    assert _report(root, again) == _report(root)
    assert again.replayed == 0


def test_changed_scanner_code_rescans_that_scanner_only(tmp_path, monkeypatch):
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "x.py").write_text(_DECODE_EXEC, encoding="utf-8")
    _report(root, ScanCache(tmp_path / "cache"))
    real = scan_cache.code_digest
    monkeypatch.setattr(scan_cache, "code_digest",
                        lambda s, root=_PKG: "edited" if s.name == "obfuscation" else real(s, root))
    cache = ScanCache(tmp_path / "cache")
    assert _report(root, cache) == _report(root)
    assert cache.replayed == _replayable() - 1


def test_a_damaged_entry_is_a_miss(tmp_path):
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "x.py").write_text(_DECODE_EXEC, encoding="utf-8")
    _report(root, ScanCache(tmp_path / "cache"))
    entries = list((tmp_path / "cache").rglob("*.json"))
    assert len(entries) == _replayable()
    for i, entry in enumerate(entries):
        entry.write_text(["{", "[]", '{"format": 1}', '{"format": 0, "result": {}}'][i % 4],
                         encoding="utf-8")
    cache = ScanCache(tmp_path / "cache")
    assert _report(root, cache) == _report(root)
    assert cache.replayed == 0


def test_an_audit_catches_a_wrong_replay_and_uses_the_fresh_result(tmp_path):
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "x.py").write_text(_DECODE_EXEC, encoding="utf-8")
    plain = _report(root)
    _report(root, ScanCache(tmp_path / "cache"))
    # Make the stored obfuscation result say nothing was found.
    (entry,) = (tmp_path / "cache" / "obfuscation").rglob("*.json")
    data = json.loads(entry.read_text(encoding="utf-8"))
    assert data["result"]["findings"]
    data["result"]["findings"] = []
    entry.write_text(json.dumps(data), encoding="utf-8")
    trusting = ScanCache(tmp_path / "cache")
    assert _report(root, trusting) != plain  # the planted entry is replayed as is
    audited = ScanCache(tmp_path / "cache", audit_every=1)
    assert _report(root, audited) == plain
    assert audited.mismatches == ["obfuscation"]
    assert audited.replayed == 0
    # The audit rewrote the entry with the fresh result.
    assert _report(root, ScanCache(tmp_path / "cache")) == plain


_DISK_CALLS = {"open", "component_files", "walk_files"}
_DISK_METHODS = {"read_bytes", "read_text", "iterdir", "rglob", "scandir", "listdir"}


def _touches_disk(source: str) -> list[str]:
    hits = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute) and node.attr == "root":
            hits.append(".root")
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in _DISK_CALLS:
                hits.append(fn.id)
            if isinstance(fn, ast.Attribute) and fn.attr in _DISK_METHODS:
                hits.append(fn.attr)
    return hits


def test_a_scanner_that_reads_the_disk_says_so_and_is_never_replayed():
    # A replay is keyed on the index content, so a scanner that opens files itself (a new one an
    # agent wrote, say) must set reads_outside_index, or a changed file it reads would replay.
    for s in SCANNERS:
        hits = _touches_disk(Path(inspect.getsourcefile(type(s))).read_text(encoding="utf-8"))
        assert bool(hits) == s.reads_outside_index, (s.name, hits)
    assert {s.name for s in SCANNERS if s.reads_outside_index} == {"encrypted_archive"}
    assert _touches_disk("def scan(self, index):\n    return (index.root / 'a').read_bytes()\n")


def test_code_files_follow_imports_and_stop_at_the_package():
    secrets = {p.relative_to(_PKG).as_posix() for p in code_files("skilltotal.scanners.secrets")}
    assert {"scanners/secrets.py", "scanners/base.py", "file_index.py", "models.py"} <= secrets
    assert "scanners/python_ast.py" not in secrets
    assert "engine.py" not in secrets
    # `from skilltotal import bounded_json` depends on that module, not on the package's
    # __init__ (which holds the version every release bumps).
    mcp = {p.relative_to(_PKG).as_posix() for p in code_files("skilltotal.scanners.mcp")}
    assert "bounded_json.py" in mcp and "__init__.py" not in mcp


def test_code_files_resolve_relative_and_nested_imports(tmp_path):
    pkg = tmp_path / "skilltotal"
    (pkg / "scanners").mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "helper.py").write_text("X = 1\n", encoding="utf-8")
    (pkg / "deep.py").write_text("Y = 2\n", encoding="utf-8")
    (pkg / "unused.py").write_text("Z = 3\n", encoding="utf-8")
    (pkg / "scanners" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "scanners" / "base.py").write_text("from ..helper import X\n", encoding="utf-8")
    (pkg / "scanners" / "one.py").write_text(
        "from .base import X\n\ndef f():\n    from skilltotal import deep\n    return deep\n",
        encoding="utf-8")
    got = {p.relative_to(pkg).as_posix() for p in code_files("skilltotal.scanners.one", pkg)}
    assert got == {"scanners/one.py", "scanners/base.py", "helper.py", "deep.py"}


def test_an_index_without_a_stable_form_replays_nothing(tmp_path):
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "x.py").write_text(_DECODE_EXEC, encoding="utf-8")
    index = FileIndex.build(root)
    index.surprise = object()  # an attribute a later engine might add
    assert index_digest(index) is None


@pytest.mark.parametrize("audit_every", [0, 1])
def test_a_cache_on_an_unwritable_folder_still_scans(tmp_path, audit_every):
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "x.py").write_text(_DECODE_EXEC, encoding="utf-8")
    blocker = tmp_path / "cache"
    blocker.write_text("a file, not a folder", encoding="utf-8")
    cache = ScanCache(blocker, audit_every=audit_every)
    assert _report(root, cache) == _report(root)
    assert cache.replayed == 0
