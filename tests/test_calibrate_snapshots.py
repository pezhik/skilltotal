"""Calibration harness: stored copies of fetched components (--snapshot-dir, --refresh-snapshots).

No network: ``collect`` is replaced by a stand-in that hands out a local folder, as the collector
hands out a fetched one, and identities are fixed strings.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest

from skilltotal import engine
from skilltotal.collector import SourceContext
from skilltotal.models import Component

_CAL = Path(__file__).parent / "manual_eval" / "calibrate.py"
_spec_mod = importlib.util.spec_from_file_location("calibrate_snapshots_under_test", _CAL)
calibrate = importlib.util.module_from_spec(_spec_mod)
sys.modules["calibrate_snapshots_under_test"] = calibrate
_spec_mod.loader.exec_module(calibrate)

_DECODE_EXEC = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
_SHA = "0123456789abcdef0123456789abcdef01234567"
_SHA2 = "89abcdef0123456789abcdef0123456789abcdef"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _package(root: Path, version: str = "1.0.0", payload: str = _DECODE_EXEC) -> Path:
    """A fetched npm package: code, a manifest, a skipped dependency folder and an empty one."""
    _write(root / "package.json", json.dumps({"name": "widget", "version": version}))
    _write(root / "lib" / "run.py", payload)
    _write(root / "lib" / "util.js", "module.exports = (a, b) => a + b;\n")
    _write(root / "node_modules" / "dep" / "index.js", "module.exports = 1;\n")
    (root / "empty").mkdir(parents=True, exist_ok=True)
    return root


def _context(root: Path, spec: str, version: str = "1.0.0", ctype: str = "npm_package"):
    return SourceContext(
        root=root,
        component=Component(name="widget", type=ctype, source=spec, version=version,
                            download_url=f"https://registry.example.invalid/widget-{version}.tgz"),
        note="Scanned the package, not the page", skipped_entries=2,
        distribution_note="One file of the release scanned", unpacked_note="1 binary not read",
    )


class Upstream:
    """The stand-in registry: what a fetch of a spec gives now, and how often it was fetched."""

    def __init__(self, monkeypatch, contexts: dict, identities: dict):
        self.contexts, self.identities, self.fetches = contexts, identities, []

        @contextmanager
        def fake_collect(spec, **_kwargs):
            self.fetches.append(spec)
            yield self.contexts[spec]()

        monkeypatch.setattr(calibrate, "collect", fake_collect)
        monkeypatch.setattr(engine, "collect", fake_collect)
        monkeypatch.setattr(calibrate, "component_identity", lambda spec: self.identities.get(spec))


def _strip_time(report: dict) -> dict:
    report = json.loads(json.dumps(report))
    report["metadata"].pop("generated_at", None)
    return report


def _row(spec: str, store: Path, **kwargs):
    return calibrate.run_row("benign-baseline", spec, "", snapshot_dir=store, **kwargs)


def test_a_stored_copy_gives_the_report_a_live_fetch_gives(tmp_path, monkeypatch):
    spec = "npm:widget"
    root = _package(tmp_path / "fetched" / "package")
    up = Upstream(monkeypatch, {spec: lambda: _context(root, spec)},
                  {spec: "npm:widget@1.0.0#sha512-abc"})
    live = _strip_time(engine.analyze(spec).to_dict())

    store = tmp_path / "snapshots"
    first = _row(spec, store)
    assert first.status == "ok" and first.snapshot == "stored" and first.detail == ""
    assert first.identity == "npm:widget@1.0.0#sha512-abc" and first.component_version == "1.0.0"
    snap = calibrate.SnapshotStore(store).current(spec)
    assert snap is not None and snap.meta["version"] == "1.0.0"
    assert snap.meta["fetched_at"] == first.snapshot_fetched_at

    # Read back: the same component identity, notes and findings as the live fetch.
    unpacked = tmp_path / "unpacked"
    unpacked.mkdir()
    ctx = calibrate.SnapshotStore(store).open(snap, unpacked)
    assert ctx.component.to_dict() == _context(root, spec).component.to_dict()
    assert _strip_time(calibrate._analyze_context(ctx, None).to_dict()) == live

    up.contexts[spec] = lambda: pytest.fail("fetched a row that has a stored copy")
    again = _row(spec, store)
    assert again.snapshot == "read" and up.fetches == [spec, spec]  # analyze + the first row
    for field in calibrate._FACT_FIELDS:
        assert getattr(again, field) == getattr(first, field), field
    assert again.passed is first.passed is False  # the decode-exec payload is found both times


def test_a_stored_copy_keeps_only_the_folder_and_config_of_git(tmp_path, monkeypatch):
    spec = "https://github.com/acme/widgets"
    root = _package(tmp_path / "clone" / "repo")
    _write(root / ".git" / "config", "[core]\n\tbare = false\n")
    _write(root / ".git" / "HEAD", "ref: refs/heads/main\n")
    _write(root / ".git" / "refs" / "heads" / "main", _SHA + "\n")
    _write(root / ".git" / "objects" / "pack" / "big.pack", "x" * 1000)
    _write(root / "sub" / ".git" / "config", "[core]\n")  # a nested repository's
    Upstream(monkeypatch, {spec: lambda: _context(root, spec, ctype="repository")},
             {spec: f"git:https://github.com/acme/widgets.git@{_SHA}"})
    live = _strip_time(engine.analyze(spec).to_dict())
    store = tmp_path / "snapshots"
    res = _row(spec, store)
    assert res.snapshot == "stored", res.detail
    snap = calibrate.SnapshotStore(store).current(spec)
    assert snap.meta["commit"] == _SHA
    with zipfile.ZipFile(snap.folder / "tree.zip") as zf:
        names = set(zf.namelist())
    assert {".git/", ".git/config", "sub/.git/", "empty/", "node_modules/dep/index.js"} <= names
    assert not {n for n in names if n.startswith((".git/objects", ".git/HEAD", "sub/.git/c"))}
    unpacked = tmp_path / "unpacked"
    unpacked.mkdir()
    ctx = calibrate.SnapshotStore(store).open(snap, unpacked)
    assert _strip_time(calibrate._analyze_context(ctx, None).to_dict()) == live


def test_a_checkout_of_another_commit_is_scanned_but_not_stored(tmp_path, monkeypatch):
    spec = "https://github.com/acme/widgets"
    root = _package(tmp_path / "clone" / "repo")
    _write(root / ".git" / "HEAD", _SHA2 + "\n")  # pushed between ls-remote and the clone
    Upstream(monkeypatch, {spec: lambda: _context(root, spec, ctype="repository")},
             {spec: f"git:https://github.com/acme/widgets.git@{_SHA}"})
    res = _row(spec, tmp_path / "snapshots")
    assert res.status == "ok" and res.snapshot is None
    assert f"checked out {_SHA2}, ls-remote named {_SHA}" in res.detail
    assert calibrate.SnapshotStore(tmp_path / "snapshots").current(spec) is None


def test_a_registry_fetch_of_another_version_is_not_stored(tmp_path, monkeypatch):
    spec = "npm:widget"
    root = _package(tmp_path / "fetched" / "package", version="1.0.1")
    Upstream(monkeypatch, {spec: lambda: _context(root, spec, version="1.0.1")},
             {spec: "npm:widget@1.0.0#sha512-abc"})
    res = _row(spec, tmp_path / "snapshots")
    assert res.status == "ok" and res.snapshot is None
    assert "fetched 1.0.1, the registry named 1.0.0" in res.detail


def test_a_tree_holding_a_link_is_not_stored(tmp_path, monkeypatch):
    spec = "npm:widget"
    root = _package(tmp_path / "fetched" / "package")
    Upstream(monkeypatch, {spec: lambda: _context(root, spec)}, {spec: "npm:widget@1.0.0#x"})
    real = calibrate.is_link
    monkeypatch.setattr(calibrate, "is_link", lambda p: p.name == "util.js" or real(p))
    res = _row(spec, tmp_path / "snapshots")
    assert res.status == "ok" and res.snapshot is None
    assert "a link: lib/util.js" in res.detail
    assert calibrate.SnapshotStore(tmp_path / "snapshots").size_report()["snapshots"] == 0


def test_without_refresh_a_stored_copy_needs_no_lookup(tmp_path, monkeypatch):
    spec = "npm:widget"
    root = _package(tmp_path / "fetched" / "package")
    up = Upstream(monkeypatch, {spec: lambda: _context(root, spec)}, {spec: "npm:widget@1.0.0#x"})
    store = tmp_path / "snapshots"
    _row(spec, store)

    def no_lookup(spec):
        raise AssertionError("looked up an identity for a frozen row")

    monkeypatch.setattr(calibrate, "component_identity", no_lookup)
    up.identities[spec] = "npm:widget@2.0.0#y"  # upstream moved on: a frozen sweep does not care
    res = _row(spec, store)
    assert res.snapshot == "read" and res.identity == "npm:widget@1.0.0#x"
    assert up.fetches == [spec]


def test_a_refresh_fetches_what_changed_and_names_what_it_replaced(tmp_path, monkeypatch):
    spec, same = "npm:widget", "npm:steady"
    v1 = _package(tmp_path / "v1" / "package", payload="x = 1\n")
    v2 = _package(tmp_path / "v2" / "package", version="2.0.0")
    steady = _package(tmp_path / "steady" / "package", payload="y = 2\n")
    up = Upstream(monkeypatch,
                  {spec: lambda: _context(v1, spec), same: lambda: _context(steady, same)},
                  {spec: "npm:widget@1.0.0#a", same: "npm:steady@1.0.0#s"})
    store = tmp_path / "snapshots"
    assert _row(spec, store).passed is True
    _row(same, store)
    old = calibrate.SnapshotStore(store).current(spec)

    up.contexts[spec] = lambda: _context(v2, spec, version="2.0.0")
    up.identities[spec] = "npm:widget@2.0.0#b"
    fetched_before = len(up.fetches)
    changed = _row(spec, store, refresh=True)
    assert changed.snapshot == "stored" and changed.snapshot_previous == "npm:widget@1.0.0#a"
    assert changed.identity == "npm:widget@2.0.0#b" and changed.passed is False
    unchanged = _row(same, store, refresh=True)
    assert unchanged.snapshot == "read" and unchanged.snapshot_previous is None
    assert up.fetches[fetched_before:] == [spec]  # only the package that changed was downloaded

    # The replaced copy is unreferenced until a refresh run prunes it.
    sizes = calibrate.SnapshotStore(store).size_report()
    assert sizes == {"snapshots": 3, "sources": 2, "bytes": sizes["bytes"], "unreferenced": 1}
    assert sizes["bytes"] > 0
    assert calibrate.SnapshotStore(store).prune() == 1
    assert not old.folder.exists()
    assert calibrate.SnapshotStore(store).current(spec).identity == "npm:widget@2.0.0#b"


def test_a_failed_refresh_lookup_scans_the_stored_copy(tmp_path, monkeypatch):
    spec = "npm:widget"
    root = _package(tmp_path / "fetched" / "package")
    up = Upstream(monkeypatch, {spec: lambda: _context(root, spec)}, {spec: "npm:widget@1.0.0#x"})
    store = tmp_path / "snapshots"
    _row(spec, store)
    up.identities[spec] = None
    res = _row(spec, store, refresh=True)
    assert res.snapshot == "read" and "identity lookup failed" in res.detail
    assert up.fetches == [spec]


def test_a_damaged_copy_is_fetched_and_stored_again(tmp_path, monkeypatch):
    spec = "npm:widget"
    root = _package(tmp_path / "fetched" / "package")
    up = Upstream(monkeypatch, {spec: lambda: _context(root, spec)}, {spec: "npm:widget@1.0.0#x"})
    store = tmp_path / "snapshots"
    _row(spec, store)
    snap = calibrate.SnapshotStore(store).current(spec)
    (snap.folder / "tree.zip").write_bytes(b"PK\x03\x04 not what was stored")
    assert calibrate.SnapshotStore(store).current(spec) is None
    res = _row(spec, store)
    assert res.snapshot == "stored" and up.fetches == [spec, spec]
    assert calibrate.SnapshotStore(store).current(spec) is not None


def test_whole_row_cache_under_snapshots_keys_on_the_stored_bytes(tmp_path, monkeypatch):
    spec = "npm:widget"
    root = _package(tmp_path / "fetched" / "package")
    Upstream(monkeypatch, {spec: lambda: _context(root, spec)}, {spec: "npm:widget@1.0.0#x"})
    store, cache = tmp_path / "snapshots", tmp_path / "cache"
    first = _row(spec, store, cache_dir=cache, engine_key="k1")
    assert first.cached is False and first.index_digest
    again = _row(spec, store, cache_dir=cache, engine_key="k1")
    assert again.cached is True and again.snapshot == "read"
    assert again.index_digest == first.index_digest and again.identity == first.identity
    # A new engine misses the whole-row cache, and its scanners replay on the same files.
    third = _row(spec, store, cache_dir=cache, engine_key="k2")
    assert third.cached is False and third.index_digest == first.index_digest
    assert third.scanner_replays > 0 or third.scanner_audited


def test_archive_members_cannot_leave_the_folder():
    for bad in ("../x", "/abs", "a/../../b", "c:/x", "a\\b", "", "a//b"):
        with pytest.raises(calibrate.SnapshotUnusable):
            calibrate._member_parts(bad)
    assert calibrate._member_parts("a/b/") == ["a", "b"]


def test_local_rows_and_fixtures_never_use_the_store(tmp_path):
    local = _package(tmp_path / "local")
    res = calibrate.run_row("benign-baseline", str(local), "", snapshot_dir=tmp_path / "s")
    assert res.status == "ok" and res.snapshot is None
    assert not (tmp_path / "s").exists()
    assert calibrate._snapshot_kind("fixture:npm-trapdoor-stealer") is False
