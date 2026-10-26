"""Calibration harness: the result cache, per-row timing and the longest-first row order."""

from __future__ import annotations

import importlib.util
import json
import subprocess  # nosec B404 - the harness itself, fixed argv
import sys
from pathlib import Path

_CAL = Path(__file__).parent / "manual_eval" / "calibrate.py"
_spec_mod = importlib.util.spec_from_file_location("calibrate_cache_under_test", _CAL)
calibrate = importlib.util.module_from_spec(_spec_mod)
sys.modules["calibrate_cache_under_test"] = calibrate
_spec_mod.loader.exec_module(calibrate)

_DECODE_EXEC = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
_SHA = "0123456789abcdef0123456789abcdef01234567"


def _write(dir_: Path, name: str, content: str) -> None:
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / name).write_text(content, encoding="utf-8")


def _two_row_dataset(tmp_path: Path) -> Path:
    a, b = tmp_path / "a", tmp_path / "b"
    _write(a, "ok.py", "x = 1\n")
    _write(b, "ok.py", "y = 2\n")
    csv_path = tmp_path / "ds.csv"
    csv_path.write_text(
        "class,ecosystem,source,version,notes\n"
        f"benign-baseline,local,{a},,one\n"
        f"benign-baseline,local,{b},,two\n",
        encoding="utf-8",
    )
    return csv_path


def test_each_scanned_row_is_timed(tmp_path):
    benign = tmp_path / "b"
    _write(benign, "ok.py", "x = 1\n")
    r = calibrate.run_row("benign-baseline", str(benign), "")
    assert r.seconds is not None and r.seconds >= 0
    assert r.fetch_seconds is not None and r.scan_seconds is not None
    assert 0 <= r.fetch_seconds <= r.seconds and 0 <= r.scan_seconds <= r.seconds
    assert abs(r.fetch_seconds + r.scan_seconds - r.seconds) <= 0.002  # three roundings
    assert r.cached is False
    assert calibrate.run_row("malicious", "", "").seconds is None


def test_engine_key_follows_the_engine_files_and_the_harness(tmp_path):
    pkg = tmp_path / "pkg"
    _write(pkg, "a.py", "A = 1\n")
    _write(pkg / "sub", "b.py", "B = 2\n")
    harness = tmp_path / "calibrate.py"
    harness.write_text("# v1\n", encoding="utf-8")
    key = calibrate.engine_key(pkg, harness)
    assert key == calibrate.engine_key(pkg, harness)
    _write(pkg / "sub", "b.py", "B = 3\n")  # a detection file changes -> a new key
    key2 = calibrate.engine_key(pkg, harness)
    assert key2 != key
    harness.write_text("# v2\n", encoding="utf-8")  # the harness changes -> a new key
    assert calibrate.engine_key(pkg, harness) not in (key, key2)
    _write(pkg / "__pycache__", "a.cpython-313.pyc", "bytes\n")  # bytecode is not the engine
    harness.write_text("# v1\n", encoding="utf-8")
    _write(pkg / "sub", "b.py", "B = 2\n")
    assert calibrate.engine_key(pkg, harness) == key


def test_identity_of_a_pinned_registry_version_needs_no_network(monkeypatch):
    def no_network(url):
        raise AssertionError(f"looked up {url}")

    monkeypatch.setattr(calibrate, "_registry_json", no_network)
    assert calibrate.component_identity("npm:left-pad@1.3.0") == "npm:left-pad@1.3.0"
    assert calibrate.component_identity("npm:@scope/pkg@2.0.0-rc.1") == "npm:@scope/pkg@2.0.0-rc.1"
    assert calibrate.component_identity("pypi:requests==2.32.3") == "pypi:requests==2.32.3"
    # Never cached: local paths and fixtures are cheap and have no registry identity.
    assert calibrate.component_identity("fixture:npm-trapdoor-stealer") is None
    assert calibrate.component_identity(str(Path("some") / "dir")) is None


def test_identity_of_an_unpinned_registry_package_is_the_version_it_resolves_to(monkeypatch):
    docs = {
        "https://registry.npmjs.org/is-number/latest": {
            "version": "7.0.0", "dist": {"integrity": "sha512-abc"}},
        "https://pypi.org/pypi/six/json": {
            "info": {"version": "1.17.0"},
            "urls": [{"digests": {"sha256": "f1"}}, {"digests": {"sha256": "e2"}}]},
    }
    monkeypatch.setattr(calibrate, "_registry_json", lambda url: docs[url])
    assert calibrate.component_identity("npm:is-number") == "npm:is-number@7.0.0#sha512-abc"
    pypi = calibrate.component_identity("pypi:six")
    assert pypi is not None and pypi.startswith("pypi:six==1.17.0#")
    # The file set is part of the identity: a changed digest is a different identity.
    docs["https://pypi.org/pypi/six/json"]["urls"][0]["digests"]["sha256"] = "f9"
    assert calibrate.component_identity("pypi:six") != pypi


def test_identity_lookup_failure_means_no_cache_not_an_error(monkeypatch):
    def boom(url):
        raise OSError("registry down")

    monkeypatch.setattr(calibrate, "_registry_json", boom)
    assert calibrate.component_identity("npm:is-number") is None


def test_identity_of_a_git_source_is_the_commit_ls_remote_reports(monkeypatch):
    calls = []

    class Done:
        returncode = 0
        stdout = f"{_SHA}\tHEAD\n"

    def fake_run(argv, **kwargs):
        calls.append(argv)
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
        return Done()

    monkeypatch.setattr(calibrate.subprocess, "run", fake_run)
    monkeypatch.setattr(calibrate, "find_program", lambda name: "/usr/bin/git")
    clone_url = calibrate.parse_git_url("https://github.com/acme/widgets")[0]
    ident = calibrate.component_identity("https://github.com/acme/widgets")
    assert ident == f"git:{clone_url}@{_SHA}"
    assert calls[-1][1:] == ["ls-remote", "--exit-code", clone_url, "HEAD"]
    # A branch and a subfolder are part of what is scanned, so part of the identity.
    ident = calibrate.component_identity("https://github.com/acme/widgets/tree/dev/skills/x")
    assert ident is not None and ident.endswith("/skills/x")
    assert calls[-1][-1] == "dev"
    # A commit in the URL needs no lookup at all.
    before = len(calls)
    ident = calibrate.component_identity(f"https://github.com/acme/widgets/commit/{_SHA}")
    assert ident == f"git:{clone_url}@{_SHA}" and len(calls) == before
    # An unreachable repository: no identity, the row is scanned (and skipped) as before.
    Done.returncode = 2
    assert calibrate.component_identity("https://github.com/acme/gone") is None


def _cache_run(tmp_path, monkeypatch, spec_dir: Path, key: str, **labels):
    monkeypatch.setattr(calibrate, "component_identity", lambda spec: f"test:{spec}")
    return calibrate.run_row("benign-baseline", str(spec_dir), "", cache_dir=tmp_path / "cache",
                             engine_key=key, **labels)


def _never_scan(monkeypatch):
    def no_scan(spec):
        raise AssertionError("scanned a cached row")

    monkeypatch.setattr(calibrate, "_analyze_spec", no_scan)


def test_a_cached_row_is_replayed_without_a_scan(tmp_path, monkeypatch):
    evil = tmp_path / "evil"
    _write(evil, "x.py", _DECODE_EXEC)
    first = _cache_run(tmp_path, monkeypatch, evil, "k1")
    assert first.cached is False and first.has_malicious is True
    _never_scan(monkeypatch)
    again = _cache_run(tmp_path, monkeypatch, evil, "k1")
    assert again.cached is True and again.seconds is None
    for field in calibrate._FACT_FIELDS:
        if field != "finding_ids":
            assert getattr(again, field) == getattr(first, field), field
    assert again.passed == first.passed


def test_a_different_engine_key_misses_the_cache(tmp_path, monkeypatch):
    evil = tmp_path / "evil"
    _write(evil, "x.py", _DECODE_EXEC)
    _cache_run(tmp_path, monkeypatch, evil, "k1")
    assert _cache_run(tmp_path, monkeypatch, evil, "k2").cached is False


def test_the_judgement_is_recomputed_from_cached_facts(tmp_path, monkeypatch):
    # Relabelling a row (new golden ids, a new expected_result) must not need a rescan.
    evil = tmp_path / "evil"
    _write(evil, "x.py", _DECODE_EXEC)
    _cache_run(tmp_path, monkeypatch, evil, "k1")
    _never_scan(monkeypatch)
    r = _cache_run(tmp_path, monkeypatch, evil, "k1", forbid_findings=["ST-OBF-DECODE-EXEC"])
    assert r.cached is True and r.findings_ok is False
    assert r.unexpected_findings == ["ST-OBF-DECODE-EXEC"]
    r = _cache_run(tmp_path, monkeypatch, evil, "k1", expected="detect")
    assert r.cached is True and r.passed is True


def test_a_damaged_or_foreign_cache_entry_is_ignored(tmp_path, monkeypatch):
    evil = tmp_path / "evil"
    _write(evil, "x.py", _DECODE_EXEC)
    _cache_run(tmp_path, monkeypatch, evil, "k1")
    entries = list((tmp_path / "cache" / "k1").glob("*.json"))
    assert len(entries) == 1
    data = json.loads(entries[0].read_text(encoding="utf-8"))
    assert data["identity"] == f"test:{evil}" and data["facts"]["has_malicious"] is True
    # Facts of the wrong shape (a string where a bool belongs) are not trusted.
    data["facts"]["has_malicious"] = "no"
    entries[0].write_text(json.dumps(data), encoding="utf-8")
    assert _cache_run(tmp_path, monkeypatch, evil, "k1").cached is False
    # Nor is an entry written for another identity.
    data["facts"]["has_malicious"] = False
    data["identity"] = "test:something-else"
    entries[0].write_text(json.dumps(data), encoding="utf-8")
    r = _cache_run(tmp_path, monkeypatch, evil, "k1")
    assert r.cached is False and r.has_malicious is True
    # Not valid JSON at all.
    entries[0].write_text("{", encoding="utf-8")
    assert _cache_run(tmp_path, monkeypatch, evil, "k1").cached is False


def test_calibrate_counts_replayed_rows(tmp_path, monkeypatch):
    csv_path = _two_row_dataset(tmp_path)
    monkeypatch.setattr(calibrate, "component_identity", lambda spec: f"test:{spec}")
    _, summary = calibrate.calibrate(csv_path, cache_dir=tmp_path / "cache")
    assert summary["cached"] == 0 and summary["scan_seconds"] >= 0
    results, summary = calibrate.calibrate(csv_path, cache_dir=tmp_path / "cache")
    assert summary["cached"] == 2 and all(r.cached for r in results)
    md = calibrate.to_markdown(results, summary)
    assert "replayed from the result cache: 2 / 2" in md


def test_rows_without_a_cache_dir_are_never_cached(tmp_path, monkeypatch):
    def no_identity(spec):
        raise AssertionError("resolved an identity without a cache")

    monkeypatch.setattr(calibrate, "component_identity", no_identity)
    results, _ = calibrate.calibrate(_two_row_dataset(tmp_path))
    assert not any(r.cached for r in results)


def test_previous_report_orders_the_slowest_rows_first(tmp_path):
    report = tmp_path / "prev.json"
    report.write_text(json.dumps({"results": [
        {"source": "npm:a", "seconds": 1.0},
        {"source": "npm:b", "seconds": 30.0},
        {"source": "npm:c", "seconds": 5.0},
        {"source": "npm:skipped", "seconds": None},
    ]}), encoding="utf-8")
    seconds = calibrate.previous_seconds([report])
    assert seconds == {"npm:a": 1.0, "npm:b": 30.0, "npm:c": 5.0}
    specs = ["npm:a", "npm:b", "npm:new", "npm:c", "npm:skipped"]
    assert calibrate.longest_first(specs, seconds) == [2, 4, 1, 3, 0]
    assert calibrate.previous_seconds([tmp_path / "missing.json"]) == {}
    assert calibrate.longest_first(specs, {}) == [0, 1, 2, 3, 4]
    # A run replayed from the cache times nothing; the report before it still knows the rows.
    replayed = tmp_path / "replayed.json"
    replayed.write_text(json.dumps({"results": [
        {"source": "npm:a", "seconds": None, "cached": True},
        {"source": "npm:b", "seconds": 2.0},
    ]}), encoding="utf-8")
    merged = calibrate.previous_seconds([replayed, report])
    assert merged == {"npm:a": 1.0, "npm:b": 2.0, "npm:c": 5.0}  # the newest report wins


def test_parallel_run_with_a_cache_and_a_previous_report_gives_the_same_report(tmp_path):
    benign = tmp_path / "benign"
    _write(benign, "ok.py", "def add(a, b):\n    return a + b\n")
    evil = tmp_path / "evil"
    _write(evil, "x.py", _DECODE_EXEC)
    csv_path = tmp_path / "ds.csv"
    csv_path.write_text(
        "class,ecosystem,source,version,notes\n"
        f"benign-baseline,local,{benign},,clean\n"
        f"malicious,local,{evil},,decode-exec\n"
        "malicious,fixture,fixture:npm-trapdoor-stealer,,known stealer\n",
        encoding="utf-8",
    )
    plain = tmp_path / "plain"
    first = subprocess.run(  # nosec B603
        [sys.executable, str(_CAL), "--dataset", str(csv_path), "--out", str(plain),
         "--jobs", "2"],
        capture_output=True, text=True, timeout=300, cwd=str(_CAL.parents[2]),
    )
    assert first.returncode == 0, first.stderr[-2000:]
    fast = tmp_path / "fast"
    second = subprocess.run(  # nosec B603
        [sys.executable, str(_CAL), "--dataset", str(csv_path), "--out", str(fast), "--jobs", "2",
         "--cache-dir", str(tmp_path / "cache"), "--previous", str(plain.with_suffix(".json"))],
        capture_output=True, text=True, timeout=300, cwd=str(_CAL.parents[2]),
    )
    assert second.returncode == 0, second.stderr[-2000:]
    a = json.loads(plain.with_suffix(".json").read_text(encoding="utf-8"))
    b = json.loads(fast.with_suffix(".json").read_text(encoding="utf-8"))
    strip = {"seconds", "fetch_seconds", "scan_seconds"}
    rows_a = [{k: v for k, v in r.items() if k not in strip} for r in a["results"]]
    rows_b = [{k: v for k, v in r.items() if k not in strip} for r in b["results"]]
    assert rows_a == rows_b
    assert b["summary"]["cached"] == 0  # local paths and fixtures have no identity to cache
