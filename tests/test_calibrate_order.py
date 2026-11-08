"""Calibration harness: --order changed-first, --fail-fast, and the per-row diagnostics."""

from __future__ import annotations

import importlib.util
import json
import subprocess  # nosec B404 - the harness itself, fixed argv
import sys
from pathlib import Path

from skilltotal.scan_cache import code_digest
from skilltotal.scanners import SCANNERS

_CAL = Path(__file__).parent / "manual_eval" / "calibrate.py"
_spec_mod = importlib.util.spec_from_file_location("calibrate_order_under_test", _CAL)
calibrate = importlib.util.module_from_spec(_spec_mod)
sys.modules["calibrate_order_under_test"] = calibrate
_spec_mod.loader.exec_module(calibrate)

_DECODE_EXEC = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"


def _write(dir_: Path, name: str, content: str) -> Path:
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / name).write_text(content, encoding="utf-8")
    return dir_


def _dataset(tmp_path: Path, rows: list[tuple[str, Path]]) -> Path:
    csv_path = tmp_path / "ds.csv"
    csv_path.write_text(
        "class,ecosystem,source,version,notes\n"
        + "".join(f"{cls},local,{path},,row\n" for cls, path in rows),
        encoding="utf-8",
    )
    return csv_path


def _report(tmp_path: Path, rows: list[dict]) -> Path:
    path = tmp_path / f"prev-{len(list(tmp_path.glob('prev-*')))}.json"
    path.write_text(json.dumps({"results": rows}), encoding="utf-8")
    return path


def test_changed_first_puts_rows_with_a_changed_rule_first_then_small_to_large():
    specs = ["npm:big", "npm:small", "npm:mid", "npm:new", "npm:hit-big", "npm:hit-small"]
    seconds = {"npm:big": 900.0, "npm:small": 1.0, "npm:mid": 30.0,
               "npm:hit-big": 400.0, "npm:hit-small": 2.0}
    findings = {"npm:hit-big": ["ST-CHANGED"], "npm:hit-small": ["ST-OLD", "ST-CHANGED"],
                "npm:big": ["ST-OLD"]}
    order = calibrate.changed_first(specs, seconds, findings, {"ST-CHANGED"})
    assert [specs[i] for i in order] == [
        "npm:hit-small", "npm:hit-big",               # a changed rule fired there before
        "npm:new", "npm:small", "npm:mid", "npm:big",  # the rest: new rows, then small to large
    ]
    assert sorted(order) == list(range(len(specs)))
    # Nothing changed: small to large, the largest last.
    order = calibrate.changed_first(specs, seconds, findings, set())
    assert [specs[i] for i in order][-1] == "npm:big"


def test_previous_findings_come_from_the_newest_report_that_has_them(tmp_path):
    newest = _report(tmp_path, [{"source": "npm:a", "finding_ids": ["ST-X"]},
                                {"source": "npm:b", "finding_ids": None}])
    older = _report(tmp_path, [{"source": "npm:a", "finding_ids": ["ST-OLD"]},
                               {"source": "npm:b", "finding_ids": ["ST-Y"]},
                               {"source": "npm:c", "finding_ids": "not a list"}])
    found = calibrate.previous_findings([newest, older, tmp_path / "missing.json"])
    assert found == {"npm:a": ["ST-X"], "npm:b": ["ST-Y"]}


def test_a_scanner_with_no_folder_for_its_current_code_counts_as_changed(tmp_path):
    every = {r.id for s in SCANNERS for r in s.rules}
    assert calibrate.changed_scanner_rules(None) == every
    cache = tmp_path / "cache"
    for scanner in SCANNERS:
        (cache / calibrate.SCANNER_CACHE / scanner.name / code_digest(scanner)).mkdir(parents=True)
    assert calibrate.changed_scanner_rules(cache) == set()
    obf = next(s for s in SCANNERS if s.name == "obfuscation")
    (cache / calibrate.SCANNER_CACHE / obf.name / code_digest(obf)).rmdir()
    (cache / calibrate.SCANNER_CACHE / obf.name / "an-older-code-digest").mkdir()
    changed = calibrate.changed_scanner_rules(cache)
    assert "ST-OBF-DECODE-EXEC" in changed and changed == {r.id for r in obf.rules}


def test_fail_fast_stops_at_the_first_failure_and_says_the_report_is_partial(tmp_path):
    ok1 = _write(tmp_path / "ok1", "ok.py", "x = 1\n")
    evil = _write(tmp_path / "evil", "x.py", _DECODE_EXEC)
    ok2 = _write(tmp_path / "ok2", "ok.py", "y = 2\n")
    csv_path = _dataset(tmp_path, [("benign-baseline", ok1), ("benign-baseline", evil),
                                   ("benign-baseline", ok2)])
    results, summary = calibrate.calibrate(csv_path, fail_fast=True)
    assert [r.status for r in results] == ["ok", "ok", calibrate.NOT_RUN]
    assert results[1].passed is False
    assert "stopped the run at the failure on" in results[2].detail
    assert summary["stopped_early"] is True and summary["stopped_on"] == str(evil)
    assert summary["not_run"] == 1 and summary["scanned"] == 2
    md = calibrate.to_markdown(results, summary)
    assert "**Stopped early**" in md and "1 row(s) not run" in md
    # Without the flag every row runs, and the report says nothing about stopping.
    results, summary = calibrate.calibrate(csv_path)
    assert [r.status for r in results] == ["ok", "ok", "ok"]
    assert summary["stopped_early"] is False and summary["not_run"] == 0
    assert "Stopped early" not in calibrate.to_markdown(results, summary)


def test_a_failure_that_rests_on_a_stored_result_is_rescanned_before_it_stops_the_run(
        tmp_path, monkeypatch):
    benign = _write(tmp_path / "benign", "ok.py", "x = 1\n")
    other = _write(tmp_path / "other", "ok.py", "y = 2\n")
    evil = _write(tmp_path / "evil", "x.py", _DECODE_EXEC)
    cache = tmp_path / "cache"
    monkeypatch.setattr(calibrate, "SCAN_CACHE_AUDIT", 0)
    calibrate.calibrate(_dataset(tmp_path, [("benign-baseline", evil)]), cache_dir=cache)
    calibrate.calibrate(_dataset(tmp_path, [("benign-baseline", benign)]), cache_dir=cache)
    # Plant the evil row's obfuscation result as the benign row's: its replay now says malicious.
    store = cache / calibrate.SCANNER_CACHE / "obfuscation"
    (entry_evil,) = [e for e in store.rglob("*.json")
                     if json.loads(e.read_text(encoding="utf-8"))["result"]["findings"]]
    (entry_benign,) = [e for e in store.rglob("*.json") if e != entry_evil]
    entry_benign.write_text(entry_evil.read_text(encoding="utf-8"), encoding="utf-8")
    csv_path = _dataset(tmp_path, [("benign-baseline", benign), ("benign-baseline", other)])
    trusting, _ = calibrate.calibrate(csv_path, cache_dir=cache)
    assert trusting[0].passed is False  # the planted replay is believed
    results, summary = calibrate.calibrate(csv_path, cache_dir=cache, fail_fast=True)
    assert summary["stopped_early"] is False
    assert [r.status for r in results] == ["ok", "ok"]
    assert results[0].passed is True and results[0].scanner_replays is None  # scanned in full


def test_rows_carry_the_index_digest_and_whether_the_audit_scanned_them(tmp_path, monkeypatch):
    a = _write(tmp_path / "a", "ok.py", "x = 1\n")
    csv_path = _dataset(tmp_path, [("benign-baseline", a)])
    cache = tmp_path / "cache"
    monkeypatch.setattr(calibrate, "SCAN_CACHE_AUDIT", 0)  # the salted pick follows the engine
    first, _ = calibrate.calibrate(csv_path, cache_dir=cache)
    again, summary = calibrate.calibrate(csv_path, cache_dir=cache)
    assert first[0].index_digest and first[0].index_digest == again[0].index_digest
    assert again[0].scanner_audited is False and again[0].scanner_replays > 0
    assert summary["scanner_audited"] == 0
    monkeypatch.setattr(calibrate, "SCAN_CACHE_AUDIT", 1)
    audited, summary = calibrate.calibrate(csv_path, cache_dir=cache)
    assert audited[0].scanner_audited is True and audited[0].scanner_replays == 0
    assert summary["scanner_audited"] == 1


def test_the_parallel_run_stops_too_and_writes_a_valid_partial_report(tmp_path):
    # The failing row first, then enough rows that the pool still holds some when it fails.
    evil = _write(tmp_path / "evil", "x.py", _DECODE_EXEC)
    oks = [_write(tmp_path / f"ok{n}", "ok.py", f"x = {n}\n" * 400) for n in range(29)]
    csv_path = _dataset(tmp_path, [("benign-baseline", evil)]
                        + [("benign-baseline", p) for p in oks])
    out = tmp_path / "partial"
    done = subprocess.run(  # nosec B603
        [sys.executable, str(_CAL), "--dataset", str(csv_path), "--out", str(out), "--jobs", "2",
         "--fail-fast", "--order", "changed-first"],
        capture_output=True, text=True, timeout=300, cwd=str(_CAL.parents[2]),
    )
    assert done.returncode == 0, done.stderr[-2000:]
    report = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))
    summary = report["summary"]
    assert summary["stopped_early"] is True and summary["stopped_on"] == str(evil)
    assert summary["not_run"] >= 1
    assert summary["rows_total"] == 30 == len(report["results"])
    statuses = [r["status"] for r in report["results"]]
    assert statuses[0] == "ok" and set(statuses) <= {"ok", "not_run"}
    assert "**Stopped early**" in out.with_suffix(".md").read_text(encoding="utf-8")
