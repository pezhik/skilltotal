"""Unit tests for the calibration harness (offline: local-directory sources only)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_CAL = Path(__file__).parent / "manual_eval" / "calibrate.py"
_spec_mod = importlib.util.spec_from_file_location("calibrate", _CAL)
calibrate = importlib.util.module_from_spec(_spec_mod)
# Register before exec so @dataclass (with `from __future__ annotations`) can resolve
# field types via sys.modules during class creation.
sys.modules["calibrate"] = calibrate
_spec_mod.loader.exec_module(calibrate)


def test_spec_folds_version_pin():
    assert calibrate._spec("npm:x", "1.2.3") == "npm:x@1.2.3"
    assert calibrate._spec("pypi:y", "2.0.0") == "pypi:y==2.0.0"
    assert calibrate._spec("npm:x", "") == "npm:x"


def test_judge_rules():
    # benign: malicious indicator = fail; powerful-but-clean = pass.
    assert calibrate._judge("benign-baseline", False, "critical", 2, 8) is True
    assert calibrate._judge("benign-baseline", True, "low", 0, 0) is False
    # malicious/compromised: malicious OR elevated risk = detected.
    assert calibrate._judge("malicious", False, "high", 0, 1) is True
    assert calibrate._judge("compromised-version", False, "low", 0, 0) is False
    # lab: a risky construct is enough.
    assert calibrate._judge("vulnerable-lab", False, "medium", 1, 0) is True


def test_judge_expected_result_overrides_class():
    # An explicit gold label is authoritative over the row's class.
    # "allow" => pass only if not called malicious (even if class says malicious).
    assert calibrate._judge("malicious", False, "high", 0, 1, expected="allow") is True
    assert calibrate._judge("malicious", True, "low", 0, 0, expected="allow") is False
    # "detect" => pass only if flagged (even if class says benign-baseline).
    assert calibrate._judge("benign-baseline", True, "low", 0, 0, expected="detect") is True
    assert calibrate._judge("benign-baseline", False, "low", 0, 0, expected="detect") is False
    # "detect" on a lab keeps the softer rule (a risky construct is enough).
    assert calibrate._judge("vulnerable-lab", False, "medium", 1, 0, expected="detect") is True


def test_calibrate_fixture_source(tmp_path):
    # ``fixture:<name>`` resolves to the in-repo malicious corpus and is scanned offline,
    # giving the dataset a deterministic detection floor that never gets taken down.
    csv_path = tmp_path / "ds.csv"
    csv_path.write_text(
        "class,ecosystem,source,version,notes,expected_result\n"
        "malicious,fixture,fixture:npm-trapdoor-stealer,,known stealer,detect\n",
        encoding="utf-8",
    )
    results, summary = calibrate.calibrate(csv_path)
    assert summary["scanned"] == 1 and summary["skipped"] == 0
    row = results[0]
    assert row.status == "ok" and row.passed is True


def test_calibrate_unknown_fixture_is_skipped(tmp_path):
    csv_path = tmp_path / "ds.csv"
    csv_path.write_text(
        "class,ecosystem,source,version,notes\n"
        "malicious,fixture,fixture:does-not-exist,,typo\n",
        encoding="utf-8",
    )
    results, summary = calibrate.calibrate(csv_path)
    assert summary["skipped"] == 1
    assert results[0].status == "skipped"


def _write(dir_: Path, name: str, content: str) -> None:
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / name).write_text(content, encoding="utf-8")


def test_calibrate_offline_local_dirs(tmp_path):
    benign = tmp_path / "benign"
    _write(benign, "ok.py", "def add(a, b):\n    return a + b\n")
    evil = tmp_path / "evil"
    _write(evil, "x.py", "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n")

    csv_path = tmp_path / "ds.csv"
    csv_path.write_text(
        "class,ecosystem,source,version,notes\n"
        f"benign-baseline,local,{benign},,clean\n"
        f"malicious,local,{evil},,decode-exec\n"
        "malicious,npm,,,no source -> skipped\n",
        encoding="utf-8",
    )

    results, summary = calibrate.calibrate(csv_path)
    assert summary["scanned"] == 2 and summary["skipped"] == 1
    assert summary["benign_false_positives"] == 0
    assert summary["detect_detected"] == 1  # the evil dir is flagged malicious

    b = next(r for r in results if r.cls == "benign-baseline" and r.status == "ok")
    assert b.passed is True and b.has_malicious is False
    e = next(r for r in results if r.cls == "malicious" and r.status == "ok")
    assert e.passed is True and e.has_malicious is True
    assert any(r.status == "skipped" for r in results)


_DECODE_EXEC = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"


def test_golden_forbidden_finding_that_fires_is_a_mismatch(tmp_path):
    # A forbidden rule that DOES fire = a false positive the verdict-level metric can miss.
    evil = tmp_path / "evil"
    _write(evil, "x.py", _DECODE_EXEC)
    r = calibrate.run_row(
        "malicious", str(evil), "", forbid_findings=["ST-OBF-DECODE-EXEC"]
    )
    assert r.status == "ok" and r.finding_ids  # golden computed
    assert "ST-OBF-DECODE-EXEC" in r.finding_ids  # sanity: this sample really fires it
    assert r.findings_ok is False
    assert r.unexpected_findings == ["ST-OBF-DECODE-EXEC"]


def test_golden_expected_finding_present_passes(tmp_path):
    evil = tmp_path / "evil"
    _write(evil, "x.py", _DECODE_EXEC)
    r = calibrate.run_row(
        "malicious", str(evil), "", expect_findings=["ST-OBF-DECODE-EXEC"]
    )
    assert r.findings_ok is True and not r.missing_findings


def test_golden_expected_finding_absent_is_recall_gap(tmp_path):
    benign = tmp_path / "b"
    _write(benign, "ok.py", "def add(a, b):\n    return a + b\n")
    r = calibrate.run_row(
        "benign-baseline", str(benign), "", expect_findings=["ST-OBF-DECODE-EXEC"]
    )
    assert r.findings_ok is False
    assert r.missing_findings == ["ST-OBF-DECODE-EXEC"]


def test_golden_no_labels_leaves_findings_ok_none(tmp_path):
    # Rows without golden labels never participate in the finding-mismatch metric.
    benign = tmp_path / "b"
    _write(benign, "ok.py", "x = 1\n")
    r = calibrate.run_row("benign-baseline", str(benign), "")
    assert r.findings_ok is None and r.finding_ids is None


def test_golden_summary_counts_mismatches_via_csv(tmp_path):
    evil = tmp_path / "evil"
    _write(evil, "x.py", _DECODE_EXEC)
    clean = tmp_path / "clean"
    _write(clean, "ok.py", "y = 2\n")
    csv_path = tmp_path / "ds.csv"
    csv_path.write_text(
        "class,source,version,expected_result,forbidden_findings,expected_findings\n"
        # golden FP row: forbid a rule that fires -> 1 mismatch
        f"benign-baseline,{evil},,allow,ST-OBF-DECODE-EXEC,\n"
        # golden clean row: forbid a rule that is absent -> ok
        f"benign-baseline,{clean},,allow,ST-COMBO-EXFIL,\n"
        # non-golden row: no labels -> not counted
        f"benign-baseline,{clean},,allow,,\n",
        encoding="utf-8",
    )
    results, summary = calibrate.calibrate(csv_path)
    assert summary["golden_scanned"] == 2
    assert summary["finding_mismatches"] == 1
    md = calibrate.to_markdown(results, summary)
    assert "Per-finding golden mismatches" in md


def test_combo_on_benign_tripwire_signal(tmp_path):
    # A benign-baseline package that trips a forbidden exfil combo is the high-precision tripwire
    # signal — counted even though the decode-exec dir is not "malicious verdict" per se.
    evil = tmp_path / "evil"
    _write(evil, "x.py", _DECODE_EXEC)
    csv_path = tmp_path / "ds.csv"
    csv_path.write_text(
        "class,source,version,expected_result,forbidden_findings,expected_findings\n"
        f"benign-baseline,{evil},,allow,ST-OBF-DECODE-EXEC,\n",
        encoding="utf-8",
    )
    results, summary = calibrate.calibrate(csv_path)
    assert summary["combo_on_benign"] == 1
    md = calibrate.to_markdown(results, summary)
    assert "combo-on-benign (tripwire)" in md


def test_combo_on_benign_zero_when_clean(tmp_path):
    clean = tmp_path / "clean"
    _write(clean, "ok.py", "y = 2\n")
    csv_path = tmp_path / "ds.csv"
    csv_path.write_text(
        "class,source,version,expected_result,forbidden_findings,expected_findings\n"
        f"benign-baseline,{clean},,allow,ST-COMBO-EXFIL,\n",
        encoding="utf-8",
    )
    _, summary = calibrate.calibrate(csv_path)
    assert summary["combo_on_benign"] == 0


def test_markdown_renders(tmp_path):
    csv_path = tmp_path / "ds.csv"
    benign = tmp_path / "b"
    _write(benign, "ok.py", "x = 1\n")
    csv_path.write_text(
        "class,ecosystem,source,version,notes\n"
        f"benign-baseline,local,{benign},,clean\n",
        encoding="utf-8",
    )
    results, summary = calibrate.calibrate(csv_path)
    md = calibrate.to_markdown(results, summary)
    assert "# SkillTotal calibration report" in md
    assert "benign false positives" in md
