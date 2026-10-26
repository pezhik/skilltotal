"""Baseline suppression behavior."""

from __future__ import annotations

import json
from pathlib import Path

from skilltotal.baseline import (
    apply_suppressions,
    build_baseline,
    finding_fingerprints,
    fingerprint,
    load_baseline,
)
from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.models import Evidence, Finding, Severity

FIXTURES = Path(__file__).parent / "fixtures"


def _finding(snippet="open()", file="a.py", line=1) -> Finding:
    return Finding(
        id="ST-X", severity=Severity.HIGH, category="c", title="t", description="d",
        evidence=[Evidence(file=file, line_start=line, line_end=line, snippet=snippet)],
        recommendation="r",
    )


def test_fingerprint_is_line_independent():
    e1 = Evidence(file="a.py", line_start=10, line_end=10, snippet="os.system(x)")
    e2 = Evidence(file="a.py", line_start=99, line_end=99, snippet="os.system(x)")
    assert fingerprint("ST-SHELL-PY", e1) == fingerprint("ST-SHELL-PY", e2)


def test_fingerprint_differs_by_rule_and_snippet():
    e = Evidence(file="a.py", line_start=1, line_end=1, snippet="x")
    assert fingerprint("A", e) != fingerprint("B", e)


def test_apply_suppressions_drops_finding_and_counts():
    f = _finding()
    fp = finding_fingerprints(f)[0]
    kept, removed = apply_suppressions([f], {fp})
    assert kept == []
    assert removed == 1


def test_apply_suppressions_keeps_unmatched():
    f = _finding()
    kept, removed = apply_suppressions([f], {"deadbeef"})
    assert len(kept) == 1
    assert removed == 0


def test_partial_suppression_keeps_finding_with_remaining_evidence():
    f = Finding(
        id="ST-X", severity=Severity.HIGH, category="c", title="t", description="d",
        evidence=[
            Evidence(file="a.py", line_start=1, line_end=1, snippet="one"),
            Evidence(file="a.py", line_start=2, line_end=2, snippet="two"),
        ],
        recommendation="r",
    )
    fp_one = fingerprint("ST-X", f.evidence[0])
    kept, removed = apply_suppressions([f], {fp_one})
    assert removed == 1
    assert len(kept) == 1
    assert len(kept[0].evidence) == 1
    assert kept[0].evidence[0].snippet == "two"


def test_baseline_roundtrip(tmp_path: Path):
    f = _finding()
    doc = build_baseline([f])
    path = tmp_path / "bl.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    loaded = load_baseline(path)
    assert loaded == set(finding_fingerprints(f))


def test_load_baseline_accepts_plain_list(tmp_path: Path):
    path = tmp_path / "bl.json"
    path.write_text('["aaa", "bbb"]', encoding="utf-8")
    assert load_baseline(path) == {"aaa", "bbb"}


def test_end_to_end_suppression_zeroes_score():
    root = FIXTURES / "malicious_npm_pkg"
    component = detect_component(root, source=str(root))
    full = analyze_directory(root, component)
    assert full.findings  # sanity

    fps = {fp for f in full.findings for fp in finding_fingerprints(f)}
    suppressed = analyze_directory(root, component, suppress=fps)

    # Every fingerprint is suppressed, synthesized findings included: no evidence survives for a
    # combination to re-derive from, so nothing is left to score.
    assert full.risk_score > 0
    assert suppressed.risk_score == 0
    assert suppressed.findings == []
    assert suppressed.metadata["suppressed_count"] > 0
    assert suppressed.metadata["baseline_suppressed_count"] == (
        suppressed.metadata["suppressed_count"])
    assert "baseline_suppressed_count" not in full.metadata  # only when a baseline was given


# --- What a baseline hides is said (audit 2026-10-15) ---------------------------------------------

_DROPPER = 'eval(Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString());\n'


def test_writing_a_baseline_that_accepts_a_malicious_indicator_warns(tmp_path: Path, capsys):
    from skilltotal.cli import main

    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "index.js").write_text(_DROPPER, encoding="utf-8")
    code = main(["scan", str(tmp_path / "pkg"), "--write-baseline", str(tmp_path / "bl.json"),
                 "--no-config"])
    err = capsys.readouterr().err
    assert code == 0
    assert "warning: the baseline accepts malicious indicator(s): ST-OBF-DECODE-EXEC" in err

    (tmp_path / "pkg" / "index.js").write_text("console.log(1);\n", encoding="utf-8")
    main(["scan", str(tmp_path / "pkg"), "--write-baseline", str(tmp_path / "bl2.json"),
          "--no-config"])
    assert "warning" not in capsys.readouterr().err


def test_the_text_report_says_what_the_baseline_suppressed(tmp_path: Path, capsys):
    from skilltotal.cli import main

    root = str(FIXTURES / "malicious_npm_pkg")
    baseline = tmp_path / "bl.json"
    main(["scan", root, "--write-baseline", str(baseline), "--no-config"])
    capsys.readouterr()
    main(["scan", root, "--baseline", str(baseline), "--no-config"])
    out = capsys.readouterr().out
    header = out.split("\n\n", 1)[0]  # next to the verdict, not under the findings
    assert "Verdict   :" in header
    assert f"suppressed by baseline {baseline}" in header
    assert "Baseline  : " in header


def test_a_baseline_from_the_config_is_named_on_the_config_line(tmp_path: Path, capsys):
    from skilltotal.cli import main

    root = str(FIXTURES / "malicious_npm_pkg")
    main(["scan", root, "--write-baseline", str(tmp_path / "bl.json"), "--no-config"])
    config = tmp_path / ".skilltotal.toml"
    config.write_text('baseline = "bl.json"\n', encoding="utf-8")
    capsys.readouterr()
    main(["scan", root, "--config", str(config)])
    out = capsys.readouterr().out
    config_line = next(line for line in out.splitlines() if line.startswith("Config    :"))
    assert "baseline = bl.json" in config_line
    assert f"suppressed by baseline {tmp_path / 'bl.json'}" in out


# --- A baseline that hides a malicious indicator says so at scan time (2026-10-26) ----------------


def _scan_with_baseline(tmp_path: Path, code: str, *extra: str) -> tuple[int, str, str]:
    """Write a package, baseline it, then scan it against that baseline (text report)."""
    import io
    from contextlib import redirect_stderr, redirect_stdout

    from skilltotal.cli import main

    pkg = tmp_path / "pkg"
    pkg.mkdir(exist_ok=True)
    (pkg / "index.js").write_text(code, encoding="utf-8")
    baseline = tmp_path / "bl.json"
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        main(["scan", str(pkg), "--write-baseline", str(baseline), "--no-config"])
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code_ = main(["scan", str(pkg), "--baseline", str(baseline), "--no-config", *extra])
    return code_, out.getvalue(), err.getvalue()


def test_a_baseline_hiding_a_malicious_indicator_is_named_on_the_baseline_line(tmp_path: Path):
    code, out, err = _scan_with_baseline(tmp_path, _DROPPER, "--fail-on-high")
    assert code == 0  # the gate no longer sees it: that is exactly why the report must say so
    baseline_line = next(line for line in out.splitlines() if line.startswith("Baseline  :"))
    assert "among them malicious indicator(s) ST-OBF-DECODE-EXEC" in baseline_line
    assert "hides malicious indicator(s) ST-OBF-DECODE-EXEC" in err
    assert "the verdict and the gate do not see them" in err


def test_the_warning_reaches_a_ci_log_with_json_output(tmp_path: Path):
    import json

    code, out, err = _scan_with_baseline(tmp_path, _DROPPER, "--json")
    assert code == 0
    report = json.loads(out)
    assert report["metadata"]["baseline_suppressed_malicious"] == ["ST-OBF-DECODE-EXEC"]
    assert "warning: baseline" in err and "ST-OBF-DECODE-EXEC" in err


def test_a_baseline_of_accepted_noise_adds_no_warning(tmp_path: Path):
    # A risky construct, not a malicious indicator: child_process.exec of a fixed command.
    code, out, err = _scan_with_baseline(
        tmp_path, 'require("child_process").exec("ls -la");\n', "--json"
    )
    import json

    report = json.loads(out)
    assert report["metadata"]["baseline_suppressed_count"] > 0
    assert "baseline_suppressed_malicious" not in report["metadata"]
    assert "warning" not in err
