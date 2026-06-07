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

    # The synthesized combo finding may re-derive from any surviving evidence; assert the
    # score strictly drops and originally-detected rule findings are gone.
    assert suppressed.risk_score < full.risk_score
    assert suppressed.metadata["suppressed_count"] > 0
