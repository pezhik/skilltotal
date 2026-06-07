"""Scoring engine, including the filesystem+network combination rule."""

from __future__ import annotations

from skilltotal.models import (
    Capability,
    Evidence,
    Finding,
    Severity,
)
from skilltotal.scoring import (
    SCORE_CAP,
    combined_fs_network_finding,
    compute_score,
    risk_level,
)


def _ev(file="a.py", line=1):
    return Evidence(file=file, line_start=line, line_end=line, snippet="x")


def _finding(sev: Severity, fid="F") -> Finding:
    return Finding(
        id=fid, severity=sev, category="c", title="t", description="d",
        evidence=[_ev()], recommendation="r",
    )


def test_score_sums_weights():
    findings = [_finding(Severity.HIGH, "a"), _finding(Severity.MEDIUM, "b")]
    assert compute_score(findings) == 30  # 20 + 10


def test_score_capped_at_100():
    findings = [_finding(Severity.CRITICAL, f"c{i}") for i in range(10)]
    assert compute_score(findings) == SCORE_CAP


def test_empty_is_zero_low():
    assert compute_score([]) == 0
    assert risk_level(0).value == "low"


def test_combo_rule_fires_when_fs_and_network_present():
    caps = {
        Capability.FILESYSTEM_READ: [_ev("r.py", 1)],
        Capability.NETWORK_EGRESS: [_ev("n.py", 2)],
    }
    combo = combined_fs_network_finding(caps)
    assert combo is not None
    assert combo.severity is Severity.CRITICAL
    assert combo.evidence  # invariant preserved
    files = {e.file for e in combo.evidence}
    assert {"r.py", "n.py"} <= files


def test_combo_rule_absent_without_network():
    caps = {Capability.FILESYSTEM_READ: [_ev()]}
    assert combined_fs_network_finding(caps) is None


def test_combo_rule_absent_without_filesystem():
    caps = {Capability.NETWORK_EGRESS: [_ev()]}
    assert combined_fs_network_finding(caps) is None


def test_combo_evidence_deduplicated():
    dup = _ev("same.py", 5)
    caps = {
        Capability.FILESYSTEM_READ: [dup, dup, dup],
        Capability.NETWORK_EGRESS: [_ev("n.py", 9)],
    }
    combo = combined_fs_network_finding(caps)
    fs_evidence = [e for e in combo.evidence if e.file == "same.py"]
    assert len(fs_evidence) == 1
