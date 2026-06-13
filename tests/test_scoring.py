"""Scoring engine: risk-bearing findings score, capabilities don't, exfil combo."""

from __future__ import annotations

from skilltotal.models import (
    Capability,
    Evidence,
    Finding,
    Severity,
    ThreatClass,
)
from skilltotal.scoring import (
    SCORE_CAP,
    compute_score,
    exfiltration_finding,
    risk_level,
)


def _ev(file="a.py", line=1, off=0):
    return Evidence(file=file, line_start=line, line_end=line, snippet="x", match_offset=off)


def _finding(sev: Severity, fid="F", tc: ThreatClass = ThreatClass.RISKY_CONSTRUCT) -> Finding:
    return Finding(
        id=fid, severity=sev, category="c", title="t", description="d",
        evidence=[_ev()], recommendation="r", threat_class=tc,
    )


def test_score_sums_risk_weights():
    findings = [_finding(Severity.HIGH, "a"), _finding(Severity.MEDIUM, "b")]
    assert compute_score(findings) == 30  # 20 + 10


def test_capabilities_do_not_score():
    # Capability findings are informational: even a "critical" capability adds nothing.
    findings = [
        _finding(Severity.CRITICAL, "a", ThreatClass.CAPABILITY),
        _finding(Severity.HIGH, "b", ThreatClass.CAPABILITY),
    ]
    assert compute_score(findings) == 0


def test_only_malicious_and_risky_contribute():
    findings = [
        _finding(Severity.HIGH, "m", ThreatClass.MALICIOUS_INDICATOR),
        _finding(Severity.CRITICAL, "cap", ThreatClass.CAPABILITY),
    ]
    assert compute_score(findings) == 20  # malicious high counts; capability critical does not


def test_score_capped_at_100():
    findings = [_finding(Severity.CRITICAL, f"c{i}") for i in range(10)]
    assert compute_score(findings) == SCORE_CAP


def test_empty_is_zero_low():
    assert compute_score([]) == 0
    assert risk_level(0).value == "low"


def test_exfil_combo_fires_on_sensitive_data_plus_network():
    sens = _finding(Severity.HIGH, "ST-SENS-PATH")
    caps = {Capability.NETWORK_EGRESS: [_ev("n.py", 2)]}
    combo = exfiltration_finding([sens], caps)
    assert combo is not None
    assert combo.severity is Severity.CRITICAL
    assert combo.threat_class is ThreatClass.RISKY_CONSTRUCT
    assert combo.evidence  # invariant preserved
    assert "n.py" in {e.file for e in combo.evidence}


def test_exfil_combo_absent_for_plain_filesystem_plus_network():
    # Plain filesystem access is a capability, not sensitive-data access: no exfil finding.
    fs = _finding(Severity.MEDIUM, "ST-FS-PY-READ", ThreatClass.CAPABILITY)
    caps = {Capability.NETWORK_EGRESS: [_ev()]}
    assert exfiltration_finding([fs], caps) is None


def test_exfil_combo_absent_without_network():
    sens = _finding(Severity.HIGH, "ST-SENS-PATH")
    assert exfiltration_finding([sens], {}) is None


def test_exfil_combo_evidence_deduplicated():
    dup = _ev("same.py", 5)
    sens = Finding(
        id="ST-SENS-PATH", severity=Severity.HIGH, category="c", title="t", description="d",
        evidence=[dup, dup, dup], recommendation="r",
    )
    caps = {Capability.NETWORK_EGRESS: [_ev("n.py", 9)]}
    combo = exfiltration_finding([sens], caps)
    assert len([e for e in combo.evidence if e.file == "same.py"]) == 1
