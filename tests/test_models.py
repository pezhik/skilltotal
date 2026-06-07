"""Model invariants and serialization."""

from __future__ import annotations

import pytest

from skilltotal.models import (
    Evidence,
    Finding,
    RiskLevel,
    Severity,
)


def _evidence() -> Evidence:
    return Evidence(file="a.py", line_start=1, line_end=1, snippet="open()")


def test_finding_requires_evidence():
    with pytest.raises(ValueError):
        Finding(
            id="X",
            severity=Severity.LOW,
            category="c",
            title="t",
            description="d",
            evidence=[],
            recommendation="r",
        )


def test_finding_with_evidence_ok():
    f = Finding(
        id="X",
        severity=Severity.HIGH,
        category="c",
        title="t",
        description="d",
        evidence=[_evidence()],
        recommendation="r",
    )
    assert f.to_dict()["evidence"][0]["line_start"] == 1


@pytest.mark.parametrize(
    "sev,weight",
    [
        (Severity.CRITICAL, 30),
        (Severity.HIGH, 20),
        (Severity.MEDIUM, 10),
        (Severity.LOW, 3),
    ],
)
def test_severity_weights(sev, weight):
    assert sev.weight == weight


@pytest.mark.parametrize(
    "score,level",
    [
        (0, RiskLevel.LOW),
        (24, RiskLevel.LOW),
        (25, RiskLevel.MEDIUM),
        (49, RiskLevel.MEDIUM),
        (50, RiskLevel.HIGH),
        (74, RiskLevel.HIGH),
        (75, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_bands(score, level):
    assert RiskLevel.from_score(score) is level


def test_severity_rank_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank
