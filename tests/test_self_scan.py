"""The engine's own repository scans clean.

A security tool's source is full of the things it looks for: regexes naming credential paths,
comments quoting the idioms a hook refuses, a hook that runs a guard script. Through 0.82.0 three
rules read those as the attack itself and rated this repository malicious (critical, 100), which
is what a user running ``skilltotal scan`` on the tool would have seen first. Ruleset 83 fixed
the three; this keeps the whole repository, with its sanitized attack corpus under ``tests/``,
below the hook's ask threshold.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.engine import analyze_directory
from skilltotal.models import Component, RiskLevel, ThreatClass

REPO = Path(__file__).resolve().parents[1]


def test_the_engine_repository_is_not_rated_malicious_or_high():
    component = Component(name="skilltotal", type="directory", source=str(REPO))
    report = analyze_directory(REPO, component)
    malicious = [
        f.id for f in report.findings if f.threat_class == ThreatClass.MALICIOUS_INDICATOR
    ]
    assert malicious == [], malicious
    assert report.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM), (
        report.risk_level, [f.id for f in report.findings]
    )
