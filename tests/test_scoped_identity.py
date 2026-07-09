"""ST-AUTH-SCOPED: scoped / least-privilege identity execution-context signal.

Descriptive (capability-class, 0-score): records that a component uses a short-lived, scoped,
assumed identity, feeding the `scoped_identity` trait (CSA "Least-Privilege Service Identity").
"""

from __future__ import annotations

from skilltotal.models import Capability, ThreatClass
from skilltotal.traits import ComponentTrait
from tests.conftest import analyze_fixture

_ID = "ST-AUTH-SCOPED"


def test_scoped_identity_fires_on_assume_role():
    report = analyze_fixture("scoped_identity")
    finding = next((f for f in report.findings if f.id == _ID), None)
    assert finding is not None, "STS AssumeRole should raise ST-AUTH-SCOPED"
    assert finding.threat_class is ThreatClass.CAPABILITY
    assert finding.evidence


def test_scoped_identity_does_not_score():
    report = analyze_fixture("scoped_identity")
    assert Capability.SCOPED_IDENTITY in report.capabilities
    # No malicious/risky finding is introduced by this rule.
    assert not any(f.id == _ID and f.threat_class is not ThreatClass.CAPABILITY
                   for f in report.findings)


def test_scoped_identity_projects_the_trait():
    report = analyze_fixture("scoped_identity")
    trait_ids = {t["trait"] for t in report.to_dict()["traits"]}
    assert ComponentTrait.SCOPED_IDENTITY.value in trait_ids
