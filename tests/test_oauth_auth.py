"""ST-AUTH-DELEGATED: OAuth/OIDC delegated-authentication execution-context signal.

Descriptive (capability-class, 0-score): it records that a component authenticates with the end
user's delegated credentials, feeding the `delegated_authentication` trait. These tests pin that
it fires on real delegation flows, stays out of the score, and does NOT fire on the
client_credentials static-service-identity grant.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.models import Capability, ThreatClass
from skilltotal.traits import ComponentTrait
from tests.conftest import analyze_fixture

_ID = "ST-AUTH-DELEGATED"


def _scan_source(tmp_path: Path, name: str, content: str):
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))


def test_delegated_auth_fires_on_oauth_flow():
    report = analyze_fixture("oauth_delegated_auth")
    finding = next((f for f in report.findings if f.id == _ID), None)
    assert finding is not None, "OAuth delegation flow should raise ST-AUTH-DELEGATED"
    assert finding.threat_class is ThreatClass.CAPABILITY
    assert finding.evidence, "capability findings still carry evidence"


def test_delegated_auth_does_not_score():
    report = analyze_fixture("oauth_delegated_auth")
    # A pure delegated-auth component is not risky: this rule adds nothing to the score.
    assert report.risk_score == 0
    assert Capability.DELEGATED_AUTHENTICATION in report.capabilities


def test_delegated_auth_projects_the_trait():
    report = analyze_fixture("oauth_delegated_auth")
    trait_ids = {t["trait"] for t in report.to_dict()["traits"]}
    assert ComponentTrait.DELEGATED_AUTHENTICATION.value in trait_ids


def test_client_credentials_is_not_delegation(tmp_path):
    # client_credentials is a static service-to-service identity, NOT user delegation, so the
    # delegated-auth signal must not fire on it alone.
    report = _scan_source(
        tmp_path,
        "svc.py",
        'import requests\n'
        'r = requests.post("https://api.example.invalid/token",\n'
        '                  data={"grant_type": "client_credentials"})\n',
    )
    assert not any(f.id == _ID for f in report.findings)
