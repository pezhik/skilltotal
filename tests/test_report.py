"""Report rendering: JSON schema shape and human text."""

from __future__ import annotations

import json

from skilltotal.engine import analyze_directory
from skilltotal.models import Component
from skilltotal.report import render_json, render_text
from tests.conftest import analyze_fixture

REQUIRED_TOP_KEYS = {
    "component",
    "risk_score",
    "risk_level",
    "summary",
    "capabilities",
    "findings",
    "needs_review",
    "metadata",
}


def test_json_schema_shape(malicious_npm):
    data = json.loads(render_json(malicious_npm))
    assert REQUIRED_TOP_KEYS <= set(data)
    assert set(data["component"]) == {"name", "type", "source", "version", "download_url"}
    for f in data["findings"]:
        assert set(f) >= {
            "id", "severity", "category", "title", "description",
            "evidence", "recommendation",
        }
        assert f["evidence"], "finding must carry evidence"
        for e in f["evidence"]:
            assert set(e) == {"file", "line_start", "line_end", "snippet"}


def test_json_is_valid_for_all_fixtures():
    for name in ["malicious_npm_pkg", "malicious_py_pkg", "mcp_server",
                 "prompt_injection", "clean_pkg"]:
        data = json.loads(render_json(analyze_fixture(name)))
        assert "risk_level" in data


def test_text_report_contains_key_sections(malicious_npm):
    text = render_text(malicious_npm)
    assert "SkillTotal Security Report" in text
    assert "Risk" in text
    assert "Findings" in text
    assert "ST-SHELL-NODE" in text
    assert "Evidence:" in text


def test_clean_text_reports_no_findings(clean_report):
    text = render_text(clean_report)
    assert "Findings (0):" in text
    assert "(none)" in text


def test_text_report_leads_with_the_verdict(tmp_path, malicious_npm, clean_report):
    # An install-time dropper scores only "medium"; the verdict line must say malicious, first.
    (tmp_path / "package.json").write_text(
        '{"name": "d", "version": "1.0.0", "scripts": {"postinstall": "node setup.js"}}',
        encoding="utf-8",
    )
    (tmp_path / "setup.js").write_text(
        'eval(Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString());\n', encoding="utf-8"
    )
    report = analyze_directory(tmp_path, Component(name="d", type="directory", source="d"))
    lines = render_text(report).splitlines()
    verdict = next(i for i, line in enumerate(lines) if line.startswith("Verdict   :"))
    risk = next(i for i, line in enumerate(lines) if line.startswith("Risk      :"))
    assert verdict < risk
    assert lines[verdict].startswith("Verdict   : MALICIOUS - Malicious indicators found (")
    # High risk without malice says so, with no reasons tacked on; a clean report reads low.
    assert "Verdict   : HIGH - High-risk capabilities" in render_text(malicious_npm)
    clean = render_text(clean_report)
    assert "Verdict   : LOW - " in clean and "MALICIOUS" not in clean


def test_text_report_labels_capabilities_and_keeps_evidence_short(tmp_path):
    # Seen in a pre-launch audit: "Risk: LOW (score 0/100)" above "[HIGH] ST-...", and up to 25
    # locations per capability. A capability is labeled as not scored; --json keeps every location.
    import re

    (tmp_path / "index.js").write_text(
        "const cp = require('child_process');\n"
        + "".join(f"cp.execSync('ls {i}');\n" for i in range(6)),
        encoding="utf-8",
    )
    report = analyze_directory(tmp_path, Component(name="d", type="directory", source="d"))
    text = render_text(report)
    shell = next(f for f in report.findings if f.id == "ST-SHELL-NODE")
    assert shell.threat_class.value == "capability"
    assert "- capability, not scored] ST-SHELL-NODE" in text
    assert re.search(r"- index\.js:\d+\n", text)  # one line reads as one line, not "2-2"
    assert f"... and {len(shell.evidence) - 3} more (all of them in --json)" in text


def test_verdict_reasons_lead_with_what_is_scored(tmp_path):
    # A dropper's reasons once listed two capabilities and dropped the install-time dropper.
    (tmp_path / "package.json").write_text(
        '{"name": "d", "version": "1.0.0", "scripts": {"postinstall": "node setup.js"}}',
        encoding="utf-8",
    )
    (tmp_path / "setup.js").write_text(
        "const fs = require('fs'); const https = require('https');\n"
        "fs.readFileSync(require('os').homedir() + '/.npmrc');\n"
        'eval(Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString());\n',
        encoding="utf-8",
    )
    report = analyze_directory(tmp_path, Component(name="d", type="directory", source="d"))
    by_title = {f.title: f.threat_class.value for f in report.findings}
    reasons = report.verdict["reasons"]
    order = {"malicious_indicator": 0, "risky_construct": 1, "exposure": 2, "capability": 3}
    ranks = [order[by_title[r]] for r in reasons]
    assert ranks == sorted(ranks)
    assert by_title[reasons[0]] == "malicious_indicator"
