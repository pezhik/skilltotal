"""Report rendering: JSON schema shape and human text."""

from __future__ import annotations

import json

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
    assert set(data["component"]) == {"name", "type", "source", "version"}
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
