"""Threat-class axis + fast malware verdict (engine projection)."""

from __future__ import annotations

from skilltotal.models import ThreatClass


def _by_id(report):
    return {f.id: f for f in report.findings}


def test_prompt_injection_is_malicious_and_sets_verdict(prompt_report):
    f = _by_id(prompt_report)["ST-PROMPT-INJECTION"]
    assert f.threat_class == ThreatClass.MALICIOUS_INDICATOR
    assert prompt_report.verdict["has_malicious_indicators"] is True
    assert prompt_report.verdict["malicious_indicators"] >= 1
    # serialized form carries it too (schema 1.3)
    assert f.to_dict()["threat_class"] == "malicious_indicator"
    assert prompt_report.to_dict()["verdict"]["has_malicious_indicators"] is True


def test_capability_findings_do_not_trip_the_verdict(mcp_report):
    # The MCP fixture has dangerous-tool/detected capability findings; on their own they
    # are capabilities, not malware indicators — but this fixture also has poisoning, so
    # assert the *capability* findings are classified as capability regardless.
    by_id = _by_id(mcp_report)
    if "ST-MCP-DANGEROUS-TOOL" in by_id:
        assert by_id["ST-MCP-DANGEROUS-TOOL"].threat_class == ThreatClass.CAPABILITY
    if "ST-MCP-DETECTED" in by_id:
        assert by_id["ST-MCP-DETECTED"].threat_class == ThreatClass.CAPABILITY


def test_clean_component_verdict_is_clean(clean_report):
    assert clean_report.verdict["has_malicious_indicators"] is False
    assert clean_report.verdict["malicious_indicators"] == 0


def test_combo_finding_is_capability_not_malware(malicious_py):
    # filesystem+network combo is an exfiltration *surface*, not proof of intent.
    by_id = _by_id(malicious_py)
    if "ST-COMBO-FS-NET" in by_id:
        assert by_id["ST-COMBO-FS-NET"].threat_class == ThreatClass.CAPABILITY


def test_every_finding_has_a_threat_class(malicious_npm, malicious_py, mcp_report):
    for report in (malicious_npm, malicious_py, mcp_report):
        for f in report.findings:
            assert isinstance(f.threat_class, ThreatClass)
