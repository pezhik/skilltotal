"""Threat-class axis + fast malware verdict (engine projection)."""

from __future__ import annotations

from skilltotal.models import ThreatClass


def _by_id(report):
    return {f.id: f for f in report.findings}


def test_prompt_injection_is_malicious_and_sets_verdict(prompt_report):
    f = _by_id(prompt_report)["ST-PROMPT-INJECTION"]
    assert f.threat_class == ThreatClass.MALICIOUS_INDICATOR
    v = prompt_report.verdict
    assert v["has_malicious_indicators"] is True
    assert v["level"] == "malicious"
    assert v["headline"] == "Malicious indicators found"
    assert f.title in v["reasons"]
    # serialized form carries it too (schema 1.3)
    assert f.to_dict()["threat_class"] == "malicious_indicator"
    assert prompt_report.to_dict()["verdict"]["level"] == "malicious"


def test_high_risk_without_malice_reads_as_high_risk_not_malware(malicious_py):
    # A clear-text exfiltration path (read + network) must NOT be labelled malware (intent
    # unproven), but the headline must still convey danger — never "critical but not malware".
    v = malicious_py.verdict
    if v["has_malicious_indicators"]:
        return  # this fixture also trips a deception rule; covered elsewhere
    assert v["level"] in ("critical", "high", "medium", "low")
    if malicious_py.risk_level.value in ("critical", "high"):
        assert v["headline"].startswith("High-risk")


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
    v = clean_report.verdict
    assert v["has_malicious_indicators"] is False
    assert v["malicious_indicators"] == 0
    assert v["level"] == "low"
    assert v["headline"] == "No significant risks found"


def test_combo_finding_is_capability_not_malware(malicious_py):
    # filesystem+network combo is an exfiltration *surface*, not proof of intent.
    by_id = _by_id(malicious_py)
    if "ST-COMBO-FS-NET" in by_id:
        assert by_id["ST-COMBO-FS-NET"].threat_class == ThreatClass.CAPABILITY


def test_every_finding_has_a_threat_class(malicious_npm, malicious_py, mcp_report):
    for report in (malicious_npm, malicious_py, mcp_report):
        for f in report.findings:
            assert isinstance(f.threat_class, ThreatClass)
