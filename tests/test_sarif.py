"""SARIF 2.1.0 output shape and severity mapping."""

from __future__ import annotations

import json
from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.sarif import render_sarif

FIXTURES = Path(__file__).parent / "fixtures"


def _report(name: str):
    root = FIXTURES / name
    return analyze_directory(root, detect_component(root, source=str(root)))


def test_sarif_basic_shape():
    data = json.loads(render_sarif(_report("malicious_npm_pkg")))
    assert data["version"] == "2.1.0"
    assert data["$schema"].endswith("sarif-2.1.0.json")
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "SkillTotal"
    assert run["tool"]["driver"]["rules"], "rule descriptors present"
    assert run["results"], "results present"


def test_sarif_result_fields_and_levels():
    data = json.loads(render_sarif(_report("malicious_npm_pkg")))
    results = data["runs"][0]["results"]
    for r in results:
        assert r["ruleId"]
        assert r["level"] in {"error", "warning", "note"}
        loc = r["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        region = loc["region"]
        assert region["startLine"] >= 1
        assert region["endLine"] >= region["startLine"]
        assert region["snippet"]["text"]
    # The synthesized critical combo finding must map to SARIF "error".
    combo = [r for r in results if r["ruleId"] == "ST-COMBO-EXFIL"]
    assert combo and all(r["level"] == "error" for r in combo)


def test_sarif_rule_descriptor_has_security_severity():
    # Every rule that is risk (a malicious indicator, a risky construct, an exposure) is ranked
    # for GitHub; a capability is not risk and is not ranked as a security alert.
    from skilltotal.models import ThreatClass
    from skilltotal.rules import get_rules

    data = json.loads(render_sarif(_report("malicious_py_pkg")))
    rules = {r["id"]: r for r in data["runs"][0]["tool"]["driver"]["rules"]}
    for spec in get_rules():
        props = rules[spec.id]["properties"]
        if spec.threat_class == ThreatClass.CAPABILITY:
            assert "security-severity" not in props
            assert rules[spec.id]["defaultConfiguration"]["level"] == "note"
        else:
            assert "security-severity" in props


def test_a_capability_finding_is_a_note_whatever_its_severity():
    # six's exec() is a high-severity capability: it never fails the gate, so it must not reach
    # Code Scanning as an error the green gate contradicts.
    report = _report("malicious_py_pkg")
    data = json.loads(render_sarif(report))
    by_rule = {f.id: f.threat_class for f in report.findings}
    for r in data["runs"][0]["results"]:
        if by_rule[r["ruleId"]].value == "capability":
            assert r["level"] == "note"


def test_sarif_clean_has_no_results():
    data = json.loads(render_sarif(_report("clean_pkg")))
    assert data["runs"][0]["results"] == []


def test_sarif_owasp_taxonomy_present():
    data = json.loads(render_sarif(_report("malicious_py_pkg")))
    run = data["runs"][0]
    taxa = run["taxonomies"]
    assert len(taxa) == 1
    comp = taxa[0]
    assert comp["name"] == "OWASP Agentic Skills Top 10"
    ids = [t["id"] for t in comp["taxa"]]
    assert ids == [f"AST{n:02d}" for n in range(1, 11)]
    guid = comp["guid"]
    # a mapped rule (decode-and-execute -> AST01) links to the taxonomy by guid
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    rel = rules["ST-OBF-DECODE-EXEC"]["relationships"]
    assert rel[0]["target"]["id"] == "AST01"
    assert rel[0]["target"]["toolComponent"]["guid"] == guid
    assert "AST01" in rules["ST-OBF-DECODE-EXEC"]["properties"]["tags"]
    # an unmapped capability rule carries no relationships
    assert "relationships" not in rules["ST-FS-PY-READ"]
