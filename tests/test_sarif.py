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
    data = json.loads(render_sarif(_report("malicious_py_pkg")))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        assert "security-severity" in rule["properties"]


def test_sarif_clean_has_no_results():
    data = json.loads(render_sarif(_report("clean_pkg")))
    assert data["runs"][0]["results"] == []
