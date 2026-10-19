"""Every SARIF report validates against the official SARIF 2.1.0 schema and GitHub's rules.

``tests/data/sarif-schema-2.1.0.json`` is the OASIS SARIF 2.1.0 (Errata 01) JSON schema, vendored
unmodified from
https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
(identical to sarif-2.1/schema/sarif-schema-2.1.0.json in github.com/oasis-tcs/sarif-spec;
SHA-256 c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e). Copyright OASIS Open,
redistributed under the OASIS IPR Policy that governs the SARIF specification. Vendored so the
test runs offline and against a fixed version.

GitHub Code Scanning accepts files the schema allows and still drops or misranks results: a
location URI must be relative to the repository, ``security-severity`` must be a number written
as a string, and a result's ``ruleId`` must name a rule the run declares.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

import jsonschema  # a dev dependency: missing, this test fails rather than skips
import pytest

from skilltotal.sarif import render_sarif
from tests.conftest import analyze_fixture

SCHEMA = Path(__file__).resolve().parent / "data" / "sarif-schema-2.1.0.json"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
# Every scannable fixture folder (baselines/ holds baseline files, not a component).
FIXTURE_NAMES = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir() and p.name != "baselines")


def _schema() -> dict:
    return json.loads(SCHEMA.read_text(encoding="utf-8"))


def _sarif(name: str, uri_prefix: str = "") -> dict:
    return json.loads(render_sarif(analyze_fixture(name), uri_prefix=uri_prefix))


def test_the_vendored_schema_is_sarif_2_1_0():
    schema = _schema()
    assert schema["$schema"] == "http://json-schema.org/draft-04/schema#"
    assert schema["properties"]["version"]["enum"] == ["2.1.0"]
    jsonschema.Draft4Validator.check_schema(schema)


def test_the_fixtures_are_found():
    assert len(FIXTURE_NAMES) >= 15, FIXTURE_NAMES
    assert {"malicious_npm_pkg", "malicious_py_pkg", "clean_pkg"} <= set(FIXTURE_NAMES)


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture_sarif_validates_and_meets_github_constraints(name):
    sarif = _sarif(name, uri_prefix="services/agent")
    jsonschema.Draft4Validator(_schema()).validate(sarif)

    (run,) = sarif["runs"]
    rules = run["tool"]["driver"]["rules"]
    rule_ids = [rule["id"] for rule in rules]
    assert len(rule_ids) == len(set(rule_ids)), "a rule id is declared twice"
    for rule in rules:
        severity = rule["properties"].get("security-severity")
        if severity is None:
            continue
        assert isinstance(severity, str), f"{rule['id']}: security-severity {severity!r}"
        assert 0.0 <= float(severity) <= 10.0, f"{rule['id']}: security-severity {severity}"

    for result in run["results"]:
        assert result["ruleId"] in rule_ids, f"result for undeclared rule {result['ruleId']}"
        for location in result["locations"]:
            uri = location["physicalLocation"]["artifactLocation"]["uri"]
            parts = urlsplit(uri)
            assert not parts.scheme and not parts.netloc, f"absolute URI {uri!r}"
            assert not uri.startswith("/") and "\\" not in uri, f"not a relative path: {uri!r}"
            assert ".." not in uri.split("/"), f"URI leaves the repository: {uri!r}"
            assert uri.startswith("services/agent/"), f"URI prefix missing: {uri!r}"


def test_a_risky_fixture_has_results_to_check():
    """The constraint loop above is not vacuous: a risky fixture yields located results."""
    run = _sarif("malicious_npm_pkg")["runs"][0]
    assert run["results"]
    assert any("security-severity" in rule["properties"] for rule in run["tool"]["driver"]["rules"])
