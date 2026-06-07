"""Contract guard: every report must validate against docs/report.schema.json.

This locks the engine<->consumer (web app) contract. A change to Report.to_dict() that is
not reflected in the schema breaks this test, forcing a deliberate schema + version bump.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal import REPORT_SCHEMA_VERSION, RULESET_VERSION
from tests.conftest import analyze_fixture

jsonschema = pytest.importorskip("jsonschema")

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "docs" / "report.schema.json"
FIXTURES = [
    "malicious_npm_pkg",
    "malicious_py_pkg",
    "mcp_server",
    "prompt_injection",
    "clean_pkg",
]


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_schema_is_valid_jsonschema():
    jsonschema.Draft202012Validator.check_schema(_schema())


@pytest.mark.parametrize("name", FIXTURES)
def test_report_validates_against_schema(name):
    report = analyze_fixture(name).to_dict()
    jsonschema.validate(instance=report, schema=_schema())


def test_metadata_carries_contract_versions():
    meta = analyze_fixture("malicious_npm_pkg").to_dict()["metadata"]
    assert meta["schema_version"] == REPORT_SCHEMA_VERSION
    assert meta["ruleset_version"] == RULESET_VERSION
    assert "skilltotal_version" in meta
