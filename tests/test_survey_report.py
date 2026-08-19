"""Offline tests for the published registry study.

Two of these guard editorial discipline rather than arithmetic: the report must never name a
component, and must never print a count of embedded secrets. Both rules exist because a sample
of the secret-shaped hits in this population turned out to be values published on purpose, so a
raw count would read as an accusation against named projects that the data does not support.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SR = Path(__file__).parent / "manual_eval" / "survey_report.py"
_spec = importlib.util.spec_from_file_location("survey_report", _SR)
sr = importlib.util.module_from_spec(_spec)
sys.modules["survey_report"] = sr
_spec.loader.exec_module(sr)

_META = {
    "generated": "2026-08-19",
    "engine": "0.41.0",
    "ruleset": 45,
    "registry_entries": 73460,
    "registry_url": "https://registry.modelcontextprotocol.io/v0/servers",
    "clone_mb": 50,
    "timeout": 60,
}


def _rows() -> list[dict]:
    return [
        {
            "source": "https://github.com/acme/one", "ecosystem": "git", "status": "ok",
            "risk_level": "low", "malicious": False,
            "capabilities": ["network_egress", "shell_execution"],
        },
        {
            "source": "https://github.com/acme/two", "ecosystem": "git", "status": "ok",
            "risk_level": "high", "malicious": True,
            "capabilities": ["network_egress"],
        },
        {
            "source": "npm:secret-sauce", "ecosystem": "npm", "status": "ok",
            "risk_level": "low", "malicious": False, "capabilities": [],
        },
        {
            "source": "npm:gone", "ecosystem": "npm", "status": "skipped",
            "reason": "fatal: repository 'https://github.com/x/y.git/' not found",
        },
        {
            "source": "pypi:slow", "ecosystem": "pypi", "status": "skipped", "reason": "timeout",
        },
    ]


def test_counts_population_scanned_and_skipped():
    s = sr.summarize(_rows())
    assert s["population"] == 5
    assert s["scanned"] == 3
    assert s["skipped"] == 2


def test_buckets_skip_reasons_into_readable_causes():
    assert sr.bucket_skip("fatal: repository 'x' not found") == (
        "repository or package no longer reachable"
    )
    assert sr.bucket_skip("timeout") == "slower than the time bound"
    assert sr.bucket_skip("SourceTooLargeError: exceeds the 50 MB scan limit") == (
        "larger than the size bound"
    )
    assert sr.bucket_skip("something unexpected") == "other"


def test_capability_share_counts_scanned_components_only():
    s = sr.summarize(_rows())
    assert s["capabilities"]["network_egress"] == 2
    assert s["capabilities"]["shell_execution"] == 1
    assert s["risk_level"]["low"] == 2 and s["risk_level"]["high"] == 1
    assert s["malicious_indicators"] == 1


def test_registry_shape_measures_owner_concentration():
    s = sr.summarize(_rows())["registry_shape"]
    assert s["git_sources"] == 2 and s["distinct_owners"] == 1
    assert s["largest_owner_share"] == 100.0


def test_report_never_names_a_component():
    """Population statistics only — a source string in the output would be an accusation."""
    text = sr.render_markdown(sr.summarize(_rows()), _META)
    for row in _rows():
        assert row["source"] not in text
    assert "acme" not in text and "secret-sauce" not in text


def test_report_publishes_no_embedded_secret_count():
    """Withheld on purpose; the document must say so rather than quietly omit it."""
    text = sr.render_markdown(sr.summarize(_rows()), _META)
    assert "ST-SECRET-EMBEDDED" not in text
    assert "does not claim" in text
    assert "published on purpose" in text


def test_report_states_coverage_and_versions():
    text = sr.render_markdown(sr.summarize(_rows()), _META)
    assert "0.41.0" in text and "ruleset 45" in text
    assert "Not scanned" in text  # coverage is disclosed, never implied


def test_json_and_markdown_come_from_one_dataset(tmp_path):
    survey = tmp_path / "survey.jsonl"
    survey.write_text(
        "\n".join(json.dumps(r) for r in _rows()) + "\n", encoding="utf-8"
    )
    prefix = tmp_path / "out"
    sr.main([
        str(survey), "--out-prefix", str(prefix), "--engine", "0.41.0",
        "--ruleset", "45", "--registry-entries", "73460",
    ])
    data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    text = (tmp_path / "out.md").read_text(encoding="utf-8")
    assert data["summary"]["scanned"] == 3
    assert f"{data['summary']['scanned']:,}" in text
