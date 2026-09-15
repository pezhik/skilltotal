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


def test_report_states_the_population_snapshot_when_it_differs_from_the_scan_date():
    """A re-run over an earlier registry snapshot must say so, or 17,535 will not reconcile
    against the live registry a reader checks today."""
    meta = {**_META, "generated": "2026-09-13", "population_snapshot": "2026-08-16"}
    text = sr.render_markdown(sr.summarize(_rows()), meta)
    assert "scanned on 2026-09-13 against the registry as of 2026-08-16" in text
    assert "as of 2026-08-16, deduplicated by source" in text
    # Same-day runs keep the plain wording.
    same = sr.render_markdown(sr.summarize(_rows()), _META)
    assert "run on 2026-08-19" in same and "against the registry as of" not in same


def test_report_states_coverage_and_versions():
    text = sr.render_markdown(sr.summarize(_rows()), _META)
    assert "0.41.0" in text and "ruleset 45" in text
    assert "Not scanned" in text  # coverage is disclosed, never implied


def test_partition_shares_sum_to_their_total():
    """The published risk column summed to 99.9 under independent rounding; it must add up.

    Real counts from the 2026-08-20 survey. The web renderer's tests assert the same vector, so
    the two implementations cannot drift apart.
    """
    assert sr.partition_shares([15109, 143, 256, 30], 15538) == [97.2, 0.9, 1.7, 0.2]
    assert sr.partition_shares([1593, 194, 146, 60, 4], 17535, 11.4) == [9.1, 1.1, 0.8, 0.4, 0.0]
    # Each share is the floor or the ceiling of its exact value: never more than 0.1 away.
    for counts, whole in (([15109, 143, 256, 30], 15538), ([1, 1, 1], 3)):
        for c, shr in zip(counts, sr.partition_shares(counts, whole), strict=True):
            assert abs(shr - 100 * c / whole) < 0.1
    # Tenths summed as floats land at 99.99999999999999; the column is exact in tenths.
    assert abs(sum(sr.partition_shares([1, 1, 1], 3)) - 100.0) < 1e-9


def test_report_discloses_the_rounding_method():
    text = sr.render_markdown(sr.summarize(_rows()), _META)
    assert "sums exactly to its total" in text


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


def test_report_makes_no_claim_of_absence():
    """Zero indicators is what the rules matched, not a verdict that the registry is clean."""
    rows = [r for r in _rows() if not r.get("malicious")]
    text = sr.render_markdown(sr.summarize(rows), _META)
    assert "No claim that any component is safe" in text
    # A capability nobody carries is left out rather than printed as 0.0%.
    assert "evaluates code dynamically" not in text
    assert "can reach the network" in text


def test_report_discloses_a_mixed_ruleset_run():
    rows = _rows()
    for r in rows:
        if r["status"] == "ok":
            r["ruleset_version"] = 52
    rows[1]["ruleset_version"] = 53
    text = sr.render_markdown(sr.summarize(rows), _META)
    assert "2 with ruleset 52, 1 with ruleset 53" in text
    single = [dict(r, ruleset_version=53) if r["status"] == "ok" else r for r in _rows()]
    assert "Scanned components by ruleset" not in sr.render_markdown(sr.summarize(single), _META)


def test_a_non_zero_count_never_prints_as_zero_percent():
    """4 critical of 15,457 rounds to 0.0%, which reads as none; the label says <0.1%."""
    assert sr.share_label(0.0, 4) == "<0.1%"
    assert sr.share_label(0.0, 0) == "0.0%"
    assert sr.share_label(0.21, 33) == "0.2%"
    assert sr.pct(4, 15457) == "<0.1%"


def test_report_says_shipped_secrets_do_not_raise_the_level():
    text = sr.render_markdown(sr.summarize(_rows()), _META)
    assert "reports separately as an exposure" in text
