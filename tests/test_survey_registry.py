"""Offline tests for the full-registry survey harness.

The network run is scheduled and manual; what is tested here is the logic a published study
depends on: correct deduplication of the population, and resume behaviour that cannot silently
lose or double-count a component.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SR = Path(__file__).parent / "manual_eval" / "survey_registry.py"
_spec = importlib.util.spec_from_file_location("survey_registry", _SR)
sr = importlib.util.module_from_spec(_spec)
sys.modules["survey_registry"] = sr
_spec.loader.exec_module(sr)


def _npm(identifier: str, name: str = "com.x/srv") -> dict:
    return {
        "server": {
            "name": name,
            "packages": [{"registryType": "npm", "identifier": identifier, "version": "1"}],
        }
    }


def test_population_is_deduplicated_by_source():
    """The registry lists a server per published VERSION, so the same package recurs.

    Counting those repeats would multiply one package across every percentage in the study --
    the real dump collapses ~73k entries to ~17.5k distinct sources.
    """
    items = [_npm("a-mcp"), _npm("a-mcp"), _npm("a-mcp"), _npm("b-mcp")]
    assert sr.unique_sources(items) == [("npm:a-mcp", "npm"), ("npm:b-mcp", "npm")]


def test_population_keeps_first_seen_order():
    items = [_npm("z-mcp"), _npm("a-mcp")]
    assert [s for s, _ in sr.unique_sources(items)] == ["npm:z-mcp", "npm:a-mcp"]


def test_population_rejects_sources_failing_the_hygiene_allowlist():
    bad = {"server": {"name": "com.x/local", "packages": [
        {"registryType": "npm", "identifier": "../../etc/passwd", "version": "1"}]}}
    assert sr.unique_sources([bad, _npm("ok-mcp")]) == [("npm:ok-mcp", "npm")]


def test_population_skips_entries_with_no_usable_source():
    assert sr.unique_sources([{"server": {"name": "com.x/none"}}]) == []


def test_resume_reads_completed_sources(tmp_path):
    out = tmp_path / "survey.jsonl"
    out.write_text(
        json.dumps({"source": "npm:a", "status": "ok"}) + "\n"
        + json.dumps({"source": "npm:b", "status": "skipped"}) + "\n",
        encoding="utf-8",
    )
    # A skipped component counts as done: re-running it would just fail again and cost the same
    # wall-clock, and the study reports it as a disclosed skip either way.
    assert sr.already_done(out) == {"npm:a", "npm:b"}


def test_resume_tolerates_a_torn_final_line(tmp_path):
    """A run killed mid-write leaves a partial line; resuming must not crash on it."""
    out = tmp_path / "survey.jsonl"
    out.write_text(
        json.dumps({"source": "npm:a", "status": "ok"}) + "\n" + '{"source": "npm:trunc"',
        encoding="utf-8",
    )
    assert sr.already_done(out) == {"npm:a"}


def test_resume_on_missing_file_is_empty(tmp_path):
    assert sr.already_done(tmp_path / "nope.jsonl") == set()


def test_scan_one_records_aggregates_and_no_evidence(tmp_path):
    """The row must carry what the study aggregates -- and must NOT carry evidence.

    Evidence quotes a named project's code; the study reports population statistics, so the
    collector never records it in the first place.
    """
    (tmp_path / "m.py").write_text("import os\nos.system('id')\n", encoding="utf-8")
    row = sr.scan_one(str(tmp_path))
    assert row["risk_level"] in {"low", "medium", "high", "critical"}
    assert "ST-SHELL-PY" in row["rules"]
    assert "shell_execution" in row["capabilities"]
    assert row["findings_count"] >= 1
    assert "evidence" not in json.dumps(row)
    assert all(isinstance(t, str) and t for t in row["traits"])  # traits are keyed "trait"
