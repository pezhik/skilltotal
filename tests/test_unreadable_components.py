"""A component nothing could be read from is "not analyzed", never "no significant risks".

A scan that reads nothing finds nothing, and a score of 0 then says nothing about the component.
The verdict must not word that as a clean result, and the install guard must treat it like an
install script it could not read: not checked, so the person decides.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.agent_hook import hook_response
from skilltotal.engine import analyze_directory
from skilltotal.guard import evaluate
from skilltotal.models import Component

NOTHING_READ = "Nothing in this component could be read"


def _package(root: Path):
    return analyze_directory(root, Component(name="x", type="npm_package", source="npm:x"))


def _binary_only(root: Path) -> Path:
    (root / "server.exe").write_bytes(b"MZ\x90\x00" + bytes(64))
    return root


def _minified_only(root: Path) -> Path:
    (root / "bundle.js").write_text("var a=1;" * 5000, encoding="utf-8")
    return root


def _empty(root: Path) -> Path:
    return root


@pytest.mark.parametrize("make", [_binary_only, _minified_only, _empty])
def test_nothing_read_is_never_reported_as_no_risk(tmp_path, make):
    report = _package(make(tmp_path))
    assert report.metadata["files_indexed"] == 0
    assert report.verdict["headline"] != "No significant risks found"
    assert report.verdict["headline"].startswith("Not analyzed")
    # Unread code is not evidence of risk: the score and level stay what the findings make them.
    assert (report.risk_score, report.risk_level.value) == (0, "low")
    assert report.verdict["level"] == "low"
    assert [n.title for n in report.needs_review].count(NOTHING_READ) == 1


def test_the_note_says_what_was_found_instead(tmp_path):
    report = _package(_binary_only(tmp_path))
    note = next(n for n in report.needs_review if n.title == NOTHING_READ)
    assert "1 binary" in note.reason


def test_a_component_with_a_readable_file_is_unchanged(tmp_path):
    (tmp_path / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    report = _package(_binary_only(tmp_path))
    assert report.verdict["headline"] == "No significant risks found"
    assert NOTHING_READ not in [n.title for n in report.needs_review]


def test_the_guard_does_not_pass_a_package_nothing_could_be_read_from(tmp_path):
    decision = evaluate(_package(_binary_only(tmp_path)).to_dict())
    assert not decision.allow
    assert decision.reasons == ["not analyzed: nothing in it could be read"]


def test_the_guard_still_passes_a_readable_clean_package(tmp_path):
    (tmp_path / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    assert evaluate(_package(tmp_path).to_dict()).allow


def test_the_hook_asks_the_person_and_says_why(tmp_path):
    report = _package(_binary_only(tmp_path)).to_dict()
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
             "tool_input": {"command": "npm install x"}}
    spec = hook_response(event, scan=lambda source, timeout: report)["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask"
    assert "nothing in it could be read" in spec["permissionDecisionReason"]


def test_a_cached_verdict_still_says_nothing_was_read(tmp_path, monkeypatch):
    # The hook cache keeps a trimmed report. Trimming the note away turned the second
    # `npm install x` into a silent pass for a package the first one asked about.
    from skilltotal import cli, collector

    monkeypatch.setenv("SKILLTOTAL_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(collector, "resolve_release", lambda source, timeout=0: None)
    (tmp_path / "pkg").mkdir()
    report = _package(_binary_only(tmp_path / "pkg")).to_dict()
    scans = []
    monkeypatch.setattr(cli, "_hook_scan",
                        lambda source, timeout, job=None: scans.append(source) or report)
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
             "tool_input": {"command": "npm install x"}}
    for _ in range(2):
        spec = hook_response(event, scan=cli._hook_scan_cached)["hookSpecificOutput"]
        assert spec["permissionDecision"] == "ask"
        assert "nothing in it could be read" in spec["permissionDecisionReason"]
    assert scans == ["npm:x"]  # the second answer came from the cache
