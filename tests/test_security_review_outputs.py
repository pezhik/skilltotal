"""Output and local-surface findings of the security review of 2026-10-15.

* A report written under a folder that is a link (a repository can commit `reports/` as a link
  out of the checkout) was written through it.
* `skilltotal diff` printed a component name, finding ids/titles and capabilities from a report
  as they were: a newline in a package.json name put a forged `::error` line at column zero.
* `inventory --project` followed a link in the project's `.claude/skills` to a folder outside.
* A ZIP with a huge central directory made the encrypted-archive check load it whole.
"""

from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pytest

from skilltotal import cli
from skilltotal.diff import diff_reports
from skilltotal.inventory import discover
from skilltotal.report import render_diff_text
from skilltotal.scanners import encrypted_archive

NL = chr(10)


def _link_dir(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        import subprocess

        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],  # noqa: S603,S607
                       check=True, capture_output=True)


def test_a_report_is_not_written_through_a_linked_folder_inside_the_working_dir(
        tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    _link_dir(work / "reports", outside)
    monkeypatch.chdir(work)
    with pytest.raises(cli.UnsafeOutputPath):
        cli._write_file("reports/out.json", "{}")
    assert not (outside / "out.json").exists()


def test_a_report_in_an_ordinary_folder_is_written(tmp_path, monkeypatch):
    (tmp_path / "reports").mkdir()
    monkeypatch.chdir(tmp_path)
    cli._write_file("reports/out.json", "{}")
    assert (tmp_path / "reports" / "out.json").read_text(encoding="utf-8") == "{}"


def _side(name: str, findings: list[dict], caps: list[str]) -> dict:
    return {"component": {"name": name, "type": "directory"}, "risk_score": 0,
            "risk_level": "low", "ruleset_version": 75, "findings": findings,
            "capabilities": {c: [] for c in caps}}


def test_diff_text_prints_every_report_field_on_one_line():
    forged = NL + "::error title=FORGED::x"
    finding = {"id": "ST-X" + forged, "title": "T" + forged, "severity": "high",
               "threat_class": "risky_construct",
               "evidence": [{"file": "a.py" + forged, "line_start": 1, "line_end": 1,
                             "snippet": "s" + forged}]}
    old = _side("old", [], [])
    new = _side("name" + forged, [finding], ["cap" + forged])
    text = render_diff_text(diff_reports(old, new))
    assert not any(line.startswith("::") for line in text.splitlines()), text
    assert "<U+000A>" in text


def test_inventory_does_not_follow_a_project_skill_link_out_of_the_project(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.js").write_text("x", encoding="utf-8")
    project = tmp_path / "project"
    skills = project / ".claude" / "skills"
    skills.mkdir(parents=True)
    (skills / "own").mkdir()
    _link_dir(skills / "linked", outside)
    found = {c.name: c for c in discover(home=tmp_path / "home", project=project, environ={})}
    assert found["own"].scannable
    assert not found["linked"].scannable and found["linked"].source is None
    assert "outside the project" in found["linked"].note


def test_a_zip_declaring_a_huge_directory_is_not_opened(tmp_path, monkeypatch):
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("x.txt", "x")
    opened: list[str] = []
    monkeypatch.setattr(encrypted_archive, "_MAX_ZIP_DIRECTORY_BYTES", 10)
    monkeypatch.setattr(encrypted_archive.zipfile, "ZipFile",
                        lambda *a, **k: opened.append("x") or (_ for _ in ()).throw(AssertionError))
    assert encrypted_archive._encrypted_entry_count(path) == 0
    assert opened == []


def test_a_broken_zip_never_stops_the_scan(tmp_path):
    path = tmp_path / "b.zip"
    path.write_bytes(b"PK" + bytes(range(256)) * 4)
    assert encrypted_archive._encrypted_entry_count(path) == 0


def test_staged_runs_git_without_lfs_downloads(tmp_path, monkeypatch):
    calls: list[dict] = []

    class Done:
        returncode = 1
        stdout = ""
        stderr = "stop"

    def fake_run(argv, **kwargs):
        calls.append({"argv": argv, "env": kwargs.get("env") or {}})
        return Done()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(cli.StagedError), cli._staged_snapshot(str(tmp_path)):
        pass
    assert calls and calls[0]["env"].get("GIT_LFS_SKIP_SMUDGE") == "1"
    assert "core.fsmonitor=false" in calls[0]["argv"]


def test_json_report_fixture_is_valid():
    # Keeps the helper honest: the sides above are what diff_reports reads.
    assert json.dumps(_side("x", [], []))
