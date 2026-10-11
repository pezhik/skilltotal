"""A long scan says what it is doing on a terminal, and nowhere else.

`scan npm:next` took 813 s with nothing on the screen until the end, which reads as a hang. The
engine reports each stage through an optional callback (it never prints); the CLI draws one line
that rewrites itself, only when stderr is a terminal, so pipes, CI logs and the hook's child scan
stay as they were.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from skilltotal.cli import EXIT_OK, main
from skilltotal.engine import analyze_directory
from skilltotal.models import Component
from skilltotal.scanners import SCANNERS


class _Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def _component(tmp_path: Path) -> Path:
    (tmp_path / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    return tmp_path


def test_the_engine_reports_each_stage_through_the_callback(tmp_path):
    seen: list[str] = []
    analyze_directory(_component(tmp_path), Component(name="x", type="directory", source="x"),
                      progress=seen.append)
    assert seen[0] == "Reading files"
    assert seen[1:] == [f"Scanning 1 files: check {i} of {len(SCANNERS)}"
                        for i in range(1, len(SCANNERS) + 1)]


def test_a_terminal_sees_one_line_that_is_erased_at_the_end(tmp_path, monkeypatch, capsys):
    terminal = _Terminal()
    monkeypatch.setattr("sys.stderr", terminal)
    assert main(["scan", str(_component(tmp_path)), "--json"]) == EXIT_OK
    shown = terminal.getvalue()
    assert shown.startswith("\rFetching... 0s")
    assert f"check {len(SCANNERS)} of {len(SCANNERS)}" in shown
    assert shown.endswith("\r")  # the line is blanked out: the report starts on a clean line
    assert "\n" not in shown
    json.loads(capsys.readouterr().out)  # stdout is the report alone


def test_a_pipe_or_ci_log_gets_no_progress(tmp_path, capsys):
    assert main(["scan", str(_component(tmp_path)), "--json"]) == EXIT_OK
    err = capsys.readouterr().err
    assert "\r" not in err and "Scanning" not in err
