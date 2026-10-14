"""CLI and hook settings a customer can get wrong are said, never a traceback or a fallback."""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.cli import _hook_settings_note, invalid_settings, main


@pytest.mark.parametrize(("name", "value"), [
    ("SKILLTOTAL_MAX_ARCHIVE_MB", "150mb"), ("SKILLTOTAL_MAX_CLONE_MB", "-5"),
    ("SKILLTOTAL_WORKERS", "two"), ("SKILLTOTAL_CLONE_TIMEOUT", "0"),
])
def test_a_bad_whole_number_setting_is_an_error(name, value):
    assert name in invalid_settings({name: value})


def test_good_settings_pass():
    assert invalid_settings({"SKILLTOTAL_MAX_ARCHIVE_MB": "300", "SKILLTOTAL_WORKERS": "2"}) == ""


def test_the_cli_exits_1_on_a_bad_setting(tmp_path: Path, monkeypatch, capsys):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setenv("SKILLTOTAL_MAX_ARCHIVE_MB", "150mb")
    assert main(["scan", str(tmp_path)]) == 1
    assert "SKILLTOTAL_MAX_ARCHIVE_MB" in capsys.readouterr().err


def test_json_and_sarif_together_are_refused(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(tmp_path), "--json", "--sarif"])
    assert exc.value.code != 0


def test_with_output_the_console_gets_the_summary(tmp_path: Path, capsys):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    out = tmp_path / "r.sarif"
    assert main(["scan", str(tmp_path), "--sarif", "--output", str(out)]) == 0
    printed = capsys.readouterr().out
    assert '"$schema"' not in printed and out.read_text(encoding="utf-8").startswith("{")


@pytest.mark.parametrize(("environ", "said"), [
    ({"SKILLTOTAL_ALLOW_UNCHECKED": "lockfiles"}, "unknown kind(s) lockfiles"),
    ({"SKILLTOTAL_HOOK_BUDGET": "abc"}, "seconds from 1 to 100"),
    ({"SKILLTOTAL_HOOK_BUDGET": "1000"}, "seconds from 1 to 100"),
])
def test_a_hook_setting_it_cannot_use_is_said(environ, said):
    assert said in _hook_settings_note(environ, 100.0)


def test_good_hook_settings_say_nothing():
    assert _hook_settings_note({"SKILLTOTAL_ALLOW_UNCHECKED": "lockfile, local",
                                "SKILLTOTAL_HOOK_BUDGET": "90"}, 100.0) == ""
