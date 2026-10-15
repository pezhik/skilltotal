"""CLI integration: commands, flags, and exit codes."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from skilltotal.cli import (
    EXIT_ERROR,
    EXIT_FAIL_ON_HIGH,
    EXIT_OK,
    main,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_text_output(capsys):
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg")])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "SkillTotal Security Report" in out


def test_scan_json_output(capsys):
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--json"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    data = json.loads(out)
    # Sensitive-path access (.js) + network egress -> ST-COMBO-EXFIL (critical risky) + the
    # sensitive-path finding => high. Plain capabilities (shell/install/fs) no longer score.
    assert data["risk_level"] == "high"


def test_scan_output_file(tmp_path: Path, capsys):
    target = tmp_path / "report.json"
    code = main(["scan", str(FIXTURES / "clean_pkg"), "--output", str(target)])
    capsys.readouterr()
    assert code == EXIT_OK
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["component"]["name"] == "cleanlib"


def test_fail_on_high_triggers_for_malicious(capsys):
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--fail-on-high"])
    capsys.readouterr()
    assert code == EXIT_FAIL_ON_HIGH


def test_fail_on_high_ok_for_clean(capsys):
    code = main(["scan", str(FIXTURES / "clean_pkg"), "--fail-on-high"])
    capsys.readouterr()
    assert code == EXIT_OK


def test_scan_missing_path_errors(capsys):
    code = main(["scan", str(FIXTURES / "does_not_exist_xyz")])
    err = capsys.readouterr().err
    assert code == EXIT_ERROR
    assert "error:" in err


def test_scan_sarif_output(capsys):
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--sarif"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    data = json.loads(out)
    assert data["version"] == "2.1.0"


def test_scan_sarif_output_file(tmp_path: Path, capsys):
    target = tmp_path / "out.sarif"
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--sarif", "--output", str(target)])
    capsys.readouterr()
    assert code == EXIT_OK
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["runs"][0]["tool"]["driver"]["name"] == "SkillTotal"


def test_write_baseline_then_suppress(tmp_path: Path, capsys):
    target = str(FIXTURES / "malicious_npm_pkg")
    baseline = tmp_path / "bl.json"

    # 1. Snapshot current findings into a baseline.
    main(["scan", target, "--write-baseline", str(baseline)])
    capsys.readouterr()
    assert baseline.exists()

    # 2. Re-scan with the baseline: findings are suppressed, score drops below critical.
    main(["scan", target, "--baseline", str(baseline), "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["metadata"]["suppressed_count"] > 0
    assert data["risk_score"] < 100


def test_baseline_with_fail_on_high_passes_after_suppression(tmp_path: Path, capsys):
    target = str(FIXTURES / "malicious_npm_pkg")
    baseline = tmp_path / "bl.json"
    main(["scan", target, "--write-baseline", str(baseline)])
    capsys.readouterr()
    code = main(["scan", target, "--baseline", str(baseline), "--fail-on-high"])
    capsys.readouterr()
    assert code == EXIT_OK


def test_missing_baseline_file_errors(capsys):
    code = main(["scan", str(FIXTURES / "clean_pkg"), "--baseline", "nope_xyz.json"])
    err = capsys.readouterr().err
    assert code == EXIT_ERROR
    assert "baseline" in err


def test_rules_list_text(capsys):
    code = main(["rules", "list"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "ST-SHELL-PY" in out
    assert "ST-COMBO-EXFIL" in out


def test_rules_list_json(capsys):
    code = main(["rules", "list", "--json"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    rules = json.loads(out)
    ids = {r["id"] for r in rules}
    assert "ST-MCP-DANGEROUS-TOOL" in ids


def test_fail_on_level_critical_triggers(capsys):
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--fail-on", "critical"])
    capsys.readouterr()
    assert code == EXIT_FAIL_ON_HIGH  # ST-COMBO-EXFIL is a critical finding


def test_fail_on_score_triggers(capsys):
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--fail-on-score", "1"])
    capsys.readouterr()
    assert code == EXIT_FAIL_ON_HIGH


def test_fail_on_score_high_threshold_passes(capsys):
    code = main(["scan", str(FIXTURES / "clean_pkg"), "--fail-on-score", "50"])
    capsys.readouterr()
    assert code == EXIT_OK


def test_exclude_flag_drops_findings(capsys):
    # Excluding the stealer .js removes the sensitive-path + network egress -> no exfil combo.
    main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--exclude", "*.js", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["risk_level"] == "low"


def test_config_drives_gate(tmp_path: Path, capsys):
    cfg = tmp_path / ".skilltotal.toml"
    cfg.write_text('fail_on = "high"\n', encoding="utf-8")
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--config", str(cfg)])
    capsys.readouterr()
    assert code == EXIT_FAIL_ON_HIGH


def test_config_ignore_rule(tmp_path: Path, capsys):
    cfg = tmp_path / ".skilltotal.toml"
    cfg.write_text('ignore = ["ST-COMBO-EXFIL"]\n', encoding="utf-8")
    main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--config", str(cfg), "--json"])
    out = capsys.readouterr().out
    ids = {f["id"] for f in json.loads(out)["findings"]}
    assert "ST-COMBO-EXFIL" not in ids


def test_no_command_errors():
    with pytest.raises(SystemExit):
        main([])


def test_a_usage_error_exits_1_not_the_gate_code(capsys):
    # Exit code 2 means a gate tripped; a mistyped level must not look like a failed component.
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(FIXTURES / "clean_pkg"), "--fail-on", "hihg"])
    capsys.readouterr()
    assert exc.value.code == EXIT_ERROR


def test_a_bare_package_name_gets_a_hint(capsys):
    code = main(["scan", "some-package-that-is-not-a-folder"])
    err = capsys.readouterr().err
    assert code == EXIT_ERROR
    assert "npm:some-package-that-is-not-a-folder or pypi:some-package-that-is-not-a-folder" in err


def test_the_output_file_is_written_even_if_the_console_cannot_print(tmp_path, monkeypatch):
    # Seen on Windows: `scan --output r.json` left no file when printing a snippet to a legacy
    # code-page console failed first.
    import io
    import sys

    class Legacy(io.TextIOWrapper):
        pass

    target = tmp_path / "r.json"
    legacy = Legacy(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", legacy)
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--json", "--output", str(target)])
    assert code == EXIT_OK
    assert json.loads(target.read_text(encoding="utf-8"))["findings"]
    legacy.flush()
    assert legacy.encoding.lower().replace("-", "") == "utf8"  # reconfigured for redirection


# --- CLI usability audit 2026-10-15 (B1-B12) ------------------------------------------------------


@pytest.mark.parametrize("command", [["inventory", "--no-scan"], ["guard", "--installed"]])
def test_a_missing_project_directory_is_an_error(tmp_path: Path, capsys, command):
    # A mistyped --project DIR checked nothing there and exited 0.
    missing = tmp_path / "no-such-project"
    assert main([*command, "--project", str(missing)]) == EXIT_ERROR
    assert f"project directory not found: {missing}" in capsys.readouterr().err
    a_file = tmp_path / "file.txt"
    a_file.write_text("x", encoding="utf-8")
    assert main([*command, "--project", str(a_file)]) == EXIT_ERROR
    assert "project directory not found" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--output", "--write-baseline"])
def test_an_output_into_a_missing_folder_fails_before_the_scan(tmp_path: Path, capsys,
                                                               monkeypatch, flag):
    def no_scan(*args, **kwargs):
        raise AssertionError("the scan ran before the output folder was checked")

    monkeypatch.setattr("skilltotal.engine.analyze", no_scan)
    target = tmp_path / "no-such-dir" / "r.json"
    assert main(["scan", str(FIXTURES / "clean_pkg"), flag, str(target)]) == EXIT_ERROR
    err = capsys.readouterr().err
    assert "does not exist; create it first" in err


def test_a_diff_output_into_a_missing_folder_fails_before_the_scans(tmp_path: Path, capsys):
    target = tmp_path / "no-such-dir" / "d.json"
    code = main(["diff", str(FIXTURES / "clean_pkg"), str(FIXTURES / "clean_pkg"),
                 "--output", str(target)])
    assert code == EXIT_ERROR
    assert "cannot write the diff report" in capsys.readouterr().err


def test_abbreviated_options_are_refused(tmp_path: Path, capsys):
    # `--out` was taken for `--output`; a future `--outline` would make it mean something else.
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(FIXTURES / "clean_pkg"), "--out", str(tmp_path / "r.json")])
    assert exc.value.code == EXIT_ERROR
    assert "unrecognized arguments: --out" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        main(["rules", "list", "--js"])
    capsys.readouterr()


def test_the_false_positive_hint_fits_the_source(tmp_path: Path, capsys):
    import io
    import tarfile

    code = b"eval(x)\n"
    project = tmp_path / "project"
    project.mkdir()
    (project / "m.py").write_bytes(code)
    archive = tmp_path / "pkg.tgz"
    with tarfile.open(archive, "w:gz") as tf:
        info = tarfile.TarInfo("package/m.py")
        info.size = len(code)
        tf.addfile(info, io.BytesIO(code))

    main(["scan", str(project)])
    own = capsys.readouterr().out
    assert "put `# skilltotal:ignore[RULE-ID]` on its line" in own
    # A marker in a fetched package or archive is never honored: the hint must not suggest one.
    main(["scan", str(archive)])
    fetched = capsys.readouterr().out
    assert "put `# skilltotal:ignore" not in fetched
    assert "--write-baseline FILE and scan with --baseline FILE" in fetched
    assert "[policy] in .skilltotal.toml" in fetched


def test_a_joined_argument_gets_a_trailing_backslash_hint(capsys):
    # PowerShell: `skilltotal scan '.\my comp\' --json` reaches the program as one argument.
    code = main(["scan", '.\\no such comp" --json'])
    err = capsys.readouterr().err
    assert code == EXIT_ERROR
    assert "trailing backslash before the closing quote joined your arguments" in err
    main(["scan", str(FIXTURES / "does_not_exist_xyz")])
    assert "trailing backslash" not in capsys.readouterr().err


def test_with_output_the_console_gets_a_short_summary(tmp_path: Path, capsys):
    target = tmp_path / "r.json"
    code = main(["scan", str(FIXTURES / "malicious_npm_pkg"), "--json", "--output", str(target),
                 "--fail-on-high"])
    captured = capsys.readouterr()
    assert code == EXIT_FAIL_ON_HIGH
    assert json.loads(target.read_text(encoding="utf-8"))["findings"]
    out = captured.out
    assert "Verdict   :" in out and "Risk      :" in out
    assert "risk finding(s)" in out  # the counts
    assert f"Full report: {target}" in out
    assert "Evidence:" not in out and "Recommendation:" not in out  # not the full report
    assert "gate: --fail-on-high tripped by" in captured.err
    # Without --output the full text report is printed, as before.
    main(["scan", str(FIXTURES / "malicious_npm_pkg")])
    assert "Evidence:" in capsys.readouterr().out


def test_text_reports_never_carry_terminal_escapes():
    from skilltotal.report import _terminal_safe

    assert _terminal_safe("ok\x1b[2J\r\x07\tx\n") == "ok\\x1b[2J\\x0d\\x07\tx\n"


def test_guard_installed_text_never_carries_terminal_escapes(monkeypatch, capsys):
    """A server name comes from a config file anyone can write (a repository's `.mcp.json`): its
    escape sequences must not reach the terminal and rewrite what the person reads."""
    from skilltotal.inventory import DiscoveredComponent

    esc, bel = chr(27), chr(7)
    fake = [DiscoveredComponent(host="Claude Code", name=f"srv{esc}[2J{esc}]0;pwned{bel}",
                                kind="mcp_server", source=None, scannable=False,
                                note=f"remote{esc}[31m")]
    monkeypatch.setattr("skilltotal.inventory.discover", lambda project=None: fake)
    assert main(["guard", "--installed"]) == EXIT_ERROR  # nothing could be checked
    out = capsys.readouterr().out
    assert esc not in out and bel not in out
    assert "srv<U+001B>[2J" in out  # a name is printed as one line, controls shown


def test_the_cli_turns_off_the_current_directory_lookup_on_windows_only():
    from skilltotal.cli import _no_lookup_in_current_directory

    windows: dict[str, str] = {}
    _no_lookup_in_current_directory(windows, "nt")
    assert windows == {"NoDefaultCurrentDirectoryInExePath": "1"}
    posix: dict[str, str] = {}
    _no_lookup_in_current_directory(posix, "posix")
    assert posix == {}


@pytest.mark.skipif(os.name != "nt", reason="the current-directory lookup is Windows' own")
def test_a_program_planted_in_the_current_directory_never_runs(tmp_path):
    """Windows looks for a bare program name in the current directory before PATH: a `git.exe`
    committed to a repository would run when the CLI calls `git` from inside it. A copy of a
    harmless system program stands in for the planted one."""
    import shutil
    import subprocess
    import sys

    repo = tmp_path / "repo"
    repo.mkdir()
    where = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "where.exe"
    shutil.copyfile(where, repo / "git.exe")
    script = (
        "import contextlib, io, subprocess\n"
        "from skilltotal import cli\n"
        "with contextlib.redirect_stdout(io.StringIO()):\n"
        "    cli.main(['rules', 'list', '--json'])\n"
        "try:\n"
        "    done = subprocess.run(['git', '--version'], capture_output=True, text=True,\n"
        "                          timeout=60)\n"
        "    print(done.stdout.strip() or f'exit {done.returncode}, no output')\n"
        "except FileNotFoundError:\n"
        "    print('not found')\n"
    )
    env = {k: v for k, v in os.environ.items()
           if k.lower() != "nodefaultcurrentdirectoryinexepath"}
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    try:
        done = subprocess.run([sys.executable, "-c", script], cwd=repo, env=env,  # noqa: S603
                              capture_output=True, text=True, timeout=120)
    finally:
        (repo / "git.exe").unlink()  # no planted program is left behind
    assert done.returncode == 0, done.stderr
    shown = done.stdout.strip()
    assert shown.startswith("git version") or shown == "not found", shown
