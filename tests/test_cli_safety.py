"""The CLI runs inside repositories it does not trust (pre-commit, CI): what it starts, writes,
prints and reads from them must not be the repository's to choose.

Covers: git resolved from PATH only, report files never written through a link, file names that
cannot forge report or log lines, SIGTERM cleanup, the scanned repository's config named in the
output, `--no-config`, `--fail-on none` / `--fail-on-default`, gate reasons on stderr, unknown rule
ids in a config, `--write-baseline` exiting 0, SARIF locations and category, and error messages.
The snippets are inert detection fixtures written to temp files; nothing runs them.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess  # nosec B404 - runs git with fixed arguments in a temp repository
from dataclasses import replace
from pathlib import Path

import pytest

from skilltotal import cli
from skilltotal.cli import EXIT_ERROR, EXIT_FAIL_ON_HIGH, EXIT_OK, main
from skilltotal.collector import CollectionError, collect, find_program
from skilltotal.engine import analyze_directory
from skilltotal.models import Component
from skilltotal.report import render_text
from skilltotal.sarif import artifact_uri, render_sarif

# ST-DESERIALIZE-PY: high severity, risky construct.
RISKY = "import pickle\nobj = pickle.loads(blob)\n"
# ST-DYN-PY: high severity, capability.
CAPABILITY = "eval(user_input)\n"


def _component(tmp_path: Path, files: dict[str, str], name: str = "component") -> Path:
    root = tmp_path / name
    root.mkdir()
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body, encoding="utf-8", newline="")
    return root


# --- 1. git comes from PATH, never from the current directory ---------------------------------

def _plant(folder: Path, marker: Path) -> str:
    """A fake git in ``folder`` that leaves ``marker`` behind if anything runs it."""
    if os.name == "nt":
        name = "git.bat"
        (folder / name).write_text(f'@echo off\r\necho planted> "{marker}"\r\n', encoding="utf-8")
    else:
        name = "git"
        (folder / name).write_text(f"#!/bin/sh\necho planted > '{marker}'\n", encoding="utf-8")
        (folder / name).chmod(0o755)
    return name


def test_find_program_skips_the_current_directory_and_relative_path_entries(tmp_path, monkeypatch):
    repo, bin_dir = tmp_path / "repo", tmp_path / "bin"
    repo.mkdir()
    bin_dir.mkdir()
    name = _plant(repo, tmp_path / "ran")
    _plant(bin_dir, tmp_path / "ran")
    monkeypatch.chdir(repo)
    env = {"PATH": os.pathsep.join([".", "", "repo", str(bin_dir)]), "PATHEXT": ".EXE;.BAT"}
    found = find_program("git", env)
    assert found is not None
    assert os.path.normcase(found) == os.path.normcase(str(bin_dir / name))
    assert find_program("git", {"PATH": os.pathsep.join([".", ""]), "PATHEXT": ".EXE;.BAT"}) is None


def test_staged_scan_never_runs_a_git_planted_in_the_repository(tmp_path, monkeypatch, capsys):
    # The pre-commit hook runs `skilltotal scan --staged .` inside the repository being committed;
    # Python 3.10/3.11 `shutil.which` on Windows looked in the current directory first.
    repo = _component(tmp_path, {"app.py": "x = 1\n"}, "repo")
    marker = tmp_path / "ran"
    _plant(repo, marker)
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PATH", os.pathsep.join([".", ""]))
    assert main(["scan", "--staged", "."]) == EXIT_ERROR
    assert "git is not installed" in capsys.readouterr().err
    assert not marker.exists()


def test_a_remote_scan_never_runs_a_git_planted_in_the_current_directory(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    _plant(tmp_path, marker)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", ".")
    with pytest.raises(CollectionError, match="git is required"):
        with collect("https://github.com/example/example"):
            pass
    assert not marker.exists()


# --- 2. a report file is never written through a link ----------------------------------------

def _link_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create a symbolic link here: {exc}")


@pytest.mark.parametrize("flag", ["--output", "--write-baseline"])
def test_a_report_path_that_is_a_link_is_refused(tmp_path, capsys, flag):
    root = _component(tmp_path, {"m.py": RISKY})
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me", encoding="utf-8")
    link = root / "skilltotal.sarif"
    _link_or_skip(link, outside)
    assert main(["scan", str(root), "--sarif", flag, str(link)]) == EXIT_ERROR
    assert "symbolic link" in capsys.readouterr().err
    assert outside.read_text(encoding="utf-8") == "keep me"


@pytest.mark.skipif(os.name != "nt", reason="junctions are a Windows feature")
def test_a_report_path_that_is_a_junction_is_refused(tmp_path, capsys):
    root = _component(tmp_path, {"m.py": RISKY})
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "report.json"
    done = subprocess.run(  # nosec B603 B607 - cmd's own mklink, fixed arguments
        ["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True, check=False)
    if done.returncode != 0:
        pytest.skip("cannot create a junction here")
    assert main(["scan", str(root), "--output", str(link)]) == EXIT_ERROR
    assert "symbolic link or junction" in capsys.readouterr().err
    assert list(outside.iterdir()) == []


def test_a_report_file_is_replaced_whole_and_leaves_no_temp_file(tmp_path, capsys):
    root = _component(tmp_path, {"m.py": RISKY})
    out = tmp_path / "out" / "report.json"
    out.parent.mkdir()
    out.write_text("old", encoding="utf-8")
    assert main(["scan", str(root), "--output", str(out)]) == EXIT_OK
    assert json.loads(out.read_text(encoding="utf-8"))["findings"]
    assert [p.name for p in out.parent.iterdir()] == ["report.json"]


# --- 3. a file name cannot forge a line --------------------------------------------------------

SPOOF = "a\n::error title=SPOOF::x\r\n.js"


def _spoofed_report(tmp_path):
    root = _component(tmp_path, {"m.py": RISKY})
    report = analyze_directory(root, Component(name="c", type="directory", source=str(root)))
    finding = report.findings[0]
    report.findings[0] = replace(
        finding, evidence=[replace(finding.evidence[0], file=SPOOF)])
    return report


def test_a_file_name_with_a_newline_stays_on_its_line_in_the_text_report(tmp_path):
    text = render_text(_spoofed_report(tmp_path))
    assert not any(line.lstrip().startswith("::") for line in text.splitlines())
    assert "a<U+000A>::error title=SPOOF::x<U+000D><U+000A>.js" in text


def test_sarif_locations_are_percent_encoded_uri_references(tmp_path):
    assert artifact_uri("a b/c#d%e?.js") == "a%20b/c%23d%25e%3F.js"
    assert artifact_uri("a:b.js") == "a%3Ab.js"  # never reads as a URI scheme
    assert artifact_uri("x.py", "fx-high") == "fx-high/x.py"
    assert artifact_uri("x.py", "./") == "x.py"
    doc = json.loads(render_sarif(_spoofed_report(tmp_path)))
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in doc["runs"][0]["results"]]
    assert "a%0A::error%20title=SPOOF::x%0D%0A.js".replace("::", "%3A%3A") in uris


def test_the_action_log_prints_file_names_on_one_line(tmp_path):
    # The step that lists findings in the Action log, run as the runner runs it.
    import re
    import sys
    import textwrap

    action = (Path(__file__).resolve().parent.parent / "action.yml").read_text(encoding="utf-8")
    code = re.search(r'python -I -c "\n(.*?def safe.*?)\n\s*" "\$REPORT_JSON"', action, re.S)
    assert code is not None
    report = tmp_path / "r.json"
    findings = [{"id": "ST-X", "severity": "high", "title": "t", "threat_class": "risky_construct",
                 "evidence": [{"file": SPOOF, "line_start": i + 1} for i in range(12)]}]
    report.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    done = subprocess.run(  # nosec B603 - this interpreter, the action's own snippet
        [sys.executable, "-I", "-c", textwrap.dedent(code.group(1)), str(report)],
        capture_output=True, text=True, encoding="utf-8", check=True)
    lines = done.stdout.splitlines()
    assert not any(line.lstrip().startswith("::") for line in lines)
    assert sum("SPOOF" in line for line in lines) == 10  # every location, up to 10
    assert "... and 2 more location(s)" in done.stdout
    # The log runs with workflow commands off while scanned text is printed.
    assert 'echo "::stop-commands::$STOP_TOKEN"' in action
    assert 'echo "::$STOP_TOKEN::"' in action


# --- 4. SIGTERM ends a scan the way Ctrl-C does ------------------------------------------------

def test_sigterm_raises_so_temporary_folders_are_removed():
    previous = signal.getsignal(signal.SIGTERM)
    try:
        cli._exit_on_sigterm()
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        with pytest.raises(SystemExit) as caught:
            handler(signal.SIGTERM, None)
        assert caught.value.code == 128 + signal.SIGTERM
    finally:
        signal.signal(signal.SIGTERM, previous)


@pytest.mark.skipif(os.name == "nt", reason="SIGTERM ends a Windows process without a handler")
def test_sigterm_during_a_scan_removes_the_temporary_folder(tmp_path):
    import sys
    import time

    script = (
        "import sys, tempfile, time\n"
        "from skilltotal import cli\n"
        "cli._exit_on_sigterm()\n"
        "with tempfile.TemporaryDirectory(dir=sys.argv[1]) as d:\n"
        "    print(d, flush=True)\n"
        "    time.sleep(30)\n"
    )
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parent.parent)}
    proc = subprocess.Popen(  # nosec B603 - this interpreter, a fixed script
        [sys.executable, "-c", script, str(tmp_path)], stdout=subprocess.PIPE, text=True, env=env)
    folder = Path(proc.stdout.readline().strip())
    assert folder.is_dir()
    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=20) == 128 + signal.SIGTERM
    time.sleep(0.1)
    assert not folder.exists()


# --- 5. the scanned repository's config is named; --no-config ignores it -----------------------

def _config(folder: Path, text: str) -> Path:
    path = folder / ".skilltotal.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_an_applied_config_is_named_in_the_report_and_the_log(tmp_path, monkeypatch, capsys):
    root = _component(tmp_path, {"m.py": RISKY, "vendor/v.py": RISKY})
    _config(root, 'exclude = ["vendor/*"]\nignore = ["ST-DYN-PY"]\nfail_on = "critical"\n')
    monkeypatch.chdir(root)
    out = root.parent / "r.json"
    assert main(["scan", ".", "--output", str(out)]) == EXIT_OK
    applied = json.loads(out.read_text(encoding="utf-8"))["metadata"]["config_applied"]
    assert applied == {"path": ".skilltotal.toml", "exclude": 1, "ignore": 1, "policy": 0,
                       "fail_on": "critical"}
    text = capsys.readouterr().out
    assert ("Config    : .skilltotal.toml (1 exclude(s), 1 ignored rule(s), "
            "0 policy override(s), fail_on = critical)") in text
    # With the report on stdout, the log names it.
    assert main(["scan", ".", "--json"]) == EXIT_OK
    assert "config applied: .skilltotal.toml (1 exclude(s)" in capsys.readouterr().err


def test_no_config_ignores_the_repository_config(tmp_path, monkeypatch, capsys):
    root = _component(tmp_path, {"m.py": RISKY})
    _config(root, 'exclude = ["m.py"]\n')
    monkeypatch.chdir(root)
    assert main(["scan", ".", "--json", "--fail-on", "high"]) == EXIT_OK  # excluded by the config
    assert "config_applied" in capsys.readouterr().out
    assert main(["scan", ".", "--json", "--fail-on", "high", "--no-config"]) == EXIT_FAIL_ON_HIGH
    captured = capsys.readouterr()
    assert "config_applied" not in captured.out
    assert "config applied" not in captured.err
    with pytest.raises(SystemExit):
        main(["scan", ".", "--config", ".skilltotal.toml", "--no-config"])


# --- 6. --fail-on none and --fail-on-default ---------------------------------------------------

def test_fail_on_none_turns_every_config_gate_off(tmp_path, monkeypatch, capsys):
    root = _component(tmp_path, {"m.py": RISKY})
    _config(root, 'fail_on = "low"\nfail_on_score = 1\n[policy]\n"ST-DESERIALIZE-PY" = "block"\n')
    monkeypatch.chdir(root)
    assert main(["scan", ".", "--json"]) == EXIT_FAIL_ON_HIGH
    assert main(["scan", ".", "--json", "--fail-on", "none"]) == EXIT_OK
    # A gate set by a flag next to it still counts.
    assert main(["scan", ".", "--json", "--fail-on", "none", "--fail-on-score", "1"]) == 2


def test_fail_on_default_applies_only_when_nothing_sets_a_gate(tmp_path, monkeypatch, capsys):
    root = _component(tmp_path, {"m.py": RISKY})
    monkeypatch.chdir(root)
    assert main(["scan", ".", "--json", "--fail-on-default", "high"]) == EXIT_FAIL_ON_HIGH
    _config(root, 'fail_on = "critical"\n')  # the config's gate wins over the default
    assert main(["scan", ".", "--json", "--fail-on-default", "high"]) == EXIT_OK
    _config(root, "fail_on_score = 90\n")
    assert main(["scan", ".", "--json", "--fail-on-default", "high"]) == EXIT_OK
    _config(root, 'exclude = ["nothing/*"]\n')  # a config without a gate: the default applies
    assert main(["scan", ".", "--json", "--fail-on-default", "high"]) == EXIT_FAIL_ON_HIGH


# --- 7. a tripped gate says which one and why --------------------------------------------------

def test_a_tripped_gate_says_why_on_stderr(tmp_path, capsys):
    root = _component(tmp_path, {"m.py": RISKY, "n.py": RISKY})
    assert main(["scan", str(root), "--json", "--fail-on", "high"]) == EXIT_FAIL_ON_HIGH
    err = capsys.readouterr().err
    assert "gate: --fail-on high tripped by ST-DESERIALIZE-PY (" in err
    assert ".py:2)" in err
    assert main(["scan", str(root), "--json", "--fail-on-score", "1"]) == EXIT_FAIL_ON_HIGH
    assert "gate: --fail-on-score 1 tripped: risk score " in capsys.readouterr().err
    cfg = _config(tmp_path, '[policy]\n"ST-DYN-PY" = "block"\n')
    cap = _component(tmp_path, {"m.py": CAPABILITY}, "cap")
    assert main(["scan", str(cap), "--json", "--config", str(cfg)]) == EXIT_FAIL_ON_HIGH
    assert 'gate: [policy] "ST-DYN-PY" = "block" tripped by ST-DYN-PY (m.py:1)' in (
        capsys.readouterr().err)


def test_a_passing_gate_prints_nothing_about_gates(tmp_path, capsys):
    root = _component(tmp_path, {"m.py": "x = 1\n"})
    assert main(["scan", str(root), "--json", "--fail-on", "low"]) == EXIT_OK
    assert "gate:" not in capsys.readouterr().err


# --- 8. a rule id no rule has is an error ------------------------------------------------------

@pytest.mark.parametrize("text", [
    'ignore = ["ST-SHEL-PY"]\n',
    '[policy]\n"ST-SHEL-PY" = "block"\n',
])
def test_an_unknown_rule_id_in_the_config_stops_the_scan(tmp_path, capsys, text):
    root = _component(tmp_path, {"m.py": RISKY})
    cfg = _config(tmp_path, text)
    assert main(["scan", str(root), "--config", str(cfg)]) == EXIT_ERROR
    err = capsys.readouterr().err
    assert "unknown rule id 'ST-SHEL-PY'" in err
    assert "did you mean ST-SHELL-PY?" in err


def test_synthesized_rule_ids_are_known(tmp_path, capsys):
    root = _component(tmp_path, {"m.py": RISKY})
    cfg = _config(tmp_path, 'ignore = ["ST-COMBO-EXFIL", "ST-CONVERGENCE"]\n')
    assert main(["scan", str(root), "--json", "--config", str(cfg)]) == EXIT_OK


# --- 11. --write-baseline is an adoption step: exit 0 ------------------------------------------

def test_write_baseline_exits_zero_even_with_a_gate(tmp_path, capsys):
    root = _component(tmp_path, {"m.py": RISKY})
    baseline = tmp_path / "bl.json"
    assert main(["scan", str(root), "--fail-on", "low", "--write-baseline", str(baseline)]) == 0
    assert json.loads(baseline.read_text(encoding="utf-8"))["suppressed"]
    # ...and with it the same gate passes.
    assert main(["scan", str(root), "--json", "--fail-on", "low", "--baseline", str(baseline)]) == 0


# --- 12. SARIF paths from the repository root, and a category --------------------------------

def test_sarif_uri_prefix_and_category(tmp_path, capsys):
    root = _component(tmp_path, {"m.py": RISKY}, "fx-high")
    out = tmp_path / "s.sarif"
    assert main(["scan", str(root), "--sarif", "--output", str(out),
                 "--sarif-uri-prefix", "fx-high", "--sarif-category", "skilltotal/fx-high"]) == 0
    run = json.loads(out.read_text(encoding="utf-8"))["runs"][0]
    assert run["automationDetails"] == {"id": "skilltotal/fx-high/"}
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in run["results"]}
    assert uris == {"fx-high/m.py"}


def test_sarif_without_options_is_unchanged(tmp_path, capsys):
    root = _component(tmp_path, {"m.py": RISKY})
    assert main(["scan", str(root), "--sarif"]) == EXIT_OK
    run = json.loads(capsys.readouterr().out)["runs"][0]
    assert "automationDetails" not in run
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "m.py"


# --- 16/17. suppression said in the text report; messages ------------------------------------

# Two occurrences, one marked; a blank line keeps the marker off the second one (a marker also
# covers the line below it).
IGNORED_ONE_OF_TWO = (
    "import pickle\nobj = pickle.loads(b)  # skilltotal:ignore\n\nother = pickle.loads(c)\n"
)

def test_the_text_report_says_what_was_suppressed_and_how_to_suppress(tmp_path, capsys):
    root = _component(tmp_path, {"m.py": IGNORED_ONE_OF_TWO})
    assert main(["scan", str(root)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "1 finding occurrence(s) suppressed by a baseline or an inline skilltotal:ignore" in out
    assert "To accept a false positive: put `# skilltotal:ignore[RULE-ID]` on its line" in out


def test_the_occurrence_count_is_what_is_left_after_suppression(tmp_path):
    root = _component(tmp_path, {"m.py": IGNORED_ONE_OF_TWO})
    from skilltotal.engine import analyze

    report = analyze(str(root), inline_ignores=True)
    finding = next(f for f in report.findings if f.id == "ST-DESERIALIZE-PY")
    assert len(finding.evidence) == 1
    assert "occurrence(s) shown as evidence" not in finding.description


def test_a_missing_archive_is_not_offered_as_a_package_name(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["scan", "risky.zip"]) == EXIT_ERROR
    err = capsys.readouterr().err
    assert "Path does not exist: risky.zip" in err and "npm:" not in err
    assert main(["scan", "lodash"]) == EXIT_ERROR
    assert "npm:lodash or pypi:lodash" in capsys.readouterr().err


def test_an_npm_range_says_to_pin_an_exact_version(capsys):
    assert main(["scan", "npm:left-pad@^1.0.0"]) == EXIT_ERROR  # refused before any request
    assert "ranges are not supported" in capsys.readouterr().err


def test_fail_on_help_lists_the_levels(capsys):
    with pytest.raises(SystemExit):
        main(["scan", "--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert "low, medium, high or critical" in help_text
    assert "--no-config" in help_text


def test_a_config_baseline_is_read_relative_to_the_config(tmp_path, monkeypatch, capsys):
    root = _component(tmp_path, {"m.py": RISKY})
    conf_dir = tmp_path / "conf"
    conf_dir.mkdir()
    assert main(["scan", str(root), "--write-baseline", str(conf_dir / "bl.json")]) == EXIT_OK
    cfg = _config(conf_dir, 'baseline = "bl.json"\nfail_on = "low"\n')
    monkeypatch.chdir(tmp_path)  # not the config's folder
    assert main(["scan", str(root), "--json", "--config", str(cfg)]) == EXIT_OK
