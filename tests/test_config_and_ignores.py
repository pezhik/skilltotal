"""Phase A — config file, rule/inline ignores, and path excludes."""

from __future__ import annotations

from pathlib import Path

import pytest

import skilltotal.config as config_module
from skilltotal.collector import detect_component
from skilltotal.config import ConfigError, load_config
from skilltotal.engine import analyze_directory


def _use_parser(monkeypatch, parser: str) -> None:
    """``fallback`` is the parser Python 3.10 (no tomllib) runs; test it on every version."""
    if parser == "fallback":
        monkeypatch.setattr(config_module, "tomllib", None)
    elif config_module.tomllib is None:
        pytest.skip("no tomllib on this Python")


DOCUMENTED = (
    'fail_on = "high"           # comment\n'
    "fail_on_score = 50\n"
    "fail_on_unanalyzed = true\n"
    'exclude = ["vendor/*", "*.min.js"]\n'
    'ignore = ["ST-NET-PY"]\n'
    'baseline = ".skilltotal-baseline.json"\n'
    "\n"
    "[policy]\n"
    "# accepted\n"
    '"ST-SHELL-PIPE-EXEC" = "block"   # trips\n'
    '"ST-SENS-WORD" = "ignore"\n'
)


@pytest.mark.parametrize("parser", ["tomllib", "fallback"])
def test_both_parsers_read_the_documented_config_alike(tmp_path: Path, monkeypatch, parser):
    _use_parser(monkeypatch, parser)
    p = tmp_path / ".skilltotal.toml"
    p.write_text(DOCUMENTED, encoding="utf-8")
    cfg = load_config(p)
    assert cfg.fail_on_score == 50
    assert cfg.exclude == ["vendor/*", "*.min.js"]
    assert cfg.policy == {"ST-SHELL-PIPE-EXEC": "block", "ST-SENS-WORD": "ignore"}


def _analyze(root: Path, **kw):
    return analyze_directory(root, detect_component(root, source=str(root)), **kw)


def _ids(report) -> set[str]:
    return {f.id for f in report.findings}


# --- config parsing -----------------------------------------------------------------

def test_config_parses_all_keys(tmp_path: Path):
    p = tmp_path / ".skilltotal.toml"
    p.write_text(
        'fail_on = "medium"\n'
        "fail_on_score = 40\n"
        'exclude = ["vendor/*", "*.min.js"]\n'
        'ignore = ["ST-NET-PY"]\n'
        'baseline = "bl.json"\n',
        encoding="utf-8",
    )
    c = load_config(p)
    assert c.fail_on == "medium"
    assert c.fail_on_score == 40
    assert c.exclude == ["vendor/*", "*.min.js"]
    assert c.ignore == ["ST-NET-PY"]
    assert c.baseline == "bl.json"


def test_config_invalid_level_is_an_error_not_a_gate_switched_off(tmp_path: Path):
    # Read leniently, `fail_on = "hgih"` was dropped and the CI gate it set was off, exit 0.
    p = tmp_path / ".skilltotal.toml"
    p.write_text('fail_on = "bogus"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="fail_on must be one of"):
        load_config(p)


@pytest.mark.parametrize(("text", "message"), [
    ('fail_on = "high\n', "not valid TOML"),
    ('fail_onn = "high"\n', "unknown key"),
    ("fail_on_score = 200\n", "from 0 to 100"),
    ('fail_on_score = "abc"\n', "from 0 to 100"),
    ('exclude = "vendor/*"\n', "list of non-empty strings"),
    ('[policy]\n"ST-SHELL-PY" = "blok"\n', "block, warn or ignore"),
    ('[policy]\n"ST-SHELL-PY" = block\n', "not valid TOML"),
    ('[polcy]\n"ST-SHELL-PY" = "block"\n', "unknown key"),
])
@pytest.mark.parametrize("parser", ["tomllib", "fallback"])
def test_a_config_that_cannot_be_honored_is_an_error(tmp_path: Path, monkeypatch, text, message,
                                                     parser):
    # The fallback is what Python 3.10 (no tomllib) runs: it must be as strict, on every version.
    _use_parser(monkeypatch, parser)
    p = tmp_path / ".skilltotal.toml"
    p.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_config(p)


def test_a_bad_config_fails_the_scan_with_exit_1(tmp_path: Path, monkeypatch, capsys):
    from skilltotal.cli import main

    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".skilltotal.toml").write_text('fail_on = "hgih"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert main(["scan", str(tmp_path)]) == 1
    assert "error:" in capsys.readouterr().err


def test_a_missing_config_file_fails_the_scan_with_exit_1(tmp_path: Path, capsys):
    from skilltotal.cli import main

    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--config", str(tmp_path / "nope.toml")]) == 1
    assert "cannot read config" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["200", "-5", "abc"])
def test_a_score_threshold_outside_0_to_100_is_refused(tmp_path: Path, value):
    from skilltotal.cli import main

    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(tmp_path), "--fail-on-score", value])
    assert exc.value.code != 0


def test_an_unwritable_output_is_an_error_not_a_traceback(tmp_path: Path, capsys):
    from skilltotal.cli import main

    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    out = tmp_path / "no-such-dir" / "r.json"
    assert main(["scan", str(tmp_path), "--json", "--output", str(out)]) == 1
    assert "cannot write the report" in capsys.readouterr().err


def test_config_with_utf8_bom_is_parsed(tmp_path: Path):
    # Windows editors / PowerShell often write a UTF-8 BOM. tomllib rejects a BOM, so without
    # utf-8-sig the whole config is silently dropped — which would disable a configured CI gate.
    p = tmp_path / ".skilltotal.toml"
    p.write_bytes(b"\xef\xbb\xbf" + b'fail_on = "high"\nfail_on_score = 30\n')
    c = load_config(p)
    assert c.fail_on == "high"
    assert c.fail_on_score == 30


# --- rule-id ignore -----------------------------------------------------------------

def test_ignore_rules_drops_whole_rule(tmp_path: Path):
    (tmp_path / "m.py").write_text("eval(user_input)\n", encoding="utf-8", newline="")
    assert "ST-DYN-PY" in _ids(_analyze(tmp_path))
    assert "ST-DYN-PY" not in _ids(_analyze(tmp_path, ignore_rules={"ST-DYN-PY"}))


# --- inline ignore ------------------------------------------------------------------
# A marker is the code owner's decision, so it counts only when the caller says the code is the
# person's own (`scan` of a local directory). In a package someone else wrote, one comment from
# its author would otherwise silence the finding that should stop the install.

def test_inline_ignore_bare_marker(tmp_path: Path):
    (tmp_path / "m.py").write_text("eval(x)  # skilltotal:ignore\n", encoding="utf-8", newline="")
    assert "ST-DYN-PY" not in _ids(_analyze(tmp_path, inline_ignores=True))


def test_inline_ignore_targeted_id(tmp_path: Path):
    code = "import pickle\nexec(pickle.loads(d))  # skilltotal:ignore[ST-DESERIALIZE-PY]\n"
    (tmp_path / "m.py").write_text(code, encoding="utf-8", newline="")
    ids = _ids(_analyze(tmp_path, inline_ignores=True))
    assert "ST-DESERIALIZE-PY" not in ids
    assert "ST-DYN-PY" in ids  # a targeted ignore leaves other rules on the line intact


@pytest.mark.parametrize(
    "marker", ["# skilltotal:ignore", "# skilltotal:ignore[ST-OBF-DECODE-EXEC-PY]"]
)
def test_an_inline_marker_never_hides_a_malicious_indicator(tmp_path: Path, marker: str):
    """A folder scanned as local is not always the reader's own code (an unpacked package or
    skill), so a marker its author wrote must not silence a malicious indicator (2026-10-15)."""
    code = f"import marshal\nexec(marshal.loads(d))  {marker}\n"
    (tmp_path / "m.py").write_text(code, encoding="utf-8", newline="")
    report = _analyze(tmp_path, inline_ignores=True)
    assert "ST-OBF-DECODE-EXEC-PY" in _ids(report)
    assert report.verdict["has_malicious_indicators"]
    notes = [n for n in report.needs_review if n.category == "suppression"]
    assert notes and "ST-OBF-DECODE-EXEC-PY" in notes[0].reason
    assert "baseline" in notes[0].reason


def test_inline_ignore_on_line_above(tmp_path: Path):
    (tmp_path / "m.py").write_text(
        "# skilltotal:ignore[ST-DYN-PY]\neval(x)\n", encoding="utf-8", newline=""
    )
    assert "ST-DYN-PY" not in _ids(_analyze(tmp_path, inline_ignores=True))


def test_a_package_cannot_silence_its_own_findings(tmp_path: Path):
    # Found by a pre-launch audit: a dropper with the marker on the same line scanned as clean.
    (tmp_path / "index.js").write_text(
        "eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString()); // skilltotal:ignore\n",
        encoding="utf-8", newline="",
    )
    report = _analyze(tmp_path)
    assert "ST-OBF-DECODE-EXEC" in _ids(report)
    assert report.verdict["has_malicious_indicators"]


def test_an_honored_marker_is_counted_as_suppressed(tmp_path: Path):
    (tmp_path / "m.py").write_text("eval(x)  # skilltotal:ignore\n", encoding="utf-8", newline="")
    assert _analyze(tmp_path, inline_ignores=True).metadata["suppressed_count"] == 1
    assert _analyze(tmp_path).metadata["suppressed_count"] == 0


def test_scan_honors_markers_only_in_a_local_directory(tmp_path: Path, capsys):
    import io
    import json
    import tarfile

    from skilltotal.cli import main

    code = b"eval(x)  # skilltotal:ignore\n"
    project = tmp_path / "project"
    project.mkdir()
    (project / "m.py").write_bytes(code)
    archive = tmp_path / "pkg.tgz"
    with tarfile.open(archive, "w:gz") as tf:
        info = tarfile.TarInfo("package/m.py")
        info.size = len(code)
        tf.addfile(info, io.BytesIO(code))

    main(["scan", str(project), "--json"])
    own = json.loads(capsys.readouterr().out)
    main(["scan", str(archive), "--json"])
    downloaded = json.loads(capsys.readouterr().out)

    assert "ST-DYN-PY" not in {f["id"] for f in own["findings"]}
    assert "ST-DYN-PY" in {f["id"] for f in downloaded["findings"]}


# --- path exclude -------------------------------------------------------------------

def test_exclude_glob_skips_file(tmp_path: Path):
    (tmp_path / "keep.py").write_text("eval(a)\n", encoding="utf-8", newline="")
    (tmp_path / "skip.py").write_text("eval(b)\n", encoding="utf-8", newline="")
    report = _analyze(tmp_path, exclude=["skip.py"])
    dyn = next(f for f in report.findings if f.id == "ST-DYN-PY")
    files = {e.file for e in dyn.evidence}
    assert "keep.py" in files
    assert "skip.py" not in files
