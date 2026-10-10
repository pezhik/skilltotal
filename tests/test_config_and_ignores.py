"""Phase A — config file, rule/inline ignores, and path excludes."""

from __future__ import annotations

from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.config import load_config
from skilltotal.engine import analyze_directory


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


def test_config_invalid_level_is_dropped(tmp_path: Path):
    p = tmp_path / ".skilltotal.toml"
    p.write_text('fail_on = "bogus"\n', encoding="utf-8")
    assert load_config(p).fail_on is None


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
    code = "import marshal\nexec(marshal.loads(d))  # skilltotal:ignore[ST-OBF-DECODE-EXEC-PY]\n"
    (tmp_path / "m.py").write_text(code, encoding="utf-8", newline="")
    ids = _ids(_analyze(tmp_path, inline_ignores=True))
    assert "ST-OBF-DECODE-EXEC-PY" not in ids
    assert "ST-DYN-PY" in ids  # a targeted ignore leaves other rules on the line intact


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
