"""Installed editor extensions in `inventory` / `guard --installed`, and update drift (--state).

A trojanized editor extension update (2026-10-29) arrived through a marketplace auto-update, with
no install command for the Claude Code hook to see; a scheduled inventory is where it shows up.
Every test builds a fake home in tmp_path and passes its own environment, so no real extension
folder on the machine running them is read. The pickle snippet is an inert detection fixture:
a string written to a temp file for the scanner to flag, never executed.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from skilltotal.cli import EXIT_ERROR, EXIT_FAIL_ON_HIGH, EXIT_OK, main
from skilltotal.drift import STATE_FORMAT, component_key, detect, load_state, record
from skilltotal.guard import evaluate_installed
from skilltotal.inventory import EDITOR_EXTENSION, discover
from skilltotal.sbom import build_aibom

CLEAN_JS = 'const vscode = require("vscode");\nexports.activate = () => {};\n'
# Deserializing untrusted data -> ST-DESERIALIZE-PY, a high risky construct.
PICKLE_PY = "import pickle\n\ndef load(blob):\n    return pickle.loads(blob)\n"

HOST_FOLDERS = [
    ("VS Code", ".vscode"),
    ("VS Code Insiders", ".vscode-insiders"),
    ("Cursor", ".cursor"),
    ("Windsurf", ".windsurf"),
    ("VSCodium", ".vscode-oss"),
    ("VS Code Server", ".vscode-server"),
    ("VSCodium Server", ".vscodium-server"),
    ("Cursor Server", ".cursor-server"),
]


@pytest.fixture
def home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    return home


def _extension(folder: Path, dirname: str, manifest: dict | str | None,
               files: dict[str, str] | None = None) -> Path:
    root = folder / dirname
    root.mkdir(parents=True)
    if manifest is not None:
        text = manifest if isinstance(manifest, str) else json.dumps(manifest)
        (root / "package.json").write_text(text, encoding="utf-8")
    for name, text in (files or {"extension.js": CLEAN_JS}).items():
        (root / name).write_text(text, encoding="utf-8")
    return root


def _manifest(name: str = "quillwidget", version: str = "1.0.0", publisher: str = "acme") -> dict:
    return {"name": name, "version": version, "publisher": publisher, "main": "extension.js"}


def _extensions(components):
    return [c for c in components if c.kind == EDITOR_EXTENSION]


# --- Discovery -----------------------------------------------------------------------------------


@pytest.mark.parametrize(("host", "folder"), HOST_FOLDERS)
def test_each_editor_folder_is_found(home, host, folder):
    root = _extension(home / folder / "extensions", "acme.quillwidget-1.0.0", _manifest())
    (found,) = _extensions(discover(home=home, environ={}))
    assert found.host == host
    assert found.name == "acme.quillwidget@1.0.0"
    assert found.version == "1.0.0"
    assert found.source == str(root)
    assert found.scannable
    assert found.config == str(home / folder / "extensions")


def test_vscode_extensions_variable_is_honoured(home, tmp_path):
    moved = tmp_path / "custom-extensions"
    _extension(moved, "acme.moved-2.0.0", _manifest("moved", "2.0.0"))
    found = _extensions(discover(home=home, environ={"VSCODE_EXTENSIONS": str(moved)}))
    assert [(c.host, c.name) for c in found] == [("VS Code (VSCODE_EXTENSIONS)",
                                                   "acme.moved@2.0.0")]


def test_the_same_folder_twice_is_listed_once(home):
    folder = home / ".vscode" / "extensions"
    _extension(folder, "acme.quillwidget-1.0.0", _manifest())
    found = _extensions(discover(home=home, environ={"VSCODE_EXTENSIONS": str(folder)}))
    assert len(found) == 1


def test_nothing_is_read_from_the_real_machine(home, tmp_path, monkeypatch):
    """A fake home means no VSCODE_EXTENSIONS from the process environment either."""
    elsewhere = tmp_path / "real-extensions"
    _extension(elsewhere, "acme.leak-1.0.0", _manifest("leak"))
    monkeypatch.setenv("VSCODE_EXTENSIONS", str(elsewhere))
    assert discover(home=home) == []


def test_obsolete_and_non_extension_entries_are_skipped(home):
    folder = home / ".vscode" / "extensions"
    _extension(folder, "acme.quillwidget-1.0.0", _manifest(version="1.0.0"))
    _extension(folder, "acme.quillwidget-1.1.0", _manifest(version="1.1.0"))
    _extension(folder, "acme.nomanifest-1.0.0", None)          # no package.json: not loaded
    _extension(folder, ".acme.tmp-1.0.0", _manifest("tmp"))    # the editor's own temp folder
    (folder / "extensions.json").write_text("[]", encoding="utf-8")
    (folder / "stray.txt").write_text("x", encoding="utf-8")
    # VS Code writes the keys in its own case; the folders are lower case.
    (folder / ".obsolete").write_text(json.dumps({"Acme.QuillWidget-1.0.0": True}),
                                      encoding="utf-8")
    names = [c.name for c in _extensions(discover(home=home, environ={}))]
    assert names == ["acme.quillwidget@1.1.0"]


def test_unreadable_obsolete_file_skips_nothing(home):
    folder = home / ".vscode" / "extensions"
    _extension(folder, "acme.quillwidget-1.0.0", _manifest())
    (folder / ".obsolete").write_text("{ not json", encoding="utf-8")
    assert len(_extensions(discover(home=home, environ={}))) == 1


def test_manifest_without_publisher_or_version(home):
    folder = home / ".cursor" / "extensions"
    _extension(folder, "bare-1", {"name": "bare"})
    _extension(folder, "nover-1", {"name": "nover", "publisher": "acme"})
    _extension(folder, "broken-1", "{ not json")
    _extension(folder, "odd-1", {"name": ["not", "a", "string"], "version": 3})
    found = {c.source.rsplit(os.sep, 1)[1]: c for c in _extensions(discover(home=home,
                                                                            environ={}))}
    assert found["bare-1"].name == "bare"
    assert found["nover-1"].name == "acme.nover"
    assert found["broken-1"].name == "broken-1"   # the folder name stands in
    assert found["odd-1"].name == "odd-1"
    assert all(c.version == "" for c in found.values())


def test_hidden_characters_in_a_manifest_name_are_shown(home):
    rlo = chr(0x202E)
    _extension(home / ".vscode" / "extensions", "acme.x-1.0.0",
               _manifest(name=f"safe{rlo}gnp"))
    (found,) = _extensions(discover(home=home, environ={}))
    assert rlo not in found.name
    assert "<U+202E>" in found.name


def _link_dir(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        try:
            import _winapi

            _winapi.CreateJunction(str(target), str(link))
        except (ImportError, OSError) as exc:
            pytest.skip(f"cannot create a link here: {exc}")


def test_link_out_of_the_extensions_folder_is_listed_not_scanned(home, tmp_path):
    folder = home / ".vscode" / "extensions"
    folder.mkdir(parents=True)
    outside = _extension(tmp_path / "elsewhere", "secret-place", _manifest("outside"))
    _link_dir(folder / "acme.linked-1.0.0", outside)
    (found,) = _extensions(discover(home=home, environ={}))
    assert found.name == "acme.linked-1.0.0"   # its manifest is not read through the link
    assert found.source is None
    assert not found.scannable
    assert "outside the extensions folder" in found.note


# --- Guard policy --------------------------------------------------------------------------------


def _report(risk_level: str, *, malicious: bool = False, typosquat: bool = False) -> dict:
    findings = [{"id": "ST-TYPOSQUAT", "threat_class": "risky_construct", "severity": "high",
                 "evidence": []}] if typosquat else []
    return {"risk_level": risk_level, "risk_score": 60 if risk_level == "high" else 0,
            "verdict": {"has_malicious_indicators": malicious}, "findings": findings,
            "needs_review": []}


def test_editor_extension_blocks_on_malicious_indicators_by_default():
    """Measured 2026-10-30: widely used language and debugger extensions score high (risky
    constructs in their bundled Python code), so `high` would block them on every machine."""
    high = _report("high", typosquat=True)
    assert evaluate_installed(high, EDITOR_EXTENSION).allow
    assert not evaluate_installed(high, "mcp_server").allow
    assert not evaluate_installed(high, EDITOR_EXTENSION, "high").allow
    assert not evaluate_installed(_report("low", malicious=True), EDITOR_EXTENSION).allow
    # The npm-style name in an extension's package.json is not what anyone installed it by.
    assert evaluate_installed(_report("low", typosquat=True), EDITOR_EXTENSION, "high").allow


# --- Drift (unit) --------------------------------------------------------------------------------


def _risky(rule: str, snippet: str, *, cls: str = "risky_construct",
           severity: str = "high") -> dict:
    return {"id": rule, "threat_class": cls, "severity": severity,
            "evidence": [{"file": "a.py", "line_start": 1, "snippet": snippet}]}


def test_drift_needs_a_version_change_and_new_risk():
    clean = {"findings": [_risky("ST-SHELL-PY", "os.system(x)", cls="capability")]}
    risky = {"findings": [_risky("ST-DESERIALIZE-PY", "pickle.loads(blob)")]}
    assert detect(None, risky, "2.0.0") is None                       # first sight
    assert detect(record(clean, "1.0.0"), clean, "2.0.0") is None     # capabilities never drift
    assert detect(record(clean, "1.0.0"), risky, "1.0.0") is None     # same version
    assert detect(record(risky, "1.0.0"), risky, "2.0.0") is None     # risk it already had
    drift = detect(record(clean, "1.0.0"), risky, "2.0.0")
    assert drift is not None
    assert (drift.old_version, drift.new_version, drift.rule_ids, drift.blocking) == (
        "1.0.0", "2.0.0", ["ST-DESERIALIZE-PY"], True)
    medium = {"findings": [_risky("ST-EXPOSE-BIND", "bind 0.0.0.0", severity="medium")]}
    assert detect(record(clean, "1.0.0"), medium, "2.0.0").blocking is False


def test_component_key_drops_the_version():
    assert component_key("VS Code", EDITOR_EXTENSION, "acme.x@1.2.3", "1.2.3") == \
        component_key("VS Code", EDITOR_EXTENSION, "acme.x@1.3.0", "1.3.0")


@pytest.mark.parametrize("text", ["{ not json", "[]", '{"format": "other"}',
                                  json.dumps({"format": STATE_FORMAT, "version": 99,
                                              "components": {}}),
                                  json.dumps({"format": STATE_FORMAT, "version": 1,
                                              "components": {"k": "v"}})])
def test_a_foreign_state_file_is_refused(text):
    from skilltotal.drift import StateError

    with pytest.raises(StateError):
        load_state(text)


# --- CLI -----------------------------------------------------------------------------------------


@pytest.fixture
def fake_home(home, monkeypatch):
    monkeypatch.setattr("skilltotal.inventory.discover",
                        lambda project=None: discover(home=home, project=project, environ={}))
    return home


def test_cli_inventory_json_lists_extensions(fake_home, capsys):
    _extension(fake_home / ".vscode" / "extensions", "acme.quillwidget-1.0.0", _manifest())
    assert main(["inventory", "--json"]) == EXIT_OK
    (item,) = json.loads(capsys.readouterr().out)
    assert (item["kind"], item["name"], item["version"]) == (
        EDITOR_EXTENSION, "acme.quillwidget@1.0.0", "1.0.0")
    assert item["guard"] == "allow"
    assert main(["inventory", "--json", "--no-extensions"]) == EXIT_OK
    assert json.loads(capsys.readouterr().out) == []


def test_cli_inventory_sbom_carries_the_extension_version(fake_home, capsys):
    _extension(fake_home / ".vscode" / "extensions", "acme.quillwidget-1.0.0", _manifest())
    assert main(["inventory", "--sbom", "--no-scan"]) == EXIT_OK
    (component,) = json.loads(capsys.readouterr().out)["components"]
    assert component["version"] == "1.0.0"
    assert {"name": "skilltotal:kind", "value": EDITOR_EXTENSION} in component["properties"]


def test_cli_guard_installed_checks_extensions(fake_home, capsys):
    _extension(fake_home / ".vscode" / "extensions", "acme.quillwidget-1.0.0", _manifest())
    assert main(["guard", "--installed"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "[ok] acme.quillwidget@1.0.0 (VS Code, editor_extension)" in out
    # Without the extensions nothing is left to check, which is never a pass.
    assert main(["guard", "--installed", "--no-extensions"]) == EXIT_ERROR


def test_state_flags_need_installed(capsys, tmp_path):
    assert main(["guard", str(tmp_path), "--state", str(tmp_path / "s.json")]) == EXIT_ERROR
    assert "--installed" in capsys.readouterr().err


def _update(folder: Path, old: str, new: str, version: str, files: dict[str, str]) -> None:
    shutil.rmtree(folder / old)
    _extension(folder, new, _manifest(version=version), files)


def test_cli_drift_after_an_update_that_adds_risk(fake_home, tmp_path, capsys):
    folder = fake_home / ".vscode" / "extensions"
    state = tmp_path / "state.json"
    _extension(folder, "acme.quillwidget-1.0.0", _manifest())

    # First run: records only.
    assert main(["guard", "--installed", "--state", str(state)]) == EXIT_OK
    capsys.readouterr()
    recorded = json.loads(state.read_text(encoding="utf-8"))
    assert recorded["format"] == STATE_FORMAT
    (entry,) = recorded["components"].values()
    assert entry == {"version": "1.0.0", "risk": []}

    # A clean update: no drift.
    _update(folder, "acme.quillwidget-1.0.0", "acme.quillwidget-1.1.0", "1.1.0",
            {"extension.js": CLEAN_JS + "// 1.1.0\n"})
    assert main(["guard", "--installed", "--state", str(state)]) == EXIT_OK
    assert "drift" not in capsys.readouterr().out

    # An update that adds a high risky construct: drift, and the guard blocks.
    _update(folder, "acme.quillwidget-1.1.0", "acme.quillwidget-1.2.0", "1.2.0",
            {"extension.js": CLEAN_JS, "quillwidget.py": PICKLE_PY})
    assert main(["guard", "--installed", "--state", str(state), "--json"]) == EXIT_FAIL_ON_HIGH
    (item,) = json.loads(capsys.readouterr().out)
    assert item["decision"] == "block"
    assert item["drift"]["from"] == "1.1.0" and item["drift"]["to"] == "1.2.0"
    assert "ST-DESERIALIZE-PY" in item["drift"]["rules"]
    assert any("gained risk findings" in reason for reason in item["reasons"])

    # The state holds ids, versions and fingerprints: nothing from the files.
    text = state.read_text(encoding="utf-8")
    assert "pickle" not in text and "require" not in text

    # Same version again: no drift, and the guard is back to its usual policy.
    assert main(["guard", "--installed", "--state", str(state)]) == EXIT_OK
    assert "drift" not in capsys.readouterr().out


def test_cli_inventory_reports_drift_in_text_json_and_sbom(fake_home, tmp_path, capsys):
    folder = fake_home / ".cursor" / "extensions"
    state = tmp_path / "state.json"
    _extension(folder, "acme.quillwidget-1.0.0", _manifest())
    assert main(["inventory", "--json", "--state", str(state)]) == EXIT_OK
    capsys.readouterr()
    _update(folder, "acme.quillwidget-1.0.0", "acme.quillwidget-2.0.0", "2.0.0",
            {"extension.js": CLEAN_JS, "quillwidget.py": PICKLE_PY})
    # --state is updated on every run, so each format below gets its own copy of the old state.
    old = state.read_text(encoding="utf-8")

    assert main(["inventory", "--state", str(state)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "acme.quillwidget@2.0.0: updated from 1.0.0 to 2.0.0 and gained risk findings" in out

    state.write_text(old, encoding="utf-8")
    assert main(["inventory", "--sbom", "--state", str(state)]) == EXIT_OK
    (component,) = json.loads(capsys.readouterr().out)["components"]
    drift = {p["name"]: p["value"] for p in component["properties"]}["skilltotal:drift"]
    assert drift.startswith("1.0.0 -> 2.0.0: ") and "ST-DESERIALIZE-PY" in drift


def test_cli_corrupt_state_is_an_error_and_is_kept(fake_home, tmp_path, capsys):
    _extension(fake_home / ".vscode" / "extensions", "acme.quillwidget-1.0.0", _manifest())
    state = tmp_path / "state.json"
    state.write_text("{ not json", encoding="utf-8")
    assert main(["guard", "--installed", "--state", str(state)]) == EXIT_ERROR
    assert "cannot use the state file" in capsys.readouterr().err
    assert state.read_text(encoding="utf-8") == "{ not json"
    assert main(["inventory", "--no-scan", "--state", str(state)]) == EXIT_ERROR


def test_drift_build_aibom_without_drift_has_no_property():
    (component,) = build_aibom([{"name": "x", "kind": EDITOR_EXTENSION}])["components"]
    assert all(p["name"] != "skilltotal:drift" for p in component["properties"])
