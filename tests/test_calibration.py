"""Regression tests for false-positive calibration against real components."""

from __future__ import annotations

from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.file_index import FileIndex, is_test_path
from skilltotal.scanners.install_scripts import InstallScriptsScanner
from skilltotal.scanners.sensitive_paths import SensitivePathScanner

_NODE_SHELL = "const cp = require('child_process');\ncp.exec('ls');\n"


def _write(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8", newline="")


# --- is_test_path -------------------------------------------------------------
def test_is_test_path():
    assert is_test_path("__tests__/a.test.ts")
    assert is_test_path("src/foo.spec.js")
    assert is_test_path("tests/test_thing.py")
    assert is_test_path("pkg/conftest.py")
    assert not is_test_path("src/index.ts")
    assert not is_test_path("lib/contest.py")  # not 'conftest'


# --- sensitive paths: process.env must not be flagged -------------------------
def _sens(tmp_path: Path, content: str):
    _write(tmp_path, "f.js", content)
    return SensitivePathScanner().scan(FileIndex.build(tmp_path))


def test_process_env_is_not_sensitive_path(tmp_path: Path):
    result = _sens(tmp_path, "const p = process.env.PORT || 3001;\n")
    assert result.findings == []
    assert result.needs_review == []


def test_env_file_is_sensitive_path(tmp_path: Path):
    result = _sens(tmp_path, "fs.writeFile(path.join(d, '.env'), data);\n")
    assert any(f.id == "ST-SENS-PATH" for f in result.findings)


def test_ssh_key_is_sensitive_path(tmp_path: Path):
    result = _sens(tmp_path, "open('~/.ssh/id_rsa')\n")
    assert any(f.id == "ST-SENS-PATH" for f in result.findings)


def test_bare_secret_word_goes_to_needs_review(tmp_path: Path):
    result = _sens(tmp_path, "const credentials = loadConfig();\n")
    assert result.findings == []
    assert any("secret-related word" in n.title for n in result.needs_review)


# --- prepare hook severity ----------------------------------------------------
def test_prepare_is_medium_install_high(tmp_path: Path):
    _write(
        tmp_path,
        "package.json",
        '{\n  "scripts": {\n    "postinstall": "node x.js",\n'
        '    "prepare": "npm run build"\n  }\n}\n',
    )
    result = InstallScriptsScanner().scan(FileIndex.build(tmp_path))
    by_id = {f.id: f for f in result.findings}
    assert by_id["ST-INSTALL-NPM"].severity.value == "high"
    assert by_id["ST-INSTALL-NPM-PREPARE"].severity.value == "medium"


# --- test-code demotion (engine-level) ----------------------------------------
def test_findings_only_in_test_code_become_needs_review(tmp_path: Path):
    _write(tmp_path, "index.js", "module.exports = 1;\n")  # clean prod file
    _write(tmp_path, "__tests__/a.test.js", _NODE_SHELL)
    component = detect_component(tmp_path, source=str(tmp_path))
    report = analyze_directory(tmp_path, component)
    assert all(f.id != "ST-SHELL-NODE" for f in report.findings)
    assert any("test code only" in n.title for n in report.needs_review)


def test_mixed_prod_and_test_keeps_prod_evidence(tmp_path: Path):
    _write(tmp_path, "index.js", _NODE_SHELL)
    _write(tmp_path, "__tests__/a.test.js", _NODE_SHELL)
    component = detect_component(tmp_path, source=str(tmp_path))
    report = analyze_directory(tmp_path, component)
    shell = next(f for f in report.findings if f.id == "ST-SHELL-NODE")
    assert all(not e.file.startswith("__tests__") for e in shell.evidence)
