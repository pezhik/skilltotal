"""`scan --fail-on-unanalyzed`: a CI gate that fails when part of the component was not analyzed.

A low score says nothing about code the scan never read. The gate is opt-in (CLI flag,
`fail_on_unanalyzed = true` in .skilltotal.toml, or the Action's `fail-on-unanalyzed` input) and
keys on the needs_review titles in `UNANALYZED_TITLES`.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import skilltotal
from skilltotal.cli import EXIT_ERROR, EXIT_FAIL_ON_HIGH, EXIT_OK, build_parser, main
from skilltotal.config import ConfigError, _fallback_parse, load_config
from skilltotal.engine import analyze_directory
from skilltotal.file_index import MAX_FILE_BYTES
from skilltotal.models import (
    NOTHING_READ,
    UNANALYZED_INSTALL_SCRIPT,
    UNANALYZED_LOADED_CODE,
    UNANALYZED_TITLES,
    Component,
)

ACTION = Path(__file__).resolve().parent.parent / "action.yml"
GO = 'package main\nimport ("os/exec")\nfunc main() { exec.Command("id").Run() }\n'


def _component(tmp_path: Path, files: dict[str, str]) -> str:
    root = tmp_path / "component"
    root.mkdir()
    for rel, body in files.items():
        (root / rel).write_text(body, encoding="utf-8")
    return str(root)


def _scan(root: str, *flags: str) -> int:
    return main(["scan", root, "--json", *flags])


def test_code_in_a_language_not_analyzed_fails_the_gate_and_says_why(tmp_path: Path, capsys):
    root = _component(tmp_path, {"main.go": GO, "x.py": "x = 1\n"})
    capsys.readouterr()
    assert _scan(root, "--fail-on-unanalyzed") == EXIT_FAIL_ON_HIGH
    err = capsys.readouterr().err
    assert "Not everything was analyzed: Code in languages not analyzed for behavior." in err
    assert _scan(root) == EXIT_OK  # opt-in: off by default


def test_c_code_fails_the_gate_too(tmp_path: Path, capsys):
    root = _component(tmp_path, {"addon.c": "int main(void) { return 0; }\n"})
    assert _scan(root, "--fail-on-unanalyzed") == EXIT_FAIL_ON_HIGH


def test_a_python_file_that_could_not_be_parsed_fails_the_gate(tmp_path: Path, capsys):
    root = _component(tmp_path, {"broken.py": "def broken(:\n    pass\n"})
    assert _scan(root, "--fail-on-unanalyzed") == EXIT_FAIL_ON_HIGH
    assert "Unparseable Python file" in capsys.readouterr().err


def test_a_fully_analyzed_component_passes(tmp_path: Path, capsys):
    root = _component(tmp_path, {"x.py": "x = 1\n", "y.js": "const y = 1;\n"})
    assert _scan(root, "--fail-on-unanalyzed") == EXIT_OK
    assert "Not everything was analyzed" not in capsys.readouterr().err


def test_a_note_that_is_not_a_gap_does_not_fail_it(tmp_path: Path, capsys):
    # A dynamic import is a signal to read; the file itself was analyzed.
    root = _component(tmp_path, {"x.py": "import importlib\nm = importlib.import_module(name)\n"})
    capsys.readouterr()
    assert _scan(root, "--fail-on-unanalyzed") == EXIT_OK
    report = json.loads(capsys.readouterr().out)
    assert [n["title"] for n in report["needs_review"]] == ["Dynamic module import"]


def test_the_config_key_turns_it_on(tmp_path: Path, capsys):
    root = _component(tmp_path, {"main.go": GO})
    on = tmp_path / "on.toml"
    on.write_text("fail_on_unanalyzed = true\n", encoding="utf-8")
    off = tmp_path / "off.toml"
    off.write_text("fail_on_unanalyzed = false\n", encoding="utf-8")
    assert _scan(root, "--config", str(on)) == EXIT_FAIL_ON_HIGH
    assert _scan(root, "--config", str(off)) == EXIT_OK
    assert _scan(root, "--config", str(off), "--fail-on-unanalyzed") == EXIT_FAIL_ON_HIGH


def test_the_config_value_must_be_a_boolean(tmp_path: Path):
    for text, expected in (("fail_on_unanalyzed = true\n", True),
                           ("fail_on_unanalyzed = false\n", False),
                           ("fail_on = \"high\"\n", False)):
        path = tmp_path / ".skilltotal.toml"
        path.write_text(text, encoding="utf-8")
        assert load_config(path).fail_on_unanalyzed is expected, text


@pytest.mark.parametrize("value", ['"true"', '"yes"', "1", "yes"])
def test_a_value_that_is_not_a_boolean_is_an_error_not_off(tmp_path: Path, capsys, value):
    # `"true"` (a string) once read as off: a CI gate switched off by a pair of quotes.
    cfg = tmp_path / ".skilltotal.toml"
    cfg.write_text(f"fail_on_unanalyzed = {value}\n", encoding="utf-8")
    if value != "yes":  # bare `yes` is not TOML at all: the file does not parse
        with pytest.raises(ConfigError, match="fail_on_unanalyzed must be true or false"):
            load_config(cfg)
        root = tmp_path / "c"
        root.mkdir()
        (root / "x.py").write_text("x = 1\n", encoding="utf-8")
        assert main(["scan", str(root), "--json", "--config", str(cfg)]) == EXIT_ERROR
        assert "fail_on_unanalyzed must be true or false" in capsys.readouterr().err
    # The Python 3.10 parser keeps what it cannot read as a boolean, so it is refused too.
    assert _fallback_parse(f"fail_on_unanalyzed = {value}\n")["fail_on_unanalyzed"] not in (
        True, False)


def test_the_python_3_10_parser_reads_the_key():
    assert _fallback_parse("fail_on_unanalyzed = true\n")["fail_on_unanalyzed"] is True
    assert _fallback_parse("fail_on_unanalyzed = false\n")["fail_on_unanalyzed"] is False
    assert "fail_on_unanalyzed" not in _fallback_parse('fail_on = "high"\n')
    assert "fail_on" not in _fallback_parse("fail_on_unanalyzed = true\n")


def test_it_adds_to_the_other_gates(tmp_path: Path, capsys):
    root = _component(tmp_path, {"main.go": GO})
    assert _scan(root, "--fail-on", "critical") == EXIT_OK
    assert _scan(root, "--fail-on", "critical", "--fail-on-unanalyzed") == EXIT_FAIL_ON_HIGH


def _string_literals(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
            and isinstance(n.value, str)}


def test_every_title_in_the_set_is_one_the_engine_writes():
    # A renamed note must not drop out of the gate in silence.
    package = Path(skilltotal.__file__).parent
    written: set[str] = set()
    for path in package.rglob("*.py"):
        if path.name != "models.py":
            written |= _string_literals(path)
    # Titles defined as constants in models.py are written through the constant's name.
    constants = {UNANALYZED_INSTALL_SCRIPT, NOTHING_READ, UNANALYZED_LOADED_CODE}
    for title in UNANALYZED_TITLES - constants:
        assert title in written, title
    users = [p for p in package.rglob("*.py") if p.name != "models.py"]
    assert any("UNANALYZED_LOADED_CODE" in p.read_text(encoding="utf-8") for p in users)


def test_the_action_input_is_wired_like_fail_on():
    text = ACTION.read_text(encoding="utf-8")
    assert "  fail-on-unanalyzed:\n" in text
    block = text.split("  fail-on-unanalyzed:\n", 1)[1].split("\n  upload-sarif:", 1)[0]
    assert 'default: "false"' in block
    # Through env only, validated, and an unknown value fails rather than turning the gate off.
    assert "INPUT_FAIL_ON_UNANALYZED: ${{ inputs.fail-on-unanalyzed }}" in text
    assert "true) GATE+=(--fail-on-unanalyzed) ;;" in text
    assert "fail-on-unanalyzed must be true or false" in text
    # The gate goes on the JSON run, whose exit code becomes gate-exit.
    json_run = next(line for line in text.splitlines() if '--json --output "$REPORT_JSON"' in line)
    assert '"${GATE[@]}"' in json_run


# --- What the walk sets aside by size is said too -------------------------------------------------

BIG = "// padding\n" * (MAX_FILE_BYTES // 11 + 10)


def _scan_report(root: Path):
    return analyze_directory(root, Component(name="x", type="directory", source=str(root)))


def test_a_text_file_too_large_to_read_gets_a_note_and_fails_the_gate(tmp_path: Path, capsys):
    root = _component(tmp_path, {"x.py": "x = 1\n", "big.js": BIG})
    (note,) = [n for n in _scan_report(Path(root)).needs_review
               if n.title == "Files too large to analyze"]
    assert note.category == "coverage"
    assert "big.js" in note.reason
    capsys.readouterr()
    assert _scan(root, "--fail-on-unanalyzed") == EXIT_FAIL_ON_HIGH
    assert "Files too large to analyze" in capsys.readouterr().err


def test_a_large_binary_file_stays_silent(tmp_path: Path):
    root = tmp_path / "c"
    root.mkdir()
    (root / "x.py").write_text("x = 1\n", encoding="utf-8")
    (root / "model.bin").write_bytes(b"\x00\x01" * (MAX_FILE_BYTES // 2 + 10))
    titles = [n.title for n in _scan_report(root).needs_review]
    assert "Files too large to analyze" not in titles


def test_a_large_install_script_keeps_its_own_note_only(tmp_path: Path):
    root = _component(tmp_path, {
        "package.json": '{"name": "x", "version": "1.0.0", '
                        '"scripts": {"postinstall": "node i.js"}}',
        "i.js": BIG,
    })
    titles = [n.title for n in _scan_report(Path(root)).needs_review]
    assert UNANALYZED_INSTALL_SCRIPT in titles
    assert "Files too large to analyze" not in titles


def test_with_sarif_the_log_names_what_was_not_analyzed(tmp_path: Path, capsys):
    root = _component(tmp_path, {"main.go": GO})
    capsys.readouterr()
    assert main(["scan", root, "--sarif", "--fail-on-unanalyzed"]) == EXIT_FAIL_ON_HIGH
    err = capsys.readouterr().err
    assert "Code in languages not analyzed for behavior" in err
    assert "needs_review" not in err  # SARIF carries no needs_review


def test_the_help_says_what_does_not_count():
    scan = next(a for a in build_parser()._subparsers._group_actions[0].choices["scan"]._actions
                if "--fail-on-unanalyzed" in a.option_strings)
    assert "binary files and dependency folders are skipped by design" in scan.help
