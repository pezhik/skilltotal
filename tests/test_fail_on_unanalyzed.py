"""`scan --fail-on-unanalyzed`: a CI gate that fails when part of the component was not analyzed.

A low score says nothing about code the scan never read. The gate is opt-in (CLI flag,
`fail_on_unanalyzed = true` in .skilltotal.toml, or the Action's `fail-on-unanalyzed` input) and
keys on the needs_review titles in `UNANALYZED_TITLES`.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import skilltotal
from skilltotal.cli import EXIT_FAIL_ON_HIGH, EXIT_OK, main
from skilltotal.config import _fallback_parse, load_config
from skilltotal.models import NOTHING_READ, UNANALYZED_INSTALL_SCRIPT, UNANALYZED_TITLES

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
                           ('fail_on_unanalyzed = "yes"\n', False),
                           ("fail_on = \"high\"\n", False)):
        path = tmp_path / ".skilltotal.toml"
        path.write_text(text, encoding="utf-8")
        assert load_config(path).fail_on_unanalyzed is expected, text


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
    for title in UNANALYZED_TITLES - {UNANALYZED_INSTALL_SCRIPT, NOTHING_READ}:
        assert title in written, title


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
    json_run = next(line for line in text.splitlines() if "--json --output skilltotal.json" in line)
    assert '"${GATE[@]}"' in json_run
