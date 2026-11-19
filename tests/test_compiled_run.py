"""Compiled or binary code a component starts.

* Python bytecode with no source beside it that a command or the component's own import runs is
  ``ST-BYTECODE-NO-SOURCE`` (risky construct): what it does is unknown, so it is never called
  malicious.
* A native program a command starts is a coverage note ("Started file not analyzed"): a server
  shipped as a binary is common and honest, and the report still says nothing in it was checked.
* Bytecode beside its source, a tool started from ``node_modules`` and a text script run by path
  stay quiet.

The "binaries" here are a few placeholder bytes; nothing is executed or imported.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.models import COMPILED_WITHOUT_SOURCE, UNANALYZED_TITLES, Component, ThreatClass
from skilltotal.rules import get_rules

RULE = "ST-BYTECODE-NO-SOURCE"
STARTED_NOT_ANALYZED = "Started file not analyzed"
BANNER_PY = "# FIXTURE ONLY - synthetic detection test sample, not real malware\n"
BLOB = b"\x00\x00FIXTURE ONLY - inert placeholder bytes, not a program\x00\x00"
SKILL = "---\nname: formatter\ndescription: Formats reports.\n---\n\n# Formatter\n\n"
PLUGIN = {"name": "fmt", "version": "1.0.0"}


def _write(root: Path, files: dict[str, object]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
            continue
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_text(text, encoding="utf-8")
    return root


def _report(root: Path):
    return analyze_directory(root, Component(name="x", type="directory", source=str(root)))


def _evidence(report):
    return [e for f in report.findings if f.id == RULE for e in f.evidence]


def _note(report, title: str):
    return next((n for n in report.needs_review if n.title == title), None)


def _hook(command: str) -> dict:
    return {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": command}]}]}}


def _mcp(command: str, *args: str) -> dict:
    return {"mcpServers": {"notes": {"command": command, "args": list(args)}}}


def test_the_rule_is_a_registered_risky_construct_with_no_capability():
    rule = next(r for r in get_rules() if r.id == RULE)
    assert rule.threat_class is ThreatClass.RISKY_CONSTRUCT
    assert rule.capability is None


@pytest.mark.parametrize(
    ("files", "where"),
    [
        ({"SKILL.md": SKILL + "Before first use run `python scripts/tool.pyc` once.\n",
          "scripts/tool.pyc": BLOB}, ("SKILL.md", "scripts/tool.pyc")),
        ({".claude-plugin/plugin.json": PLUGIN,
          "hooks/hooks.json": _hook("python3 ${CLAUDE_PLUGIN_ROOT}/hooks/start.pyc"),
          "hooks/start.pyc": BLOB}, ("hooks/hooks.json", "hooks/start.pyc")),
        ({".mcp.json": _mcp("python", "server.pyo"), "server.pyo": BLOB},
         (".mcp.json", "server.pyo")),
        ({"package.json": {"name": "p", "version": "1.0.0",
                           "scripts": {"postinstall": "python tools/setup_helper.pyc"}},
          "tools/setup_helper.pyc": BLOB}, ("package.json", "tools/setup_helper.pyc")),
        # A file in __pycache__ is never walked; a command can still be started on it.
        ({"SKILL.md": SKILL + "Run `python scripts/__pycache__/helper.cpython-311.pyc` once.\n",
          "scripts/__pycache__/helper.cpython-311.pyc": BLOB},
         ("SKILL.md", "scripts/__pycache__/helper.cpython-311.pyc")),
    ],
)
def test_a_command_that_starts_bytecode_without_source_is_reported(tmp_path, files, where):
    report = _report(_write(tmp_path, files))
    evidence = _evidence(report)
    assert len(evidence) == 1
    assert evidence[0].file == where[0]
    assert evidence[0].line_start >= 1
    assert f"runs {where[1]}" in evidence[0].snippet
    assert report.verdict["has_malicious_indicators"] is False


@pytest.mark.parametrize(
    ("importer", "line"),
    [
        ("import helper\n\nhelper.main()\n", 2),
        ("from helper import main\n\nmain()\n", 2),
        ("from . import helper\n", 2),
        ("import importlib.machinery as m\n\nm.SourcelessFileLoader('h', 'helper.pyc')\n", 4),
    ],
)
def test_the_components_own_import_of_bytecode_without_source_is_reported(
    tmp_path, importer, line
):
    report = _report(_write(tmp_path, {
        "pkg/run.py": BANNER_PY + importer, "pkg/helper.pyc": BLOB,
    }))
    evidence = _evidence(report)
    assert [(e.file, e.line_start) for e in evidence] == [("pkg/run.py", line)]
    # The coverage note stays: the finding names the line, the note names the file.
    assert _note(report, COMPILED_WITHOUT_SOURCE) is not None


@pytest.mark.parametrize(
    "files",
    [
        # Bytecode beside its source is a build artifact.
        {"SKILL.md": SKILL + "Run `python scripts/tool.py`.\n",
         "scripts/tool.py": BANNER_PY + 'print("ok")\n', "scripts/tool.pyc": BLOB},
        {"SKILL.md": SKILL + "Run `python scripts/tool.pyc`.\n",
         "scripts/tool.py": BANNER_PY + 'print("ok")\n', "scripts/tool.pyc": BLOB},
        {"pkg/run.py": BANNER_PY + "import helper\n", "pkg/helper.py": BANNER_PY + "X = 1\n",
         "pkg/helper.pyc": BLOB},
        # The interpreter's cache next to the module it came from.
        {"SKILL.md": SKILL + "Run `python scripts/__pycache__/tool.cpython-311.pyc`.\n",
         "scripts/tool.py": BANNER_PY + 'print("ok")\n',
         "scripts/__pycache__/tool.cpython-311.pyc": BLOB},
        # A compiled extension with its source beside it, loaded by the package.
        {"pkg/__init__.py": BANNER_PY + "from pkg import _speedups\n",
         "pkg/_speedups.c": "/* FIXTURE ONLY */\nint add(int a, int b) { return a + b; }\n",
         "pkg/_speedups.so": b"\x7fELF" + BLOB},
    ],
)
def test_honest_compiled_files_are_not_a_finding(tmp_path, files):
    report = _report(_write(tmp_path, files))
    assert not _evidence(report)
    assert _note(report, STARTED_NOT_ANALYZED) is None
    assert report.risk_score == 0


def test_bytecode_without_source_that_nothing_runs_keeps_its_note_only(tmp_path):
    report = _report(_write(tmp_path, {
        "SKILL.md": SKILL + "Run `python scripts/run.py`.\n",
        "scripts/run.py": BANNER_PY + 'print("ok")\n', "cache/legacy.pyc": BLOB,
    }))
    assert not _evidence(report)
    assert _note(report, COMPILED_WITHOUT_SOURCE) is not None


@pytest.mark.parametrize(
    ("files", "target"),
    [
        ({"SKILL.md": SKILL + "Before first use run `./bin/helper` once.\n",
          "bin/helper": b"\x7fELF" + BLOB}, "bin/helper"),
        ({".claude-plugin/plugin.json": PLUGIN,
          "hooks/hooks.json": _hook("${CLAUDE_PLUGIN_ROOT}/bin/fmt-helper --check"),
          "bin/fmt-helper": b"\x7fELF" + BLOB}, "bin/fmt-helper"),
        ({".mcp.json": _mcp("./bin/notes-server"), "bin/notes-server": b"\x7fELF" + BLOB},
         "bin/notes-server"),
        ({"SKILL.md": SKILL + "Convert with `wasmtime tools/convert.wasm input.md`.\n",
          "tools/convert.wasm": b"\x00asm" + BLOB}, "tools/convert.wasm"),
        ({".mcp.json": _mcp("./server.exe", "--stdio"), "server.exe": b"MZ" + BLOB},
         "server.exe"),
    ],
)
def test_a_native_program_a_command_starts_is_a_coverage_note_not_a_finding(
    tmp_path, files, target
):
    report = _report(_write(tmp_path, files))
    note = _note(report, STARTED_NOT_ANALYZED)
    assert note is not None and note.file == target
    assert target in note.reason and "compiled or binary" in note.reason
    assert STARTED_NOT_ANALYZED in UNANALYZED_TITLES
    assert not _evidence(report)
    assert report.risk_score == 0
    assert report.verdict["has_malicious_indicators"] is False


@pytest.mark.parametrize(
    "files",
    [
        # A text script run by its path was read like any file.
        {"SKILL.md": SKILL + "Run `./scripts/setup` once.\n",
         "scripts/setup": "#!/bin/sh\n# FIXTURE ONLY\necho ready\n"},
        # A tool started from a dependency folder: that folder has a note of its own.
        {".claude-plugin/plugin.json": PLUGIN,
         "hooks/hooks.json": _hook("./node_modules/.bin/eslint --fix"),
         "node_modules/.bin/eslint": b"\x7fELF" + BLOB},
        # A binary nothing starts, and an image a script takes as an argument.
        {"SKILL.md": SKILL + "Run `python scripts/thumb.py ./assets/logo.bin`.\n",
         "scripts/thumb.py": BANNER_PY + 'print("ok")\n', "assets/logo.bin": BLOB,
         "bin/unused": b"\x7fELF" + BLOB},
        # A path outside the component is never looked up.
        {"SKILL.md": SKILL + "Run `./../outside/tool` or `/usr/local/bin/tool`.\n"},
    ],
)
def test_ordinary_commands_get_no_started_file_note(tmp_path, files):
    report = _report(_write(tmp_path, files))
    assert _note(report, STARTED_NOT_ANALYZED) is None
    assert not _evidence(report)


def test_a_binary_an_install_command_starts_keeps_the_install_note(tmp_path):
    report = _report(_write(tmp_path, {
        "package.json": {"name": "p", "version": "1.0.0",
                         "scripts": {"postinstall": "./bin/helper"}},
        "bin/helper": b"\x7fELF" + BLOB,
    }))
    titles = [n.title for n in report.needs_review]
    assert "Install script not analyzed" in titles
    assert STARTED_NOT_ANALYZED not in titles  # one note per file, the install one
