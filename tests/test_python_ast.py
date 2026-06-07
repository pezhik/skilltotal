"""AST scanner precision: cases where regex was wrong."""

from __future__ import annotations

from pathlib import Path

from skilltotal.file_index import FileIndex
from skilltotal.scanners.python_ast import PythonAstScanner


def _scan(tmp_path: Path, code: str):
    (tmp_path / "m.py").write_text(code, encoding="utf-8", newline="")
    result = PythonAstScanner().scan(FileIndex.build(tmp_path))
    return result, {f.id for f in result.findings}


def test_api_name_in_string_or_comment_is_not_a_finding(tmp_path: Path):
    code = (
        'doc = "use subprocess.run to spawn"  # os.system(x) and eval(y) mentioned\n'
        "value = 1\n"
    )
    _result, ids = _scan(tmp_path, code)
    assert ids == set(), "string/comment mentions must not trigger findings"


def test_open_write_mode_is_write_not_read(tmp_path: Path):
    _result, ids = _scan(tmp_path, "open('/tmp/x', 'w')\n")
    assert "ST-FS-PY-WRITE" in ids
    assert "ST-FS-PY-READ" not in ids


def test_open_default_mode_is_read(tmp_path: Path):
    _result, ids = _scan(tmp_path, "open('/tmp/x')\n")
    assert "ST-FS-PY-READ" in ids
    assert "ST-FS-PY-WRITE" not in ids


def test_import_alias_shell_is_resolved(tmp_path: Path):
    code = "import subprocess as sp\nsp.run(['ls'])\n"
    _result, ids = _scan(tmp_path, code)
    assert "ST-SHELL-PY" in ids


def test_from_import_shell_is_resolved(tmp_path: Path):
    code = "from os import system\nsystem('whoami')\n"
    _result, ids = _scan(tmp_path, code)
    assert "ST-SHELL-PY" in ids


def test_network_alias_resolved(tmp_path: Path):
    code = "import requests as r\nr.get('http://x')\n"
    _result, ids = _scan(tmp_path, code)
    assert "ST-NET-PY" in ids


def test_asyncio_subprocess_is_shell(tmp_path: Path):
    code = "import asyncio\nasyncio.create_subprocess_shell('ls')\n"
    _result, ids = _scan(tmp_path, code)
    assert "ST-SHELL-PY" in ids


def test_shell_library_import_is_shell(tmp_path: Path):
    _result, ids = _scan(tmp_path, "import sh\nsh.ls()\n")
    assert "ST-SHELL-PY" in ids


def test_dynamic_calls(tmp_path: Path):
    code = "eval('1+1')\nexec('x=2')\n"
    _result, ids = _scan(tmp_path, code)
    assert "ST-DYN-PY" in ids


def test_syntax_error_falls_back_to_regex_and_flags_review(tmp_path: Path):
    # Invalid Python (Python-2 style print) but regex can still see subprocess.run(.
    code = "print 'hi'\nsubprocess.run(['x'])\n"
    result, ids = _scan(tmp_path, code)
    assert "ST-SHELL-PY" in ids
    assert any("Unparseable" in n.title for n in result.needs_review)


def test_findings_have_accurate_line_numbers(tmp_path: Path):
    code = "x = 1\ny = 2\nimport subprocess\nsubprocess.run(['ls'])\n"
    result, _ids = _scan(tmp_path, code)
    shell = next(f for f in result.findings if f.id == "ST-SHELL-PY")
    assert shell.evidence[0].line_start == 4
