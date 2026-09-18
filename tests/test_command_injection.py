"""Command-injection signal: shell + dynamic command (Python AST + Node regex)."""

from __future__ import annotations

import pytest

from skilltotal.file_index import FileIndex
from skilltotal.scanners.python_ast import PythonAstScanner
from skilltotal.scanners.shell_exec import ShellExecScanner


def _py(tmp_path, code):
    (tmp_path / "m.py").write_text(code, encoding="utf-8")
    return {f.id for f in PythonAstScanner().scan(FileIndex.build(tmp_path)).findings}


def _node(tmp_path, code):
    (tmp_path / "m.js").write_text(code, encoding="utf-8")
    return {f.id for f in ShellExecScanner().scan(FileIndex.build(tmp_path)).findings}


# --- Python: should flag -------------------------------------------------------------
def test_py_os_system_fstring(tmp_path):
    assert "ST-CMDI-PY" in _py(tmp_path, "import os\nos.system(f'rm -rf {path}')\n")


def test_py_subprocess_shell_true_concat(tmp_path):
    code = "import subprocess\nsubprocess.run('git ' + branch, shell=True)\n"
    assert "ST-CMDI-PY" in _py(tmp_path, code)


def test_py_os_popen_variable(tmp_path):
    assert "ST-CMDI-PY" in _py(tmp_path, "import os\nos.popen(cmd)\n")


def test_py_subprocess_shell_true_format(tmp_path):
    code = "import subprocess\nsubprocess.run('ls {}'.format(d), shell=True)\n"
    assert "ST-CMDI-PY" in _py(tmp_path, code)


# --- Python: should NOT flag (FP guards) ---------------------------------------------
def test_py_argv_list_without_shell_is_safe(tmp_path):
    # argv form, no shell -> not injectable even with a variable arg
    code = "import subprocess\nsubprocess.run(['git', 'checkout', branch])\n"
    ids = _py(tmp_path, code)
    assert "ST-SHELL-PY" in ids and "ST-CMDI-PY" not in ids


def test_py_constant_command_not_flagged(tmp_path):
    code = "import os\nos.system('ls -la')\n"
    ids = _py(tmp_path, code)
    assert "ST-SHELL-PY" in ids and "ST-CMDI-PY" not in ids


def test_py_subprocess_dynamic_without_shell_not_cmdi(tmp_path):
    # dynamic string but no shell=True -> not the shell-injection pattern we flag
    code = "import subprocess\nsubprocess.run(f'git {branch}')\n"
    assert "ST-CMDI-PY" not in _py(tmp_path, code)


def test_py_cmdi_suppressed_when_taint_shell_fires(tmp_path):
    # When taint proves an untrusted source reaches the shell, the specific ST-TAINT-SHELL-PY
    # finding supersedes the weaker ST-CMDI-PY on the same node (scored once).
    ids = _py(tmp_path, "import os\nos.system(os.getenv('X'))\n")
    assert "ST-TAINT-SHELL-PY" in ids and "ST-CMDI-PY" not in ids


# --- Node: should flag ---------------------------------------------------------------
def test_node_exec_template_literal(tmp_path):
    code = "const cp=require('child_process');\ncp.exec(`ls ${dir}`);\n"
    assert "ST-CMDI-NODE" in _node(tmp_path, code)


def test_node_execsync_concat(tmp_path):
    code = "const {execSync}=require('child_process');\nexecSync('git ' + branch);\n"
    assert "ST-CMDI-NODE" in _node(tmp_path, code)


# --- Node: should NOT flag -----------------------------------------------------------
def test_node_exec_constant_not_cmdi(tmp_path):
    code = "const cp=require('child_process');\ncp.exec('ls -la');\n"
    ids = _node(tmp_path, code)
    assert "ST-SHELL-NODE" in ids and "ST-CMDI-NODE" not in ids


def test_node_regex_exec_not_cmdi(tmp_path):
    # regex.exec(userInput) is NOT command execution and must not be flagged
    code = "const re=/x/;\nconst m = re.exec(userInput);\n"
    assert "ST-CMDI-NODE" not in _node(tmp_path, code)


# --- Node: a method named exec is not child_process (the ST-SHELL-NODE false positive) --------
# A research repo's `while ((m = re.exec(text)) !== null)` was reported as shell execution.
@pytest.mark.parametrize(
    "code",
    [
        "while ((m = re.exec(text)) !== null) last = m;\n",
        "const m = /a(b)/g.exec(s);\n",
        "const cm = closeRe.exec(text);\n",
        "db.exec(`CREATE TABLE ${table} (id INTEGER)`);\n",       # better-sqlite3
        "const docs = await Model.find({}).exec();\n",             # mongoose
        "const r = new RegExp(p).exec(line);\n",
        "worker.spawn(task);\n",
        "const $exec = 1; $exec(x);\n",
        # A child_process import elsewhere in the file does not turn regex.exec into a shell call.
        "const { spawn } = require('child_process');\nconst m = re.exec(text);\n",
    ],
)
def test_node_method_named_exec_is_not_shell_execution(tmp_path, code):
    ids = _node(tmp_path, code)
    if "child_process" in code:
        # The import is evidence; the regex call must not be among it.
        (tmp_path / "m.js").write_text(code, encoding="utf-8")
        f = next(iter(ShellExecScanner().scan(FileIndex.build(tmp_path)).findings))
        assert [e.line_start for e in f.evidence] == [1]
    else:
        assert "ST-SHELL-NODE" not in ids
    assert "ST-CMDI-NODE" not in ids


@pytest.mark.parametrize(
    ("code", "line"),
    [
        ("const cp = require('child_process');\ncp.exec('ls');\n", 2),
        ("const { exec } = require('node:child_process');\nexec('ls');\n", 2),
        ("import * as cp from 'child_process';\ncp.spawn('ls');\n", 2),
        ("import cp from 'child_process';\ncp.execSync('ls');\n", 2),
        ("import cp = require('child_process');\ncp.spawnSync('ls');\n", 2),
        ("import { spawn } from 'child_process';\nspawn('ls', []);\n", 2),
        ("require('child_process').exec('ls');\n", 1),
        ("const p = Bun.spawn(['ls']);\n", 1),
        ("import { execa } from 'execa';\n", 1),
    ],
)
def test_node_child_process_calls_still_flagged(tmp_path, code, line):
    (tmp_path / "m.js").write_text(code, encoding="utf-8")
    findings = ShellExecScanner().scan(FileIndex.build(tmp_path)).findings
    shell = next(f for f in findings if f.id == "ST-SHELL-NODE")
    assert line in [e.line_start for e in shell.evidence]


def test_node_cmdi_through_alias_still_flagged(tmp_path):
    code = "import * as proc from 'child_process';\nproc.exec(`git ${args}`);\n"
    assert "ST-CMDI-NODE" in _node(tmp_path, code)


def test_node_bare_exec_without_child_process_import_is_not_cmdi(tmp_path):
    # e.g. a local helper or a database wrapper: nothing ties it to a shell.
    assert "ST-CMDI-NODE" not in _node(tmp_path, "exec(`SELECT * FROM ${t}`);\n")
