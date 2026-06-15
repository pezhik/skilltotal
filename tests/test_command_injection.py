"""Command-injection signal: shell + dynamic command (Python AST + Node regex)."""

from __future__ import annotations

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
