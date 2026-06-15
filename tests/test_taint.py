"""Intra-procedural taint: untrusted source -> dangerous sink (Python AST).

ST-TAINT-EXEC-PY / ST-TAINT-SHELL-PY / ST-TAINT-DESERIAL-PY. Conservative by design:
a Finding only when a flow from a known source to an exec/shell/deserialize sink is provable
within one function body; otherwise nothing (false-positive control).
"""

from __future__ import annotations

from skilltotal.file_index import FileIndex
from skilltotal.scanners.python_ast import PythonAstScanner


def _ids(tmp_path, code):
    (tmp_path / "m.py").write_text(code, encoding="utf-8")
    return {f.id for f in PythonAstScanner().scan(FileIndex.build(tmp_path)).findings}


# --- true positives (must flag) ------------------------------------------------------
def test_env_subscript_to_exec(tmp_path):
    assert "ST-TAINT-EXEC-PY" in _ids(tmp_path, "import os\nexec(os.environ['X'])\n")


def test_env_local_to_exec(tmp_path):
    assert "ST-TAINT-EXEC-PY" in _ids(tmp_path, "import os\nx = os.getenv('C')\nexec(x)\n")


def test_argv_to_os_system(tmp_path):
    assert "ST-TAINT-SHELL-PY" in _ids(tmp_path, "import os, sys\nos.system(sys.argv[1])\n")


def test_fstring_argv_to_shell(tmp_path):
    code = "import os, sys\ncmd = f'ls {sys.argv[1]}'\nos.system(cmd)\n"
    assert "ST-TAINT-SHELL-PY" in _ids(tmp_path, code)


def test_input_to_eval(tmp_path):
    assert "ST-TAINT-EXEC-PY" in _ids(tmp_path, "eval(input())\n")


def test_network_body_to_exec(tmp_path):
    code = "import requests\nr = requests.get(u).text\nexec(r)\n"
    assert "ST-TAINT-EXEC-PY" in _ids(tmp_path, code)


def test_env_concat_to_subprocess_shell(tmp_path):
    code = "import subprocess, os\nsubprocess.run('git ' + os.getenv('B'), shell=True)\n"
    assert "ST-TAINT-SHELL-PY" in _ids(tmp_path, code)


def test_network_body_to_pickle(tmp_path):
    code = "import requests, pickle\ndata = requests.get(u).content\npickle.loads(data)\n"
    assert "ST-TAINT-DESERIAL-PY" in _ids(tmp_path, code)


def test_mcp_tool_param_to_shell(tmp_path):
    code = "import os\n@mcp.tool\ndef run(cmd):\n    os.system(cmd)\n"
    assert "ST-TAINT-SHELL-PY" in _ids(tmp_path, code)


def test_dedupe_taint_shell_supersedes_cmdi(tmp_path):
    # env -> os.system is both "dynamic command" (CMDI) and "tainted" (TAINT-SHELL);
    # only the more specific taint finding should remain on that node.
    ids = _ids(tmp_path, "import os\nos.system(os.getenv('X'))\n")
    assert "ST-TAINT-SHELL-PY" in ids
    assert "ST-CMDI-PY" not in ids


# --- true negatives (must NOT raise a taint finding) ---------------------------------
def test_constant_to_exec_clean(tmp_path):
    assert "ST-TAINT-EXEC-PY" not in _ids(tmp_path, "exec('1 + 1')\n")


def test_constant_to_os_system_clean(tmp_path):
    assert "ST-TAINT-SHELL-PY" not in _ids(tmp_path, "import os\nos.system('ls -la')\n")


def test_inline_shlex_quote_sanitizes(tmp_path):
    code = "import os, shlex\nos.system(shlex.quote(os.getenv('X')))\n"
    assert "ST-TAINT-SHELL-PY" not in _ids(tmp_path, code)


def test_var_shlex_quote_sanitizes(tmp_path):
    code = "import os, shlex, sys\ncmd = shlex.quote(sys.argv[1])\nos.system(cmd)\n"
    assert "ST-TAINT-SHELL-PY" not in _ids(tmp_path, code)


def test_int_coercion_sanitizes(tmp_path):
    code = "import os, sys\nos.system('sleep %d' % int(sys.argv[1]))\n"
    assert "ST-TAINT-SHELL-PY" not in _ids(tmp_path, code)


def test_argv_list_without_shell_no_taint_finding(tmp_path):
    code = "import subprocess, sys\nsubprocess.run(['echo', sys.argv[1]])\n"
    assert "ST-TAINT-SHELL-PY" not in _ids(tmp_path, code)


def test_safe_sink_not_flagged(tmp_path):
    ids = _ids(tmp_path, "import sys\nprint(sys.argv[1])\n")
    assert not any(i.startswith("ST-TAINT-") for i in ids)


def test_reassignment_clears_taint(tmp_path):
    code = "import os\nx = os.getenv('X')\nx = 'safe'\nexec(x)\n"
    assert "ST-TAINT-EXEC-PY" not in _ids(tmp_path, code)


def test_plain_parameter_is_not_a_source(tmp_path):
    # a non-MCP function parameter is not treated as untrusted in v1
    code = "import os\ndef f(cmd):\n    os.system(cmd)\n"
    assert "ST-TAINT-SHELL-PY" not in _ids(tmp_path, code)


def test_taint_does_not_cross_function_scopes(tmp_path):
    code = "import os\ndef a():\n    x = os.getenv('X')\ndef b():\n    exec(x)\n"
    assert not any(i.startswith("ST-TAINT-") for i in _ids(tmp_path, code))
