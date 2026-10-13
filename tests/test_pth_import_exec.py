"""A .pth file that imports a module of the same package whose top level spawns a process
(ST-PTH-IMPORT-EXEC).

Python runs a .pth file's import lines at every interpreter start. A .pth that only says
`import helper` looks harmless to ST-PTH-EXEC, which reads the .pth alone; the payload sits in
helper.py, at module level, so importing it is running it. Real .pth files (setuptools'
distutils shim, virtualenv, pywin32, editable installs) import modules whose top level only
defines things.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.engine import analyze_directory
from skilltotal.models import Component, ThreatClass

RULE = "ST-PTH-IMPORT-EXEC"


def _component(tmp_path: Path, files: dict[str, str]):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return analyze_directory(tmp_path, Component(name="x", type="python_package", source="x"))


SPAWNING = (
    'import os\n'
    '_mod = __import__("o" + "s")\n'
    '_fn = getattr(_mod, "sys" + "tem")\n'
    '_fn("ec" + "ho fixture")\n'
)


def test_a_pth_that_imports_a_module_running_a_shell_at_import_is_malicious(tmp_path):
    report = _component(tmp_path, {
        "helper.pth": 'import os; exec("import helper")\n',
        "helper.py": SPAWNING,
    })
    finding = next(f for f in report.findings if f.id == RULE)
    assert finding.threat_class == ThreatClass.MALICIOUS_INDICATOR
    assert report.verdict["has_malicious_indicators"]
    files = {ev.file for ev in finding.evidence}
    assert files == {"helper.pth", "helper.py"}


def test_plain_and_listed_imports_count_too(tmp_path):
    report = _component(tmp_path, {
        "a.pth": "import sys, pkg.boot\n",
        "pkg/__init__.py": "",
        "pkg/boot.py": "import subprocess\nsubprocess.Popen(['sh', '-c', 'echo fixture'])\n",
    })
    assert RULE in {f.id for f in report.findings}


def test_dunder_import_in_a_pth_counts(tmp_path):
    report = _component(tmp_path, {
        "x.pth": "import os; __import__('starter')\n",
        "src/starter/__init__.py": "import os\nos.system('echo fixture')\n",
    })
    assert RULE in {f.id for f in report.findings}


def test_a_spawn_inside_a_function_is_not_run_by_the_import(tmp_path):
    # setuptools' distutils-precedence.pth and its _distutils_hack: the import only defines.
    report = _component(tmp_path, {
        "distutils-precedence.pth": (
            "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local')"
            " == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n"
        ),
        "_distutils_hack/__init__.py": (
            "import subprocess\n\n"
            "def add_shim():\n"
            "    subprocess.run(['echo', 'shim'])\n\n"
            "class Finder:\n"
            "    def spec(self):\n"
            "        subprocess.run(['echo', 'x'])\n"
        ),
    })
    assert RULE not in {f.id for f in report.findings}


def test_a_main_block_is_not_run_by_the_import(tmp_path):
    report = _component(tmp_path, {
        "tool.pth": "import tool\n",
        "tool.py": "import os\nif __name__ == '__main__':\n    os.system('echo fixture')\n",
    })
    assert RULE not in {f.id for f in report.findings}


def test_a_module_no_pth_imports_is_left_to_the_other_rules(tmp_path):
    report = _component(tmp_path, {
        "paths.pth": "src\n",  # a path line: never executed
        "helper.py": SPAWNING,
    })
    ids = {f.id for f in report.findings}
    assert RULE not in ids
    assert "ST-SHELL-PY" in ids


def test_a_pth_naming_a_module_it_does_not_ship_is_not_flagged(tmp_path):
    report = _component(tmp_path, {
        "x.pth": "import some_other_package\n",
        "helper.py": SPAWNING,
    })
    assert RULE not in {f.id for f in report.findings}


def test_a_test_folder_copy_does_not_count(tmp_path):
    # The module the .pth imports is the shipped one; a same-named file under tests/ is not it.
    report = _component(tmp_path, {
        "helper.pth": "import helper\n",
        "helper.py": "VALUE = 1\n",
        "tests/helper.py": SPAWNING,
    })
    assert RULE not in {f.id for f in report.findings}
