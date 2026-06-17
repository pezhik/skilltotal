"""Auto-executing .pth file detection (ST-PTH-EXEC)."""

from __future__ import annotations

from pathlib import Path

from skilltotal.file_index import FileIndex
from skilltotal.models import ThreatClass
from skilltotal.scanners.pth_exec import PthExecScanner


def _scan(tmp_path: Path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8", newline="\n")
    result = PthExecScanner().scan(FileIndex.build(tmp_path))
    return {f.id for f in result.findings}, result


def test_pth_with_exec_base64_is_malicious(tmp_path: Path):
    ids, result = _scan(
        tmp_path, "evil.pth", 'import os,base64;exec(base64.b64decode(b"eA=="))\n'
    )
    assert "ST-PTH-EXEC" in ids
    f = next(f for f in result.findings if f.id == "ST-PTH-EXEC")
    assert f.threat_class == ThreatClass.MALICIOUS_INDICATOR


def test_pth_with_subprocess_is_malicious(tmp_path: Path):
    ids, _ = _scan(tmp_path, "x.pth", "import subprocess; subprocess.Popen(['sh','-c','id'])\n")
    assert "ST-PTH-EXEC" in ids


# --- false-positive guards: legitimate .pth files must stay clean ---

def test_plain_path_pth_is_clean(tmp_path: Path):
    ids, _ = _scan(tmp_path, "easy-install.pth", "../src\n/opt/lib/site\n")
    assert ids == set()


def test_editable_install_pth_is_clean(tmp_path: Path):
    # setuptools editable install: an import + finder .install() call, but no exec/decode/network.
    ids, _ = _scan(
        tmp_path,
        "__editable__.pkg-0.1.pth",
        "import __editable___pkg_0_1_finder; __editable___pkg_0_1_finder.install()\n",
    )
    assert ids == set()


def test_namespace_pth_is_clean(tmp_path: Path):
    # Classic setuptools namespace .pth: import sys/os + __import__('importlib…'), no exec/decode.
    ids, _ = _scan(
        tmp_path,
        "ns.pth",
        "import sys, types, os; p = os.path.join('a'); "
        "__import__('importlib.util'); m = sys.modules.setdefault('ns', types.ModuleType('ns'))\n",
    )
    assert ids == set()
