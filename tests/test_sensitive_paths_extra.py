"""Expanded cloud/registry/wallet credential paths (ST-SENS-PATH)."""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.file_index import FileIndex
from skilltotal.scanners.sensitive_paths import SensitivePathScanner


def _scan(tmp_path: Path, content: str) -> set[str]:
    # Use a .js file so the engine's Python string/comment demotion is irrelevant at scanner level.
    (tmp_path / "steal.js").write_text(content, encoding="utf-8", newline="\n")
    result = SensitivePathScanner().scan(FileIndex.build(tmp_path))
    return {f.id for f in result.findings}


@pytest.mark.parametrize(
    "snippet",
    [
        'fs.readFileSync(os.homedir() + "/.docker/config.json")',
        'open("~/.azure/accessTokens.json")',
        'read("~/.git-credentials")',
        'load("application_default_credentials.json")',
        'fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/")',
        'copy("~/.config/solana/id.json")',
    ],
)
def test_new_credential_paths_flagged(tmp_path: Path, snippet: str):
    assert "ST-SENS-PATH" in _scan(tmp_path, snippet + "\n")


def test_ordinary_path_not_flagged(tmp_path: Path):
    assert "ST-SENS-PATH" not in _scan(tmp_path, 'open("./data/config.json")\n')
