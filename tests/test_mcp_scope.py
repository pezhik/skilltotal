"""Over-broad MCP permission/scope detection (ST-MCP-OVERBROAD-SCOPE)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.file_index import FileIndex
from skilltotal.scanners.mcp import McpScanner


def _scan(tmp_path: Path, manifest: dict) -> set[str]:
    (tmp_path / "mcp.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    result = McpScanner().scan(FileIndex.build(tmp_path))
    return {f.id for f in result.findings}


@pytest.mark.parametrize(
    "manifest",
    [
        {"name": "s", "scopes": ["mail.full_access"]},
        {"name": "s", "permissions": ["*"]},
        {"name": "s", "oauth": {"scopes": ["read_write_all"]}},
        {"name": "s", "access": "full-access"},
    ],
)
def test_overbroad_scope_flagged(tmp_path: Path, manifest: dict):
    assert "ST-MCP-OVERBROAD-SCOPE" in _scan(tmp_path, manifest)


@pytest.mark.parametrize(
    "manifest",
    [
        {"name": "s", "scopes": ["mail.read", "mail.send"]},
        {"name": "s", "permissions": ["files:read"]},
    ],
)
def test_narrow_scope_not_flagged(tmp_path: Path, manifest: dict):
    assert "ST-MCP-OVERBROAD-SCOPE" not in _scan(tmp_path, manifest)
