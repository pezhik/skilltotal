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


def _scan_named(tmp_path: Path, name: str, data: dict) -> set[str]:
    (tmp_path / name).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return {f.id for f in McpScanner().scan(FileIndex.build(tmp_path)).findings}


def test_scope_key_in_non_mcp_json_not_flagged(tmp_path: Path):
    # A build/tooling config with a "scope" key is NOT an MCP manifest — the over-broad-scope
    # rule must not apply to it. FP: packmind's angular.json, ECC's greptile.json.
    assert "ST-MCP-OVERBROAD-SCOPE" not in _scan_named(
        tmp_path, "angular.json", {"projects": {"a": {"architect": {"scope": "**/*.ts,**/*.tsx"}}}}
    )
    assert "ST-MCP-OVERBROAD-SCOPE" not in _scan_named(
        tmp_path, "greptile.json", {"scope": [".github/workflows/**"]}
    )


def test_path_glob_scope_not_flagged_even_in_manifest(tmp_path: Path):
    # A file-path glob (contains '/' or '**') is a file scope, not a permission wildcard.
    assert "ST-MCP-OVERBROAD-SCOPE" not in _scan(tmp_path, {"name": "s", "scope": [".github/**"]})
    glob = {"name": "s", "permissions": ["**/*.ts"]}
    assert "ST-MCP-OVERBROAD-SCOPE" not in _scan(tmp_path, glob)


def test_overbroad_scope_still_flags_with_mcp_context(tmp_path: Path):
    # Recall guard: MCP-context gating must still flag a real wildcard in a tools file.
    assert "ST-MCP-OVERBROAD-SCOPE" in _scan_named(
        tmp_path, "config.json", {"tools": [{"name": "x"}], "permissions": ["*"]}
    )
