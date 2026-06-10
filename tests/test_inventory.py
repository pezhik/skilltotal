"""Inventory discovery: parse agent configs, derive scannable sources, CLI."""

from __future__ import annotations

import json
from pathlib import Path

from skilltotal.inventory import DiscoveredComponent, derive_source, discover


def _write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


# --- derive_source -------------------------------------------------------------------
def test_derive_npx(tmp_path):
    src, _ = derive_source({"command": "npx", "args": ["-y", "@scope/mcp-foo@1.2.0"]}, tmp_path)
    assert src == "npm:@scope/mcp-foo"


def test_derive_uvx(tmp_path):
    src, _ = derive_source({"command": "uvx", "args": ["mcp-server-git"]}, tmp_path)
    assert src == "pypi:mcp-server-git"


def test_derive_remote_url_not_scannable(tmp_path):
    src, note = derive_source({"url": "https://example.com/sse"}, tmp_path)
    assert src is None and "remote" in note


def test_derive_local_script(tmp_path):
    (tmp_path / "server.js").write_text("//", encoding="utf-8")
    src, _ = derive_source({"command": "node", "args": ["server.js"]}, tmp_path)
    assert src == str(tmp_path)


def test_derive_unknown_launcher(tmp_path):
    src, note = derive_source({"command": "weirdlauncher", "args": []}, tmp_path)
    assert src is None and note


# --- discover ------------------------------------------------------------------------
def test_discover_from_home_and_project(tmp_path):
    home = tmp_path / "home"
    project = tmp_path / "proj"
    # Claude Code global config
    _write(home / ".claude.json", {"mcpServers": {"git": {"command": "uvx", "args": ["mcp-server-git"]}}})  # noqa: E501
    # project-local .mcp.json
    _write(project / ".mcp.json", {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "fs-mcp"]}}})  # noqa: E501
    # a skill
    skill = project / ".claude" / "skills" / "helper"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# Helper", encoding="utf-8")

    comps = discover(home=home, project=project)
    by_name = {c.name: c for c in comps}
    assert by_name["git"].source == "pypi:mcp-server-git"
    assert by_name["fs"].source == "npm:fs-mcp"
    assert by_name["helper"].kind == "skill"
    assert by_name["helper"].scannable


def test_discover_ignores_missing_and_bad_configs(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".claude.json").write_text("{ not json", encoding="utf-8")
    assert discover(home=home) == []


# --- CLI -----------------------------------------------------------------------------
def test_cli_inventory_json_no_scan(tmp_path, capsys, monkeypatch):
    from skilltotal import cli

    home = tmp_path / "home"
    cfg = {"mcpServers": {"git": {"command": "uvx", "args": ["mcp-server-git"]}}}
    _write(home / ".cursor" / "mcp.json", cfg)
    monkeypatch.setattr(cli, "discover", lambda **kw: discover(home=home))

    rc = cli.main(["inventory", "--json", "--no-scan"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert any(i["source"] == "pypi:mcp-server-git" and i["host"] == "Cursor" for i in out)


def test_discovered_component_dataclass():
    c = DiscoveredComponent(host="h", name="n", kind="mcp_server", source="npm:x", scannable=True)
    assert c.scannable and c.note == ""
