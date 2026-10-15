"""Inventory discovery: parse agent configs, derive scannable sources, CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.inventory import DiscoveredComponent, derive_source, discover


def _write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


# --- derive_source -------------------------------------------------------------------
def test_derive_npx(tmp_path):
    src, _ = derive_source({"command": "npx", "args": ["-y", "@scope/mcp-foo@1.2.0"]}, tmp_path)
    assert src == "npm:@scope/mcp-foo@1.2.0"  # the pinned release is the one that runs


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
    monkeypatch.setattr("skilltotal.inventory.discover", lambda **kw: discover(home=home))

    rc = cli.main(["inventory", "--json", "--no-scan"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert any(i["source"] == "pypi:mcp-server-git" and i["host"] == "Cursor" for i in out)


@pytest.mark.parametrize("server", [
    {"command": "skilltotal", "args": ["mcp"]},
    {"command": "skilltotal.exe", "args": ["mcp"]},
    {"command": "uvx", "args": ["skilltotal", "mcp"]},
    {"command": "uvx", "args": ["skilltotal@0.72.0", "mcp"]},
    {"command": "npx", "args": ["-y", "skilltotal", "mcp"]},
    {"command": "python", "args": ["-m", "skilltotal", "mcp"]},
])
def test_skilltotals_own_mcp_server_is_recognised(tmp_path, server):
    home = tmp_path / "home"
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"st": server}})
    (found,) = discover(home=home)
    assert found.this_tool and not found.scannable and not found.remote
    assert found.note == "this scanner (skilltotal mcp)"


@pytest.mark.parametrize("server", [
    {"command": "./skilltotal", "args": ["mcp"]},  # a program committed to a repository
    {"command": "uvx", "args": ["--from", "git+https://example.invalid/st", "skilltotal", "mcp"]},
    {"command": "uvx", "args": ["--index-url", "https://example.invalid", "skilltotal", "mcp"]},
    {"command": "npx", "args": ["-y", "skilltotal-mcp"]},
    {"command": "skilltotal", "args": ["scan", "x"]},
])
def test_a_lookalike_of_the_own_server_is_not_trusted(tmp_path, server):
    home = tmp_path / "home"
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"st": server}})
    (found,) = discover(home=home)
    assert not found.this_tool


def test_a_remote_server_is_marked_remote(tmp_path):
    home = tmp_path / "home"
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"r": {"url": "https://example.com/sse"}}})
    (found,) = discover(home=home)
    assert found.remote and not found.this_tool
    assert found.note == "remote server (not scannable)"


def test_inventory_flags_what_guard_blocks(tmp_path, capsys, monkeypatch):
    # A typosquatted name scores low, and `guard --installed` blocks it: inventory said nothing.
    from skilltotal import cli

    pkg = tmp_path / "loddash"  # one edit from "lodash"
    pkg.mkdir()
    (pkg / "package.json").write_text('{"name": "loddash", "version": "1.0.0"}', encoding="utf-8")
    (pkg / "index.js").write_text("module.exports = {}\n", encoding="utf-8")
    fake = [DiscoveredComponent(host="Cursor", name="loddash", kind="mcp_server",
                                source=str(pkg), scannable=True)]
    monkeypatch.setattr("skilltotal.inventory.discover", lambda project=None: fake)

    assert cli.main(["inventory"]) == 0
    out = capsys.readouterr().out
    assert "1 component(s) need attention" in out
    assert "loddash: its name is a letter or two away from a popular package" in out
    assert cli.main(["inventory", "--json"]) == 0
    (item,) = json.loads(capsys.readouterr().out)
    assert item["guard"] == "block" and item["guard_reasons"]
    assert cli.main(["guard", "--installed"]) == cli.EXIT_FAIL_ON_HIGH  # the two agree
    capsys.readouterr()


def test_discovered_component_dataclass():
    c = DiscoveredComponent(host="h", name="n", kind="mcp_server", source="npm:x", scannable=True)
    assert c.scannable and c.note == ""
