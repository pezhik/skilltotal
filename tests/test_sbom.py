"""AI-BOM export: CycloneDX structure, purl derivation, and the inventory --sbom flag."""

from __future__ import annotations

import json
from pathlib import Path

import skilltotal
from skilltotal.cli import EXIT_OK, main
from skilltotal.inventory import DiscoveredComponent
from skilltotal.sbom import build_aibom, purl_from_source


def test_purl_from_source_variants():
    assert purl_from_source("npm:left-pad@1.3.0") == "pkg:npm/left-pad@1.3.0"
    assert purl_from_source("npm:left-pad") == "pkg:npm/left-pad"
    assert purl_from_source("npm:@scope/pkg@2.0.0") == "pkg:npm/%40scope/pkg@2.0.0"
    assert purl_from_source("npm:@scope/pkg") == "pkg:npm/%40scope/pkg"
    assert purl_from_source("pypi:requests==2.31.0") == "pkg:pypi/requests@2.31.0"
    assert purl_from_source("pypi:requests") == "pkg:pypi/requests"
    assert purl_from_source("C:/some/local/path") is None
    assert purl_from_source(None) is None


def test_build_aibom_structure_and_properties():
    items = [
        {
            "host": "Claude Desktop",
            "name": "filesystem",
            "kind": "mcp_server",
            "source": "npm:@modelcontextprotocol/server-filesystem@0.6.2",
            "config": "claude_desktop_config.json",
            "risk_level": "low",
            "risk_score": 0,
            "verdict": "low",
            "has_malicious_indicators": False,
        },
        {
            "host": "Cursor",
            "name": "opaque",
            "kind": "mcp_server",
            "source": None,
            "scannable": False,
            "note": "docker launcher",
        },
    ]
    bom = build_aibom(items)

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:")
    tool = bom["metadata"]["tools"]["components"][0]
    assert tool == {
        "type": "application",
        "name": "skilltotal",
        "version": skilltotal.__version__,
    }

    scanned, opaque = bom["components"]
    assert scanned["purl"] == "pkg:npm/%40modelcontextprotocol/server-filesystem@0.6.2"
    assert scanned["version"] == "0.6.2"
    props = {p["name"]: p["value"] for p in scanned["properties"]}
    assert props["skilltotal:host"] == "Claude Desktop"
    assert props["skilltotal:kind"] == "mcp_server"
    assert props["skilltotal:risk_level"] == "low"
    assert props["skilltotal:risk_score"] == "0"
    assert props["skilltotal:has_malicious_indicators"] == "false"

    assert "purl" not in opaque
    assert opaque["name"] == "opaque"


def test_cli_inventory_sbom(tmp_path: Path, capsys, monkeypatch):
    root = tmp_path / "skill"
    root.mkdir()
    (root / "SKILL.md").write_text("---\nname: demo\n---\nhello\n", encoding="utf-8")
    fake = [
        DiscoveredComponent(
            host="Claude skills", name="demo", kind="skill",
            source=str(root), scannable=True,
        )
    ]
    monkeypatch.setattr("skilltotal.cli.discover", lambda project=None: fake)

    code = main(["inventory", "--sbom"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    bom = json.loads(out)
    assert bom["bomFormat"] == "CycloneDX"
    component = bom["components"][0]
    props = {p["name"]: p["value"] for p in component["properties"]}
    assert props["skilltotal:kind"] == "skill"
    assert "skilltotal:risk_level" in props  # scan ran and attached a verdict
