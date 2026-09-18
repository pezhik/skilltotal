"""Offline, deterministic tests for the MCP-registry client behind the survey harness."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_DM = Path(__file__).parent / "manual_eval" / "discover_mcp.py"
_spec = importlib.util.spec_from_file_location("discover_mcp", _DM)
dm = importlib.util.module_from_spec(_spec)
sys.modules["discover_mcp"] = dm  # register before exec so dataclass annotations resolve
_spec.loader.exec_module(dm)


# --- normalize_entry -------------------------------------------------------------------------


def test_hygiene_rejects_traversal_shaped_identifiers():
    """`.` and `/` are legal in scoped npm names, so the pattern alone let `..` through.

    Not exploitable (collector.npm_package_spec refuses traversal, so the candidate never
    resolves), but this gate advertises that it stops local paths, and no real npm/PyPI/GitHub
    name contains `..`.
    """
    for bad in ("npm:../../etc/passwd", "pypi:../x", "https://github.com/o/../../etc"):
        assert not dm.hygiene_ok(dm.Candidate(bad, "npm", "mcp", "x")), bad
    for good in ("npm:@scope/pkg-mcp", "pypi:mcp-srv", "https://github.com/owner/repo"):
        assert dm.hygiene_ok(dm.Candidate(good, "npm", "mcp", "x")), good


def test_normalize_prefers_npm_package():
    item = {
        "server": {
            "name": "com.x/remote-filesystem",
            "packages": [{"registryType": "npm", "identifier": "remote-fs-mcp", "version": "1"}],
        }
    }
    c = dm.normalize_entry(item)
    assert (c.source, c.ecosystem, c.type, c.name) == (
        "npm:remote-fs-mcp",
        "npm",
        "mcp",
        "remote-filesystem",
    )


def test_normalize_pypi_package():
    item = {
        "server": {
            "name": "io.github.o/srv",
            "packages": [{"registryType": "pypi", "identifier": "mcp-srv", "version": "1"}],
        }
    }
    c = dm.normalize_entry(item)
    assert c.source == "pypi:mcp-srv"
    assert (c.ecosystem, c.type, c.name) == ("pypi", "mcp", "srv")


def test_normalize_falls_back_to_github_repo():
    item = {
        "server": {
            "name": "io.github.o/srv",
            "repository": {"url": "https://github.com/o/srv", "source": "github"},
        }
    }
    c = dm.normalize_entry(item)
    assert (c.source, c.ecosystem, c.type) == ("https://github.com/o/srv", "git", "mcp")


def test_normalize_skips_when_no_usable_coordinate():
    remotes = {"server": {"name": "x/y", "remotes": [{"type": "sse", "url": "https://h"}]}}
    oci = {"server": {"name": "x/y", "packages": [{"registryType": "oci", "identifier": "img"}]}}
    assert dm.normalize_entry(remotes) is None
    assert dm.normalize_entry(oci) is None
    assert dm.normalize_entry({"server": {}}) is None
    assert dm.normalize_entry({}) is None


# --- hygiene ---------------------------------------------------------------------------------


def test_hygiene_allowlist_accepts_clean_and_rejects_malformed():
    assert dm.hygiene_ok(dm.Candidate("npm:safe-pkg", "npm", "mcp", "safe"))
    assert dm.hygiene_ok(dm.Candidate("pypi:safe_pkg", "pypi", "mcp", "safe"))
    assert dm.hygiene_ok(dm.Candidate("npm:@scope/pkg", "npm", "mcp", "pkg"))
    assert dm.hygiene_ok(dm.Candidate("https://github.com/owner/repo", "git", "mcp", "repo"))
    assert not dm.hygiene_ok(dm.Candidate("npm:bad name", "npm", "mcp", "bad"))  # whitespace
    assert not dm.hygiene_ok(dm.Candidate("file:///etc/passwd", "git", "mcp", "x"))
