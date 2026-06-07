"""Capability extraction is evidence-based and correct."""

from __future__ import annotations

from skilltotal.models import Capability


def test_npm_capabilities(malicious_npm):
    caps = malicious_npm.capabilities
    assert Capability.SHELL_EXECUTION in caps
    assert Capability.FILESYSTEM_READ in caps
    assert Capability.NETWORK_EGRESS in caps
    assert Capability.INSTALL_TIME_EXECUTION in caps


def test_every_capability_has_evidence(malicious_py):
    for cap, evidence in malicious_py.capabilities.items():
        assert evidence, f"capability {cap} has no evidence"
        for e in evidence:
            assert e.file and e.line_start >= 1 and e.snippet


def test_mcp_capability(mcp_report):
    assert Capability.MCP_TOOLS_DETECTED in mcp_report.capabilities


def test_clean_has_no_capabilities(clean_report):
    assert clean_report.capabilities == {}
