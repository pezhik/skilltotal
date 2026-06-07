"""Per-scanner behavior against fixtures, and the universal evidence invariant."""

from __future__ import annotations

import pytest

from tests.conftest import analyze_fixture

ALL_FIXTURES = [
    "malicious_npm_pkg",
    "malicious_py_pkg",
    "mcp_server",
    "prompt_injection",
    "clean_pkg",
]


def _finding_ids(report) -> set[str]:
    return {f.id for f in report.findings}


def test_npm_shell_install_network_fs(malicious_npm):
    ids = _finding_ids(malicious_npm)
    assert {"ST-SHELL-NODE", "ST-INSTALL-NPM", "ST-NET-NODE", "ST-FS-NODE-READ",
            "ST-SENS-PATH"} <= ids


def test_py_shell_dynamic_obfuscation_network(malicious_py):
    ids = _finding_ids(malicious_py)
    assert {"ST-SHELL-PY", "ST-DYN-PY", "ST-OBF-DECODE-EXEC", "ST-NET-PY",
            "ST-FS-PY-READ", "ST-SENS-PATH", "ST-INSTALL-PY"} <= ids


def test_mcp_dangerous_and_server_exec(mcp_report):
    ids = _finding_ids(mcp_report)
    assert {"ST-MCP-DANGEROUS-TOOL", "ST-MCP-SERVER-EXEC", "ST-MCP-DETECTED"} <= ids
    dangerous = next(f for f in mcp_report.findings if f.id == "ST-MCP-DANGEROUS-TOOL")
    # description lists detected categories
    for cat in ("shell", "filesystem", "network", "credential"):
        assert cat in dangerous.description


def test_prompt_injection_strong_and_weak(prompt_report):
    ids = _finding_ids(prompt_report)
    assert "ST-PROMPT-INJECTION" in ids
    # "before answering" is weak -> needs_review, never a finding
    assert any("Ambiguous" in n.title for n in prompt_report.needs_review)


def test_node_shell_library_import_detected(tmp_path):
    """Importing a process-spawning library (zx/execa) signals shell execution."""
    from skilltotal.file_index import FileIndex
    from skilltotal.scanners.shell_exec import ShellExecScanner

    (tmp_path / "s.ts").write_text('import { $ } from "zx";\n$`ls`;\n', encoding="utf-8")
    result = ShellExecScanner().scan(FileIndex.build(tmp_path))
    assert any(f.id == "ST-SHELL-NODE" for f in result.findings)


def test_mcp_code_defined_tool_classified_ts(tmp_path):
    """A dangerous MCP tool registered in TS code is classified, not just detected."""
    from skilltotal.file_index import FileIndex
    from skilltotal.scanners.mcp import McpScanner

    (tmp_path / "server.ts").write_text(
        'server.tool("execute_command", { command: z.string() }, async () => {});\n',
        encoding="utf-8",
    )
    result = McpScanner().scan(FileIndex.build(tmp_path))
    assert any(f.id == "ST-MCP-DANGEROUS-TOOL" for f in result.findings)


def test_mcp_code_defined_tool_classified_py(tmp_path):
    """A dangerous MCP tool defined via a Python decorator is classified."""
    from skilltotal.file_index import FileIndex
    from skilltotal.scanners.mcp import McpScanner

    (tmp_path / "srv.py").write_text(
        "@mcp.tool()\ndef read_file(path: str) -> str:\n    return open(path).read()\n",
        encoding="utf-8",
    )
    result = McpScanner().scan(FileIndex.build(tmp_path))
    dangerous = [f for f in result.findings if f.id == "ST-MCP-DANGEROUS-TOOL"]
    assert dangerous
    assert "filesystem" in dangerous[0].description


def test_mcp_benign_code_tool_not_dangerous(tmp_path):
    """A harmless tool name is detected as a surface but not flagged dangerous."""
    from skilltotal.file_index import FileIndex
    from skilltotal.scanners.mcp import McpScanner

    (tmp_path / "srv.py").write_text(
        "@mcp.tool()\ndef add_numbers(a: int, b: int) -> int:\n    return a + b\n",
        encoding="utf-8",
    )
    result = McpScanner().scan(FileIndex.build(tmp_path))
    assert not any(f.id == "ST-MCP-DANGEROUS-TOOL" for f in result.findings)


def test_clean_has_no_findings(clean_report):
    assert clean_report.findings == []
    assert clean_report.risk_score == 0


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_every_finding_has_valid_evidence(name):
    """The core invariant: no confirmed finding without complete evidence."""
    report = analyze_fixture(name)
    for f in report.findings:
        assert f.evidence, f"{f.id} has no evidence"
        for e in f.evidence:
            assert e.file
            assert e.line_start >= 1
            assert e.line_end >= e.line_start
            assert isinstance(e.snippet, str) and e.snippet != ""
