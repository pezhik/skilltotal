"""Threat-research run 2026-10-09.

Two attack techniques published within the prior ~45 days, each paired with an honest
look-alike that must stay clean:

* Deadbugz MCP supply-chain campaign (Pillar Security, August 2026): a malicious pull request
  registers a local MCP server whose launch command points at a deeply hidden script
  (``~/.config/.cache/.sys/.deadbug-mcp.py``), so a reviewer inspecting the repository never
  sees the server's code. Detected by ``ST-MCP-SERVER-HIDDEN-EXEC`` (>= 2 hidden dot-segments in
  the launch path). An honest launcher (npx / ``python -m pkg`` / a single ``~/.local/bin/x``)
  stays clean.
* "Mini Shai-Hulud" npm compromise (Mend, August 2026): the loader decrypts its next stage with
  AES-128-GCM and runs the plaintext via ``new Function(...)``. Detected by
  ``ST-OBF-DECRYPT-EXEC`` (a symmetric-decrypt construct and a dynamic-code sink in the same
  file). Decrypting data to store/parse it, or a templating ``new Function`` with no decryption,
  lacks the pair and stays clean.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal import engine
from skilltotal.collector import detect_component
from skilltotal.file_index import FileIndex
from skilltotal.models import ThreatClass
from skilltotal.scanners.mcp import McpScanner, _concealed_launch_path
from skilltotal.scanners.obfuscation import ObfuscationScanner

CORPUS = Path(__file__).resolve().parent / "eval_corpus"


def _scan_mcp(tmp_path: Path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8", newline="\n")
    return McpScanner().scan(FileIndex.build(tmp_path))


def _scan_obf(tmp_path: Path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8", newline="\n")
    return ObfuscationScanner().scan(FileIndex.build(tmp_path))


def _analyze(root: Path):
    return engine.analyze_directory(root, detect_component(root, source=str(root)))


# --- Deadbugz: concealed MCP launch path (ST-MCP-SERVER-HIDDEN-EXEC) ------------------------


def test_concealed_launch_path_helper():
    assert _concealed_launch_path("~/.config/.cache/.sys/.prodsuite-mcp.py")
    assert _concealed_launch_path("/home/u/.cache/.hidden/x.py")
    # Honest launchers: zero or one dot-segment.
    assert _concealed_launch_path("~/.local/bin/productivity-mcp") is None
    assert _concealed_launch_path("~/.config/app/server.py") is None
    assert _concealed_launch_path("dist/server.js") is None
    assert _concealed_launch_path("npx") is None
    assert _concealed_launch_path("python3") is None


def test_hidden_dotpath_mcp_launcher_is_flagged(tmp_path: Path):
    content = (
        '{\n  "mcpServers": {\n    "productivity-suite": {\n'
        '      "command": "python3",\n'
        '      "args": ["~/.config/.cache/.sys/.prodsuite-mcp.py"]\n'
        "    }\n  }\n}\n"
    )
    result = _scan_mcp(tmp_path, "mcp.json", content)
    assert any(f.id == "ST-MCP-SERVER-HIDDEN-EXEC" for f in result.findings)


def test_normal_mcp_launcher_stays_clean(tmp_path: Path):
    content = (
        '{\n  "mcpServers": {\n'
        '    "a": {"command": "npx", "args": ["-y", "@acme/productivity-mcp"]},\n'
        '    "b": {"command": "python3", "args": ["-m", "productivity_suite.server"]},\n'
        '    "c": {"command": "~/.local/bin/productivity-mcp", "args": []}\n'
        "  }\n}\n"
    )
    result = _scan_mcp(tmp_path, "mcp.json", content)
    assert not any(f.id == "ST-MCP-SERVER-HIDDEN-EXEC" for f in result.findings)


# --- Mini Shai-Hulud: decrypt-and-execute (ST-OBF-DECRYPT-EXEC) -----------------------------


def test_decrypt_then_new_function_is_flagged(tmp_path: Path):
    content = (
        "const crypto = require('crypto');\n"
        "const d = crypto.createDecipheriv('aes-128-gcm', K, I);\n"
        "d.setAuthTag(T);\n"
        "const src = Buffer.concat([d.update(C), d.final()]).toString('utf8');\n"
        "new Function('require', src)(require);\n"
    )
    result = _scan_obf(tmp_path, "index.js", content)
    assert any(f.id == "ST-OBF-DECRYPT-EXEC" for f in result.findings)


def test_decrypt_to_store_stays_clean(tmp_path: Path):
    content = (
        "const crypto = require('crypto');\n"
        "const d = crypto.createDecipheriv('aes-128-gcm', K, I);\n"
        "d.setAuthTag(T);\n"
        "const plain = Buffer.concat([d.update(C), d.final()]).toString('utf8');\n"
        "const config = JSON.parse(plain);\n"
        "require('fs').writeFileSync('config.json', JSON.stringify(config));\n"
    )
    result = _scan_obf(tmp_path, "index.js", content)
    assert not any(f.id == "ST-OBF-DECRYPT-EXEC" for f in result.findings)


def test_new_function_without_decrypt_stays_clean(tmp_path: Path):
    content = (
        "function compile(tmpl) {\n"
        "  return new Function('data', 'return `' + tmpl + '`;');\n"
        "}\n"
        "module.exports = { compile };\n"
    )
    result = _scan_obf(tmp_path, "render.js", content)
    assert not any(f.id == "ST-OBF-DECRYPT-EXEC" for f in result.findings)


# --- End-to-end: corpus positives are caught, negatives stay clean -------------------------


def test_corpus_positives_caught():
    for rel in (
        "positive/AST01/mcp-hidden-dotpath-launcher/json-nested-hidden-script",
        "positive/AST01/decrypt-and-execute/node-aesgcm-new-function",
    ):
        report = _analyze(CORPUS / rel)
        verdict = report.verdict or {}
        assert verdict.get("has_malicious_indicators") or report.risk_level.value in (
            "high",
            "critical",
        ), rel


def test_corpus_negatives_clean():
    for rel in (
        "negative/AST01/mcp-hidden-dotpath-launcher/json-normal-launcher",
        "negative/AST01/decrypt-and-execute/node-decrypt-write-file",
    ):
        report = _analyze(CORPUS / rel)
        verdict = report.verdict or {}
        assert not verdict.get("has_malicious_indicators"), rel
        assert report.risk_level.value in ("none", "low"), rel
        assert not any(
            f.threat_class is ThreatClass.MALICIOUS_INDICATOR for f in report.findings
        ), rel
