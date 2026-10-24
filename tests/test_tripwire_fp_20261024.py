"""Reputable-corpus false positives of two ruleset-81 rules (tripwire 2026-10-24).

Each case reduces the construct a popular package ships to a sanitized look-alike that must stay
clean, next to the attack shape that must keep firing:

* ``ST-PY-STDLIB-SHADOW``: ``exec`` of a string literal that only imports or defines a function
  (sympy ``abc.py``, execnet ``script/socketserver.py``), and a read of the module's own
  ``sys.modules[__name__]`` entry (google-cloud-pubsub ``pubsub_v1/types.py``).
* ``ST-MCP-STATIC-AUTH-EXEC``: a ``"Bearer <token>"`` redaction placeholder and a
  ``"Bearer $MY_TOKEN"`` help string in a bundle that also spawns processes
  (@anthropic-ai/claude-agent-sdk).
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory


def _ids(root: Path) -> set[str]:
    report = analyze_directory(root, detect_component(root, source=str(root)))
    return {f.id for f in report.findings}


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return root


# --- ST-PY-STDLIB-SHADOW -------------------------------------------------------------------


def test_exec_of_import_literal_stays_clean(tmp_path):
    root = _write(tmp_path, "pkg/abc.py", "ns = {}\nexec('from pkg import *', ns)\n")
    _write(tmp_path, "pkg/__init__.py", "")
    assert "ST-PY-STDLIB-SHADOW" not in _ids(root)


def test_exec_of_function_definition_literal_stays_clean(tmp_path):
    root = _write(
        tmp_path,
        "pkg/script/socketserver.py",
        'exec(\n    """def exec_(source, locs):\n    exec(source, locs)"""\n)\n',
    )
    assert "ST-PY-STDLIB-SHADOW" not in _ids(root)


def test_read_of_own_sys_modules_entry_stays_clean(tmp_path):
    root = _write(
        tmp_path,
        "pkg/types.py",
        "import sys\n"
        "names = []\n"
        "for name, message in {'A': 1}.items():\n"
        "    setattr(sys.modules[__name__], name, message)\n"
        "    names.append(name)\n",
    )
    assert "ST-PY-STDLIB-SHADOW" not in _ids(root)


def test_exec_of_shell_literal_still_flagged(tmp_path):
    root = _write(tmp_path, "struct.py", "exec('import os; os.system(\"echo fixture-only\")')\n")
    assert "ST-PY-STDLIB-SHADOW" in _ids(root)


def test_exec_of_unparsable_literal_still_flagged(tmp_path):
    root = _write(tmp_path, "json.py", "exec('this is not python (')\n")
    assert "ST-PY-STDLIB-SHADOW" in _ids(root)


def test_exec_of_variable_still_flagged(tmp_path):
    root = _write(tmp_path, "base64.py", "payload = open('data.bin').read()\nexec(payload)\n")
    assert "ST-PY-STDLIB-SHADOW" in _ids(root)


def test_sys_modules_write_still_flagged(tmp_path):
    root = _write(
        tmp_path,
        "struct.py",
        "import sys\nimport _struct\nsys.modules[__name__] = _struct\n",
    )
    assert "ST-PY-STDLIB-SHADOW" in _ids(root)


# --- ST-MCP-STATIC-AUTH-EXEC ---------------------------------------------------------------

_MCP_EXEC_HEAD = (
    "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"
    "import { execFile } from 'child_process';\n"
    "const server = new McpServer({ name: 'fixture', version: '0.0.0' });\n"
    "server.tool('run', {}, async () => { execFile('echo', ['fixture-only']); return {}; });\n"
)


def test_bearer_placeholders_stay_clean(tmp_path):
    root = _write(
        tmp_path,
        "server.mjs",
        _MCP_EXEC_HEAD
        + "const REDACT = { bearer: [/Bearer\\s+\\S+/gi, \"Bearer <token>\"] };\n"
        + "const HELP = 'Use env vars (e.g., \"Authorization\": \"Bearer $MY_TOKEN\").';\n"
        + "const HELP2 = 'Or \"Bearer ${MY_TOKEN}\".';\n",
    )
    assert "ST-MCP-STATIC-AUTH-EXEC" not in _ids(root)


def test_literal_bearer_token_still_flagged(tmp_path):
    root = _write(
        tmp_path,
        "server.mjs",
        _MCP_EXEC_HEAD
        + "const STATIC = \"Bearer fixture-static-token-not-real\";\n"
        + "export function ok(h) { return h === STATIC; }\n",
    )
    assert "ST-MCP-STATIC-AUTH-EXEC" in _ids(root)
