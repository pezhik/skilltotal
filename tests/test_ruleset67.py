"""Ruleset 67: false positives a pre-launch review found on well-known packages.

Each case is pinned beside a test that the construct it resembles still fires. Sanitized fixtures
only: nothing here is executed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.models import Component


def _report(root: Path):
    return analyze_directory(root, Component(name="x", type="directory", source=str(root)))


def _ids(root: Path) -> set[str]:
    return {f.id for f in _report(root).findings}


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


# --- ST-EXPOSE-BIND: an address literal handed to a string method is text, not a bind --------

@pytest.mark.parametrize(
    "line",
    [
        # pytest's terminal summary: a test id split at "::", maxsplit 1 (it scored pytest 30).
        'counts = Counter(item.nodeid.split("::", 1)[0] for item in items)\n',
        'head, _, tail = nodeid.rpartition("::")\n',
        'parts = name.rsplit("::", 2)\n',
        'host = url.replace("0.0.0.0", "localhost", 1)\n',
        'if addr.startswith("0.0.0.0", 0):\n    pass\n',
    ],
)
def test_an_address_passed_to_a_string_method_is_not_a_bind(tmp_path, line):
    assert "ST-EXPOSE-BIND" not in _ids(_write(tmp_path, {"terminal.py": line}))


@pytest.mark.parametrize(
    "line",
    [
        'web.TCPSite(runner, "0.0.0.0", 8080)\n',
        'web.TCPSite(runner, "::", 8080)\n',
        'app.run(host="0.0.0.0", port=80)\n',
        "server.listen(3000, '0.0.0.0')\n",
    ],
)
def test_a_real_bind_still_fires(tmp_path, line):
    assert "ST-EXPOSE-BIND" in _ids(_write(tmp_path, {"srv.py": line}))


# --- ST-CMDI-PY: a loop over literal strings does not make the command dynamic ------------------

_MCP_NPX_PROBE = (
    "import subprocess\n"
    'for cmd in ["npx.cmd", "npx.exe", "npx"]:\n'
    "    try:\n"
    '        subprocess.run([cmd, "--version"], check=True, capture_output=True, shell=True)\n'
    "        break\n"
    "    except subprocess.CalledProcessError:\n"
    "        continue\n"
)


@pytest.mark.parametrize(
    "source",
    [
        # The official MCP Python SDK's npx probe (mcp/cli/cli.py); it scored the SDK medium 40.
        _MCP_NPX_PROBE,
        'import subprocess\nfor tool in ("git", "hg"):\n'
        '    subprocess.run(f"{tool} --version", shell=True)\n',
        'import subprocess\nfor flag in ["-a", "-l"]:\n'
        '    subprocess.run("ls " + flag, shell=True)\n',
    ],
)
def test_a_command_built_from_a_loop_over_literal_strings_is_not_injectable(tmp_path, source):
    ids = _ids(_write(tmp_path, {"cli.py": source}))
    assert "ST-CMDI-PY" not in ids
    assert "ST-SHELL-PY" in ids  # still a shell capability


@pytest.mark.parametrize(
    "source",
    [
        # the loop runs over something that is not a list of literal strings
        'import subprocess\nfor cmd in commands:\n    subprocess.run(cmd, shell=True)\n',
        'import subprocess\nfor cmd in [user_cmd, "ls"]:\n    subprocess.run(cmd, shell=True)\n',
        # the loop variable is rebound inside the body
        'import subprocess\nfor cmd in ["ls"]:\n    cmd = cmd + arg\n'
        '    subprocess.run(cmd, shell=True)\n',
        # a constant loop variable next to a dynamic part
        'import subprocess\nfor flag in ["-a"]:\n'
        '    subprocess.run("ls " + flag + path, shell=True)\n',
        # the same name used after the loop is not covered by it
        'import subprocess\nfor cmd in ["ls"]:\n    pass\ncmd = input()\n'
        'subprocess.run(cmd, shell=True)\n',
    ],
)
def test_a_dynamic_command_near_a_loop_still_fires(tmp_path, source):
    # A command traced from input() is raised as the stronger taint flow instead of ST-CMDI-PY.
    assert {"ST-CMDI-PY", "ST-TAINT-SHELL-PY"} & _ids(_write(tmp_path, {"cli.py": source}))


# --- MCP tool rules: a tool named in a comment or a Python string is not a tool ---------------

_MCP_RULES = {"ST-MCP-DETECTED", "ST-MCP-DANGEROUS-TOOL"}


@pytest.mark.parametrize(
    ("name", "source"),
    [
        # SkillTotal's own MCP scanner documents the shapes it matches; its self-scan opened with
        # a HIGH dangerous-tool finding on this comment.
        ("scanner.py",
         '# JS/TS: server.tool("execute_command", ...) / server.registerTool("name", ...)\n'
         "import re\n"),
        ("docs_example.py",
         'EXAMPLE = """\nfrom mcp.server.fastmcp import FastMCP\n@mcp.tool()\n'
         'def run_command(cmd: str) -> str:\n    ...\n"""\n'),
        ("index.js",
         'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
         '// server.tool("execute_command", schema, handler) registers a shell tool\n'
         "export const x = 1;\n"),
    ],
)
def test_a_tool_named_in_a_comment_or_a_python_string_is_not_a_tool(tmp_path, name, source):
    assert not _ids(_write(tmp_path, {name: source})) & _MCP_RULES


@pytest.mark.parametrize(
    ("name", "source"),
    [
        ("index.js",
         'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
         'server.tool("execute_command", schema, async () => run());\n'),
        ("server.py",
         "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
         "@mcp.tool()\ndef run_command(cmd: str) -> str:\n    return cmd\n"),
    ],
)
def test_a_real_tool_definition_still_fires(tmp_path, name, source):
    assert "ST-MCP-DANGEROUS-TOOL" in _ids(_write(tmp_path, {name: source}))


# --- ST-NET-PY: only an imported network library is network -----------------------------------

@pytest.mark.parametrize(
    "source",
    [
        # a parameter that happens to be called `requests` (mcp, langchain)
        "def handle(requests: dict):\n    for key, req in requests.items():\n        print(key)\n",
        # the package's own module named requests (fastapi, django)
        "from .requests import Request\n",
        "from ..requests import RequestSite\n",
        # a variable whose name starts with urllib (requests' own version check)
        'urllib3_version_list = []\nurllib3_version_list.append("0")\n',
        # the status-code table of http.client (fastapi)
        "import http.client\nSTATUS = http.client.responses[404]\n",
    ],
)
def test_a_name_that_only_looks_like_a_network_library_is_not_network(tmp_path, source):
    assert "ST-NET-PY" not in _ids(_write(tmp_path, {"mod.py": source}))


def test_a_credentials_reader_with_a_requests_dict_is_not_exfiltration(tmp_path):
    # The path to a false critical: reading an AWS profile plus `requests.items()` on a dict made
    # ST-COMBO-EXFIL (credential read + network egress).
    source = (
        "from pathlib import Path\n"
        "def profiles(requests: dict) -> dict:\n"
        '    text = (Path.home() / ".aws" / "credentials").read_text()\n'
        "    return {k: v for k, v in requests.items() if k in text}\n"
    )
    ids = _ids(_write(tmp_path, {"aws.py": source}))
    assert "ST-NET-PY" not in ids
    assert "ST-COMBO-EXFIL" not in ids


@pytest.mark.parametrize(
    "source",
    [
        "import requests\nrequests.get(url)\n",
        "import requests as r\nr.post(url, data=x)\n",
        "from urllib.request import urlopen\nurlopen(url)\n",
        'import http.client\nconn = http.client.HTTPSConnection("example.invalid")\n',
        "import httpx\n",
        "from requests import Session\n",
        "import urllib.request\nurllib.request.urlopen(url)\n",
    ],
)
def test_a_real_network_library_still_fires(tmp_path, source):
    assert "ST-NET-PY" in _ids(_write(tmp_path, {"mod.py": source}))
