"""MCP server shapes the engine did not recognise, and process wrappers it did not see.

Found on 2026-10-05: 10 of the 65 MCP servers in the hosted catalog produced no ST-MCP-DETECTED,
three of them the official reference servers (git, time, fetch), and the git server -- which
commits, resets and checks out on the user's behalf through GitPython -- reported no capability
at all. Each test below is a minimal reproduction written for this suite (no vendored code) of a
shape seen in a real package, plus the near-miss that must stay silent.
"""

from __future__ import annotations

import json

from skilltotal.file_index import FileIndex
from skilltotal.scanners.mcp import McpScanner
from skilltotal.scanners.python_ast import PythonAstScanner
from skilltotal.scanners.shell_exec import ShellExecScanner


def _mcp(tmp_path, files: dict[str, str]):
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return McpScanner().scan(FileIndex.build(tmp_path))


def _ids(result) -> set[str]:
    return {f.id for f in result.findings}


# --- Python low-level SDK: Server + @server.list_tools / @server.call_tool (git, time, fetch) ---

LOW_LEVEL_PY = '''from mcp.server import Server
from mcp.types import Tool, TextContent

server = Server("demo")

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [Tool(name="{name}", description="d", inputSchema={{}})]

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    return []
'''


def test_python_low_level_server_is_an_mcp_surface(tmp_path):
    result = _mcp(tmp_path, {"server.py": LOW_LEVEL_PY.format(name="get_current_time")})
    assert "ST-MCP-DETECTED" in _ids(result)
    assert "ST-MCP-DANGEROUS-TOOL" not in _ids(result)


def test_python_low_level_tool_names_are_classified(tmp_path):
    result = _mcp(tmp_path, {"server.py": LOW_LEVEL_PY.format(name="execute_command")})
    dangerous = [f for f in result.findings if f.id == "ST-MCP-DANGEROUS-TOOL"]
    assert dangerous and "shell" in dangerous[0].description


def test_a_tool_named_in_a_file_with_no_mcp_import_is_not_classified(tmp_path):
    """`Tool(name=...)` is a common shape outside MCP (agent frameworks, CLIs)."""
    src = 'from langchain.tools import Tool\nt = Tool(name="execute_command", func=f)\n'
    result = _mcp(tmp_path, {"agent.py": src})
    assert not _ids(result) & {"ST-MCP-DETECTED", "ST-MCP-DANGEROUS-TOOL"}


# --- programmatic registration: mcp.add_tool(FunctionTool.from_function(...)) (keboola) ---


def test_add_tool_on_an_mcp_server_is_a_surface(tmp_path):
    result = _mcp(tmp_path, {"tools.py": (
        "from fastmcp import FastMCP\nfrom fastmcp.tools import FunctionTool\n\n"
        "def add_tools(mcp: FastMCP) -> None:\n"
        "    mcp.add_tool(FunctionTool.from_function(list_buckets))\n"
    )})
    assert "ST-MCP-DETECTED" in _ids(result)


def test_add_tool_outside_mcp_is_not(tmp_path):
    result = _mcp(tmp_path, {"agent.py": "agent = Agent()\nagent.add_tool(search)\n"})
    assert "ST-MCP-DETECTED" not in _ids(result)


# --- decorator frameworks: @Tool({ name }) in TS, `(0, x.Tool)({ name })` once compiled (anki) ---


def test_mcp_nest_decorator_is_a_surface_in_source_and_compiled(tmp_path):
    src = _mcp(tmp_path / "src", {"note.tool.ts": (
        "import { Tool } from '@rekog/mcp-nest';\n"
        "export class NoteTool {\n"
        "  @Tool({ name: 'addNote', description: 'Add a note' })\n  add() {}\n}\n"
    )})
    assert "ST-MCP-DETECTED" in _ids(src)
    built = _mcp(tmp_path / "dist", {"note.tool.js": (
        'const mcp_nest_1 = require("@rekog/mcp-nest");\n'
        "__decorate([\n    (0, mcp_nest_1.Tool)({\n"
        "        name: \"execute_command\",\n"
        "        description: \"x\",\n    })\n], NoteTool.prototype, \"add\", null);\n"
    )})
    assert {"ST-MCP-DETECTED", "ST-MCP-DANGEROUS-TOOL"} <= _ids(built)


def test_a_tool_decorator_with_no_mcp_import_is_not_a_surface(tmp_path):
    result = _mcp(tmp_path, {"weather.ts": (
        "import { Tool } from 'some-agent-kit';\n"
        "class W {\n  @Tool({ name: 'get_weather' })\n  run() {}\n}\n"
    )})
    assert "ST-MCP-DETECTED" not in _ids(result)


# --- JS low-level SDK: server.setRequestHandler(ListToolsRequestSchema, ...) ---


def test_js_low_level_request_handler_is_a_surface(tmp_path):
    result = _mcp(tmp_path, {"index.js": (
        'import { Server } from "@modelcontextprotocol/sdk/server/index.js";\n'
        "const s = makeServer();\n"
        "s.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));\n"
    )})
    assert "ST-MCP-DETECTED" in _ids(result)


# --- a package that only launches the real server (native binary or a dependency) ---


def _launcher(tmp_path, extra: dict[str, str] | None = None):
    files = {
        "package.json": json.dumps({
            "name": "@vendor/thing-mcp",
            "mcpName": "io.github.vendor/thing",
            "bin": {"thing-mcp": "index.js"},
            "optionalDependencies": {"@vendor/thing-mcp-linux-x64": "1.0.0"},
        }),
        "index.js": "#!/usr/bin/env node\nrequire('./launch')(process.argv.slice(2));\n",
    }
    files.update(extra or {})
    return _mcp(tmp_path, files)


def test_a_launcher_package_says_the_server_is_not_in_it(tmp_path):
    result = _launcher(tmp_path)
    notes = [n for n in result.needs_review if "code not found" in n.title]
    assert len(notes) == 1 and notes[0].file == "package.json"
    # A note, never a finding: it must not move the score or claim a capability.
    assert not _ids(result)


def test_a_package_with_its_server_inside_gets_no_launcher_note(tmp_path):
    result = _launcher(tmp_path, {"server.js": 'const s = new McpServer({ name: "x" });\n'})
    assert not [n for n in result.needs_review if "code not found" in n.title]


def test_a_package_that_is_not_an_mcp_server_gets_no_launcher_note(tmp_path):
    files = {"package.json": json.dumps({"name": "left-pad"}), "index.js": "module.exports = 1;\n"}
    result = _mcp(tmp_path, files)
    assert not result.needs_review


# --- process wrappers: GitPython (Python) and simple-git (Node) run the git binary ---


def _py(tmp_path, text: str):
    (tmp_path / "m.py").write_text(text, encoding="utf-8")
    return PythonAstScanner().scan(FileIndex.build(tmp_path))


def test_gitpython_is_command_execution(tmp_path):
    for i, src in enumerate(("import git\nrepo = git.Repo('.')\nrepo.git.checkout(branch)\n",
                             "from git import Repo\nRepo('.').git.reset('--hard')\n")):
        d = tmp_path / str(i)
        d.mkdir()
        assert "ST-SHELL-PY" in _ids(_py(d, src)), src


def test_a_local_module_named_like_a_wrapper_is_not(tmp_path):
    """`from .git import x` / `from .sh import y` are the package's own modules."""
    result = _py(tmp_path, "from .git import parse_ref\nfrom .sh import quote\n")
    assert "ST-SHELL-PY" not in _ids(result)


def test_simple_git_is_command_execution_in_node(tmp_path):
    src = "const simpleGit = require('simple-git');\nsimpleGit().checkout(b);\n"
    (tmp_path / "g.js").write_text(src, encoding="utf-8")
    result = ShellExecScanner().scan(FileIndex.build(tmp_path))
    assert "ST-SHELL-NODE" in _ids(result)


def test_a_proxy_serving_mcp_over_stdio_is_an_mcp_server(tmp_path):
    """mcp-remote registers no tool of its own; it serves a remote server's tools over stdio."""
    result = _mcp(tmp_path, {"proxy.js": (
        'import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";\n'
        "const local = new StdioServerTransport();\n"
    )})
    assert "ST-MCP-DETECTED" in _ids(result)


def test_an_mcp_client_building_its_own_tools_is_not_a_server(tmp_path):
    """A client of MCP servers that also makes LangChain tools: no server surface of its own."""
    result = _mcp(tmp_path, {"agent.py": (
        "from mcp import ClientSession\nfrom langchain.tools import Tool\n"
        't = Tool(name="execute_command", func=run)\nagent.add_tool(t)\n'
    )})
    assert not _ids(result) & {"ST-MCP-DETECTED", "ST-MCP-DANGEROUS-TOOL"}


def test_a_server_shown_only_in_docs_or_tests_still_gets_the_launcher_note(tmp_path):
    """@playwright/mcp's README documents an SDK server; the package itself only launches one."""
    result = _launcher(tmp_path, {
        "README.md": "```js\nconst server = new McpServer({ name: 'x' });\n```\n",
        "tests/server.test.js": "const s = new McpServer({ name: 't' });\n",
    })
    assert [n for n in result.needs_review if "code not found" in n.title]


def test_a_decorator_named_in_a_comment_is_not_a_surface(tmp_path):
    """boss-agent-cli explains in a comment that mcp 2.0 removed `@server.list_tools()`."""
    result = _mcp(tmp_path, {
        "pyproject.toml": "# mcp 2.0 removed the `@server.list_tools()` decorators\n",
        "notes.py": "# we used to write @server.call_tool() here\nx = 1\n",
    })
    assert "ST-MCP-DETECTED" not in _ids(result)


def test_python_sdk_2_request_handlers_are_a_surface(tmp_path):
    """mcp 2.0 replaced the decorators with add_request_handler (boss-agent-cli)."""
    result = _mcp(tmp_path, {"mcp_server.py": (
        "from mcp.server import Server\n"
        "server = Server('boss')\n"
        'server.add_request_handler("tools/list", PaginatedRequestParams, list_tools)\n'
    )})
    assert "ST-MCP-DETECTED" in _ids(result)


def test_python_stdio_server_counts_only_with_a_server_import(tmp_path):
    served = _mcp(tmp_path / "a", {"main.py": (
        "from mcp.server.stdio import stdio_server\n"
        "async def main():\n    async with stdio_server() as (r, w):\n        pass\n"
    )})
    assert "ST-MCP-DETECTED" in _ids(served)
    unrelated = _mcp(tmp_path / "b", {"main.py": "def stdio_server():\n    return None\n"})
    assert "ST-MCP-DETECTED" not in _ids(unrelated)


def test_mcp_patterns_stay_linear():
    """Every MCP surface pattern on adversarial input of each shape it could backtrack over.

    `\s*\)?\s*` in the tool-name pattern was quadratic: "Tool" + 20k spaces took 2.3 s, and a
    file can be 2 MiB. Doubling the input must not much more than double the time.
    """
    import time

    from skilltotal.scanners import mcp

    patterns = [mcp._CODE_SURFACE, mcp._MCP_IMPORT, mcp._CONTEXT_SURFACE, mcp._CONTEXT_TOOL_NAME]
    fillers = [" ", "\t", "\n", " \n", "(", ")", "{", "@", "@x.", "Tool", "Tool(", "Tool)", "name"]

    def worst(n: int) -> float:
        slowest = 0.0
        for filler in fillers:
            for head in ("Tool", "@server.", "add_request_handler(", "mcp.server", "new "):
                text = head + filler * n + "!"
                start = time.perf_counter()
                for pat in patterns:
                    for _ in pat.finditer(text):
                        pass
                slowest = max(slowest, time.perf_counter() - start)
        return slowest

    small, large = worst(5_000), worst(40_000)
    # 8x the input: linear is ~8x, quadratic ~64x. Generous bound for a noisy CI machine.
    assert large < 1.0, f"{large:.2f}s on 40k-character input"
    assert large < max(small, 0.002) * 25, f"{small:.4f}s -> {large:.4f}s"
