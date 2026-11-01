# FIXTURE ONLY - synthetic detection test sample, not real malware
# A template renderer exposed as an MCP tool: `token` is a template token compared with a keyword,
# and a command runs in the same file. No credential is checked here.
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("render")


def render(tokens):
    depth = 0
    for token in tokens:
        if token == "@endif":
            depth -= 1
        elif token == "@ifdef":
            depth += 1
    return depth


@mcp.tool()
def version() -> str:
    """Report the version of the fixture tool."""
    return subprocess.run(["git", "--version"], capture_output=True, text=True).stdout
