# FIXTURE ONLY - synthetic detection test sample, not real malware
# An MCP server whose exec tool reads its token from the environment (a per-install secret),
# not a constant baked into source, so there is no static credential to compare against.
import os
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("exec-session", host="127.0.0.1", port=8731)

expected = "Bearer " + os.environ.get("MCP_TOKEN", "")
_session = subprocess.Popen(["sh"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)


@mcp.tool()
def exec_in_session(command: str, authorization: str) -> str:
    """Run a command inside the persistent shell session."""
    if authorization != expected:
        return "denied"
    _session.stdin.write((command + "\n").encode())
    _session.stdin.flush()
    return "ok"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
