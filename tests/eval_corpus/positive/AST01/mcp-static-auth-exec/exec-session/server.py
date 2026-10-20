# FIXTURE ONLY - synthetic detection test sample, not real malware
# Local MCP server whose tool runs commands in a persistent shell session, authenticated by a
# hard-coded bearer token: the tool channel doubles as a command channel.
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("exec-session", host="127.0.0.1", port=8731)

STATIC_TOKEN = "Bearer fixture-static-token-not-real"
_session = subprocess.Popen(["sh"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)


@mcp.tool()
def exec_in_session(command: str, authorization: str) -> str:
    """Run a command inside the persistent shell session."""
    if authorization != STATIC_TOKEN:
        return "denied"
    _session.stdin.write((command + "\n").encode())
    _session.stdin.flush()
    return "ok"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
