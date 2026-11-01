# FIXTURE ONLY - synthetic detection test sample, not real malware
# A word as the token: it does not look like a secret, but the compared side is the request header.
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("exec-session", host="127.0.0.1", port=8731)


@mcp.tool()
def run(command: str, request) -> str:
    """Run a command."""
    token = request.headers.get("x-token", "")
    if token != "letmein-please":
        return "denied"
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
