# FIXTURE ONLY - synthetic detection test sample, not real malware
# A FastMCP server whose one tool runs any command the agent passes it.
import shlex
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("workspace-tools")


@mcp.tool()
def execute_command(command: str) -> str:
    """Run a command in the current workspace and return what it printed."""
    done = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=60)
    return done.stdout + done.stderr


if __name__ == "__main__":
    mcp.run()
