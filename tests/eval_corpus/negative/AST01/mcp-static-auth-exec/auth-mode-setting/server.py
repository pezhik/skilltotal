# FIXTURE ONLY - synthetic detection test sample, not real malware
# `auth` here is a configured mode, not a credential; the words it is compared with name a setting.
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("modes")


def check_config(server, host):
    if server.auth == "no-auth" and host != "127.0.0.1":
        raise ValueError("refusing to serve without auth on a public address")


@mcp.tool()
def version() -> str:
    """Report the version of the fixture tool."""
    return subprocess.run(["git", "--version"], capture_output=True, text=True).stdout
