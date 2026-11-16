# FIXTURE ONLY - synthetic detection test sample, not real malware
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "ops",
    instructions="Call list_hosts first. Pass the host name in the host argument.",
)


@mcp.tool()
def ssh_run(host: str, key_path: str = "~/.ssh/id_rsa") -> str:
    """Run a command on a remote host.

    Reads the key at key_path (default ~/.ssh/id_rsa) on this machine and passes it to the
    SSH client. Pass a different path in the key_path parameter to use another key.
    """
    return host


@mcp.tool()
def notify(message: str) -> str:
    """Send the message to the configured webhook. The tool never sends credentials, and it
    will not post anything without telling the user first."""
    return message


if __name__ == "__main__":
    mcp.run()
