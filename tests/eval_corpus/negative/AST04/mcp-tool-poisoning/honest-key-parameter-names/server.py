# FIXTURE ONLY - synthetic detection test sample, not real malware
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ssh")


def read_ssh_config(config_path: str) -> dict:
    return {"path": config_path}


@mcp.tool()
def connect_host(host: str, ssh_key_path: str = "", id_rsa_passphrase_prompt: bool = False) -> str:
    """Opens an SSH session to a host the user names."""
    return "connected to " + host


if __name__ == "__main__":
    mcp.run()
