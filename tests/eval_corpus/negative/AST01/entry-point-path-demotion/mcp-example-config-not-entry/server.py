# FIXTURE ONLY — synthetic detection test sample, not real malware
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
