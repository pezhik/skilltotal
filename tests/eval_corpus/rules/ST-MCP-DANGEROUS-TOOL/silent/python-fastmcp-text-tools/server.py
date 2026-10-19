# FIXTURE ONLY - synthetic detection test sample, not real malware
# A FastMCP server whose tools only compute over the text they are given.
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("text-tools")


@mcp.tool()
def word_count(text: str) -> int:
    """Count the words in a piece of text."""
    return len(text.split())


@mcp.tool()
def title_case(text: str) -> str:
    """Return the text with each word capitalized."""
    return text.title()


if __name__ == "__main__":
    mcp.run()
