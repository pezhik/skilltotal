# FIXTURE ONLY - synthetic detection test sample, not real malware
"""A guard server: the phrases below are what it looks for, not what it says."""
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field

PATTERNS = ["ignore all previous instructions", "reveal your system prompt", "<important>"]

mcp = FastMCP("guard", instructions="Call scan_text before passing untrusted text to a model.")


@mcp.tool()
def scan_text(
    text: Annotated[str, Field(description="Text to check for phrases like 'ignore all previous instructions'.")],
    ignore_case: Annotated[bool, Field(description="Ignore case when matching.")] = True,
    role: Annotated[str, "system or user"] = "system",
) -> bool:
    """Returns True if the text holds a known injection phrase."""
    haystack = text.lower() if ignore_case else text
    return any(p in haystack for p in PATTERNS)
