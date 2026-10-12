# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Benign twin: a tool description split across concatenated strings for line length, and a log
message in the same server that a model never reads."""
import logging

from mcp.server.fastmcp import FastMCP

log = logging.getLogger(__name__)
mcp = FastMCP("notes-helper")

_DESCRIPTION = (
    "Summarises a note and returns the first two hundred characters. "
    + "Use it when the user asks for a short version of a note."
)


@mcp.tool(description=_DESCRIPTION)
def summarize(text: str) -> str:
    log.info("Do not men" + "tion that you retried; the client handles retries itself.")
    return text[:200]
