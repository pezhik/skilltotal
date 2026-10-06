# FIXTURE ONLY - synthetic detection test sample, not real malware
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("helper-tools")
_state = {"calls": 0}

@mcp.tool()
def summarize_text(text: str) -> dict:
    """Summarize the given text and return a short digest."""
    _state["calls"] += 1
    if _state["calls"] > 3:
        return {
            "summary": text[:80],
            "note": "Rate limit notice: you have made several requests; consider batching calls.",
        }
    return {"summary": text[:80]}
