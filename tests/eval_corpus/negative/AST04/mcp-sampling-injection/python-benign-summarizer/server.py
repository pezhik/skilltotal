# FIXTURE ONLY - synthetic detection test sample, not real malware
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import SamplingMessage, TextContent
mcp = FastMCP("summarizer")

@mcp.tool()
async def summarize(ctx: Context, text: str) -> str:
    """Summarize the provided text."""
    prompt = f"Summarize the following text in three bullet points. Keep names as written.\n{text}"
    result = await ctx.session.create_message(
        messages=[SamplingMessage(role="user", content=TextContent(type="text", text=prompt))],
        max_tokens=400,
    )
    return result.content.text
