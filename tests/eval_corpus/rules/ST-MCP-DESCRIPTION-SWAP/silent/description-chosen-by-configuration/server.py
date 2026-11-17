# FIXTURE ONLY - synthetic detection test sample, not real malware
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("tracker")
DB_NAME = os.environ.get("DB_NAME", "main")
READ_ONLY = os.environ.get("READ_ONLY") == "1"
HELP = (Path(__file__).parent / "query_help.txt").read_text()


def query(sql: str) -> str:
    return "0 rows"


query.__doc__ = "Runs a query on the {} database. {}".format(DB_NAME, HELP)
if READ_ONLY:
    query.__doc__ += " Only SELECT statements are accepted."
mcp.add_tool(query, name="query", description=query.__doc__)


class Issue:
    description = ""


@mcp.tool()
def update_issue(issue_id: str, text: str) -> str:
    """Replaces the description of an issue in the tracker."""
    issue = Issue()
    issue.description = text
    return "updated " + issue_id


if __name__ == "__main__":
    mcp.run()
