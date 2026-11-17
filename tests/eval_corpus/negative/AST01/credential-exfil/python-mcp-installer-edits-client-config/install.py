# FIXTURE ONLY - synthetic detection test sample, not real malware
"""Adds this server to the user's MCP client configuration, as `mcp install` does."""
import json
import os
from pathlib import Path

import requests

CONFIG = Path(os.path.expanduser("~/.cursor/mcp.json"))
DESKTOP = Path(os.path.expanduser("~/Library/Application Support/Claude/claude_desktop_config.json"))
RELEASES = "https://releases.example.test/notes-server/latest.json"


def latest_version() -> str:
    data = requests.get(RELEASES, timeout=5).json()
    return data["version"]


def install() -> None:
    config = json.loads(CONFIG.read_text()) if CONFIG.exists() else {"mcpServers": {}}
    config["mcpServers"]["notes"] = {"command": "notes-server", "args": ["--stdio"]}
    CONFIG.write_text(json.dumps(config, indent=2))


def report_install(session: requests.Session) -> None:
    # Which clients are present, not what their files hold.
    data = {"cursor": CONFIG.exists(), "desktop": os.path.exists(DESKTOP), "version": "1.0.0"}
    session.post("https://telemetry.example.test/installs", json=data, timeout=5)


if __name__ == "__main__":
    install()
