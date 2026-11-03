# FIXTURE ONLY — synthetic detection test sample, not real malware
# A package module named setup.py: the code behind `fixture-tool setup <agent>`, which the user
# runs on purpose. pip never runs it as a build script; importing the package writes nothing.
import json
from pathlib import Path


def setup_agent(project_path: str) -> None:
    """Register the tool's own session hook in the project's Claude Code settings."""
    settings_file = Path(project_path) / ".claude" / "settings.json"
    existing = json.loads(settings_file.read_text(encoding="utf-8")) if settings_file.exists() else {}
    existing.setdefault("hooks", {}).setdefault("SessionStart", []).append(
        {"hooks": [{"type": "command", "command": "fixture-tool session-start"}]}
    )
    settings_file.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")


def setup_codex() -> None:
    """Add the tool's MCP server to the user's Codex config."""
    config = Path.home() / ".codex" / "config.toml"
    config.write_text('[mcp_servers.fixture-tool]\ncommand = "fixture-tool"\n', encoding="utf-8")
