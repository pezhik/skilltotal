"""An MCP server launched at whatever release is current (a review note, never scored).

`npx -y pkg`, `npx -y pkg@latest`, `uvx pkg` or `docker run image:latest` in a client's MCP
configuration fetch the newest release at every launch, so the server that runs next week is not
the one any scan saw. It is the common way to configure MCP servers, so it is listed for review,
one note per report, and never scored."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.models import Component

TITLE = "MCP server runs whatever release is current"


def _report(tmp_path: Path, command: str, args: list[str]):
    (tmp_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"x": {"command": command, "args": args}}}, indent=2), encoding="utf-8")
    return analyze_directory(tmp_path, Component(name="x", type="project", source="x"))


def _note(report):
    return next((n for n in report.needs_review if n.title == TITLE), None)


UNPINNED = [
    ("npx", ["-y", "@modelcontextprotocol/server-github"]),
    ("npx", ["-y", "left-pad@latest"]),
    ("npx", ["-y", "@scope/pkg@^1.2.0"]),
    ("npx", ["--package=left-pad", "lp"]),
    ("bunx", ["left-pad"]),
    ("pnpm", ["dlx", "left-pad"]),
    ("uvx", ["mcp-server-fetch"]),
    ("uvx", ["--from", "mcp-server-fetch", "mcp-server-fetch"]),
    ("pipx", ["run", "mcp-server-fetch"]),
    ("docker", ["run", "-i", "--rm", "mcp/github"]),
    ("docker", ["run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/acme/server:latest"]),
]


@pytest.mark.parametrize(("command", "args"), UNPINNED)
def test_a_server_at_the_current_release_is_noted(tmp_path, command, args):
    report = _report(tmp_path, command, args)
    note = _note(report)
    assert note is not None and note.file == ".mcp.json"
    assert not any("UNPINNED" in f.id for f in report.findings)


PINNED = [
    ("npx", ["-y", "left-pad@1.3.0"]),
    ("npx", ["-y", "@scope/pkg@2.0.0-beta.1"]),
    ("uvx", ["mcp-server-fetch==2025.4.7"]),
    ("uvx", ["mcp-server-fetch@2025.4.7"]),
    ("uvx", ["--from", "mcp-server-fetch==2025.4.7", "mcp-server-fetch"]),
    ("docker", ["run", "-i", "--rm", "mcp/github:1.4.0"]),
    ("docker", ["run", "-i", "--rm", "mcp/github@sha256:" + "a" * 64]),
    ("node", ["build/index.js"]),
    ("python", ["-m", "my_server"]),
]


@pytest.mark.parametrize(("command", "args"), PINNED)
def test_a_pinned_or_local_server_is_not_noted(tmp_path, command, args):
    assert _note(_report(tmp_path, command, args)) is None


def test_one_note_lists_every_server(tmp_path):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "a": {"command": "npx", "args": ["-y", "pkg-a"]},
        "b": {"command": "uvx", "args": ["pkg-b"]},
    }}), encoding="utf-8")
    report = analyze_directory(tmp_path, Component(name="x", type="project", source="x"))
    notes = [n for n in report.needs_review if n.title == TITLE]
    assert len(notes) == 1
    assert notes[0].reason.startswith("2 ")


# --- the hook: an MCP server added at the current release -----------------------------------

def _clean(source, timeout):
    return {"risk_score": 0, "risk_level": "low", "verdict": {}, "findings": [],
            "needs_review": [], "metadata": {}, "component": {"source": source}}


def _console(command):
    from skilltotal.agent_hook import hook_response

    out = hook_response({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                         "tool_input": {"command": command}}, scan=_clean)
    return out["systemMessage"]


@pytest.mark.parametrize("command", [
    "claude mcp add github -- npx -y @modelcontextprotocol/server-github",
    "codex mcp add fetch -- uvx mcp-server-fetch",
    "claude mcp add lp -- npx -y left-pad@latest",
])
def test_the_hook_says_an_added_server_runs_the_current_release(command):
    assert "each time it starts" in _console(command)


@pytest.mark.parametrize("command", [
    "claude mcp add lp -- npx -y left-pad@1.3.0",
    "codex mcp add fetch -- uvx mcp-server-fetch==2025.4.7",
    "npm install left-pad",
    "npx -y left-pad",
])
def test_the_hook_says_nothing_of_it_for_a_pinned_server_or_a_plain_install(command):
    assert "each time it starts" not in _console(command)
