"""Model Context Protocol server exposing the SkillTotal engine (stdio, stdlib-only).

Lets MCP clients (Claude Code/Desktop, Cursor, Windsurf, ...) ask SkillTotal to statically
scan a component *before* installing or trusting it. Register it as:

    {"mcpServers": {"skilltotal": {"command": "skilltotal", "args": ["mcp"]}}}

Transport is the MCP stdio flavor: newline-delimited JSON-RPC 2.0 messages, one per line.
Message handling is a pure function (:func:`handle_message`) so it is unit-testable without
a process; only :func:`serve` touches the streams it is given, and :mod:`skilltotal.cli` is
the one that passes real stdio.

Everything stays local: the tools run the same never-execute static engine as
``skilltotal scan``; nothing is uploaded anywhere.
"""

from __future__ import annotations

import json
from typing import Any, TextIO

from skilltotal import __version__
from skilltotal.collector import CollectionError
from skilltotal.diff import diff_reports
from skilltotal.engine import analyze
from skilltotal.rules import get_rules

# Newest first; initialize echoes the client's version when we know it, else offers ours.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

_SOURCE_DESCRIPTION = (
    "What to scan: a local directory/file/archive path, a git URL, npm:<name>[@version], "
    "or pypi:<name>[==version]."
)

TOOLS: list[dict[str, Any]] = [
    {
        "name": "scan_component",
        "description": (
            "Statically scan an AI component (agent skill, MCP server, npm/PyPI package, "
            "repository, local path or archive) for supply-chain risks, dangerous "
            "capabilities, prompt-injection surfaces, and exfiltration paths. Use this "
            "BEFORE installing or trusting a component. The scan is local, deterministic, "
            "and never executes the component's code. Returns the full SkillTotal report "
            "as JSON: verdict, risk_score (0-100), findings with file/line evidence, and "
            "capabilities."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "description": _SOURCE_DESCRIPTION},
            },
            "required": ["source"],
        },
        # Reads the component (downloads a registry package or clones a repository into a temp
        # folder that is removed afterwards) and changes nothing.
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True},
    },
    {
        "name": "diff_components",
        "description": (
            "Compare two versions of a component and report what changed: new/resolved/"
            "changed findings, capability changes, and the risk-score delta. Use for "
            "upgrade reviews (is the new version riskier than the one already vetted?). "
            "Both sides accept the same sources as scan_component."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "old": {"type": "string", "description": "Old side. " + _SOURCE_DESCRIPTION},
                "new": {"type": "string", "description": "New side. " + _SOURCE_DESCRIPTION},
            },
            "required": ["old", "new"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True},
    },
    {
        "name": "list_rules",
        "description": (
            "List every SkillTotal detection rule: id, severity, category, title, threat class "
            "and capability. Pass verbose=true for each rule's description and recommendation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "verbose": {
                    "type": "boolean",
                    "description": "Also return each rule's description and recommendation.",
                },
            },
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    },
]
# What list_rules returns per rule unless asked for everything (the texts are most of its size).
_RULE_SUMMARY = ("id", "severity", "category", "title", "threat_class", "capability")


def serve(stdin: TextIO, stdout: TextIO) -> None:
    """Run the newline-delimited JSON-RPC loop until the client closes stdin.

    A message the server cannot read or answer gets a JSON-RPC error, and the loop goes on: one
    bad request must not end the client's session.
    """
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except (ValueError, RecursionError):  # not JSON, or nested past what Python reads
            _write(stdout, _error(None, -32700, "parse error"))
            continue
        if not isinstance(message, dict):
            _write(stdout, _error(None, -32600, "invalid request"))
            continue
        try:
            response = handle_message(message)
        except Exception:  # noqa: BLE001 - a failure answering one request is that request's
            response = _error(message.get("id"), -32603, "internal error") if (
                message.get("id") is not None) else None
        if response is not None:
            _write(stdout, response)


def handle_message(message: dict[str, Any]) -> dict[str, Any] | None:
    """Handle one JSON-RPC message; returns the response, or None for notifications."""
    method = message.get("method")
    msg_id = message.get("id")
    if not isinstance(method, str):
        return None if msg_id is None else _error(msg_id, -32600, "invalid request")
    if msg_id is None:
        # Notifications (e.g. notifications/initialized) get no response.
        return None
    params = message.get("params")
    if params is None or params == []:
        params = {}
    if not isinstance(params, dict):
        return _error(msg_id, -32602, "invalid params: params must be an object")
    if method == "initialize":
        return _result(msg_id, _initialize(params))
    if method == "ping":
        return _result(msg_id, {})
    if method == "tools/list":
        return _result(msg_id, {"tools": TOOLS})
    if method == "tools/call":
        return _tools_call(msg_id, params)
    return _error(msg_id, -32601, f"method not found: {method}")


def _initialize(params: dict[str, Any]) -> dict[str, Any]:
    requested = params.get("protocolVersion")
    version = (
        requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
    )
    return {
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": "skilltotal", "version": __version__},
        "instructions": (
            "SkillTotal statically analyzes AI components (skills, MCP servers, npm/PyPI "
            "packages, repos) for supply-chain risk. Call scan_component before installing "
            "or trusting a component; call diff_components to review an upgrade. Scans are "
            "local and never execute the component's code."
        ),
    }


def _tools_call(msg_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    args = params.get("arguments")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return _error(msg_id, -32602, "invalid params: arguments must be an object")
    try:
        if name == "scan_component":
            payload: Any = analyze(str(args["source"])).to_dict()
        elif name == "diff_components":
            old = analyze(str(args["old"])).to_dict()
            new = analyze(str(args["new"])).to_dict()
            payload = diff_reports(old, new).to_dict()
        elif name == "list_rules":
            rules = [r.to_dict() for r in get_rules()]
            payload = rules if args.get("verbose") is True else [
                {key: rule.get(key) for key in _RULE_SUMMARY} for rule in rules]
        else:
            return _error(msg_id, -32602, f"unknown tool: {name}")
    except KeyError as exc:
        return _error(msg_id, -32602, f"missing required argument: {exc.args[0]}")
    except CollectionError as exc:
        return _result(msg_id, _tool_error(str(exc)))
    except Exception as exc:  # noqa: BLE001 - one bad scan must not kill the session
        return _result(msg_id, _tool_error(f"scan failed: {exc}"))
    return _result(
        msg_id,
        {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
            "isError": False,
        },
    )


def _tool_error(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": True}


def _result(msg_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _write(stdout: TextIO, response: dict[str, Any]) -> None:
    # One message per line; json.dumps without indent never emits embedded newlines.
    text = json.dumps(response, ensure_ascii=False)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate (a client may send one as `\ud800`, a file name may hold one) cannot
        # travel as UTF-8: escaped, the reply still goes out instead of ending the session.
        text = json.dumps(response)
    stdout.write(text + "\n")
    stdout.flush()
