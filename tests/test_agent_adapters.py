"""Every agent's hook format: its documented event in, its documented answer out."""

from __future__ import annotations

import io
import json

import pytest

from skilltotal import agent_adapters, cli
from skilltotal.agent_adapters import ADAPTERS, MCP, SESSION, SHELL, Request, first_call

COMMAND = "npm install left-pad"

# The payload each agent's documentation shows, with its command.
EVENTS = {
    "cursor": {
        "conversation_id": "c", "generation_id": "g", "model": "m",
        "hook_event_name": "beforeShellExecution", "cursor_version": "2.0",
        "workspace_roots": ["/work"], "user_email": None, "transcript_path": None,
        "command": COMMAND, "cwd": "/work/sub", "sandbox": False,
    },
    "windsurf": {
        "agent_action_name": "pre_run_command", "trajectory_id": "t", "execution_id": "e",
        "timestamp": "2026-10-31T00:00:00Z",
        "tool_info": {"command_line": COMMAND, "cwd": "/work/sub"},
    },
    "devin": {"hook_event_name": "PreToolUse", "tool_name": "exec", "session_id": "s",
              "tool_input": {"command": COMMAND}, "cwd": "/work/sub"},
    "codex": {"session_id": "s", "transcript_path": "/t", "cwd": "/work/sub",
              "hook_event_name": "PreToolUse", "model": "m", "permission_mode": "default",
              "turn_id": "u", "tool_name": "Bash", "tool_use_id": "i",
              "tool_input": {"command": COMMAND}},
    "gemini": {"session_id": "s", "transcript_path": "/t", "cwd": "/work",
               "hook_event_name": "BeforeTool", "timestamp": "2026-10-31T00:00:00Z",
               "tool_name": "run_shell_command",
               "tool_input": {"command": COMMAND, "description": "d", "dir_path": "/work/sub"}},
    "copilot": {"sessionId": "s", "timestamp": 1, "cwd": "/work/sub", "toolName": "bash",
                "toolArgs": json.dumps({"command": COMMAND})},
}


def answer(permission=None, reason="the reason", line="the line"):
    spec = {"hookEventName": "PreToolUse"}
    if permission:
        spec.update(permissionDecision=permission, permissionDecisionReason=reason)
    return {"hookSpecificOutput": spec, "systemMessage": line}


@pytest.mark.parametrize("agent", EVENTS)
def test_each_agents_event_names_the_command(agent):
    request = ADAPTERS[agent].read(EVENTS[agent])
    assert (request.kind, request.command, request.cwd) == (SHELL, COMMAND, "/work/sub")


def test_copilots_snake_case_alias_is_read_too():
    request = ADAPTERS["copilot"].read({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                        "cwd": "/w", "tool_input": {"command": COMMAND}})
    assert (request.kind, request.command) == (SHELL, COMMAND)


@pytest.mark.parametrize("agent, event", [
    ("codex", {"tool_name": "apply_patch", "tool_input": {"command": "x"}}),
    ("gemini", {"tool_name": "read_file", "tool_input": {"path": "x"}}),
    ("copilot", {"toolName": "view", "toolArgs": {"path": "x"}}),
    ("copilot", {"toolName": "bash", "toolArgs": "{not json"}),
    ("windsurf", {"agent_action_name": "post_run_command", "tool_info": {}}),
    ("devin", {"hook_event_name": "PostToolUse", "tool_input": {"command": "x"}}),
    ("cursor", {"hook_event_name": "afterFileEdit"}),
])
def test_an_event_about_something_else_asks_for_nothing(agent, event):
    assert ADAPTERS[agent].read(event).kind == agent_adapters.NOTHING


def test_cursor_answers_in_its_own_fields():
    cursor = ADAPTERS["cursor"]
    for permission in ("deny", "ask"):
        assert json.loads(cursor.render(answer(permission), Request()).stdout) == {
            "permission": permission, "user_message": "the line", "agent_message": "the reason"}


@pytest.mark.parametrize("given", [None, answer()])
def test_cursor_always_gets_a_reply_its_schema_takes(given):
    assert json.loads(ADAPTERS["cursor"].render(given, Request()).stdout)["permission"] == "allow"


def test_a_cursor_console_line_with_no_decision_reaches_the_person():
    reply = json.loads(ADAPTERS["cursor"].render(answer(), Request()).stdout)
    assert reply == {"permission": "allow", "user_message": "the line"}


def test_windsurf_blocks_with_exit_code_2_and_the_reason_on_stderr():
    reply = ADAPTERS["windsurf"].render(answer("deny"), Request())
    assert (reply.code, reply.stderr, reply.stdout) == (2, "the reason", "")


def test_devin_blocks_both_ways():
    reply = ADAPTERS["devin"].render(answer("deny"), Request())
    assert reply.code == 2
    assert json.loads(reply.stdout) == {"decision": "block", "reason": "the reason"}


def test_codex_denies_in_its_documented_shape():
    reply = json.loads(ADAPTERS["codex"].render(answer("deny"), Request()).stdout)
    assert reply["hookSpecificOutput"] == {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": "the reason"}


def test_gemini_denies_with_decision_and_reason():
    reply = json.loads(ADAPTERS["gemini"].render(answer("deny"), Request()).stdout)
    assert (reply["decision"], reply["reason"]) == ("deny", "the reason")


def test_copilot_asks_and_denies_with_top_level_fields():
    for permission in ("ask", "deny"):
        reply = ADAPTERS["copilot"].render(answer(permission), Request())
        assert json.loads(reply.stdout) == {"permissionDecision": permission,
                                            "permissionDecisionReason": "the reason"}


@pytest.mark.parametrize("agent", ["windsurf", "devin", "codex", "gemini"])
def test_an_agent_that_cannot_ask_refuses_and_says_how_to_go_ahead(agent):
    reply = ADAPTERS[agent].render(answer("ask"), Request())
    text = reply.stdout + reply.stderr
    assert "cannot ask you" in text and "yourself outside the agent" in text
    if agent in ("windsurf", "devin"):
        assert reply.code == 2
    elif agent == "codex":
        decision = json.loads(reply.stdout)["hookSpecificOutput"]["permissionDecision"]
        assert decision == "deny"  # `ask` is parsed by Codex, then lets the call run
    else:
        assert json.loads(reply.stdout)["decision"] == "deny"


@pytest.mark.parametrize("agent", ["windsurf", "devin", "codex", "gemini", "copilot"])
def test_silence_stays_silent(agent):
    reply = ADAPTERS[agent].render(None, Request())
    assert (reply.stdout, reply.stderr, reply.code) == ("", "", 0)


@pytest.mark.parametrize("agent", ["windsurf", "devin", "codex", "gemini", "copilot"])
def test_a_no_decision_answer_keeps_the_console_line(agent):
    reply = ADAPTERS[agent].render(answer(), Request())
    assert "the line" in reply.stdout + reply.stderr
    assert reply.code == 0


# --- Through the CLI --------------------------------------------------------------------------


def run(monkeypatch, capsys, agent, raw):
    monkeypatch.setattr("sys.stdin", io.StringIO(raw))
    code = cli.main(["hook", agent])
    out = capsys.readouterr()
    return code, out.out, out.err


@pytest.mark.parametrize("agent", EVENTS)
@pytest.mark.parametrize("raw", ["not json", "[1, 2]", "{", '"text"', "null"])
def test_malformed_stdin_never_crashes_and_stays_out_of_the_way(monkeypatch, capsys, agent, raw):
    code, out, _ = run(monkeypatch, capsys, agent, raw)
    assert code == 0
    if agent == "cursor":
        assert json.loads(out)["permission"] == "allow"  # no output could block every command
    else:
        assert out == ""


@pytest.mark.parametrize("agent", EVENTS)
def test_malformed_stdin_in_ci_is_refused(monkeypatch, capsys, agent):
    monkeypatch.setenv("SKILLTOTAL_STRICT", "1")
    code, out, err = run(monkeypatch, capsys, agent, "not json")
    assert "blocked" in out + err
    assert code == (2 if agent in ("windsurf", "devin") else 0)


def stub_decide(monkeypatch, result=None, boom=False):
    calls = []

    def decide(event, strict_by=""):
        calls.append(event)
        if boom:
            raise RuntimeError("boom")
        return result

    monkeypatch.setattr(cli, "_hook_decide", decide)
    return calls


@pytest.mark.parametrize("agent", EVENTS)
def test_the_event_reaches_the_one_decision(monkeypatch, capsys, agent):
    calls = stub_decide(monkeypatch)
    run(monkeypatch, capsys, agent, json.dumps(EVENTS[agent]))
    assert calls[0]["tool_input"]["command"] == COMMAND
    assert calls[0]["cwd"] == "/work/sub"
    assert calls[0]["tool_name"] in ("Bash", "PowerShell")


@pytest.mark.parametrize("agent", ["cursor", "copilot"])
def test_a_failure_of_ours_asks_where_the_agent_can(monkeypatch, capsys, agent):
    stub_decide(monkeypatch, boom=True)
    _, out, _ = run(monkeypatch, capsys, agent, json.dumps(EVENTS[agent]))
    assert "ask" in out and "could not check" in out


@pytest.mark.parametrize("agent", ["windsurf", "devin", "codex", "gemini"])
def test_a_failure_of_ours_is_never_a_silent_pass(monkeypatch, capsys, agent):
    stub_decide(monkeypatch, boom=True)
    _, out, err = run(monkeypatch, capsys, agent, json.dumps(EVENTS[agent]))
    assert "could not check" in out + err


def test_claude_code_keeps_its_own_answer(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": "ls"}})))
    assert cli.main(["hook", "claude-code"]) == 0
    assert capsys.readouterr().out == ""


# --- An MCP server's first call ---------------------------------------------------------------


def decider(result=None):
    calls = []

    def decide(event):
        calls.append(event["tool_input"]["command"])
        return result

    return decide, calls


CURSOR_MCP = {
    "hook_event_name": "beforeMCPExecution", "tool_name": "search", "tool_input": "{}",
    "mcp_server_name": "docs", "command": "npx -y some-server", "workspace_roots": ["/w"],
}
WINDSURF_MCP = {
    "agent_action_name": "pre_mcp_tool_use",
    "tool_info": {"mcp_server_name": "github", "mcp_tool_name": "create_issue",
                  "mcp_tool_arguments": {"owner": "o"}},
}


def test_mcp_events_name_the_server():
    cursor = ADAPTERS["cursor"].read(CURSOR_MCP)
    assert (cursor.kind, cursor.server, cursor.command) == (MCP, "docs", "npx -y some-server")
    remote = ADAPTERS["cursor"].read({
        "hook_event_name": "beforeMCPExecution", "mcp_server_name": "r",
        "url": "https://mcp.example.test/sse"})
    assert (remote.kind, remote.url) == (MCP, "https://mcp.example.test/sse")
    windsurf = ADAPTERS["windsurf"].read(WINDSURF_MCP)
    assert (windsurf.kind, windsurf.server) == (MCP, "github")


def test_a_server_is_checked_on_its_first_call_only(tmp_path):
    seen = tmp_path / "seen.json"
    request = Request(MCP, command="npx -y some-server", server="docs")
    decide, calls = decider()
    for _ in range(3):
        assert first_call("cursor", request, seen, decide, now=1000.0) is None
    assert calls == ["npx -y some-server"]


def test_a_changed_command_or_another_server_is_a_new_identity(tmp_path):
    seen = tmp_path / "seen.json"
    decide, calls = decider()
    first_call("cursor", Request(MCP, command="npx a", server="docs"), seen, decide, now=1.0)
    first_call("cursor", Request(MCP, command="npx b", server="docs"), seen, decide, now=1.0)
    first_call("cursor", Request(MCP, command="npx a", server="other"), seen, decide, now=1.0)
    assert calls == ["npx a", "npx b", "npx a"]


def test_a_server_is_checked_again_after_a_day(tmp_path):
    seen = tmp_path / "seen.json"
    request = Request(MCP, command="npx a", server="docs")
    decide, calls = decider()
    first_call("cursor", request, seen, decide, now=1.0)
    first_call("cursor", request, seen, decide, now=1.0 + agent_adapters.MCP_SEEN_TTL_S + 1)
    assert len(calls) == 2


@pytest.mark.parametrize("permission", ["deny", "ask"])
def test_a_server_that_did_not_pass_is_not_remembered(tmp_path, permission):
    seen = tmp_path / "seen.json"
    request = Request(MCP, command="npx bad", server="docs")
    decide, calls = decider(answer(permission))
    first_call("cursor", request, seen, decide, now=1.0)
    assert first_call("cursor", request, seen, decide, now=2.0) == answer(permission)
    assert len(calls) == 2


def test_a_remote_server_is_judged_as_what_registers_one(tmp_path):
    decide, calls = decider()
    request = Request(MCP, server="r; rm -rf", url="https://mcp.example.test/sse")
    first_call("cursor", request, tmp_path / "seen.json", decide, now=1.0)
    assert calls == ["claude mcp add --transport http 'r; rm -rf' 'https://mcp.example.test/sse'"]


def test_a_broken_seen_file_only_means_another_check(tmp_path):
    seen = tmp_path / "seen.json"
    seen.write_text("{not json", encoding="utf-8")
    decide, calls = decider()
    assert first_call("cursor", Request(MCP, command="npx a"), seen, decide, now=1.0) is None
    assert calls == ["npx a"]


def test_windsurfs_server_command_comes_from_its_config(tmp_path):
    config = tmp_path / ".codeium" / "windsurf"
    config.mkdir(parents=True)
    (config / "mcp_config.json").write_text(json.dumps({"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "some server"]},
        "odd": {"command": 3},
    }}), encoding="utf-8")
    command = agent_adapters.windsurf_server_command
    assert command("github", tmp_path) == "'npx' '-y' 'some server'"
    assert command("odd", tmp_path) == ""
    assert command("absent", tmp_path) == ""
    assert command("github", None) == ""


def test_the_cli_checks_a_server_once(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("SKILLTOTAL_CACHE_DIR", str(tmp_path))
    calls = stub_decide(monkeypatch)
    for _ in range(2):
        code, out, _ = run(monkeypatch, capsys, "cursor", json.dumps(CURSOR_MCP))
        assert code == 0 and json.loads(out)["permission"] == "allow"
    assert len(calls) == 1


def test_a_session_event_is_told_apart():
    assert ADAPTERS["cursor"].read({"hook_event_name": "sessionStart",
                                    "workspace_roots": ["/w"]}) == Request(SESSION, cwd="/w")
