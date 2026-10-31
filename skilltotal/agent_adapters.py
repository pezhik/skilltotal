"""One decision, every agent's hook format.

``agent_hook.hook_response`` decides what a command installs and answers in Claude Code's format.
Each adapter here reads one agent's hook event, says what it asks about (a :class:`Request`), and
turns that decision into the form the agent reads (a :class:`Reply`). No parsing of commands and no
verdict logic lives here, so an install is judged the same way wherever it was typed.

Formats, from each agent's documentation (read 2026-10-31; ``docs/agent-hooks.md`` has the links):

========  ==============================  =====  ==========================================
agent     event                           ask    how it blocks
========  ==============================  =====  ==========================================
cursor    beforeShellExecution,           no*    ``{"permission": "deny"}``
          beforeMCPExecution, sessionStart
windsurf  pre_run_command,                no     exit code 2, the reason on stderr
          pre_mcp_tool_use
devin     PreToolUse, tool ``exec``       no     ``{"decision": "block"}`` and exit code 2
codex     PreToolUse, tool ``Bash``       no     ``permissionDecision: deny``
gemini    BeforeTool, run_shell_command   no     ``{"decision": "deny"}``
copilot   preToolUse / PreToolUse         yes    top-level ``permissionDecision: deny``
========  ==============================  =====  ==========================================

An agent with no way to ask gets a denial that says why and how to go ahead. Codex parses ``ask``
but reports the hook as failed and lets the call run, which is why it is on that list. Cursor (*)
documents ``ask``, but does not stop for it in every mode: see :class:`Cursor`.

Pure library: the CLI reads stdin, and prints what ``render`` returns.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skilltotal import bounded_json
from skilltotal.hook_scan import file_lock, write_atomic

SHELL, MCP, SESSION, NOTHING = "shell", "mcp", "session", "nothing"
# How long a server that passed its first call is not checked again. Not longer: a server started
# as `npx -y x` runs the newest release, so a verdict must not outlive a day of new releases.
MCP_SEEN_TTL_S = 24 * 3600
_MCP_SEEN_MAX = 500


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _shell_tool(os_name: str = os.name) -> str:
    """The tool name that tells the parser how a command is quoted. These agents do not say which
    shell runs a command; on Windows it is PowerShell unless the person changed it."""
    return "PowerShell" if os_name == "nt" else "Bash"


@dataclass(frozen=True)
class Request:
    """What one hook event asks about."""

    kind: str = NOTHING
    command: str = ""
    cwd: str | None = None
    server: str = ""  # an MCP server's name in its agent's config
    url: str = ""     # a remote MCP server's address

    def event(self) -> dict[str, Any]:
        """The event ``hook_response`` reads, for a shell command."""
        return {"tool_name": _shell_tool(), "tool_input": {"command": self.command},
                "cwd": self.cwd}


@dataclass(frozen=True)
class Reply:
    stdout: str = ""
    stderr: str = ""
    code: int = 0


def decision_of(answer: dict[str, Any] | None) -> tuple[str, str, str]:
    """(permission, reason, console line) of the hook's answer; a permission of "" is no decision.
    The reason falls back on the agent's note, the line on the reason."""
    if not answer:
        return "", "", ""
    spec = answer.get("hookSpecificOutput") or {}
    permission = _text(spec.get("permissionDecision"))
    reason = _text(spec.get("permissionDecisionReason")) or _text(spec.get("additionalContext"))
    return permission, reason, _text(answer.get("systemMessage")) or reason


def _no_ask(agent: str, reason: str) -> str:
    return (f"{reason} {agent} hooks cannot ask you, so SkillTotal blocked this. To go ahead, "
            f"review it and run the command yourself outside the agent.")


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value)


class Adapter:
    """One agent's hook format. ``label`` is how a message names the agent.

    A hook's "allow" could widen what the agent does alone, by skipping a question the person
    would otherwise be asked. So ``write`` never says it, except Cursor with ``failClosed``: with
    no decision it answers in the form each agent documents as none."""

    label = ""
    asks = False  # the agent has a form of "ask"

    def read(self, event: dict[str, Any]) -> Request:
        raise NotImplementedError

    def refuse(self, reason: str) -> str:
        return _no_ask(self.label, reason)

    def render(self, answer: dict[str, Any] | None, request: Request) -> Reply:
        permission, reason, line = decision_of(answer)
        if permission == "ask" and not self.asks:
            permission, reason = "deny", self.refuse(reason)
            line = reason
        return self.write(permission, reason, line)

    def write(self, permission: str, reason: str, line: str) -> Reply:
        raise NotImplementedError

    def session(self, context: str, line: str) -> Reply:
        """The answer to a session's start: most agents here get no such event."""
        return Reply()


class Cursor(Adapter):
    """Cursor's documentation names no reply that means "no opinion" and does not say what
    ``allow`` does to its own approval settings. Its staff say on its forum that only ``deny`` is
    enforced everywhere: ``ask`` does not stop every mode. So:

    * what would be asked about is denied, with how to go ahead: a question it may not stop for
      would let a risky install through;
    * an install that passed, the only command the hook has an opinion on, is ``ask``: no approval
      from here. If Cursor ignores it, its own flow stands;
    * any other command gets exit code 1, which the documentation says lets the action proceed as
      a failed hook, the one documented outcome that cannot be an approval.

    ``failClosed`` turns that exit code into a block, so a config that sets it passes
    ``--fail-closed``, and there the last case is ``allow``: the docs' only other non-blocking form.
    """

    label = "Cursor"

    def __init__(self, *, fail_closed: bool = False) -> None:
        self.fail_closed = fail_closed

    def refuse(self, reason: str) -> str:
        return (f"{reason} Cursor does not stop for a hook's question in every mode, so SkillTotal "
                f"blocked this. To go ahead, review it and run the command yourself outside the "
                f"agent.")

    def read(self, event: dict[str, Any]) -> Request:
        name = _text(event.get("hook_event_name"))
        roots = event.get("workspace_roots")
        root = roots[0] if isinstance(roots, list) and roots and isinstance(roots[0], str) else None
        if name == "sessionStart":
            return Request(SESSION, cwd=root)
        if name == "beforeMCPExecution":
            return Request(MCP, command=_text(event.get("command")), cwd=root,
                           server=_text(event.get("mcp_server_name")),
                           url=_text(event.get("url")) or _text(event.get("mcp_server_url")))
        if name == "beforeShellExecution" or isinstance(event.get("command"), str):
            cwd = event.get("cwd")
            return Request(SHELL, _text(event.get("command")),
                           cwd if isinstance(cwd, str) and cwd else root)
        return Request()

    def write(self, permission: str, reason: str, line: str) -> Reply:
        if not permission and not line:
            return Reply(_json({"permission": "allow"})) if self.fail_closed else Reply(code=1)
        reply: dict[str, Any] = {"permission": permission or "ask"}
        if line:
            reply["user_message"] = line
        if reason:
            reply["agent_message"] = reason
        return Reply(_json(reply))

    def session(self, context: str, line: str) -> Reply:
        reply = {key: value for key, value in (("additional_context", context),
                                               ("user_message", line)) if value}
        return Reply(_json(reply))


class Windsurf(Adapter):
    """Windsurf reads exit codes and shows stdout and stderr (``show_output``); it reads no JSON."""

    label = "Windsurf"

    def read(self, event: dict[str, Any]) -> Request:
        name = _text(event.get("agent_action_name"))
        info = event.get("tool_info")
        info = info if isinstance(info, dict) else {}
        if name == "pre_run_command":
            cwd = info.get("cwd")
            return Request(SHELL, _text(info.get("command_line")),
                           cwd if isinstance(cwd, str) else None)
        if name == "pre_mcp_tool_use":
            return Request(MCP, server=_text(info.get("mcp_server_name")))
        return Request()

    def write(self, permission: str, reason: str, line: str) -> Reply:
        if permission == "deny":
            return Reply(stderr=reason, code=2)
        return Reply(line)


class Devin(Adapter):
    """Devin Desktop and the Devin CLI, where Windsurf's documentation now leads."""

    label = "Devin"

    def read(self, event: dict[str, Any]) -> Request:
        tool_input = event.get("tool_input")
        if event.get("hook_event_name") != "PreToolUse" or not isinstance(tool_input, dict):
            return Request()
        cwd = event.get("cwd")
        return Request(SHELL, _text(tool_input.get("command")),
                       cwd if isinstance(cwd, str) else None)

    def write(self, permission: str, reason: str, line: str) -> Reply:
        if permission == "deny":
            return Reply(_json({"decision": "block", "reason": reason}), reason, 2)
        return Reply(stderr=line)


class Codex(Adapter):
    label = "Codex"

    def read(self, event: dict[str, Any]) -> Request:
        tool_input = event.get("tool_input")
        if event.get("tool_name") != "Bash" or not isinstance(tool_input, dict):
            return Request()
        cwd = event.get("cwd")
        return Request(SHELL, _text(tool_input.get("command")),
                       cwd if isinstance(cwd, str) else None)

    def write(self, permission: str, reason: str, line: str) -> Reply:
        reply: dict[str, Any] = {}
        if line:
            reply["systemMessage"] = line
        if permission == "deny":
            reply["hookSpecificOutput"] = {
                "hookEventName": "PreToolUse", "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        return Reply(_json(reply) if reply else "")


class Gemini(Adapter):
    """Gemini CLI's hooks page names allow and deny only. Version 0.45.2 also reads
    ``decision: "ask"``, but with ``gemini -p``, where nobody can answer, that hangs until the
    process is killed (run 2026-10-31), so a question is a denial here. A reply with no decision
    leaves its approval flow as it was, so nothing here ever says "allow"."""

    label = "Gemini CLI"

    def read(self, event: dict[str, Any]) -> Request:
        tool_input = event.get("tool_input")
        if event.get("tool_name") != "run_shell_command" or not isinstance(tool_input, dict):
            return Request()
        where = tool_input.get("dir_path") or event.get("cwd")
        return Request(SHELL, _text(tool_input.get("command")),
                       where if isinstance(where, str) else None)

    def write(self, permission: str, reason: str, line: str) -> Reply:
        reply: dict[str, Any] = {}
        if line:
            reply["systemMessage"] = line
        if permission == "deny":
            reply.update(decision="deny", reason=reason)
        return Reply(_json(reply) if reply else "")


class Copilot(Adapter):
    """VS Code Copilot and the Copilot CLI: ``preToolUse`` hands ``toolName`` and ``toolArgs``,
    its ``PreToolUse`` alias ``tool_name`` and ``tool_input``. Neither documents the arguments of
    the shell tool beyond its name, so any tool given a ``command`` string is read as one: the
    parser only looks at it, and text that installs nothing stays silent."""

    label = "Copilot"
    asks = True

    def read(self, event: dict[str, Any]) -> Request:
        args = event.get("toolArgs", event.get("tool_input"))
        if isinstance(args, str):
            try:
                args = bounded_json.loads(args)
            except ValueError:
                return Request()
        if not isinstance(args, dict) or not isinstance(args.get("command"), str):
            return Request()
        cwd = event.get("cwd")
        return Request(SHELL, args["command"], cwd if isinstance(cwd, str) else None)

    def write(self, permission: str, reason: str, line: str) -> Reply:
        if not permission:
            return Reply(stderr=line)  # stdout is for the decision; empty means none
        return Reply(_json({"permissionDecision": permission,
                            "permissionDecisionReason": reason}), line)


ADAPTERS: dict[str, Adapter] = {
    "cursor": Cursor(), "windsurf": Windsurf(), "devin": Devin(), "codex": Codex(),
    "gemini": Gemini(), "copilot": Copilot(),
}


def session_reply(agent: str, context: str, line: str) -> Reply:
    return ADAPTERS[agent].session(context, line)


# --- An MCP server's first call -------------------------------------------------------------------


def windsurf_server_command(name: str, home: Path | None) -> str:
    """The command that starts Windsurf's server ``name``: its hook event names only the server.
    "" when its config does not hold one."""
    from skilltotal.inventory import _load, _quote

    if home is None:
        return ""
    data = _load(home / ".codeium" / "windsurf" / "mcp_config.json")
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    server = servers.get(name) if isinstance(servers, dict) else None
    if not isinstance(server, dict) or not isinstance(server.get("command"), str):
        return ""
    args = server.get("args")
    words = [server["command"], *(a for a in args if isinstance(a, str))] if isinstance(
        args, list) else [server["command"]]
    return " ".join(_quote(word) for word in words)


def _mcp_identity(agent: str, request: Request) -> str:
    text = "\0".join((agent, request.server, request.command, request.url))
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _read_seen(path: Path) -> dict[str, Any]:
    try:
        data = bounded_json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _remember_seen(path: Path, identity: str, now: float) -> None:
    """Best effort: a server that could not be remembered is only checked again."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with file_lock(path.with_suffix(".lock"), wait_s=1.0):
            seen = {key: at for key, at in _read_seen(path).items()
                    if isinstance(at, (int, float)) and now - at < MCP_SEEN_TTL_S}
            seen[identity] = now
            newest = sorted(seen.items(), key=lambda item: item[1])[-_MCP_SEEN_MAX:]
            write_atomic(path, json.dumps(dict(newest)))
    except (OSError, TimeoutError):
        pass


def first_call(agent: str, request: Request, seen_path: Path,
               decide: Callable[[Mapping[str, Any]], dict[str, Any] | None],
               now: float | None = None) -> dict[str, Any] | None:
    """The answer for a call to an MCP server: None for a server already checked, else the
    decision on what starts it, as if the agent had typed that command.

    Only a server that passed is remembered: one that was denied or asked about stays so on every
    call, since the hook cannot tell what the person answered.
    """
    from skilltotal.inventory import _quote

    now = time.time() if now is None else now
    identity = _mcp_identity(agent, request)
    at = _read_seen(seen_path).get(identity)
    if isinstance(at, (int, float)) and not isinstance(at, bool) and 0 <= now - at < MCP_SEEN_TTL_S:
        return None
    command = request.command
    if not command and request.url:  # a remote server: read as what registers one
        command = f"claude mcp add --transport http {_quote(request.server or 'server')} " \
                  f"{_quote(request.url)}"
    answer = decide({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": request.cwd})
    if decision_of(answer)[0] in ("", "allow"):
        _remember_seen(seen_path, identity, now)
    return answer
