"""Model Context Protocol server exposing the SkillTotal engine (stdio, stdlib-only).

Lets MCP clients (Claude Code/Desktop, Cursor, Windsurf, ...) ask SkillTotal to statically
scan a component *before* installing or trusting it. Register it as:

    {"mcpServers": {"skilltotal": {"command": "skilltotal", "args": ["mcp"]}}}

Transport is the MCP stdio flavor: newline-delimited JSON-RPC 2.0 messages, one per line.
Message handling is a pure function (:func:`handle_message`) so it is unit-testable without
a process; only :func:`serve` touches the streams it is given, and :mod:`skilltotal.cli` is
the one that passes real stdio.

Tool calls run on a small thread pool, so a scan that takes a minute does not hold up a ping or
a second call; everything else is answered on the reading thread, at once.

Everything stays local: the tools run the same never-execute static engine as
``skilltotal scan``; nothing is uploaded anywhere.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import stat
import sys
import tempfile
import threading
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, TextIO

from skilltotal import __version__
from skilltotal.collector import (
    INT_SETTINGS,
    TEMP_DIR_PREFIX,
    CollectionError,
    SizeLimitError,
    SourceTooLargeError,
    classify_source,
    registry_suggestion,
)
from skilltotal.diff import diff_reports
from skilltotal.engine import analyze
from skilltotal.models import UNANALYZED_TITLES
from skilltotal.report import one_line
from skilltotal.rules import get_rules

# Newest first; initialize echoes the client's version when we know it, else offers ours.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")

# Tool calls that may run at once. A scan is CPU-bound and may start worker processes of its
# own, so two keep a second request moving without doubling the machine's load again and again.
MAX_CONCURRENT_CALLS = 2

_SOURCE_DESCRIPTION = (
    "What to scan: an absolute path to a local folder, file or archive, a git URL (a subfolder "
    "as https://github.com/<owner>/<repo>/tree/<ref>/<path>), npm:<name>[@version], or "
    "pypi:<name>[==version]."
)
_DETAIL_PROPERTY = {
    "type": "string",
    "enum": ["summary", "full"],
    "description": (
        "summary (default): the verdict, why (findings with up to 3 locations each), "
        "capabilities, counts, what to check by hand and what was not checked. full: the "
        "complete SkillTotal report JSON (every finding, all evidence, traits, needs_review)."
    ),
    "examples": ["summary"],
}
# Said in each scanning tool's description: how to read the answer, and where it stops.
_HOW_TO_READ = (
    " Decide on the verdict (level, headline, has_malicious_indicators), not on the number of "
    "findings: a finding whose threat_class is \"capability\" is something the component can do "
    "(run commands, read files, reach the network) and adds no risk; malicious_indicator and "
    "risky_construct findings are what the verdict and score rest on. Not checked: the code of "
    "the component's dependencies, known vulnerabilities (CVEs), and runtime behaviour."
)
_SUMMARY_SHAPE = (
    " The default summary is a JSON object: component, verdict {level, headline, "
    "has_malicious_indicators}, decision (one line), risk_score, risk_level, why [{rule, "
    "threat_class, severity, title, evidence [\"file:line  snippet\"]}] (risk findings first), "
    "capabilities [names], counts {findings_by_threat_class, needs_review}, check_manually "
    "[notes to read], not_checked [what this scan does not cover], engine {version, ruleset}."
)

TOOLS: list[dict[str, Any]] = [
    {
        "name": "scan_component",
        "title": "Scan a component",
        "description": (
            "Statically scan an AI component (agent skill, MCP server, npm/PyPI package, "
            "repository, local path or archive) for supply-chain risks, dangerous "
            "capabilities, prompt-injection surfaces, and exfiltration paths. Use this "
            "BEFORE installing or trusting a component. The scan is local, deterministic, "
            "and never executes the component's code."
            + _HOW_TO_READ + _SUMMARY_SHAPE
            + " Pass detail=\"full\" for the complete report."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "minLength": 1, "description": _SOURCE_DESCRIPTION,
                           "examples": ["npm:mcp-remote"]},
                "detail": _DETAIL_PROPERTY,
            },
            "required": ["source"],
        },
        # Reads the component (downloads a registry package or clones a repository into a temp
        # folder that is removed afterwards) and changes nothing.
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True},
    },
    {
        "name": "diff_components",
        "title": "Compare two versions of a component",
        "description": (
            "Compare two versions of a component and report what changed. Use for upgrade "
            "reviews (is the new version riskier than the one already vetted?). Both sides "
            "accept the same sources as scan_component. The default summary gives each side's "
            "verdict, the verdict change, the risk-score delta, new and removed risk findings "
            "(in scan_component's why shape) and capability changes; detail=\"full\" returns "
            "the complete diff with every new/resolved/changed finding." + _HOW_TO_READ
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "old": {"type": "string", "minLength": 1,
                        "description": "Old side. " + _SOURCE_DESCRIPTION,
                        "examples": ["npm:mcp-remote@0.1.0"]},
                "new": {"type": "string", "minLength": 1,
                        "description": "New side. " + _SOURCE_DESCRIPTION,
                        "examples": ["npm:mcp-remote@0.1.1"]},
                "detail": _DETAIL_PROPERTY,
            },
            "required": ["old", "new"],
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True},
    },
    {
        "name": "list_rules",
        "title": "List detection rules",
        "description": (
            "List SkillTotal detection rules: id, severity, category, title, threat class "
            "and capability. Narrow it with ids (exact rule ids) or query (text in a rule's id "
            "or title); pass verbose=true for each rule's description and recommendation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "verbose": {
                    "type": "boolean",
                    "description": "Also return each rule's description and recommendation.",
                    "examples": [True],
                },
                "ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Only these rule ids (case-insensitive).",
                    "examples": [["ST-SHELL-PIPE-EXEC"]],
                },
                "query": {
                    "type": "string",
                    "description": "Only rules whose id or title contains this text "
                                   "(case-insensitive).",
                    "examples": ["prompt injection"],
                },
            },
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    },
]
_TOOLS_BY_NAME = {tool["name"]: tool for tool in TOOLS}
# What list_rules returns per rule unless asked for everything (the texts are most of its size).
_RULE_SUMMARY = ("id", "severity", "category", "title", "threat_class", "capability")

# What a static scan of the component's own files never covers, said with every summary so an
# agent does not read "low" as "checked for everything".
NOT_CHECKED = (
    "the code of the component's dependencies (only the component's own files are read)",
    "known vulnerabilities (CVEs) in the component or its dependencies",
    "runtime behaviour (nothing is executed)",
)
# Summary limits: locations per finding, characters per snippet, notes to check by hand.
_SUMMARY_EVIDENCE = 3
_SUMMARY_SNIPPET_CHARS = 120
_SUMMARY_REVIEW_NOTES = 5
_CLASS_ORDER = {"malicious_indicator": 0, "risky_construct": 1, "exposure": 2, "capability": 3}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Temporary folders a killed scan left behind are swept at start once they are this old: no scan
# runs that long (clone and download timeouts end it first), so none is still in use.
STALE_TEMP_SECONDS = 6 * 3600


def serve(stdin: Iterable[str | bytes], stdout: TextIO) -> None:
    """Run the newline-delimited JSON-RPC loop until the client closes stdin.

    ``stdin`` yields lines as text, or as bytes (the real stdin's buffer), which are read as
    UTF-8. A message the server cannot read or answer gets a JSON-RPC error, and the loop goes
    on: one bad request must not end the client's session. At end of input the calls still
    running are finished and answered before this returns.
    """
    session = _Session(stdout)
    try:
        for raw in stdin:
            session.receive(raw)
    finally:
        session.close()


class _Session:
    """The state one stdio connection shares between its reading thread and its call workers:
    the output stream (one writer at a time) and the tool calls not answered yet."""

    def __init__(self, stdout: TextIO) -> None:
        self._stdout = stdout
        self._write_lock = threading.Lock()
        self._calls_lock = threading.Lock()
        # Request ids (as _id_key) of tool calls queued or running, and those of them the client
        # has cancelled: a cancelled call is not started, or its answer is not sent.
        self._pending: dict[str, int] = {}
        self._cancelled: set[str] = set()
        self._pool = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_CALLS,
                                        thread_name_prefix="skilltotal-mcp")

    def receive(self, raw: str | bytes) -> None:
        if isinstance(raw, bytes):
            try:
                line = raw.decode("utf-8")
            except UnicodeDecodeError:
                # JSON text is UTF-8 (RFC 8259): a line that is not is unreadable, and only it.
                self.write(_error(None, -32700, "parse error: the message is not valid UTF-8"))
                return
        else:
            line = raw
        line = line.strip()
        if not line:
            return
        try:
            message = json.loads(line)
        except (ValueError, RecursionError):  # not JSON, or nested past what Python reads
            self.write(_error(None, -32700, "parse error"))
            return
        if not isinstance(message, dict):
            self.write(_error(None, -32600, "invalid request"))
            return
        method = message.get("method")
        if method == "notifications/cancelled" and message.get("id") is None:
            self._cancel(message.get("params"))
            return
        if method == "tools/call" and message.get("id") is not None:
            key = _id_key(message["id"])
            with self._calls_lock:
                self._pending[key] = self._pending.get(key, 0) + 1
            self._pool.submit(self._run_call, key, message)
            return
        self._answer(message)

    def close(self) -> None:
        self._pool.shutdown(wait=True)

    def write(self, response: dict[str, Any]) -> None:
        text = _encode(response)
        with self._write_lock:
            self._stdout.write(text + "\n")
            self._stdout.flush()

    def _answer(self, message: dict[str, Any]) -> dict[str, Any] | None:
        try:
            response = handle_message(message)
        except Exception:  # noqa: BLE001 - a failure answering one request is that request's
            response = _error(message.get("id"), -32603, "internal error") if (
                message.get("id") is not None) else None
        if response is not None:
            self.write(response)
        return response

    def _run_call(self, key: str, message: dict[str, Any]) -> None:
        try:
            if not self._finish(key, started=False):
                return  # cancelled while it waited for a worker: not run at all
            try:
                response = handle_message(message)
            except Exception:  # noqa: BLE001 - as in _answer
                response = _error(message.get("id"), -32603, "internal error")
            if self._finish(key, started=True):
                self.write(response)
        except OSError:
            pass  # the client closed stdout: there is no one left to answer

    def _finish(self, key: str, *, started: bool) -> bool:
        """Whether the call ``key`` still goes ahead; after it ran, also forget it."""
        with self._calls_lock:
            go_ahead = key not in self._cancelled
            if started or not go_ahead:
                left = self._pending.get(key, 0) - 1
                if left > 0:
                    self._pending[key] = left
                else:
                    self._pending.pop(key, None)
                    self._cancelled.discard(key)
            return go_ahead

    def _cancel(self, params: Any) -> None:
        # MCP: the receiver of notifications/cancelled SHOULD stop the request and MUST NOT
        # answer it. A scan already running is not interrupted (the engine has no safe point to
        # stop at), but its answer is dropped; an unknown or finished id is ignored.
        if not isinstance(params, dict) or "requestId" not in params:
            return
        key = _id_key(params["requestId"])
        with self._calls_lock:
            if key in self._pending:
                self._cancelled.add(key)


def _id_key(msg_id: Any) -> str:
    # Ids are strings or numbers, but any JSON value is hashable this way.
    return json.dumps(msg_id, sort_keys=True)


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
            "or trusting a component; call diff_components to review an upgrade. Decide on "
            "the verdict; findings of threat_class \"capability\" add no risk. Scans are "
            "local and never execute the component's code."
        ),
    }


def _tools_call(msg_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    args = params.get("arguments")
    if args is None:
        args = {}
    tool = _TOOLS_BY_NAME.get(name) if isinstance(name, str) else None
    # A protocol error only where the request itself is malformed: the MCP spec answers an unknown
    # tool with -32602, and arguments that are not an object are not a call at all. Arguments
    # that are only wrong (missing, mistyped, a refused path) are the tool's error, returned as
    # an isError result, so the model sees the message and can correct its next call.
    if tool is None:
        return _error(msg_id, -32602, f"unknown tool: {name}")
    if not isinstance(args, dict):
        return _error(msg_id, -32602, "invalid params: arguments must be an object")
    args = {key: value for key, value in args.items() if value is not None}
    problem = _argument_problem(tool, args)
    if problem:
        return _result(msg_id, _tool_error(problem))
    try:
        if name == "scan_component":
            source = _checked_source(args["source"])
            report = analyze(source).to_dict()
            payload: Any = report if args.get("detail") == "full" else summarize_report(report)
        elif name == "diff_components":
            old_source, new_source = _checked_source(args["old"]), _checked_source(args["new"])
            old = analyze(old_source).to_dict()
            new = analyze(new_source).to_dict()
            diff = diff_reports(old, new)
            payload = diff.to_dict() if args.get("detail") == "full" else summarize_diff(
                old, new, diff.to_dict())
        else:
            payload = _list_rules(args)
    except _RefusedSource as exc:
        return _result(msg_id, _tool_error(str(exc)))
    except SizeLimitError as exc:
        return _result(msg_id, _tool_error(_size_limit_message(exc, args)))
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


# --- arguments --------------------------------------------------------------------------------


def _argument_problem(tool: dict[str, Any], args: dict[str, Any]) -> str:
    """What is wrong with ``args`` against the tool's own input schema, with an example of a
    right value; empty when nothing is. A value is never coerced: `"source": 123` is refused, not
    scanned as the path "123", and `"verbose": "true"` is not quietly false."""
    schema = tool["inputSchema"]
    properties = schema["properties"]
    for name in schema.get("required", ()):
        if name not in args:
            return _bad_argument(name, properties[name], "is required")
    for name, value in args.items():
        spec = properties.get(name)
        if spec is None:
            continue  # an argument the tool does not take is ignored
        problem = _value_problem(spec, value)
        if problem:
            return _bad_argument(name, spec, problem)
    return ""


def _value_problem(spec: dict[str, Any], value: Any) -> str:
    kind = spec["type"]
    if kind == "string":
        if not isinstance(value, str):
            return f"must be a string, not {_json_type(value)}"
        if len(value.strip()) < spec.get("minLength", 0):
            return "must not be empty"
        if "enum" in spec and value not in spec["enum"]:
            return "must be one of " + ", ".join(json.dumps(v) for v in spec["enum"])
    elif kind == "boolean" and not isinstance(value, bool):
        return f"must be true or false, not {_json_type(value)}"
    elif kind == "array" and not (
            isinstance(value, list) and all(isinstance(item, str) for item in value)):
        return "must be an array of strings"
    return ""


def _bad_argument(name: str, spec: dict[str, Any], problem: str) -> str:
    example = json.dumps(spec["examples"][0])
    return f'Argument "{name}" {problem}. For example: "{name}": {example}'


def _json_type(value: Any) -> str:
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "an array"
    if isinstance(value, dict):
        return "an object"
    return "null"


class _RefusedSource(Exception):
    """A source the server will not scan, with the reason and what to send instead."""


def _checked_source(source: str) -> str:
    """``source`` stripped, or :class:`_RefusedSource` for a local path the server must not guess.

    A relative path resolves against the server's working directory, which the client cannot
    see and which is often the user's home: `"~"` or `"."` scanned a whole profile. So a local
    path must be absolute, and the home directory, a folder above it, or a filesystem root is
    refused: none of them is one component. Registry names and git URLs pass unchanged.
    """
    source = source.strip()
    if classify_source(source) != "local":
        return source
    example = _EXAMPLE_PATH
    if not os.path.isabs(source):
        suggestion = registry_suggestion(source)
        package = f" To scan a package, name its registry: {suggestion}." if suggestion else ""
        raise _RefusedSource(
            f"A local source must be an absolute path, not {source!r}: the server's working "
            f"directory is not the client's. For example: \"source\": {json.dumps(example)}."
            f"{package} A git URL or npm:<name> / pypi:<name> works too."
        )
    if source.startswith(("\\\\", "//")) or (os.name == "nt" and ":" in source[2:]):
        # A network share (`\\host\share`, `\\localhost\C$\...`), a device path (`\\?\...`,
        # `\\.\...`, `\\?\GLOBALROOT\...`) or an NTFS stream (`C:\work::$INDEX_ALLOCATION`):
        # each can name the home folder, or reach another machine, under a spelling the checks
        # below would not see through.
        raise _RefusedSource(
            f"Refusing to scan {source}: network shares, device paths and alternate data "
            f"streams are not scanned. Use a local drive path, for example: \"source\": "
            f"{json.dumps(example)}."
        )
    try:
        root = Path(source).resolve()
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        return source  # the collector reports a path it cannot resolve
    if root.parent == root:
        what = "a filesystem root"
    elif _same_or_inside(home, root):
        what = "the home directory" if _same_or_inside(root, home) else "a folder above home"
    else:
        return source
    raise _RefusedSource(
        f"Refusing to scan {source} ({what}): that is not one component. Point at the "
        f"component's own folder, for example: \"source\": {json.dumps(example)}."
    )


_EXAMPLE_PATH = (r"D:\work\my-project\.claude\skills\my-skill" if os.name == "nt"
                 else "/home/me/.claude/skills/my-skill")


def _same_or_inside(path: Path, folder: Path) -> bool:
    """Whether ``path`` is ``folder`` or inside it. Folders are compared by what the file system
    says they are (``os.path.samefile``), so another spelling of the same folder (letter case,
    an 8.3 short name, a link) is no way around the check; the text comparison stays for paths
    that do not exist."""
    path_text, folder_text = os.path.normcase(str(path)), os.path.normcase(str(folder))
    if path_text == folder_text or path_text.startswith(folder_text.rstrip("\\/") + os.sep):
        return True
    for candidate in (path, *path.parents):
        try:
            if os.path.samefile(candidate, folder):
                return True
        except (OSError, ValueError):
            continue
    return False


def _size_limit_message(exc: SizeLimitError, args: dict[str, Any]) -> str:
    """The engine's refusal, plus how to raise the limit where an MCP server gets its settings:
    the `env` of its entry in the client's MCP config, not a shell the user can see."""
    raw = os.environ.get(exc.variable, "").strip()
    current = int(raw) if raw.isdigit() else (
        INT_SETTINGS.get(exc.variable) or INT_SETTINGS["SKILLTOTAL_MAX_CLONE_MB"])
    measured = exc.measured_mb if isinstance(exc, SourceTooLargeError) else None
    value = max(current * 2, measured or 0)
    if exc.variable.endswith("_MB"):
        value = int(math.ceil(value / 100.0) * 100)
    text = (
        f"{exc} For this MCP server, set it in the \"env\" of the server's entry in the MCP "
        f"client config, e.g. \"env\": {{\"{exc.variable}\": \"{value}\"}}, and restart the "
        f"server."
    )
    if exc.variable in ("SKILLTOTAL_MAX_CLONE_MB", "SKILLTOTAL_MAX_READABLE_MB"):
        sources = [str(args.get(key, "")).strip() for key in ("source", "old", "new")]
        repo = next((s for s in sources if classify_source(s) == "git"), "")
        base = repo.rstrip("/").removesuffix(".git") if repo and "/tree/" not in repo else (
            "https://github.com/<owner>/<repo>")
        text += (f" Or scan only the component's subfolder: {base}/tree/<ref>/<path>")
    return text


# --- answers ----------------------------------------------------------------------------------


def summarize_report(report: dict[str, Any]) -> dict[str, Any]:
    """The compact answer of scan_component: what an agent needs to decide, a few kilobytes even
    for a large package (the full report of mcp-remote is about 30 KB, mostly traits and every
    capability's evidence). The shape is stable and named in the tool's description."""
    verdict = report.get("verdict") or {}
    findings = report.get("findings") or []
    needs_review = report.get("needs_review") or []
    metadata = report.get("metadata") or {}
    counts = {klass: 0 for klass in _CLASS_ORDER}
    for finding in findings:
        klass = str(finding.get("threat_class", ""))
        counts[klass] = counts.get(klass, 0) + 1
    unanalyzed = [n for n in needs_review if n.get("title") in UNANALYZED_TITLES]
    to_read = [n for n in needs_review if n.get("title") not in UNANALYZED_TITLES]
    return {
        "component": _identity(report),
        "verdict": {
            "level": verdict.get("level"),
            "headline": verdict.get("headline", ""),
            "has_malicious_indicators": bool(verdict.get("has_malicious_indicators")),
        },
        "decision": _decision_line(verdict),
        "risk_score": report.get("risk_score"),
        "risk_level": report.get("risk_level"),
        "why": [_compact_finding(f) for f in _ordered(findings)],
        "capabilities": sorted(report.get("capabilities") or {}),
        "counts": {"findings_by_threat_class": counts, "needs_review": len(needs_review)},
        "check_manually": [_review_line(n) for n in to_read[:_SUMMARY_REVIEW_NOTES]],
        "not_checked": [*NOT_CHECKED, *(_review_line(n) for n in unanalyzed)],
        "engine": _engine(metadata),
        "full_report": "call again with detail=\"full\" for every finding and all evidence",
    }


def summarize_diff(old: dict[str, Any], new: dict[str, Any],
                   diff: dict[str, Any]) -> dict[str, Any]:
    """The compact answer of diff_components: the verdict change and the risk findings that came
    or went, in the same shape as scan_component's summary. Capabilities are named only."""
    old_verdict, new_verdict = old.get("verdict") or {}, new.get("verdict") or {}
    added = [f for f in diff.get("new_findings") or [] if _is_risk(f)]
    removed = [f for f in diff.get("resolved_findings") or [] if _is_risk(f)]
    grown = [
        {**c, "evidence": c.get("added_evidence") or []}
        for c in diff.get("changed_findings") or []
        if _is_risk(c) and c.get("added_evidence")
    ]
    return {
        "old": _side(old),
        "new": _side(new),
        "verdict_changed": bool(diff.get("verdict_changed")),
        "verdict_change": (f"{str(old_verdict.get('level', '?')).upper()} -> "
                           f"{str(new_verdict.get('level', '?')).upper()}"),
        "decision": _decision_line(new_verdict),
        "risk_score_delta": diff.get("risk_score_delta"),
        "new_risk_findings": [_compact_finding(f) for f in _ordered(added)],
        "risk_findings_with_new_evidence": [_compact_finding(f) for f in _ordered(grown)],
        "removed_risk_findings": [
            {key: f.get(key) for key in ("id", "threat_class", "severity", "title")}
            for f in _ordered(removed)
        ],
        "capabilities_added": diff.get("capabilities_added") or [],
        "capabilities_removed": diff.get("capabilities_removed") or [],
        "ruleset_mismatch": bool(diff.get("ruleset_mismatch")),
        "summary": diff.get("summary", ""),
        "not_checked": list(NOT_CHECKED),
        "full_report": "call again with detail=\"full\" for every new, resolved and changed "
                       "finding with all evidence",
    }


def _is_risk(finding: dict[str, Any]) -> bool:
    return finding.get("threat_class") != "capability"


def _ordered(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What the verdict rests on first (malicious, risky, exposure, then capabilities), by
    severity within each class."""
    return sorted(findings, key=lambda f: (
        _CLASS_ORDER.get(str(f.get("threat_class")), len(_CLASS_ORDER)),
        _SEVERITY_ORDER.get(str(f.get("severity")), len(_SEVERITY_ORDER)),
        str(f.get("id", "")),
    ))


def _compact_finding(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = finding.get("evidence") or []
    compact = {
        "rule": finding.get("id"),
        "threat_class": finding.get("threat_class"),
        "severity": finding.get("severity"),
        "title": finding.get("title"),
        "evidence": [_evidence_line(e) for e in evidence[:_SUMMARY_EVIDENCE]],
    }
    if len(evidence) > _SUMMARY_EVIDENCE:
        compact["more_evidence"] = len(evidence) - _SUMMARY_EVIDENCE
    return compact


def _evidence_line(evidence: dict[str, Any]) -> str:
    snippet = one_line(str(evidence.get("snippet", "")).strip())
    if len(snippet) > _SUMMARY_SNIPPET_CHARS:
        snippet = snippet[: _SUMMARY_SNIPPET_CHARS - 3] + "..."
    return f"{one_line(str(evidence.get('file', '')))}:{evidence.get('line_start')}  {snippet}"


def _review_line(note: dict[str, Any]) -> str:
    where = f" ({one_line(note['file'])})" if note.get("file") else ""
    return f"{one_line(str(note.get('title', '')))}{where}"


def _decision_line(verdict: dict[str, Any]) -> str:
    return f"{str(verdict.get('level', '')).upper()} - {verdict.get('headline', '')}"


def _identity(report: dict[str, Any]) -> dict[str, Any]:
    component = report.get("component") or {}
    return {key: component.get(key, "") for key in ("name", "type", "source", "version")}


def _engine(metadata: dict[str, Any]) -> dict[str, Any]:
    return {"version": metadata.get("skilltotal_version"),
            "ruleset": metadata.get("ruleset_version"),
            "report_schema": metadata.get("schema_version")}


def _side(report: dict[str, Any]) -> dict[str, Any]:
    verdict = report.get("verdict") or {}
    return {
        "component": _identity(report),
        "verdict": {"level": verdict.get("level"), "headline": verdict.get("headline", ""),
                    "has_malicious_indicators": bool(verdict.get("has_malicious_indicators"))},
        "risk_score": report.get("risk_score"),
        "engine": _engine(report.get("metadata") or {}),
    }


def _list_rules(args: dict[str, Any]) -> list[dict[str, Any]]:
    rules = [r.to_dict() for r in get_rules()]
    if "ids" in args:
        wanted = {rule_id.strip().upper() for rule_id in args["ids"]}
        rules = [r for r in rules if str(r.get("id", "")).upper() in wanted]
    query = str(args.get("query", "")).strip().lower()
    if query:
        rules = [r for r in rules if query in f"{r.get('id', '')}\n{r.get('title', '')}".lower()]
    if args.get("verbose") is True:
        return rules
    return [{key: rule.get(key) for key in _RULE_SUMMARY} for rule in rules]


# --- housekeeping -----------------------------------------------------------------------------


def remove_stale_temp_dirs(tmp: str | None = None, *, now: float | None = None,
                           max_age: float = STALE_TEMP_SECONDS) -> int:
    """Remove the temporary folders scans left behind when their process was killed (a client
    that ends the server mid-scan skips the cleanup); returns how many went.

    Only folders directly in the temp directory, named with the engine's own prefix, and not
    modified for ``max_age`` seconds. A link is never followed or removed. Best effort: anything
    in the way is left as it is, and nothing raises.
    """
    removed = 0
    cutoff = (time.time() if now is None else now) - max_age
    try:
        entries = list(os.scandir(tmp or tempfile.gettempdir()))
    except OSError:
        return 0
    for entry in entries:
        try:
            if not entry.name.startswith(TEMP_DIR_PREFIX) or entry.is_symlink() or (
                    getattr(entry, "is_junction", lambda: False)()):
                continue
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_mtime > cutoff:
                continue
            _rmtree(entry.path)
            removed += not os.path.lexists(entry.path)
        except OSError:
            continue
    return removed


def _rmtree(path: str) -> None:
    def retry_writable(function, target, *_exc) -> None:
        # A git checkout's pack files are read-only, which stops a delete on Windows.
        try:
            os.chmod(target, stat.S_IWRITE)
            function(target)
        except OSError:
            pass

    # shutil.rmtree removes a link inside the tree without following it.
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=retry_writable)
    else:  # pragma: no cover - the same, under its older name
        shutil.rmtree(path, onerror=retry_writable)


# --- JSON-RPC ---------------------------------------------------------------------------------


def _tool_error(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": True}


def _result(msg_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _encode(response: dict[str, Any]) -> str:
    # One message per line; json.dumps without indent never emits embedded newlines.
    text = json.dumps(response, ensure_ascii=False)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate (a client may send one as `\ud800`, a file name may hold one) cannot
        # travel as UTF-8: escaped, the reply still goes out instead of ending the session.
        text = json.dumps(response)
    return text
