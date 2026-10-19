"""Commands an AI agent host or an editor runs on its own, read from a component's files.

A component can hand a command to the tool that loads it in many places, and each place runs it
without a separate step from the user:

* the launch command of an MCP server, in every client format: ``mcpServers`` (Claude Desktop and
  Code, Cursor, Gemini CLI, a Claude Code plugin, an MCPB bundle's ``mcp_config``), VS Code's
  ``servers`` (``mcp.json``, and ``mcp.servers`` in ``settings.json``), Codex's ``[mcp_servers]``
  tables in ``.codex/config.toml``, and the ``mcpServers`` of a subagent's frontmatter;
* Claude Code project settings: hooks (a command, or an ``http`` hook that posts each event to a
  URL), the status line, and the credential and header helpers (``apiKeyHelper``,
  ``awsAuthRefresh``, ``awsCredentialExport``, ``otelHeadersHelper``, ``fileSuggestion``); an MCP
  server's ``headersHelper``;
* the hook files of other agents (Gemini CLI, Cursor, Qwen) and VS Code tasks that run when the
  folder opens;
* a Claude Code plugin: its hooks, background monitors and language servers, inline in
  ``plugin.json``, in a marketplace entry or in their default files;
* hooks in the frontmatter of a skill or a subagent.

This module only reads them: one list of :class:`AutorunCommand` per index (cached), which the
scanners judge (``agent_config`` for fetch-and-run and honest auto-run configuration,
``secret_exfil`` for a command that sends credentials off the machine, ``mcp`` for the server
surface). Nothing is ever executed.
"""

from __future__ import annotations

import json
import re
import weakref
from dataclasses import dataclass, field
from posixpath import normpath

from skilltotal import bounded_json
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Evidence, NeedsReview

# What kind of configuration a command comes from decides what an honest one means.
ORIGIN_PROJECT = "project"  # project settings, editor tasks: runs when the folder is opened
ORIGIN_PLUGIN = "plugin"  # a plugin's own hooks, monitors and language servers
ORIGIN_MCP = "mcp"  # an MCP server launch command, in any client's configuration
ORIGIN_SKILL = "skill"  # hooks in the frontmatter of a skill or a subagent

KIND_HOOK = "hook"
KIND_HTTP_HOOK = "http_hook"
KIND_STATUS_LINE = "status_line"
KIND_HELPER = "helper"
KIND_TASK = "task"
KIND_MCP_SERVER = "mcp_server"
KIND_HEADERS_HELPER = "headers_helper"
KIND_MONITOR = "monitor"
KIND_LSP_SERVER = "lsp_server"

# Agent hook files whose commands run when a session starts or a tool runs, with no further step.
_PROJECT_HOOK_FILES = (
    ".claude/settings.json", ".claude/settings.local.json", ".gemini/settings.json",
    ".cursor/hooks.json", ".qwen/settings.json",
)
_CLAUDE_SETTINGS = (".claude/settings.json", ".claude/settings.local.json")
# Claude Code settings keys that hold a command it runs on its own (string or {"command": ...}).
_SETTINGS_COMMAND_KEYS = (
    ("statusLine", KIND_STATUS_LINE), ("subagentStatusLine", KIND_STATUS_LINE),
    ("apiKeyHelper", KIND_HELPER), ("awsAuthRefresh", KIND_HELPER),
    ("awsCredentialExport", KIND_HELPER), ("otelHeadersHelper", KIND_HELPER),
    ("fileSuggestion", KIND_HELPER),
)
_PLUGIN_MANIFEST = ".claude-plugin/plugin.json"
_MARKETPLACE = ".claude-plugin/marketplace.json"
_PLUGIN_HOOKS = "hooks/hooks.json"
_PLUGIN_MONITORS = "monitors/monitors.json"
_PLUGIN_LSP = ".lsp.json"
_VSCODE_TASKS = ".vscode/tasks.json"
_VSCODE_SETTINGS = ".vscode/settings.json"
# The file names the MCP scanner reads as manifests (scanners/mcp.py MANIFEST_NAMES).
_MCP_MANIFEST_NAMES = frozenset(
    {"mcp.json", ".mcp.json", "mcp.config.json", "server.json", "manifest.json"}
)
# Bundles Claude Code unpacks and runs: their code is not in the files this scan reads.
_BUNDLE_SUFFIXES = (".mcpb", ".dxt")
MCP_BUNDLE_NOT_ANALYZED = "MCP server bundle not analyzed"
# A skill's or subagent's frontmatter longer than this reader goes (_MAX_FRONTMATTER_LINES).
FRONTMATTER_PARTLY_READ = "Frontmatter partly analyzed"


@dataclass(frozen=True)
class Piece:
    """One string of a command (the program, an argument, an environment value) and where it is
    written in the file (``start``/``end`` offsets into the file text)."""

    text: str
    start: int
    end: int


@dataclass(frozen=True, eq=False)
class AutorunCommand:
    """A command (or, for an ``http`` hook, a URL) a tool runs on its own, with its source."""

    kind: str
    origin: str
    file: IndexedFile
    pieces: tuple[Piece, ...]
    # Environment values the command is started with (an MCP server's `env`): never run
    # themselves, but a credential path handed to the command through one is still read by it.
    env: tuple[Piece, ...] = ()
    # The JSON/TOML container the entry came from ("mcpServers", "servers", "mcp_servers", ...).
    container: str = ""

    @property
    def text(self) -> str:
        """The command line as the tool runs it: the program and its arguments joined by spaces."""
        return " ".join(p.text for p in self.pieces)

    @property
    def is_http(self) -> bool:
        return self.kind == KIND_HTTP_HOOK

    def piece_at(self, offset: int) -> Piece:
        """The piece of :attr:`text` holding character ``offset`` (a joining space belongs to the
        piece before it)."""
        pos = 0
        for piece in self.pieces:
            pos += len(piece.text)
            if offset <= pos:
                return piece
            pos += 1
        return self.pieces[-1]

    def evidence(self, piece: Piece | None = None) -> Evidence:
        """Evidence on ``piece`` (default: the longest piece, where a payload usually sits)."""
        if piece is None:
            piece = max(self.pieces, key=lambda p: len(p.text))
        return self.file.evidence_for_span(piece.start, max(piece.start + 1, piece.end))


@dataclass(frozen=True, eq=False)
class AutorunScan:
    commands: tuple[AutorunCommand, ...] = ()
    reviews: tuple[NeedsReview, ...] = ()
    # Markdown files (skills, subagents) whose frontmatter declares hooks or MCP servers, mapped to
    # the last line of that frontmatter: those lines are configuration the tool runs, not
    # documentation, whatever the file's name says (its body is still prose).
    frontmatter_lines: dict[str, int] = field(default_factory=dict)


_CACHE: weakref.WeakKeyDictionary[FileIndex, AutorunScan] = weakref.WeakKeyDictionary()


def autorun_commands(index: FileIndex) -> AutorunScan:
    """Every auto-run command in ``index``, parsed once per index."""
    cached = _CACHE.get(index)
    if cached is None:
        cached = _CACHE[index] = _scan(index)
    return cached


# ------------------------------------------------------------------------------------- parsing
def _scan(index: FileIndex) -> AutorunScan:
    by_path = {f.relpath: f for f in index.files}
    out = _Collector(by_path)
    for f in index.files:
        rel = f.relpath.replace("\\", "/")
        lower = rel.lower()
        name = lower.rsplit("/", 1)[-1]
        if f.suffix == ".json" or name.endswith((".jsonc", ".json5")):
            out.json_file(f, lower, name)
        elif name == "config.toml" and lower.rsplit("/", 2)[-2:-1] == [".codex"]:
            out.codex_toml(f)
        elif f.suffix in (".md", ".mdx") and (name == "skill.md" or "/agents/" in f"/{lower}"):
            out.frontmatter(f, skill=name == "skill.md")
    return AutorunScan(
        commands=tuple(out.commands),
        reviews=tuple(out.reviews),
        frontmatter_lines=dict(out.frontmatter_lines),
    )


class _Anchors:
    """Where each string value is written in a file, found once per occurrence in order."""

    def __init__(self, f: IndexedFile) -> None:
        self.f = f
        self._next: dict[str, int] = {}

    def piece(self, value: str, key: str | None = None) -> Piece:
        text = self.f.text
        for literal in (json.dumps(value, ensure_ascii=False)[1:-1], json.dumps(value)[1:-1]):
            if not literal:
                continue
            start = self._next.get(literal, 0)
            at = text.find(literal, start)
            if at < 0 and start:
                at = text.find(literal)
            if at >= 0:
                self._next[literal] = at + len(literal)
                return Piece(value, at, at + len(literal))
        if key:
            at = text.find(f'"{key}"')
            if at >= 0:
                return Piece(value, at, at + len(key) + 2)
        return Piece(value, 0, min(1, len(text)))


class _Collector:
    def __init__(self, by_path: dict[str, IndexedFile]) -> None:
        self.by_path = by_path
        self.commands: list[AutorunCommand] = []
        self.reviews: list[NeedsReview] = []
        self.frontmatter_lines: dict[str, int] = {}
        self._parsed: dict[str, object] = {}

    # -- JSON ---------------------------------------------------------------------------------
    def json_file(self, f: IndexedFile, lower: str, name: str) -> None:
        text = f.text
        hook_file = lower.endswith(_PROJECT_HOOK_FILES)
        plugin_file = lower.endswith(
            (_PLUGIN_MANIFEST, _MARKETPLACE, _PLUGIN_HOOKS, _PLUGIN_MONITORS)
        ) or name == _PLUGIN_LSP
        candidate = (
            hook_file or plugin_file
            or lower.endswith((_VSCODE_TASKS, _VSCODE_SETTINGS))
            or name in ("mcp.json", "manifest.json")
            or '"mcpServers"' in text
            # A key written with escapes (`"mcp\u0053ervers"`) is the same name to a JSON
            # reader, so a file with any escape is parsed and its decoded keys decide.
            or "\\u" in text
        )
        if not candidate:
            return
        data = self._load(f)
        if data is None:
            return
        anchors = _Anchors(f)
        if hook_file and isinstance(data, dict):
            self._hooks(f, anchors, data.get("hooks"), ORIGIN_PROJECT)
            if lower.endswith(_CLAUDE_SETTINGS):
                self._settings_commands(f, anchors, data, ORIGIN_PROJECT)
        if lower.endswith(_VSCODE_TASKS) and isinstance(data, dict):
            self._folder_open_tasks(f, anchors, data)
        if isinstance(data, dict):
            servers = data.get("mcpServers")
            plugin_manifest = lower.endswith(_PLUGIN_MANIFEST)
            if isinstance(servers, dict):
                origin = ORIGIN_PLUGIN if plugin_manifest else ORIGIN_MCP
                self._servers(f, anchors, servers, origin, "mcpServers")
            if name == "mcp.json" and not isinstance(servers, dict):
                vscode = data.get("servers")
                if isinstance(vscode, dict):
                    self._servers(f, anchors, vscode, ORIGIN_MCP, "servers")
            if lower.endswith(_VSCODE_SETTINGS):
                nested = data.get("mcp")
                vs_servers = nested.get("servers") if isinstance(nested, dict) else None
                if not isinstance(vs_servers, dict):
                    vs_servers = data.get("mcp.servers")
                if isinstance(vs_servers, dict):
                    self._servers(f, anchors, vs_servers, ORIGIN_MCP, "mcp.servers")
            if name == "manifest.json":
                server = data.get("server")
                config = server.get("mcp_config") if isinstance(server, dict) else None
                if isinstance(config, dict):
                    self._server(f, anchors, config, ORIGIN_MCP, "mcp_config")
            if plugin_manifest:
                self._plugin_manifest(f, anchors, data, lower)
            if lower.endswith(_MARKETPLACE):
                self._marketplace(f, anchors, data)
            if lower.endswith(_PLUGIN_HOOKS):
                self._hooks(f, anchors, data.get("hooks"), ORIGIN_PLUGIN)
        if name == _PLUGIN_LSP and isinstance(data, dict):
            self._lsp_servers(f, anchors, data)
        if lower.endswith(_PLUGIN_MONITORS) and isinstance(data, list):
            self._monitors(f, anchors, data)

    def _load(self, f: IndexedFile) -> object | None:
        if f.relpath in self._parsed:
            return self._parsed[f.relpath]
        data: object | None = None
        cut = False
        for text in (f.text, _strip_jsonc(f.text)):
            try:
                data, cut = bounded_json.loads_cut(text)
                break
            except ValueError:
                continue
        # The MCP scanner already says so for a file it reads as a manifest; one note per file.
        manifest = f.name.lower() in _MCP_MANIFEST_NAMES or (
            '"mcpServers"' in f.text or '"tools"' in f.text
        )
        if cut and not manifest:
            # Imported here: the scanners package imports this module.
            from skilltotal.scanners.base import deep_json_review

            self.reviews.append(deep_json_review("agent_config", f.relpath))
        self._parsed[f.relpath] = data
        return data

    def _referenced_json(self, owner: IndexedFile, root: str, value: str) -> IndexedFile | None:
        """The indexed file a plugin manifest names by a ``./relative`` path."""
        rel = normpath(f"{root}/{value}" if root else value).lstrip("/")
        if rel.startswith("../") or rel == "..":
            return None
        return self.by_path.get(rel)

    def _entry(
        self, kind: str, origin: str, f: IndexedFile, anchors: _Anchors, command: object,
        args: object = None, env: object = None, *, key: str = "command", container: str = "",
    ) -> None:
        pieces: list[Piece] = []
        if isinstance(command, str) and command.strip():
            pieces.append(anchors.piece(command, key))
        for arg in args if isinstance(args, list) else ():
            if isinstance(arg, dict):  # VS Code task args may be {"value": ..., "quoting": ...}
                arg = arg.get("value")
            if isinstance(arg, str) and arg:
                pieces.append(anchors.piece(arg))
        if not pieces:
            return
        env_pieces = tuple(
            anchors.piece(v) for v in (env.values() if isinstance(env, dict) else ())
            if isinstance(v, str) and v
        )
        self.commands.append(AutorunCommand(
            kind=kind, origin=origin, file=f, pieces=tuple(pieces), env=env_pieces,
            container=container,
        ))

    def _hooks(self, f: IndexedFile, anchors: _Anchors, hooks: object, origin: str) -> None:
        """Every hook handler under ``hooks``: a ``command`` (with exec-form ``args``) or an
        ``http`` handler's ``url``. Depth-first with an explicit stack, in document order: json
        accepts deeper nesting than a recursive walk survives, and a hook must not hide behind it.
        """
        end = object()
        stack = [iter([hooks])] if hooks is not None else []
        while stack:
            node = next(stack[-1], end)
            if node is end:
                stack.pop()
            elif isinstance(node, dict):
                url = node.get("url")
                if str(node.get("type", "")).lower() == "http" and isinstance(url, str) and url:
                    self.commands.append(AutorunCommand(
                        kind=KIND_HTTP_HOOK, origin=origin, file=f,
                        pieces=(anchors.piece(url, "url"),), container="hooks",
                    ))
                else:
                    command = node.get("command")
                    if isinstance(command, str) and command.strip():
                        self._entry(KIND_HOOK, origin, f, anchors, command, node.get("args"),
                                    container="hooks")
                stack.append(iter(node.values()))
            elif isinstance(node, list):
                stack.append(iter(node))

    def _settings_commands(
        self, f: IndexedFile, anchors: _Anchors, data: dict, origin: str
    ) -> None:
        for key, kind in _SETTINGS_COMMAND_KEYS:
            value = data.get(key)
            if isinstance(value, dict):
                self._entry(kind, origin, f, anchors, value.get("command"), value.get("args"),
                            container=key)
            elif isinstance(value, str):
                self._entry(kind, origin, f, anchors, value, key=key, container=key)

    def _folder_open_tasks(self, f: IndexedFile, anchors: _Anchors, data: dict) -> None:
        tasks = data.get("tasks")
        for task in tasks if isinstance(tasks, list) else ():
            if not isinstance(task, dict):
                continue
            run_on = task.get("runOptions")
            if isinstance(run_on, dict) and run_on.get("runOn") == "folderOpen":
                self._entry(KIND_TASK, ORIGIN_PROJECT, f, anchors, task.get("command"),
                            task.get("args"), container="tasks")

    def _server(
        self, f: IndexedFile, anchors: _Anchors, server: dict, origin: str, container: str
    ) -> None:
        self._entry(KIND_MCP_SERVER, origin, f, anchors, server.get("command"), server.get("args"),
                    server.get("env"), container=container)
        helper = server.get("headersHelper")
        if isinstance(helper, str):
            self._entry(KIND_HEADERS_HELPER, origin, f, anchors, helper, key="headersHelper",
                        container=container)

    def _servers(
        self, f: IndexedFile, anchors: _Anchors, servers: dict, origin: str, container: str
    ) -> None:
        for server in servers.values():
            if isinstance(server, dict):
                self._server(f, anchors, server, origin, container)

    def _lsp_servers(self, f: IndexedFile, anchors: _Anchors, servers: dict) -> None:
        for server in servers.values():
            if isinstance(server, dict):
                self._entry(KIND_LSP_SERVER, ORIGIN_PLUGIN, f, anchors, server.get("command"),
                            server.get("args"), server.get("env"), container="lspServers")

    def _monitors(self, f: IndexedFile, anchors: _Anchors, monitors: list) -> None:
        for monitor in monitors:
            if isinstance(monitor, dict):
                self._entry(KIND_MONITOR, ORIGIN_PLUGIN, f, anchors, monitor.get("command"),
                            container="monitors")

    def _plugin_manifest(
        self, f: IndexedFile, anchors: _Anchors, data: dict, lower: str
    ) -> None:
        root = f.relpath[: len(f.relpath) - len(_PLUGIN_MANIFEST)].rstrip("/")
        for item in _as_list(data.get("hooks")):
            if isinstance(item, dict):
                self._hooks(f, anchors, item, ORIGIN_PLUGIN)
            elif isinstance(item, str):
                ref = self._referenced_json(f, root, item)
                ref_data = self._load(ref) if ref is not None else None
                if isinstance(ref_data, dict) and ref is not None and ref.relpath.lower() != (
                    f"{root}/{_PLUGIN_HOOKS}".lstrip("/").lower()
                ):
                    self._hooks(ref, _Anchors(ref), ref_data.get("hooks"), ORIGIN_PLUGIN)
        for item in _as_list(data.get("mcpServers")):
            if isinstance(item, str):
                self._server_reference(f, root, item)
        for item in _as_list(data.get("lspServers")):
            if isinstance(item, dict):
                self._lsp_servers(f, anchors, item)
            elif isinstance(item, str):
                ref = self._referenced_json(f, root, item)
                ref_data = self._load(ref) if ref is not None else None
                if isinstance(ref_data, dict) and ref is not None and ref.name.lower() != (
                    _PLUGIN_LSP
                ):
                    self._lsp_servers(ref, _Anchors(ref), ref_data)
        experimental = data.get("experimental")
        monitors = experimental.get("monitors") if isinstance(experimental, dict) else None
        for value in (monitors, data.get("monitors")):
            if isinstance(value, list):
                self._monitors(f, anchors, value)
            elif isinstance(value, str):
                ref = self._referenced_json(f, root, value)
                ref_data = self._load(ref) if ref is not None else None
                if isinstance(ref_data, list) and ref is not None and not ref.relpath.lower(
                ).endswith(_PLUGIN_MONITORS):
                    self._monitors(ref, _Anchors(ref), ref_data)

    def _server_reference(self, f: IndexedFile, root: str, value: str) -> None:
        """A plugin's ``mcpServers`` entry that names a file or a bundle instead of a map."""
        lower = value.lower()
        if lower.endswith(_BUNDLE_SUFFIXES) or lower.startswith(("http://", "https://")):
            self.reviews.append(NeedsReview(
                category="coverage",
                title=MCP_BUNDLE_NOT_ANALYZED,
                reason=(
                    f"The plugin starts an MCP server from {value!r}, a bundle Claude Code "
                    "unpacks (or downloads) and runs. Its code is not among the files this scan "
                    "read, so nothing in it was checked."
                ),
                file=f.relpath,
            ))
            return
        ref = self._referenced_json(f, root, value)
        ref_data = self._load(ref) if ref is not None else None
        if not isinstance(ref_data, dict) or ref is None:
            return
        if isinstance(ref_data.get("mcpServers"), dict):
            return  # read on its own like any file with an `mcpServers` map
        self._servers(ref, _Anchors(ref), ref_data, ORIGIN_PLUGIN, "referenced")

    def _marketplace(self, f: IndexedFile, anchors: _Anchors, data: dict) -> None:
        plugins = data.get("plugins")
        for entry in plugins if isinstance(plugins, list) else ():
            if not isinstance(entry, dict):
                continue
            if isinstance(entry.get("hooks"), dict):
                self._hooks(f, anchors, entry["hooks"], ORIGIN_PLUGIN)
            if isinstance(entry.get("mcpServers"), dict):
                self._servers(f, anchors, entry["mcpServers"], ORIGIN_PLUGIN, "mcpServers")
            if isinstance(entry.get("lspServers"), dict):
                self._lsp_servers(f, anchors, entry["lspServers"])

    # -- Codex TOML ---------------------------------------------------------------------------
    def codex_toml(self, f: IndexedFile) -> None:
        for server in _toml_mcp_servers(f.text):
            pieces = [p for p in (server.get("command"),) if p is not None] + server["args"]
            if not pieces:
                continue
            self.commands.append(AutorunCommand(
                kind=KIND_MCP_SERVER, origin=ORIGIN_MCP, file=f, pieces=tuple(pieces),
                env=tuple(server["env"]), container="mcp_servers",
            ))

    # -- Markdown frontmatter -----------------------------------------------------------------
    def frontmatter(self, f: IndexedFile, *, skill: bool) -> None:
        block, cut = _frontmatter_lines(f.text)
        if not block:
            return
        if cut:
            # The agent reads all of it: hooks or servers declared past the limit would run
            # unchecked, so the report says the rest was not read.
            self.reviews.append(NeedsReview(
                category="coverage",
                title=FRONTMATTER_PARTLY_READ,
                reason=(
                    f"The frontmatter is longer than {_MAX_FRONTMATTER_LINES} lines; hooks or MCP "
                    "servers declared past that were not analyzed. Read the rest before using it."
                ),
                file=f.relpath,
                line=f.line_of_offset(block[-1].start),
            ))
        found = False
        for kind, origin, piece in _frontmatter_hooks(block):
            found = True
            self.commands.append(AutorunCommand(
                kind=kind, origin=origin, file=f, pieces=(piece,), container="hooks",
            ))
        if not skill:
            for command, args, env in _frontmatter_servers(block):
                found = True
                pieces = tuple(p for p in (command, *args) if p is not None)
                if pieces:
                    self.commands.append(AutorunCommand(
                        kind=KIND_MCP_SERVER, origin=ORIGIN_MCP, file=f, pieces=pieces,
                        env=tuple(env), container="frontmatter",
                    ))
        if found:
            last = block[-1]
            self.frontmatter_lines[f.relpath] = f.line_of_offset(last.start + len(last.text)) + 1


def _as_list(value: object) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _strip_jsonc(text: str) -> str:
    """``text`` with ``//`` and ``/* */`` comments and trailing commas removed (outside strings):
    VS Code reads its ``settings.json``, ``mcp.json`` and ``tasks.json`` that way."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            nl = text.find("\n", i)
            i = n if nl < 0 else nl
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            i = n if close < 0 else close + 2
        elif ch == ",":
            k = i + 1
            while k < n and text[k] in " \t\r\n":
                k += 1
            if k < n and text[k] in "]}":
                i += 1  # a trailing comma
            else:
                out.append(ch)
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


# ------------------------------------------------------------------------------- Codex TOML
_TOML_TABLE = re.compile(r"^[ \t]*\[([^\[\]\n]+)\][ \t]*(?:#[^\n]*)?$")
_TOML_KEY_PART = r'(?:[A-Za-z0-9_-]+|"[^"\n]*"|\'[^\'\n]*\')'
_TOML_KEY = re.compile(
    rf"^[ \t]*({_TOML_KEY_PART}(?:[ \t]*\.[ \t]*{_TOML_KEY_PART})*)[ \t]*=[ \t]*"
)
_TOML_BASIC_ESCAPES = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"',
                       "\\": "\\", "e": "\x1b"}
# A server table is short; this bounds a pathological multi-line value.
_TOML_MAX_VALUE = 20_000


def _toml_key_parts(key: str) -> list[str]:
    parts = re.findall(r'"([^"\n]*)"|\'([^\'\n]*)\'|([A-Za-z0-9_-]+)', key)
    return [a or b or c for a, b, c in parts]


def _toml_strings(text: str, start: int, end: int) -> list[Piece]:
    """Every string literal in ``text[start:end]`` (basic, literal and multi-line), decoded."""
    pieces: list[Piece] = []
    i = start
    while i < end:
        ch = text[i]
        if ch == "#":
            nl = text.find("\n", i, end)
            i = end if nl < 0 else nl
            continue
        if ch not in "\"'":
            i += 1
            continue
        triple = text.startswith(ch * 3, i)
        quote = ch * 3 if triple else ch
        body_start = i + len(quote)
        k = body_start
        while k < end:
            if ch == '"' and text[k] == "\\":
                k += 2
                continue
            if text.startswith(quote, k):
                break
            if not triple and text[k] == "\n":
                break
            k += 1
        raw = text[body_start:k]
        value = _toml_unescape(raw) if ch == '"' else raw
        if triple and value.startswith("\n"):
            value = value[1:]
        pieces.append(Piece(value, i, min(end, k + len(quote))))
        i = k + len(quote)
    return pieces


def _toml_unescape(raw: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch != "\\" or i + 1 >= len(raw):
            out.append(ch)
            i += 1
            continue
        nxt = raw[i + 1]
        if nxt in _TOML_BASIC_ESCAPES:
            out.append(_TOML_BASIC_ESCAPES[nxt])
            i += 2
        elif nxt in "uU":
            width = 4 if nxt == "u" else 8
            digits = raw[i + 2 : i + 2 + width]
            try:
                out.append(chr(int(digits, 16)))
                i += 2 + width
            except ValueError:
                out.append(ch)
                i += 1
        elif nxt == "\n":  # line-ending backslash in a multi-line string: trim the whitespace
            i += 2
            while i < len(raw) and raw[i] in " \t\r\n":
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _toml_value_end(text: str, start: int) -> int:
    """Offset just past the TOML value starting at ``start``: brackets and braces are balanced
    across lines, strings (incl. multi-line) are skipped, a comment ends a line."""
    depth = 0
    i, n = start, min(len(text), start + _TOML_MAX_VALUE)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            triple = text.startswith(ch * 3, i)
            quote = ch * 3 if triple else ch
            k = i + len(quote)
            while k < n:
                if ch == '"' and text[k] == "\\":
                    k += 2
                    continue
                if text.startswith(quote, k) or (not triple and text[k] == "\n"):
                    break
                k += 1
            i = k + len(quote)
            continue
        if ch == "#":
            nl = text.find("\n", i, n)
            i = n if nl < 0 else nl
            continue
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "\n" and depth <= 0:
            return i
        i += 1
    return n


def _toml_mcp_servers(text: str) -> list[dict]:
    """The ``command`` / ``args`` / ``env`` strings of each ``[mcp_servers.<name>]`` table.

    A reader for the part of TOML these tables use: table headers, dotted keys, basic and literal
    strings (multi-line too), arrays and inline tables of strings. Each string keeps its offsets,
    so evidence points at it. Anything else in the file is passed over.
    """
    servers: dict[str, dict] = {}
    table: list[str] = []
    i, n = 0, len(text)
    while i < n:
        nl = text.find("\n", i)
        line_end = n if nl < 0 else nl
        line = text[i:line_end].rstrip("\r")
        header = _TOML_TABLE.match(line)
        if header and not line.lstrip().startswith("[["):
            table = _toml_key_parts(header.group(1))
            i = line_end + 1
            continue
        key = _TOML_KEY.match(line)
        if not key:
            i = line_end + 1
            continue
        value_start = i + key.end()
        value_end = _toml_value_end(text, value_start)
        path = table + _toml_key_parts(key.group(1))
        if len(path) >= 2 and path[0] == "mcp_servers":
            strings = _toml_strings(text, value_start, value_end)
            if len(path) == 2:  # `name = { command = "...", args = [...] }` under [mcp_servers]
                for sub, values in _inline_table(text, value_start, value_end, strings):
                    _toml_assign(servers, [path[1], *sub], values)
            else:
                _toml_assign(servers, path[1:], strings)
        i = value_end + 1
    return [s for s in servers.values() if s["command"] is not None or s["args"]]


def _toml_assign(servers: dict[str, dict], path: list[str], strings: list[Piece]) -> None:
    if len(path) < 2:
        return
    entry = servers.setdefault(path[0], {"command": None, "args": [], "env": []})
    head = path[1]
    if head == "command" and len(path) == 2 and strings:
        entry["command"] = strings[0]
    elif head == "args" and len(path) == 2:
        entry["args"].extend(strings)
    elif head == "env":
        entry["env"].extend(strings)


def _inline_table(text: str, start: int, end: int, strings: list[Piece]):
    """``(key path, strings)`` for each key of an inline table ``{ k = v, ... }``: each string
    belongs to the last key written before it (keys are never inside a string)."""
    raw = text[start:end]
    if not raw.lstrip().startswith("{"):
        return
    inside = [(s.start, s.end) for s in strings]
    keys = [
        (start + m.start(), _toml_key_parts(m.group(1)))
        for m in re.finditer(r'([A-Za-z0-9_-]+)[ \t]*=', raw)
        if not any(a <= start + m.start() < b for a, b in inside)
    ]
    for k, (key_at, key) in enumerate(keys):
        stop = keys[k + 1][0] if k + 1 < len(keys) else end
        yield key, [s for s in strings if key_at <= s.start < stop]


# ---------------------------------------------------------------------------- frontmatter
_FRONTMATTER_END = re.compile(r"^---[ \t]*\r?$", re.MULTILINE)
# Greedy value (trailing blanks are stripped in code): a lazy one re-tried the trailing-blank
# test at every character of a long line of spaces (quadratic).
_YAML_KEY = re.compile(r"^([ \t]*)(?:-[ \t]+)?([A-Za-z_][\w-]*)[ \t]*:(?:[ \t]+(.*))?$")
# A real frontmatter is a few dozen lines; past this a block is not read as one.
_MAX_FRONTMATTER_LINES = 2000
_BLOCK_SCALAR = re.compile(r"^[|>][+-]?[0-9]?$")


@dataclass(frozen=True)
class _Line:
    text: str
    start: int  # offset of the line in the file

    @property
    def indent(self) -> int:
        return len(self.text) - len(self.text.lstrip(" \t"))


def _frontmatter_lines(text: str) -> tuple[list[_Line], bool]:
    """The lines of a leading ``---`` YAML frontmatter block, with their file offsets, and whether
    the block goes on past ``_MAX_FRONTMATTER_LINES`` (the rest is not read)."""
    if not text.startswith("---"):
        return [], False
    first_nl = text.find("\n")
    if first_nl < 0:
        return [], False
    end = _FRONTMATTER_END.search(text, first_nl + 1)
    if end is None:
        return [], False
    lines: list[_Line] = []
    pos = first_nl + 1
    while pos < end.start() and len(lines) < _MAX_FRONTMATTER_LINES:
        nl = text.find("\n", pos, end.start())
        stop = end.start() if nl < 0 else nl
        lines.append(_Line(text[pos:stop].rstrip("\r"), pos))  # a CRLF file reads the same
        pos = stop + 1
    return lines, pos < end.start()


def _yaml_scalar(raw: str, offset: int) -> tuple[str, int, int]:
    """A plain or quoted YAML scalar written on one line, decoded, with its file offsets."""
    stripped = raw.strip()
    lead = raw.find(stripped) if stripped else 0
    start = offset + lead
    if stripped.startswith('"'):
        close = stripped.rfind('"')
        body = stripped[1:close] if close > 0 else stripped[1:]
        try:
            value = json.loads(f'"{body}"')
        except ValueError:
            value = body
        return value, start, start + (close + 1 if close > 0 else len(stripped))
    if stripped.startswith("'"):
        close = stripped.rfind("'")
        body = stripped[1:close] if close > 0 else stripped[1:]
        return body.replace("''", "'"), start, start + (close + 1 if close > 0 else len(stripped))
    # A comment starts at a `#` after a blank; finding that pair is linear, while `[ \t]+#`
    # re-scanned a long run of blanks from each of its characters.
    comment = re.search(r"[ \t]#", stripped)
    value = stripped[: comment.start()].rstrip() if comment else stripped
    return value, start, start + len(value)


def _section(lines: list[_Line], key: str) -> list[_Line]:
    """The lines of a top-level ``key:`` mapping (indented under it)."""
    out: list[_Line] = []
    inside = False
    for line in lines:
        stripped = line.text.strip()
        if not stripped or stripped.startswith("#"):
            if inside:
                out.append(line)
            continue
        if line.indent == 0:
            m = _YAML_KEY.match(line.text)
            inside = bool(m and m.group(2) == key)
            continue
        if inside:
            out.append(line)
    return out


def _block_value(lines: list[_Line], i: int, indent: int) -> tuple[str, int, int, int]:
    """A ``|`` / ``>`` block scalar starting after line ``i``: its text, offsets, last line."""
    parts: list[str] = []
    start = end = None
    j = i + 1
    while j < len(lines) and (not lines[j].text.strip() or lines[j].indent > indent):
        body = lines[j].text.strip()
        if body:
            parts.append(body)
            start = lines[j].start + lines[j].indent if start is None else start
            end = lines[j].start + len(lines[j].text.rstrip())
        j += 1
    if start is None:
        return "", lines[i].start, lines[i].start + 1, j - 1
    return " ".join(parts), start, end or start + 1, j - 1


def _frontmatter_hooks(lines: list[_Line]):
    """``(kind, origin, piece)`` for each hook command (or ``http`` hook URL) in ``hooks:``."""
    section = _section(lines, "hooks")
    pending_url: Piece | None = None
    pending_type: str | None = None
    for i, line in enumerate(section):
        m = _YAML_KEY.match(line.text)
        if not m:
            continue
        key, raw = m.group(2), m.group(3) or ""
        if line.text.lstrip().startswith("-"):
            if pending_url is not None and pending_type == "http":
                yield KIND_HTTP_HOOK, ORIGIN_SKILL, pending_url
            pending_url, pending_type = None, None
        if key == "type":
            pending_type = _yaml_scalar(raw, 0)[0].lower()
        elif key == "url" and raw:
            value, start, end = _yaml_scalar(raw, line.start + m.start(3))
            pending_url = Piece(value, start, end)
        elif key == "command" and raw:
            if _BLOCK_SCALAR.match(raw.strip()):
                value, start, end, _ = _block_value(section, i, line.indent)
            else:
                value, start, end = _yaml_scalar(raw, line.start + m.start(3))
            if value.strip():
                yield KIND_HOOK, ORIGIN_SKILL, Piece(value, start, end)
    if pending_url is not None and pending_type == "http":
        yield KIND_HTTP_HOOK, ORIGIN_SKILL, pending_url


def _frontmatter_servers(lines: list[_Line]):
    """``(command, args, env)`` pieces for each server under a subagent's ``mcpServers:``."""
    section = _section(lines, "mcpServers")
    if not section:
        return
    base = min((ln.indent for ln in section if ln.text.strip()), default=0)
    current: dict | None = None
    servers: list[dict] = []
    mode = ""
    mode_indent = 0
    for line in section:
        if not line.text.strip():
            continue
        if line.indent == base:
            current = {"command": None, "args": [], "env": []}
            servers.append(current)
            mode = ""
            continue
        if current is None:
            continue
        m = _YAML_KEY.match(line.text)
        item = line.text.lstrip()
        if mode == "args" and line.indent > mode_indent and item.startswith("-"):
            raw = item[1:]
            value, start, end = _yaml_scalar(raw, line.start + line.indent + 1)
            if value:
                current["args"].append(Piece(value, start, end))
            continue
        if mode == "env" and line.indent > mode_indent and m:
            raw = m.group(3) or ""
            if raw:
                value, start, end = _yaml_scalar(raw, line.start + m.start(3))
                current["env"].append(Piece(value, start, end))
            continue
        mode = ""
        if not m:
            continue
        key, raw = m.group(2), m.group(3) or ""
        if key == "command" and raw:
            value, start, end = _yaml_scalar(raw, line.start + m.start(3))
            current["command"] = Piece(value, start, end)
        elif key == "args":
            if raw.strip().startswith("["):
                at = line.start + m.start(3)
                current["args"].extend(_flow_sequence(raw, at))
            else:
                mode, mode_indent = "args", line.indent
        elif key == "env" and not raw:
            mode, mode_indent = "env", line.indent
    for srv in servers:
        if srv["command"] is not None or srv["args"]:
            yield srv["command"], srv["args"], srv["env"]


def _flow_sequence(raw: str, offset: int) -> list[Piece]:
    """The string items of a one-line YAML flow sequence ``[a, "b c", 'd']``."""
    pieces: list[Piece] = []
    body_start = raw.find("[") + 1
    body_end = raw.rfind("]")
    if body_end < body_start:
        body_end = len(raw)
    items = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\']|\'\')*\'|[^,\s][^,]*')
    for m in items.finditer(raw[body_start:body_end]):
        value, start, end = _yaml_scalar(m.group(0), offset + body_start + m.start())
        if value:
            pieces.append(Piece(value, start, end))
    return pieces
