"""MCP tool annotations that the tool's own handler contradicts.

An MCP tool declares hints about itself: ``readOnlyHint`` (it does not change its environment) and
``destructiveHint`` (its changes may be destructive; the specification's default is true, and the
hint means something only for a tool that is not read-only). Clients and app directories read
them to decide which calls can run without asking, and nothing checks them against the code. This
scanner reads the handler a tool is registered with and reports:

* ``readOnlyHint: true`` on a handler that writes or deletes a file, sends a PUT, PATCH or DELETE
  request, or runs a process whose command is not fully written out in the source (built from the
  tool's arguments or a variable, so the tool runs whatever it is handed) or is a written-out
  command from a short list that changes things (``rm``, ``git push``, ``kubectl delete``, a
  ``>`` redirect, ...). A POST does not count, since GraphQL and search APIs read through POST;
  nor does a literal ``git log`` / ``kubectl get`` / ``ls``;
* an explicit ``destructiveHint: false`` on a handler that deletes a file or directory or sends a
  DELETE request. A tool that leaves the hint out is never reported.

Registrations read: the TypeScript SDK's ``server.registerTool(name, {..., annotations}, handler)``
and ``server.tool(name, ..., annotations, handler)``; in Python, ``@mcp.tool(annotations=...)``
over a ``def`` (a dict or ``ToolAnnotations(...)``) and ``mcp.add_tool(fn, annotations=...)``.
The annotations may be named by a constant defined in the same file. The handler is the function
passed inline, the decorated ``def``, or a function of the same file passed by name. Only that
function's own body is read: a helper it calls is not followed, in this file or another, so a
write done in a helper is not reported. Calls are recognised by the same signatures as
ST-FS-*-WRITE, ST-SHELL-* and ST-NET-*, plus ``fs.promises.*`` and names imported from
``fs/promises``; calls in comments and strings do not count. Nothing is run.
"""

from __future__ import annotations

import ast
import bisect
import re
import shlex

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    alternation,
)
from skilltotal.scanners.filesystem import NODE_FS_DELETE_CALLS, NODE_FS_WRITE_CALLS, NODE_SUFFIXES
from skilltotal.scanners.python_ast import (
    EFFECT_DELETE,
    EFFECT_EXEC,
    EFFECT_NETWORK,
    EFFECT_WRITE,
    PY_SUFFIXES,
    CallEffect,
    _command_arg,
    _is_dynamic_command,
    _literal_text,
    python_call_effects,
)
from skilltotal.scanners.shell_exec import exec_call_pattern

R_ANNOTATION_MISMATCH = "ST-MCP-ANNOTATION-MISMATCH"

READ_ONLY = "readOnlyHint"
DESTRUCTIVE = "destructiveHint"
_HINT_NAMES = frozenset({READ_ONLY, DESTRUCTIVE})

# What a handler does, as far as the annotations go.
_WRITE = "write"  # writes or deletes a file
_DELETE = "delete"  # deletes a file or directory
_EXEC = "exec"  # runs a process that is not a written-out read-only command
_MUTATING_REQUEST = "mutating_request"  # PUT / PATCH / DELETE
_DELETE_REQUEST = "delete_request"  # DELETE
_READ_ONLY_EXCLUDES = frozenset({_WRITE, _DELETE, _EXEC, _MUTATING_REQUEST, _DELETE_REQUEST})
_NOT_DESTRUCTIVE_EXCLUDES = frozenset({_DELETE, _DELETE_REQUEST})
# POST is left out: GraphQL, search and JSON-RPC APIs read through POST.
_MUTATING_METHODS = frozenset({"PUT", "PATCH", "DELETE"})

# --- written-out commands that change things ----------------------------------------------------
_MUTATING_PROGRAMS = frozenset(
    {"rm", "rmdir", "mv", "cp", "dd", "chmod", "chown", "tee", "truncate"}
)
_MUTATING_SUBCOMMANDS = {
    "git": frozenset({"push", "commit", "reset", "checkout", "clean", "rm"}),
    "kubectl": frozenset({"apply", "delete", "patch", "create", "scale"}),
    "docker": frozenset({"rm", "rmi", "run"}),
    "npm": frozenset({"install", "uninstall"}),
    "pip": frozenset({"install", "uninstall"}),
}
# Options of those programs that take a value before the subcommand (`git -C repo push`).
_VALUE_OPTIONS = frozenset({"-C", "-c", "-n", "--namespace", "--context", "--kubeconfig"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
_PIP = re.compile(r"pip\d*(?:\.\d+)?")
_SEPARATOR_CHARS = frozenset(";&|()")

# A hint as written: its declared value and where it is declared (character offsets in a
# JavaScript/TypeScript file, first and last line in a Python one).
Hint = tuple[bool, tuple[int, int]]

# --- JavaScript / TypeScript patterns ------------------------------------------------------------
# Matched in the file's code view (comments, regex literals and string contents blanked).
_JS_REGISTER = re.compile(r"\.[ \t]*(?:registerTool|tool)[ \t]*\(")
_JS_ANNOTATIONS_NAME = re.compile(
    r"(?<![\w$.])annotations[ \t]*:[ \t]*([A-Za-z_$][\w$]*)[ \t]*(?=[,}\n])"
)
_JS_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
# An argument that is a bare name (read in place, so a long argument is never copied).
_JS_BARE_NAME = re.compile(r"\s*([A-Za-z_$][\w$]*)\s*")
_JS_NONSPACE = re.compile(r"\S")
# A handler passed by name: `function name(` or `const name = ` (let/var, a type allowed).
_JS_FUNCTION_DECL = re.compile(
    r"(?<![\w$.])function[ \t]*\*?[ \t]*([A-Za-z_$][\w$]*)[ \t]*(?:<[^<>\n]{0,200}>)?[ \t]*\("
)
_JS_CONST_DECL = re.compile(
    r"(?<![\w$.])(?:const|let|var)[ \t]+([A-Za-z_$][\w$]*)(?![\w$])[^=\n;]{0,200}=(?![=>])"
)
_JS_BRACKET = re.compile(r"[()\[\]{}]")
_JS_FS_WRITE = alternation(*NODE_FS_WRITE_CALLS)
_JS_FS_DELETE = alternation(*NODE_FS_DELETE_CALLS)
# The request calls ST-NET-NODE counts, and the axios shorthands that name a mutating verb.
_JS_REQUEST = re.compile(r"\bfetch\s*\(|\baxios(?:\.request)?\s*\(|\bhttps?\.request\s*\(")
_JS_AXIOS_VERB = re.compile(r"\baxios\.(put|patch|delete)\s*\(")
# fs/promises reached as `fs.promises.x(`, or by a name imported from it.
_JS_FS_PROMISE_WRITES = frozenset({"writeFile", "appendFile", "rm", "unlink", "rmdir"})
_JS_FS_PROMISE_DELETES = frozenset({"rm", "unlink", "rmdir"})
_JS_FS_PROMISES_CALL = re.compile(r"\bfs\.promises\.(writeFile|appendFile|rm|unlink|rmdir)\s*\(")
# Matched in the raw text (the module name is a string); the keyword must be code.
_JS_FS_PROMISES_IMPORT = re.compile(
    r"""\bimport[ \t]*(?:type[ \t]+)?\{([^{}]{0,2000})\}\s*from\s*(["'])(?:node:)?fs/promises\2"""
)
_JS_FS_PROMISES_REQUIRE = re.compile(
    r"""\b(?:const|let|var)[ \t]*\{([^{}]{0,2000})\}\s*=\s*require\(\s*(["'])(?:node:)?"""
    r"""fs/promises\2\s*\)"""
)
_JS_IMPORT_ITEM = re.compile(r"\s*([A-Za-z_$][\w$]*)(?:\s*(?:as\b|:)\s*([A-Za-z_$][\w$]*))?\s*")
# A string literal argument, read from the raw text (a template only without `${`).
_JS_LITERAL = re.compile(
    r"""\s*(?:"((?:[^"\\\n]|\\.){0,4000})"|'((?:[^'\\\n]|\\.){0,4000})'|`([^`\\$]{0,4000})`)\s*"""
)
# The name of the process call ST-SHELL-NODE matched (`execSync(`, `cp.spawn(`, `Bun.spawn(`).
_JS_CALL_NAME = re.compile(r"(\w+)\s*\($")
# Matched in the raw text; the key and the colon must be code in the code view.
_JS_HINT = re.compile(
    r"""(?<![\w$])(["']?)(readOnlyHint|destructiveHint)\1[ \t]*(:)[ \t]*(true|false)(?![\w$])"""
)
_JS_METHOD = re.compile(
    r"""(?<![\w$])(["']?)method\1[ \t]*(:)[ \t]*["'`]((?i:put|patch|delete))["'`]"""
)
# How far a return-type annotation between a function's parameters and its body is read.
_JS_TYPE_REACH = 400


class McpAnnotationScanner(Scanner):
    name = "mcp_annotations"
    rules = [
        RuleSpec(
            id=R_ANNOTATION_MISMATCH,
            category="mcp",
            severity=Severity.MEDIUM,
            title="Tool annotation contradicted by its code",
            description=(
                "An MCP tool declares itself read-only (readOnlyHint: true) while its handler "
                "writes or deletes files, sends a PUT/PATCH/DELETE request, or runs a command "
                "built from its arguments or one that changes things (rm, git push, kubectl "
                "delete, ...), or declares itself non-destructive (destructiveHint: false) while "
                "its handler deletes files or sends a DELETE request. Clients use these hints to "
                "decide which tool calls run without asking. Each pair of evidence lines is the "
                "hint and the first call in the handler that contradicts it. Only the handler's "
                "own body is read; calls made through helper functions are not followed."
            ),
            recommendation=(
                "Make the annotations describe what the handler does (readOnlyHint: false, and "
                "destructiveHint: true for a tool that deletes), or take the write out of the "
                "tool. Do not auto-approve this tool on the strength of its hints."
            ),
            # The calls carry their own capability already (ST-FS-*, ST-SHELL-*, ST-NET-*).
            capability=None,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        for f in index.files:
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
            if READ_ONLY not in f.text and DESTRUCTIVE not in f.text:
                continue
            if f.suffix in NODE_SUFFIXES:
                evidence.extend(_js_mismatches(f))
            elif f.suffix in PY_SUFFIXES:
                evidence.extend(_py_mismatches(f))
        if not evidence:
            return ScanResult()
        rule = self.rules[0]
        return ScanResult(findings=[_finding_from_rule(rule, evidence[:MAX_EVIDENCE_SCANNED])])


def _excluded(hints: dict[str, Hint]) -> tuple[str, frozenset[str]] | None:
    """The hint that constrains the handler and what it rules out, or None."""
    read_only = hints.get(READ_ONLY)
    if read_only is not None and read_only[0] is True:
        return READ_ONLY, _READ_ONLY_EXCLUDES
    destructive = hints.get(DESTRUCTIVE)
    if destructive is not None and destructive[0] is False:
        return DESTRUCTIVE, _NOT_DESTRUCTIVE_EXCLUDES
    return None


def command_line_mutates(command: str) -> bool:
    """Whether a written-out shell command line changes things: one of its commands (split on
    ``;``, ``&&``, ``||``, ``|``) is in the mutating list, or it redirects output into a file
    (``> out.txt``; ``2>/dev/null`` does not count). A line that cannot be split counts as not
    mutating."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return False
    segment: list[str] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token and set(token) <= _SEPARATOR_CHARS:
            if argv_mutates(segment):
                return True
            segment = []
        elif token in (">", ">>"):
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            if not target.startswith(("/dev/", "&")):
                return True
            i += 1
        else:
            segment.append(token)
        i += 1
    return argv_mutates(segment)


def argv_mutates(argv: list[str | None]) -> bool:
    """Whether an argument list runs something that changes things, or something the tool is
    handed. ``None`` stands for an argument computed at run time. True for a program that is not
    written out, for ``rm``, ``mv``, ``tee``, ...; for ``git push``, ``kubectl delete``, ``docker
    rm``, ``npm install``, ... (or such a program whose subcommand is not written out); and for a
    shell given such a command, or a computed one, with ``-c``. A computed argument after a
    written-out read command (``["git", "-C", repo, "log"]``, ``["du", "-sh", path]``) does not
    make it count: it cannot change which program runs or what it does."""
    argv = list(argv)
    while argv and argv[0] is not None and (
        "=" in argv[0] and not argv[0].startswith("-") or argv[0] == "sudo"
    ):
        argv.pop(0)  # `FOO=1 git push`, `sudo rm`
    if not argv:
        return False
    if argv[0] is None:
        return True
    program = argv[0].replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
    rest = argv[1:]
    if program in _SHELLS:
        words = [a for a in rest if a is not None]
        if len(words) != len(rest):
            return True  # a computed script or command line
        for i, arg in enumerate(words[:-1]):
            if arg.startswith("-") and not arg.startswith("--") and "c" in arg:
                return command_line_mutates(words[i + 1])
        return False
    if program in _MUTATING_PROGRAMS:
        return True
    if _PIP.fullmatch(program):
        program = "pip"
    subcommands = _MUTATING_SUBCOMMANDS.get(program)
    if subcommands is None:
        return False
    skip = False
    for arg in rest:
        if skip:
            skip = False
        elif arg is None:
            return True  # the subcommand is computed
        elif arg in _VALUE_OPTIONS:
            skip = True
        elif not arg.startswith("-"):
            return arg in subcommands
    return False


def _js_fs_promise_imports(text: str, view: str) -> dict[str, str]:
    """Local name -> fs/promises function, for the write and delete functions a file imports
    by name (``import { writeFile, rm as remove } from "fs/promises"``, ``const { unlink } =
    require("node:fs/promises")``)."""
    names: dict[str, str] = {}
    for pattern in (_JS_FS_PROMISES_IMPORT, _JS_FS_PROMISES_REQUIRE):
        if "fs/promises" not in text:
            break
        for m in pattern.finditer(text):
            if view[m.start()] != text[m.start()]:
                continue  # in a comment or a string
            for item in m.group(1).split(","):
                parsed = _JS_IMPORT_ITEM.fullmatch(item)
                if parsed and parsed.group(1) in _JS_FS_PROMISE_WRITES:
                    names[parsed.group(2) or parsed.group(1)] = parsed.group(1)
    return names


# --- JavaScript / TypeScript ---------------------------------------------------------------------
def _js_mismatches(f: IndexedFile) -> list[Evidence]:
    if ".tool" not in f.text and ".registerTool" not in f.text:
        return []
    src = _JsSource(f)
    found: list[Evidence] = []
    for m in _JS_REGISTER.finditer(src.view):
        close = src.pairs.get(m.end() - 1)
        if close is None:
            continue
        args = src.top_level_args(m.end() - 1, close)
        if len(args) < 2:
            continue
        hints = src.hints(args[1:-1])
        constraint = _excluded(hints)
        if constraint is None:
            continue
        hint_name, excluded = constraint
        body = src.handler_body(args[-1])
        if body is None:
            continue
        call = src.first_effect(body, excluded)
        if call is None:
            continue
        found.append(f.evidence_for_span(*hints[hint_name][1]))
        found.append(f.evidence_for_span(*call))
    return found


class _JsSource:
    """One JavaScript/TypeScript file, read once: its code view, its bracket pairs, and every
    call that writes, deletes, runs a process or sends a request, by offset. A handler body is
    then looked up by bisection, so a file of many tools is read in linear time."""

    def __init__(self, f: IndexedFile):
        self.text = text = f.text
        self.view = view = f.c_code_view()
        self.pairs = _bracket_pairs(view)
        self._decls: tuple[dict[str, int], dict[str, int]] | None = None
        self.effects: dict[str, list[tuple[int, int]]] = {kind: [] for kind in _READ_ONLY_EXCLUDES}
        writes: list[tuple[int, int, bool]] = [
            (m.start(), m.end(), _JS_FS_DELETE.match(view, m.start()) is not None)
            for m in _JS_FS_WRITE.finditer(view)
        ]
        writes += [
            (m.start(), m.end(), m.group(1) in _JS_FS_PROMISE_DELETES)
            for m in _JS_FS_PROMISES_CALL.finditer(view)
        ]
        imported = _js_fs_promise_imports(text, view)
        if imported:
            bare = re.compile(
                r"(?<![\w$.])(" + "|".join(re.escape(n) for n in imported) + r")\s*\("
            )
            writes += [
                (m.start(), m.end(), imported[m.group(1)] in _JS_FS_PROMISE_DELETES)
                for m in bare.finditer(view)
            ]
        for start, end, delete in sorted(writes):
            self.effects[_WRITE].append((start, end))
            if delete:
                self.effects[_DELETE].append((start, end))
        self.effects[_EXEC] = [
            m.span() for m in exec_call_pattern(f).finditer(view) if self._exec_counts(m)
        ]
        for m in _JS_AXIOS_VERB.finditer(view):
            self.effects[_MUTATING_REQUEST].append(m.span())
            if m.group(1) == "delete":
                self.effects[_DELETE_REQUEST].append(m.span())
        self.requests = [m.span() for m in _JS_REQUEST.finditer(view)]
        # Where a request names a mutating method (`method: "POST"`); the key must be code.
        self.methods: dict[str, list[int]] = {_MUTATING_REQUEST: [], _DELETE_REQUEST: []}
        for m in _JS_METHOD.finditer(text):
            if view[m.start(2)] == ":" and view[m.start()] == text[m.start()]:
                self.methods[_MUTATING_REQUEST].append(m.start())
                if m.group(3).upper() == "DELETE":
                    self.methods[_DELETE_REQUEST].append(m.start())
        # Every hint written in code, by name: (start, end, value), in file order.
        self.hint_sites: dict[str, list[tuple[int, int, bool]]] = {n: [] for n in _HINT_NAMES}
        for h in _JS_HINT.finditer(text):
            if view[h.start()] == text[h.start()] and view[h.start(3)] == ":":
                self.hint_sites[h.group(2)].append((h.start(), h.end(), h.group(4) == "true"))
        # `annotations: NAME` (an object constant named instead of written inline).
        self.annotation_names = [
            (m.start(), m.group(1)) for m in _JS_ANNOTATIONS_NAME.finditer(view)
        ]

    # -- calls in a body ------------------------------------------------------------------------
    def first_effect(
        self, body: tuple[int, int], excluded: frozenset[str]
    ) -> tuple[int, int] | None:
        """The span of the first call in ``body`` whose effect the hint rules out."""
        start, end = body
        hits = [_first_in(self.effects[kind], start, end) for kind in excluded]
        for kind in excluded & {_MUTATING_REQUEST, _DELETE_REQUEST}:
            # A fetch / axios / http.request in a body that names the method.
            i = bisect.bisect_left(self.methods[kind], start)
            if i < len(self.methods[kind]) and self.methods[kind][i] < end:
                hits.append(_first_in(self.requests, start, end))
        found = [h for h in hits if h is not None]
        return min(found) if found else None

    def _exec_counts(self, m: re.Match[str]) -> bool:
        """Whether a process call contradicts a read-only claim: the tool runs what it is
        handed (a command line with a computed part, a computed program or subcommand), or a
        written-out command that changes things. ``exec(cmd)`` takes a command line; ``spawn`` /
        ``execFile(program, [args])`` and ``Bun.spawn([argv])`` take an argument list."""
        open_at = m.end() - 1
        close = self.pairs.get(open_at)
        if close is None:
            return True
        args = self.top_level_args(open_at, close)
        if not args:
            return True
        name = _JS_CALL_NAME.search(m.group())
        call = name.group(1) if name else ""
        if call in ("exec", "execSync"):
            command = self._literal(args[0])
            return command is None or command_line_mutates(command)
        if call in ("spawn", "spawnSync") and m.group().startswith("Bun"):
            argv = self._literal_array(args[0])
            return argv is None or argv_mutates(argv)
        program = self._literal(args[0])
        if program is None:
            return True
        rest: list[str | None] = []
        if len(args) > 1 and self.view[_skip_space(self.view, args[1][0], args[1][1])] != "{":
            listed = self._literal_array(args[1])
            rest = [None] if listed is None else listed  # a computed argument list
        try:
            head: list[str | None] = list(shlex.split(program))  # `spawn("git log", {shell})`
        except ValueError:
            return False
        return argv_mutates(head + rest)

    def _literal(self, arg: tuple[int, int]) -> str | None:
        """The text of a string literal argument, or None for anything else."""
        m = _JS_LITERAL.fullmatch(self.text, arg[0], arg[1])
        if m is None or self.view[_skip_space(self.view, arg[0], arg[1])] not in "\"'`":
            return None
        return next(g for g in m.groups() if g is not None)

    def _literal_array(self, arg: tuple[int, int]) -> list[str | None] | None:
        """The elements of an array literal (None for an element that is not a string
        literal, such as a variable or a spread), or None when the argument is not one."""
        i = _skip_space(self.view, arg[0], arg[1])
        close = self.pairs.get(i) if i < arg[1] and self.view[i] == "[" else None
        if close is None:
            return None
        return [self._literal(a) for a in self.top_level_args(i, close)]

    # -- registration arguments -----------------------------------------------------------------
    def top_level_args(self, open_at: int, close_at: int) -> list[tuple[int, int]]:
        """The spans of a call's comma-separated arguments (nested brackets skipped)."""
        view = self.view
        args: list[tuple[int, int]] = []
        start = i = open_at + 1
        while i < close_at:
            ch = view[i]
            if ch in "([{":
                end = self.pairs.get(i)
                if end is None or end > close_at:
                    return args
                i = end + 1
                continue
            if ch == ",":
                args.append((start, i))
                start = i + 1
            i += 1
        if _JS_NONSPACE.search(view, start, close_at):
            args.append((start, close_at))
        return args

    def hints(self, args: list[tuple[int, int]]) -> dict[str, Hint]:
        """The hints set in the registration's non-handler arguments, or in an object constant
        of this file that one of them names (``annotations: READ_ONLY``, or ``READ_ONLY``)."""
        hints: dict[str, Hint] = {}

        def read(start: int, end: int) -> None:
            for name, found in self.hint_sites.items():
                i = bisect.bisect_left(found, (start,))
                if name not in hints and i < len(found) and found[i][0] < end:
                    hints[name] = found[i][2], (found[i][0], found[i][1])

        for start, end in args:
            read(start, end)
            names = []
            i = bisect.bisect_left(self.annotation_names, (start,))
            if i < len(self.annotation_names) and self.annotation_names[i][0] < end:
                names.append(self.annotation_names[i][1])
            bare = _JS_BARE_NAME.fullmatch(self.view, start, end)
            if bare is not None:
                names.append(bare.group(1))
            for name in names:
                obj = self._const_object(name)
                if obj is not None:
                    read(*obj)
        return hints

    # -- handler bodies -------------------------------------------------------------------------
    def handler_body(self, arg: tuple[int, int]) -> tuple[int, int] | None:
        """The body of the handler argument: an inline function, or a function of this file it
        names (``function name(...) {...}`` / ``const name = (...) => {...}``)."""
        start, end = arg
        named = _JS_BARE_NAME.fullmatch(self.view, start, end)
        if named is None:
            return self._function_body(start, end)
        bare = named.group(1)
        functions, consts = self._declarations()
        if bare in functions:
            close = self.pairs.get(functions[bare])
            return None if close is None else self._block_after(close + 1, len(self.view))
        if bare in consts:
            return self._function_body(consts[bare], len(self.view))
        return None

    def _declarations(self) -> tuple[dict[str, int], dict[str, int]]:
        """``function NAME(`` -> offset of its ``(``; ``const NAME =`` -> offset after the ``=``
        (first declaration of each name), from one pass over the file."""
        if self._decls is None:
            functions: dict[str, int] = {}
            consts: dict[str, int] = {}
            for m in _JS_FUNCTION_DECL.finditer(self.view):
                functions.setdefault(m.group(1), m.end() - 1)
            for m in _JS_CONST_DECL.finditer(self.view):
                consts.setdefault(m.group(1), m.end())
            self._decls = functions, consts
        return self._decls

    def _const_object(self, name: str) -> tuple[int, int] | None:
        """The span of ``{...}`` in ``const NAME = {...}``."""
        after = self._declarations()[1].get(name)
        if after is None:
            return None
        i = _skip_space(self.view, after, len(self.view))
        close = self.pairs.get(i) if i < len(self.view) and self.view[i] == "{" else None
        return None if close is None else (i, close + 1)

    def _function_body(self, start: int, end: int) -> tuple[int, int] | None:
        """The body of a function expression starting at ``start``: ``async function (...)
        {...}``, ``async (...) => {...}``, ``x => expr``."""
        view, pairs = self.view, self.pairs
        i = _skip_space(view, start, end)
        if view.startswith("async", i) and not _is_ident_char(view, i + 5):
            i = _skip_space(view, i + 5, end)
        if view.startswith("function", i) and not _is_ident_char(view, i + 8):
            open_at = view.find("(", i, min(end, i + _JS_TYPE_REACH))
            close = pairs.get(open_at) if open_at >= 0 else None
            return None if close is None else self._block_after(close + 1, end)
        if i < end and view[i] == "(":
            close = pairs.get(i)
            if close is None:
                return None
            after = close + 1
        else:
            ident = _JS_IDENT.match(view, i, end)
            if ident is None:
                return None
            after = ident.end()
        arrow = view.find("=>", after, min(end, after + _JS_TYPE_REACH))
        if arrow < 0 or view[after:arrow].strip()[:1] not in ("", ":"):
            return None
        j = _skip_space(view, arrow + 2, end)
        if j < end and view[j] == "{":
            close = pairs.get(j)
            return None if close is None else (j, close + 1)
        return j, self._expression_end(j, end)

    def _block_after(self, i: int, end: int) -> tuple[int, int] | None:
        """The ``{...}`` body after a parameter list, past a return-type annotation if there is
        one (``): Promise<{ ok: boolean }> {``, ``): { ok: boolean } {``)."""
        view, pairs = self.view, self.pairs
        stop = min(end, i + _JS_TYPE_REACH)
        i = _skip_space(view, i, stop)
        if i < stop and view[i] == "{":
            close = pairs.get(i)
            return None if close is None else (i, close + 1)
        if i >= stop or view[i] != ":":
            return None
        i += 1
        angle = 0
        first = True  # a `{` that starts the return type is an object type, not the body
        while i < stop:
            ch = view[i]
            if ch in "([{":
                close = pairs.get(i)
                if close is None:
                    return None
                if ch == "{" and angle == 0 and not first:
                    return i, close + 1
                first = False
                i = close + 1
                continue
            if ch == "<":
                angle += 1
            elif ch == ">" and angle:
                angle -= 1
            if not ch.isspace():
                first = False
            i += 1
        return None

    def _expression_end(self, i: int, end: int) -> int:
        """Where an arrow function's expression body ends: ``;`` or a line break outside
        brackets."""
        view = self.view
        while i < end:
            ch = view[i]
            if ch in "([{":
                close = self.pairs.get(i)
                if close is None:
                    return end
                i = close + 1
                continue
            if ch in ";\n":
                return i
            i += 1
        return end


def _bracket_pairs(view: str) -> dict[int, int]:
    """Opening bracket offset -> its closing bracket, over code with strings already blanked."""
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for m in _JS_BRACKET.finditer(view):
        if m.group() in "([{":
            stack.append(m.start())
        elif stack:
            pairs[stack.pop()] = m.start()
    return pairs


def _first_in(spans: list[tuple[int, int]], start: int, end: int) -> tuple[int, int] | None:
    """The first of the sorted ``spans`` that starts inside [start, end)."""
    i = bisect.bisect_left(spans, (start, -1))
    return spans[i] if i < len(spans) and spans[i][0] < end else None


def _skip_space(view: str, i: int, stop: int) -> int:
    while i < stop and view[i].isspace():
        i += 1
    return i


def _is_ident_char(view: str, i: int) -> bool:
    return i < len(view) and (view[i].isalnum() or view[i] in "_$")


# --- Python --------------------------------------------------------------------------------------
_PY_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _py_mismatches(f: IndexedFile) -> list[Evidence]:
    if ".tool" not in f.text and "add_tool" not in f.text:
        return []
    try:
        tree = ast.parse(f.text, filename=f.relpath)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    tools = _py_tools(tree)
    if not tools:
        return []
    kinds = {id(e.call): _py_kinds(e) for e in python_call_effects(f, tree)}
    found: list[Evidence] = []
    for fn, hints in tools:
        constraint = _excluded(hints)
        if constraint is None:
            continue
        hint_name, excluded = constraint
        hits = [
            n for stmt in fn.body for n in ast.walk(stmt)
            if isinstance(n, ast.Call) and kinds.get(id(n), frozenset()) & excluded
        ]
        if not hits:
            continue
        call = min(hits, key=lambda c: (c.lineno, c.col_offset))
        first_line, last_line = hints[hint_name][1]
        found.append(f.evidence_for_lines(first_line, last_line))
        found.append(f.evidence_for_lines(call.lineno, call.end_lineno or call.lineno))
    return found


PyFunction = ast.FunctionDef | ast.AsyncFunctionDef


def _py_tools(tree: ast.Module) -> list[tuple[PyFunction, dict[str, Hint]]]:
    """Each tool function with the hints its registration declares: ``@x.tool(annotations=...)``
    over a ``def``, or ``x.add_tool(fn, annotations=...)`` naming a module-level ``def``."""
    constants = _py_module_constants(tree)
    defs = {s.name: s for s in tree.body if isinstance(s, _PY_FUNCTIONS)}
    tools: list[tuple[PyFunction, dict[str, Hint]]] = []
    for node in ast.walk(tree):
        if isinstance(node, _PY_FUNCTIONS):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and _method_name(dec) == "tool":
                    hints = _py_hints(_keyword(dec, "annotations"), constants)
                    if hints:
                        tools.append((node, hints))
        elif isinstance(node, ast.Call) and _method_name(node) == "add_tool" and node.args:
            target = node.args[0]
            if isinstance(target, ast.Name) and target.id in defs:
                hints = _py_hints(_keyword(node, "annotations"), constants)
                if hints:
                    tools.append((defs[target.id], hints))
    return tools


def _method_name(call: ast.Call) -> str | None:
    return call.func.attr if isinstance(call.func, ast.Attribute) else None


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _py_module_constants(tree: ast.Module) -> dict[str, ast.expr]:
    """Module-level names assigned exactly once (``READ_ONLY = ToolAnnotations(...)``)."""
    seen: dict[str, list[ast.expr]] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    seen.setdefault(target.id, []).append(stmt.value)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value:
            seen.setdefault(stmt.target.id, []).append(stmt.value)
    return {name: values[0] for name, values in seen.items() if len(values) == 1}


def _py_hints(
    expr: ast.expr | None, constants: dict[str, ast.expr], *, follow: bool = True
) -> dict[str, Hint]:
    """The hints in ``{"readOnlyHint": True}`` or ``ToolAnnotations(readOnlyHint=True)`` (or a
    module constant holding either), each with the lines that declare it."""
    if isinstance(expr, ast.Name) and follow and expr.id in constants:
        return _py_hints(constants[expr.id], constants, follow=False)
    pairs: list[tuple[str | None, ast.expr, ast.AST]] = []
    if isinstance(expr, ast.Dict):
        for key, value in zip(expr.keys, expr.values, strict=True):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                pairs.append((key.value, value, key))
    elif isinstance(expr, ast.Call):
        pairs.extend((kw.arg, kw.value, kw) for kw in expr.keywords)
    hints: dict[str, Hint] = {}
    for name, value, anchor in pairs:
        if (
            name in _HINT_NAMES
            and isinstance(value, ast.Constant)
            and isinstance(value.value, bool)
        ):
            line = getattr(anchor, "lineno", value.lineno)
            end = getattr(value, "end_lineno", None) or line
            hints.setdefault(name, (value.value, (line, end)))
    return hints


def _py_kinds(effect: CallEffect) -> frozenset[str]:
    kinds: set[str] = set()
    if EFFECT_WRITE in effect.effects:
        kinds.add(_WRITE)
    if EFFECT_DELETE in effect.effects:
        kinds |= {_WRITE, _DELETE}
    if EFFECT_EXEC in effect.effects and _py_exec_counts(effect):
        kinds.add(_EXEC)
    if EFFECT_NETWORK in effect.effects:
        method = _py_http_method(effect)
        if method in _MUTATING_METHODS:
            kinds.add(_MUTATING_REQUEST)
        if method == "DELETE":
            kinds.add(_DELETE_REQUEST)
    return frozenset(kinds)


def _py_exec_counts(effect: CallEffect) -> bool:
    """Whether a process call contradicts a read-only claim (see ``_JsSource._exec_counts``):
    ``subprocess.run(["git", "log", repo])`` and ``os.system("ls")`` do not;
    ``subprocess.run(cmd)``, an f-string command line and ``subprocess.run(["git", "push"])`` do.
    ``os.exec*`` / ``os.spawn*`` are not read and always count."""
    call, name = effect.call, effect.name
    if name.endswith("create_subprocess_exec"):  # argv as positional arguments
        return argv_mutates(_py_argv(call.args)) if call.args else True
    if name.startswith("os.") and name not in ("os.system", "os.popen"):
        return True
    command = _command_arg(call)
    if command is None:
        return True
    if isinstance(command, (ast.List, ast.Tuple)):
        return argv_mutates(_py_argv(command.elts)) if command.elts else True
    if _is_dynamic_command(command):
        return True  # a command line with a computed part
    text = _literal_text(command)
    return text is None or command_line_mutates(text)


def _py_argv(exprs: list[ast.expr]) -> list[str | None]:
    """Each argument's written-out value (a string or a number), or None when it is computed.
    A ``*spread`` hides the positions after it, so it ends the list with one None."""
    out: list[str | None] = []
    for e in exprs:
        if isinstance(e, ast.Starred):
            out.append(None)
            break
        if isinstance(e, ast.Constant) and type(e.value) in (int, float):
            out.append(str(e.value))
        else:
            out.append(None if _is_dynamic_command(e) else _literal_text(e))
    return out


def _py_http_method(effect: CallEffect) -> str | None:
    """The HTTP method a network call names: ``requests.post(...)``, ``httpx.delete(...)``,
    ``requests.request("PUT", ...)``, ``urllib.request.Request(url, method="POST")``."""
    leaf = effect.name.rsplit(".", 1)[-1]
    if leaf.upper() in _MUTATING_METHODS:
        return leaf.upper()
    if leaf not in ("request", "Request"):
        return None
    call = effect.call
    method = _keyword(call, "method")
    if method is None and leaf == "request" and call.args:
        method = call.args[0]
    if isinstance(method, ast.Constant) and isinstance(method.value, str):
        return method.value.upper()
    return None
