"""Shell / command execution detection for Node.js.

Python shell execution is handled by the AST scanner (:mod:`skilltotal.scanners.python_ast`).

A bare ``exec(`` is not evidence of anything on its own: ``RegExp.prototype.exec``,
better-sqlite3's ``db.exec`` and mongoose's ``query.exec()`` are all spelled the same way, and
matching the name alone flagged ordinary regex code as shell execution. A call site therefore
counts only where it can be tied to ``child_process``:

* ``child_process.exec(...)`` spelled out, anywhere;
* in a file that imports ``child_process``, a bare ``exec(...)`` / ``spawn(...)`` (the destructured
  import) or a call through the alias that file bound (``const cp = require("child_process")`` then
  ``cp.exec(...)``);
* the forms tsc, esbuild and Babel compile those to (``child_process_1.default.exec(...)``,
  ``(0, child_process_1.exec)(...)``), read through ``IndexedFile.interop_view``.

Importing ``child_process`` or a process-spawning library is itself evidence, and ``Bun.spawn`` is
matched explicitly; the member-call exclusion above would otherwise have dropped it.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    alternation,
)
from skilltotal.scanners.node_fetch_exec import fetched_text_sinks
from skilltotal.scanners.shell_script import REMOTE_EXEC
from skilltotal.text_normalize import original_span

NODE_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

CATEGORY = "shell_execution"

_CP = r"['\"](?:node:)?child_process['\"]"
# simple-git runs the git binary for every call, like GitPython on the Python side.
_SPAWN_LIBS = r"['\"](?:execa|zx|shelljs|cross-spawn|spawn-rx|tinyexec|node-pty|simple-git)['\"]"
_IDENT = r"[A-Za-z_$][\w$]*"
# Not preceded by an identifier character or a dot: a bare call, never a method on something else.
_BARE = r"(?<![\w$.])"
_CALLS = r"(?:exec|execSync|spawn|spawnSync)"

# Call sites that run a process in any file, whatever it imports.
_ANYWHERE_CALLS = (
    r"child_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(",
    r"\bBun\.spawn(?:Sync)?\s*\(",
)
# Evidence that holds in any file, whatever it imports.
_ANYWHERE = alternation(
    _ANYWHERE_CALLS[0],
    rf"require\(\s*{_CP}\s*\)",
    rf"from\s+{_CP}",
    rf"require\(\s*{_SPAWN_LIBS}\s*\)",
    rf"from\s+{_SPAWN_LIBS}",
    _ANYWHERE_CALLS[1],
    flags=re.MULTILINE,
)
_IMPORTS_CP = re.compile(rf"require\(\s*{_CP}\s*\)|from\s+{_CP}")
# The names a file binds child_process to: CommonJS, TypeScript import-equals, namespace and
# default imports.
_ALIASES = re.compile(
    rf"(?:const|let|var)\s+({_IDENT})\s*=\s*require\(\s*{_CP}\s*\)"
    rf"|import\s+({_IDENT})\s*=\s*require\(\s*{_CP}\s*\)"
    rf"|import\s+\*\s+as\s+({_IDENT})\s+from\s+{_CP}"
    rf"|import\s+({_IDENT})\s*(?:,\s*\{{[^}}]*\}})?\s+from\s+{_CP}"
)
# exec/execSync called with a command built by interpolation or concatenation.
_INJECTION_TAILS = (
    r"\s*`[^`]*\$\{",
    r"[^)\n]*?['\"]\s*\+",
    r"[^)\n]*?\+\s*['\"]",
)


def _aliases(text: str) -> list[str]:
    return sorted({name for m in _ALIASES.finditer(text) for name in m.groups() if name})


def _call_prefixes(f: IndexedFile, text: str | None = None) -> list[str]:
    """Where an exec/spawn call counts in this file (regex prefixes before the call name).
    ``text`` is the view of the file to read the imports from (default: the file as written)."""
    text = f.text if text is None else text
    prefixes = [r"child_process\."]
    if _IMPORTS_CP.search(text):
        prefixes.append(_BARE)
        aliases = _aliases(text)
        if aliases:
            prefixes.append(_BARE + "(?:" + "|".join(re.escape(a) for a in aliases) + r")\.")
    return prefixes


def _calls(f: IndexedFile, text: str, names: str) -> str:
    """The call heads of ``names`` (an alternation of child_process functions) in this file, up to
    the opening bracket: after one of ``_call_prefixes``, or as a quoted member of the module's
    alias (`cp["exec"](`, which is how `cp["ex" + "ec"](` reads once its literals are joined)."""
    prefixes = "|".join(f"(?:{p})" for p in _call_prefixes(f, text))
    heads = rf"(?:{prefixes}){names}"
    aliases = _aliases(text) if _IMPORTS_CP.search(text) else []
    if aliases:
        receivers = "|".join(re.escape(a) for a in [*aliases, "child_process"])
        heads += rf"|{_BARE}(?:{receivers})\s*\[\s*['\"`]{names}['\"`]\s*\]"
    return heads


_QUOTED_MEMBER = re.compile(
    r"\[\s*['\"`](?:exec|execSync|spawn|spawnSync|execFile|execFileSync)['\"`]\s*\]"
)
# The names a file gives child_process.exec / execSync: a renamed destructuring or import, the
# member read off the require, and the promisified function.
_EXEC_RENAMES = re.compile(
    rf"\bexec(?:Sync)?\s*:\s*({_IDENT})(?=[^{{}}]{{0,300}}\}}\s*=\s*require\(\s*{_CP}\s*\))"
    rf"|\bexec(?:Sync)?\s+as\s+({_IDENT})(?=[^{{}}]{{0,300}}\}}\s*from\s*{_CP})"
    rf"|(?:const|let|var)\s+({_IDENT})\s*=\s*require\(\s*{_CP}\s*\)\s*\.\s*exec(?:Sync)?\b"
    rf"|(?:const|let|var)\s+({_IDENT})\s*=\s*(?:util\s*\.\s*)?promisify\(\s*"
    rf"(?:{_IDENT}\s*\.\s*)?exec\s*\)"
)


def _command_sink_heads(f: IndexedFile, text: str) -> str | None:
    """The calls of ``f`` whose first argument a shell runs as a command line (exec / execSync,
    under whatever name the file gives them), for node_fetch_exec.fetched_text_sinks."""
    if not _IMPORTS_CP.search(text) and "child_process." not in text:
        return None
    heads = _calls(f, text, r"(?:execSync|exec)")
    renamed = sorted({n for m in _EXEC_RENAMES.finditer(text) for n in m.groups() if n})
    if renamed:
        heads += rf"|{_BARE}(?:" + "|".join(re.escape(n) for n in renamed) + ")"
    return heads


def exec_call_pattern(f: IndexedFile) -> re.Pattern[str]:
    """The process-running call sites in this file: those ST-SHELL-NODE counts, with execFile /
    execFileSync as ST-SHELL-PIPE-EXEC-NODE reads them (imports left out)."""
    prefixes = "|".join(f"(?:{p})" for p in _call_prefixes(f))
    return alternation(rf"(?:{prefixes}){_PIPE_CALLS}\s*\(", *_ANYWHERE_CALLS, flags=re.MULTILINE)


SHELL_RULE = RuleSpec(
    id="ST-SHELL-NODE",
    category=CATEGORY,
    severity=Severity.HIGH,
    title="Node.js shell/command execution",
    description=(
        "Node.js process execution was detected (child_process exec/spawn, or a "
        "process-spawning library such as zx / execa / cross-spawn / shelljs)."
    ),
    recommendation=(
        "Confirm the command and its arguments are fully controlled and not "
        "derived from untrusted input; prefer execFile with an argument array."
    ),
    capability=Capability.SHELL_EXECUTION,
    # `// const { exec } = require('child_process')` in a comment or JSDoc example runs nothing.
    code_context="comments",
    suffixes=NODE_SUFFIXES,
    # The file-independent part; call sites are resolved per file in ShellExecScanner.scan.
    pattern=_ANYWHERE,
)

CMDI_RULE = RuleSpec(
    id="ST-CMDI-NODE",
    category="command_injection",
    severity=Severity.HIGH,
    title="Possible command injection (exec with dynamic command)",
    description=(
        "child_process exec/execSync is called with a command built by string "
        "interpolation (template `${...}`) or concatenation. exec runs through a "
        "shell, so untrusted input in the command is a command-injection vector."
    ),
    recommendation=(
        "Use execFile/spawn with an argument array instead of exec; never build a "
        "shell command string from external input."
    ),
    capability=None,  # shell capability already covered by ST-SHELL-NODE
    threat_class=ThreatClass.RISKY_CONSTRUCT,
    code_context="comments",
    suffixes=NODE_SUFFIXES,
    # Metadata only (rules list / docs): the effective pattern is built per file.
    pattern=alternation(
        *(r"child_process\.exec(?:Sync)?\s*\(" + tail for tail in _INJECTION_TAILS),
        flags=re.MULTILINE,
    ),
)


PIPE_EXEC_RULE = RuleSpec(
    id="ST-SHELL-PIPE-EXEC-NODE",
    category=CATEGORY,
    severity=Severity.HIGH,
    title="Remote pipe-to-shell execution (Node.js)",
    description=(
        "A child_process call (exec / execSync, or spawn of `sh -c`) is given a command that "
        "downloads code and pipes it into a shell or interpreter, e.g. "
        "`execSync(\"curl ... | bash\")`; or exec / execSync is given, as its command, the text "
        "of a response the same file fetched (fetch, http(s).get, axios, got). The component runs "
        "whatever the host serves at that moment, which no review of the component can see."
    ),
    recommendation=(
        "Ship the code instead, or download a pinned artifact, verify its checksum, and run that "
        "copy; never pipe a network response straight into a shell."
    ),
    capability=None,  # shell capability already covered by ST-SHELL-NODE
    threat_class=ThreatClass.RISKY_CONSTRUCT,
    code_context="comments",
    suffixes=NODE_SUFFIXES,
)

# The calls whose string arguments a shell receives: exec/execSync take a command line, and
# spawn/execFile run one when the program is a shell given `-c` (or when `shell: true` is set).
_PIPE_CALLS = r"(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)"
# How far into a call its arguments are read.
_ARGS_REACH = 4000


class ShellExecScanner(Scanner):
    name = "shell_exec"
    rules = [SHELL_RULE, CMDI_RULE, PIPE_EXEC_RULE]

    def scan(self, index: FileIndex) -> ScanResult:
        shell: list[Evidence] = []
        cmdi: list[Evidence] = []
        pipe: list[Evidence] = []
        seen_shell: set[tuple[str, int, int]] = set()
        seen_cmdi: set[tuple[str, int, int]] = set()
        for f in index.select(suffixes=NODE_SUFFIXES):
            # The compiled-call view, then the source with its character escapes written out (an
            # escaped letter in `exec` or in the "child_process" module name): JavaScript
            # resolves them before it runs anything.
            views: list[tuple[str, Sequence[int] | None]] = [(f.interop_view(), None)]
            plain = f.js_unescaped_or_none()
            if plain is not None:
                views.append(plain)
            # And with spliced string literals joined: `require("child_" + "process")`,
            # `cp["ex" + "ec"](...)`. Only a file that writes the module's name or a function's
            # name in pieces has more to show there than the views above.
            joined = f.concat_folded_or_none()
            if joined is not None and "child_process" in joined[0] and (
                joined[0].count("child_process") != f.text.count("child_process")
                or (_QUOTED_MEMBER.search(joined[0]) and not _QUOTED_MEMBER.search(f.text))
            ):
                views.append(joined)
            names_module = "child_process" in f.text or (
                joined is not None and "child_process" in joined[0]
            )
            pipe_lines: set[int] = set()
            for text, origin in views:
                calls = re.compile(rf"(?:{_calls(f, text, _CALLS)})\s*\(", re.MULTILINE)
                exec_heads = _calls(f, text, r"exec(?:Sync)?")
                injections = re.compile(
                    "|".join(rf"(?:(?:{exec_heads})\s*\({t})" for t in _INJECTION_TAILS),
                    re.MULTILINE,
                )
                _collect(f, text, (_ANYWHERE, calls), shell, seen_shell, origin)
                _collect(f, text, (injections,), cmdi, seen_cmdi, origin)
                if len(pipe) < MAX_EVIDENCE_SCANNED and ("curl" in text or "wget" in text):
                    pipe_calls = re.compile(
                        rf"(?:{_calls(f, text, _PIPE_CALLS)})\s*\(", re.MULTILINE
                    )
                    for m in pipe_calls.finditer(text):
                        end = _call_end(text, m.end())
                        command = " ".join(_string_literals(text, m.end(), end))
                        if not REMOTE_EXEC.search(command):
                            continue
                        ev = f.evidence_for_span(*_span(origin, m.start(), end))
                        if origin is None or ev.line_start not in pipe_lines:
                            pipe.append(ev)
                        pipe_lines.add(ev.line_start)
            # The same download-and-run with the download done by the file itself: the text of a
            # response it fetched is the command.
            if names_module and len(pipe) < MAX_EVIDENCE_SCANNED:
                for request, sink in fetched_text_sinks(
                    f, _command_sink_heads, whole_argument=True
                ):
                    for span in (request, sink):
                        ev = f.evidence_for_span(*span)
                        if ev.line_start not in pipe_lines:
                            pipe.append(ev)
                        pipe_lines.add(ev.line_start)
        findings = []
        if shell:
            findings.append(_finding_from_rule(SHELL_RULE, shell))
        if cmdi:
            findings.append(_finding_from_rule(CMDI_RULE, cmdi))
        if pipe:
            findings.append(_finding_from_rule(PIPE_EXEC_RULE, pipe[:MAX_EVIDENCE_SCANNED]))
        return ScanResult(findings=findings)


def _call_end(text: str, start: int) -> int:
    """The offset just past the ``)`` that closes a call whose arguments begin at ``start``
    (quotes and nested brackets honored), or the end of the reach when it is not found."""
    depth, quote, i = 0, "", start
    end = min(len(text), start + _ARGS_REACH)
    while i < end:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return i + 1
            depth -= 1
        i += 1
    return end


def _string_literals(text: str, start: int, end: int) -> list[str]:
    """The string and template literals in ``text[start:end]``, as written (a template's
    ``${…}`` stays in place), so a command concatenated from pieces reads as one line."""
    out: list[str] = []
    i = start
    while i < end:
        ch = text[i]
        if ch in "'\"`":
            j = i + 1
            while j < end and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i + 1:j])
            i = j + 1
        else:
            i += 1
    return out


def _span(origin: Sequence[int] | None, start: int, end: int) -> tuple[int, int]:
    """A span of a view as a span of the file."""
    return (start, end) if origin is None else original_span(origin, start, end)


def _collect(
    f: IndexedFile,
    text: str,
    patterns: tuple[re.Pattern[str], ...],
    out: list[Evidence],
    seen: set[tuple[str, int, int]],
    origin: Sequence[int] | None = None,
) -> None:
    """Add this file's matches in line order, the order a single alternation used to yield.
    ``text`` is the file's compiled-call view, or a rewritten view with ``origin`` mapping each
    of its characters to the file."""
    found: list[Evidence] = []
    for pattern in patterns:
        for m in pattern.finditer(text):
            ev = f.evidence_for_span(*_span(origin, m.start(), m.end()))
            key = (ev.file, ev.line_start, ev.line_end)
            if key not in seen:
                seen.add(key)
                found.append(ev)
    found.sort(key=lambda ev: (ev.line_start, ev.line_end))
    out.extend(found[: max(0, MAX_EVIDENCE_SCANNED - len(out))])
