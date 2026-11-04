"""Obfuscation indicator detection.

A decode-and-execute chain (e.g. ``eval(atob(...))``) is a confirmed, evidence-backed
finding. Weaker indicators that cannot be confirmed as malicious on their own — a lone
large base64 blob, heavy hex escaping, or an extremely long (minified) line — are routed
to ``needs_review`` rather than inflating the score.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from itertools import islice

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    aggregated_review,
    alternation,
    findings_from_rules,
)

CATEGORY = "obfuscation"

# The optional ``\w+\.`` prefix tolerates a module alias (``import base64 as b`` ->
# ``b.b64decode``); a method literally named ``b64decode`` is essentially always base64.
# A hex decoder by its usual names (`hexDecode`, `fromHex`, `hex2str`, `unhex`, ...).
_HEX_DECODER = (
    r"(?:[\w$]+\.)?(?i:hex_?decode|decode_?hex|from_?hex|unhex|"
    r"hex_?(?:2|to_?)(?:str|string|ascii|utf8|text))\s*\("
)
# What a sink may run straight from a decoder: Python's decoders, and the JavaScript ones --
# `atob`, Buffer-decoded base64 or hex (`new Function(Buffer.from(h, "hex").toString())()`), a hex
# decoder, and a string literal written entirely as escapes, which the parser decodes.
# Text assembled from character codes: `"".join(chr(c) for c in (105, ...))`,
# `"".join(map(chr, codes))`, `bytes([105, ...]).decode()`. No decoder name appears, yet run through
# exec it is the same hidden payload.
_PY_CODEPOINTS = (
    r"(?:[\"']{2}\.join\(\s*(?:map\(\s*chr\s*,|\[?\s*chr\s*\()"
    r"|(?:bytes|bytearray)\(\s*[\[(]\s*\d{1,3}\s*,)"
)
_PY_DECODE_CALL = (
    r"(?:\w+\.)?b64decode|bytes\.fromhex|codecs\.decode|(?:binascii\.)?(?:unhexlify|a2b_hex)\s*\("
    r"|" + _PY_CODEPOINTS
)
_JS_DECODE_CALL = (
    r"atob\s*\(|Buffer\.from\s*\([^)]*['\"](?:base64|hex)['\"]|" + _HEX_DECODER
    + r"|['\"`](?:\\x[0-9A-Fa-f]{2}|\\u00[0-9A-Fa-f]{2}){8}"
)
# One alternative per sink, each starting with a literal character. That is what lets the regex
# engine skip ahead to the few places a match can begin; an alternative opening with a group such
# as `(?:eval|Function)` or with `\b` turns that off for the whole regex (it ran five to ten times
# slower over a large package), and a dozen alternatives sharing `eval(` re-test it at every `e`.
_DECODE_EXEC_ALTERNATIVES = (
    rf"exec\s*\(\s*(?:{_PY_DECODE_CALL})",
    rf"eval\s*\(\s*(?:{_PY_DECODE_CALL}|{_JS_DECODE_CALL})",
    # Indirect eval to dodge a literal ``eval(`` token: ``(0, eval)(atob(...))``.
    r"\(\s*0\s*,\s*eval\s*\)\s*\(\s*(?:atob|Buffer\.from)\s*\(",
    rf"Function\s*\(\s*(?:{_JS_DECODE_CALL})",
)
_DECODE_EXEC = alternation(*_DECODE_EXEC_ALTERNATIVES)

# The same decode and execute split over two statements: the decoded text is kept in a variable
# that eval / the Function constructor / exec then runs (`const stage = Buffer.from(h, "hex")
# .toString(); new Function(stage)()`, or `stage` assigned a literal written entirely as escapes).
# Both halves must be there, and the sink must take that very variable: a hex utility, or a
# `new Function("return this")`, is not a decode-and-execute.
_JS_DECODED_VARIABLE = re.compile(
    # Starts with the keyword itself, so the engine can skip to the letters it begins with; the
    # word boundary in front is checked in code. An optional TypeScript annotation:
    # `const stage: string = ...`.
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]{0,60})(?:\s*:\s*[\w$.<>\[\]| ]{1,40}?)?\s*=\s*(?:"
    r"Buffer\.from\s*\([^;\n]{0,200}?['\"](?:hex|base64)['\"]"
    r"|(?:window\.|globalThis\.)?atob\s*\("
    r"|" + _HEX_DECODER
    + r"|['\"`](?:\\x[0-9A-Fa-f]{2}|\\u00[0-9A-Fa-f]{2}){8}"
    r")"
)
# A code sink and the variable it runs (for the Function constructor, its last argument, the body).
# Like the regexes above, it starts with a literal; the word boundary in front is checked in code.
_JS_CODE_SINK = re.compile(
    r"(?:eval|Function|setTimeout|setInterval|vm\.runIn(?:This|New)Context|vm\.Script)"
    r"\s*\(\s*(?:[^()\n]{0,200},\s*)?([A-Za-z_$][\w$]{0,60})(?:\.toString\(\s*\))?\s*[,)]"
)
_PY_DECODED_VARIABLE = re.compile(
    r"(?m)^[ \t]*([A-Za-z_]\w{0,60})\s*=\s*(?:"
    r"bytes\.fromhex\s*\(|(?:binascii\.)?(?:unhexlify|a2b_hex)\s*\("
    r"|codecs\.decode\s*\([^)\n]{0,200}['\"]hex['\"]|(?:\w+\.)?b64decode\s*\("
    r"|[bru]{0,2}['\"](?:\\x[0-9A-Fa-f]{2}){8}"
    r"|" + _PY_CODEPOINTS
    + r")"
)
# Builtins only: `re.compile(pattern)` is not a sink, so a `.` in front rules a match out (in code).
_PY_CODE_SINK = re.compile(r"(?:exec|eval|compile)\s*\(\s*([A-Za-z_]\w{0,60})\b")
_FLOW_REACH = 4000
# Every sink above contains one of the first tokens, every decoded source one of the second.
_JS_SINK_TOKENS = ("eval", "Function", "setTimeout", "setInterval", "runIn", "Script")
_PY_SINK_TOKENS = ("exec", "eval", "compile")
_JS_SOURCE_TOKENS = ("Buffer.from", "atob", "hex", "Hex", "HEX", "\\x", "\\u00")
_PY_SOURCE_TOKENS = (
    "fromhex", "unhexlify", "a2b_hex", "codecs", "b64decode", "\\x", "chr", "bytes(", "bytearray("
)
_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
_PY_SUFFIXES = (".py", ".pyw")


def _starts_a_word(text: str, start: int, word_chars: str) -> bool:
    """True if nothing that continues an identifier (letters, digits, ``word_chars``) sits right
    before ``start``: `eval(` but not `myeval(`, `Function(` but not `isFunction(`."""
    if not start:
        return True
    before = text[start - 1]
    return not (before.isalnum() or before in word_chars)


def _decoded_then_executed(index: FileIndex) -> list[Evidence]:
    """Evidence for a decoded value kept in a variable and run a few statements later: the
    assignment that decodes it, then the call that executes it. Each file's sinks are indexed by
    the variable they run once, so the cost stays linear in the file."""
    evidence: list[Evidence] = []
    for f in index.select(suffixes=_JS_SUFFIXES + _PY_SUFFIXES):
        text = f.text
        if f.suffix in _PY_SUFFIXES:
            source, sink = _PY_DECODED_VARIABLE, _PY_CODE_SINK
            sinks, sources, before_sink = _PY_SINK_TOKENS, _PY_SOURCE_TOKENS, "_."
        else:
            source, sink = _JS_DECODED_VARIABLE, _JS_CODE_SINK
            sinks, sources, before_sink = _JS_SINK_TOKENS, _JS_SOURCE_TOKENS, "_$"
        # No sink or no decoder in the file: substring checks skip it before any regex runs.
        if not (any(t in text for t in sinks) and any(t in text for t in sources)):
            continue
        decoded = [m for m in source.finditer(text) if _starts_a_word(text, m.start(), "_$")]
        if not decoded:
            continue
        runs: dict[str, list[re.Match[str]]] = {}
        for run in sink.finditer(text):
            if _starts_a_word(text, run.start(), before_sink):
                runs.setdefault(run.group(1), []).append(run)
        starts = {name: [r.start() for r in found] for name, found in runs.items()}
        for m in decoded:
            found = runs.get(m.group(1))
            if not found:
                continue
            k = bisect.bisect_left(starts[m.group(1)], m.end())
            if k == len(found) or found[k].start() >= m.end() + _FLOW_REACH:
                continue
            run = found[k]
            evidence.append(f.evidence_for_span(m.start(), m.end()))
            evidence.append(f.evidence_for_span(run.start(), run.end()))
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                return evidence
    return evidence


# A decode-function name resolved dynamically instead of written as a literal attribute access,
# so the call never shows the ``exec(``/``eval(`` immediately followed by ``b64decode``/``atob``
# shape _DECODE_EXEC looks for. Reported against Claude Code / OpenAI Codex agent skills in
# September 2026: commands are "rewritten into forms that mean the same thing to a computer but
# look harmless to a scanner" (cybersecuritynews.com). Covers both a getattr()/__dict__/vars()
# lookup and the decode-function name itself split across a string concatenation.
_DYNAMIC_DECODE_NAME = (
    r"""['"]b64['"]\s*\+\s*['"]decode['"]"""
    r"""|['"]b64decode['"]"""
    r"""|['"]ato['"]\s*\+\s*['"]b['"]"""
    r"""|['"]atob['"]"""
    r"""|['"]from['"]\s*\+\s*['"]hex['"]"""
    r"""|['"]fromhex['"]"""
)
_DYNAMIC_DECODE_LOOKUP = (
    rf"getattr\s*\(\s*[\w.]+\s*,\s*(?:{_DYNAMIC_DECODE_NAME})\s*\)"
    rf"|(?:\.__dict__|\bvars\([\w.]*\))\s*\[\s*(?:{_DYNAMIC_DECODE_NAME})\s*\]"
)
_DYNAMIC_DECODE_EXEC = alternation(
    rf"exec\s*\(\s*(?:{_DYNAMIC_DECODE_LOOKUP})\s*\(",
    rf"eval\s*\(\s*(?:{_DYNAMIC_DECODE_LOOKUP})\s*\(",
)

# Symmetric decryption feeding a dynamic-code sink in the SAME file: the staged-loader shape of
# the mini "Shai-Hulud" npm compromise (Mend, August 2026), whose loader decrypts its next stage
# with AES-128-GCM and runs the plaintext through `new Function(...)`. _DECODE_EXEC only catches a
# decode call written directly inside exec(/eval(; here the ciphertext is decrypted into a
# variable first, so no single call shows the shape. Decrypting data in order to EXECUTE it (not
# to read, display or write it) keeps the payload opaque to any static reviewer until runtime —
# a strong obfuscated-execution indicator distinct from a decode-and-exec one-liner.
_DECRYPT_CONSTRUCT = re.compile(
    r"\bcreateDecipher(?:iv)?\s*\(|"              # Node: crypto.createDecipheriv(...)
    r"\bsubtle\s*\.\s*decrypt\s*\(|"              # WebCrypto: crypto.subtle.decrypt(...)
    r"\bAES\s*\.\s*new\s*\([^)]*\)\s*\.\s*decrypt\b|"  # PyCryptodome: AES.new(...).decrypt(...)
    r"\bFernet\s*\([^)]*\)\s*\.\s*decrypt\b"      # cryptography.Fernet(...).decrypt(...)
)
# Dynamic-code sinks. `.exec(`/`child_process.exec` are command execution, not a code sink, so
# the method-form and the bare `exec(` token are deliberately excluded (the negative lookbehind
# drops `.eval`); `eval(`/`new Function(` are code sinks in both JS and Python.
_EXEC_SINK = re.compile(
    r"\bnew\s+Function\s*\(|"
    r"\bvm\s*\.\s*(?:runInThisContext|runInContext|runInNewContext|compileFunction)\s*\(|"
    r"\bnew\s+vm\s*\.\s*Script\s*\(|"
    r"(?<![\w.])eval\s*\("
)
# Decode-and-run-as-a-subprocess (JavaScript/TypeScript): the loader decodes an embedded blob
# (gzip/brotli/base64/hex) and launches it as code through a child process -- `spawn(execPath,
# ["-e", stage])`, `execFile(..., ["--eval", ...])`, a `node -e` / `python -c`. _DECODE_EXEC and
# the decoded-variable flow only recognize in-process sinks (eval / new Function / vm); a spawned
# interpreter running the decoded text is the same decode-and-execute with an out-of-process sink,
# the shape of an import-time detached worker in a compromised npm package. Both halves must be
# code (not a comment/string literal) and the decoded value must reach the launch: a test helper
# that builds base64 test data shares a file with a spawn of its own driver script without either
# touching the other.
_JS_DECODE_SOURCE = re.compile(
    r"\b(?:gunzipSync|gunzip|inflateSync|inflate|brotliDecompressSync|unzipSync)\s*\(|"
    r"\bBuffer\.from\s*\(|"
    r"(?:window\.|globalThis\.)?\batob\s*\("
)
# `Buffer.from(x, "base64")` decodes. `Buffer.from(x).toString("base64")` encodes, so the encoding
# must be the last argument of the Buffer.from call itself.
_JS_DECODE_ENCODING = re.compile(r"['\"](?:base64(?:url)?|hex)['\"]\s*,?\s*$")
# A launch of a code INTERPRETER (node / python / powershell, or this node binary itself) with an
# inline-code flag -- what makes the child process a code sink rather than an ordinary command.
# The interpreter is required: `-c`, `-e` and `-p` are also ordinary flags of everyday commands
# (`git -c key=val`, `grep -e pat`, `mkdir -p dir`, `sh -c cmd`), and a CLI that decodes a base64
# token and runs git is not a dropper. Shell pipelines of decoded text are ST-OBF-DECODE-EXEC-SH.
_JS_INTERPRETER = (
    r"(?:process\.execPath|process\.argv\[0\]|"
    r"['\"`](?:[\w.:/\\-]*[/\\])?(?:node|nodejs|python[\d.]*|pwsh|powershell)(?:\.exe)?['\"`])"
)
_JS_SPAWN_EVAL = re.compile(
    r"\b(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*" + _JS_INTERPRETER
    + r"[^;]{0,200}?['\"](?:-e|--eval|-c|-p|--print|-Command|-EncodedCommand|-enc)['\"]"
    # The one-string form: exec(`node -e ${stage}`), execSync("python -c " + stage).
    + r"|\b(?:exec|execSync)\s*\(\s*['\"`](?:[\w.:/\\-]*[/\\])?"
    r"(?:node|nodejs|python[\d.]*|pwsh|powershell)(?:\.exe)?\s+"
    r"(?:-e|--eval|-c|-p|--print|-Command|-EncodedCommand|-enc)\b"
)
# How a decoded value travels to a launch: an assignment or `+=`, also to a member (`this.stage`)
# and with a TypeScript annotation.
_JS_ASSIGNMENT = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)"
    r"(?:\s*:\s*[\w$.<>\[\]| ]{1,40}?)?\s*\+?=(?![=>])"
)
# A named function: its parameter list opens at the end of the match.
_JS_FUNCTION = re.compile(
    r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(|"
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\("
)
# After the parameter list: a return type, then a `{` body or an arrow.
_JS_FUNCTION_BODY = re.compile(r"\s*(?::[^={\n]{1,60})?\s*(=>)?\s*(\{)?")
_JS_NAME = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*")
_JS_QUOTED = re.compile(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"")
_JS_TEMPLATE = re.compile(r"`[^`]{0,2000}`")
_JS_TEMPLATE_VALUE = re.compile(r"\$\{([^}]*)\}")
_JS_WRITE_FILE = re.compile(r"\bwriteFile(?:Sync)?\s*\(")
_JS_LAUNCH = re.compile(r"\b(?:spawn|spawnSync|execFile|execFileSync|exec|execSync|fork)\s*\(")
# A decoded file is run when it is the program, or the script an interpreter is given (flags may
# come first). A fixed script that gets it as input (`spawn("python3", ["convert.py", tmp])`) does
# not run it.
_JS_RUN_FILE_PREFIX = (
    r"(?:process\.execPath|['\"`](?:[\w.:/\\-]*[/\\])?"
    r"(?:node|nodejs|python[\d.]*|pwsh|powershell|sh|bash|zsh|cmd)(?:\.exe)?\b)?"
    r"[\s\"'`,\[+]*(?:-[\w-]+[\s\"'`,+]*)*(?:\$\{)?"
)
# A decompression (not a base64/hex decode) whose input is a file read from disk right there.
_JS_DECOMPRESS = re.compile(
    r"(?:gunzipSync|gunzip|inflateSync|inflate|brotliDecompressSync|unzipSync)"
)
_JS_READ_FILE_ARG = re.compile(r"\s*(?:await\s+)?(?:[\w$]+\.)*readFile(?:Sync)?\s*\(")
_DECODE_SPAWN_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
_DECRYPT_EXEC_SUFFIXES = (".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
# Matches looked at per file for one in code; past this a file of comments is not read further.
_MAX_CODE_TRIES = 200


# Names followed from the decodes of one file, and the uses of each one looked at: enough for a
# loader, and a bound on what a large bundle can cost.
_MAX_FLOW_NAMES = 16
_MAX_NAME_USES = 64


def _matches_in_code(f: IndexedFile, pattern: re.Pattern[str]) -> Iterator[re.Match[str]]:
    """The matches of ``pattern`` that are code: not in a comment or a string literal."""
    for k, m in enumerate(pattern.finditer(f.text)):
        if k >= _MAX_CODE_TRIES:
            return
        at = m.start()
        if not (f.in_comment(at) or f.in_string(at) or f.in_c_comment(at) or f.in_c_string(at)):
            yield m


def _first_in_code(f: IndexedFile, pattern: re.Pattern[str]) -> re.Match[str] | None:
    """The first match of ``pattern`` that is code: not in a comment or a string literal."""
    return next(_matches_in_code(f, pattern), None)


def _balanced_end(text: str, start: int, *, statement: bool = False) -> int:
    """Where the bracket opened just before ``start`` closes, or with ``statement`` where the
    statement starting at ``start`` ends. Skips quoted strings; a template literal stays readable,
    since its ``${...}`` holds code. Gives up ``_FLOW_REACH`` characters on."""
    stop = min(len(text), start + _FLOW_REACH)
    floor = 0 if statement else 1
    depth = floor
    quote = ""
    i = start
    while i < stop:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote or ch == "\n":
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < floor:
                return i
        elif statement and depth == 0 and (
            ch == ";" or (ch == "\n" and not _statement_continues(text, i))
        ):
            return i
        i += 1
    return stop


def _statement_continues(text: str, newline: int) -> bool:
    """True if the statement goes on past this line: `zlib` then `.gunzipSync(x)`, or `x =`."""
    before = text[max(0, newline - 80) : newline].rstrip()
    after = text[newline + 1 : newline + 81].lstrip()
    return before[-1:] in tuple("=+,(&|?:") or after[:1] in tuple(".?:+|&,")


def _expression_names(code: str) -> set[str]:
    """The names an expression reads, each dotted name with its prefixes (``a.b``, ``a``).

    Strings hold no names: the ``e`` of a ``"-e"`` flag is not a variable called ``e``. Of a
    template literal only the ``${...}`` values count.
    """
    code = _JS_QUOTED.sub(" ", code)
    code = _JS_TEMPLATE.sub(lambda m: " ".join(_JS_TEMPLATE_VALUE.findall(m.group())), code)
    names: set[str] = set()
    for m in _JS_NAME.finditer(code):
        parts = m.group().split(".")
        names.update(".".join(parts[: k + 1]) for k in range(len(parts)))
    return names


@dataclass
class _DecodeFlow:
    """Where the decoded values of one file go. ``names`` maps a name that holds one to the offset
    from which it does (-1 for a function, which is hoisted) and the span of its decode."""

    text: str
    decodes: list[tuple[int, int]]
    names: dict[str, tuple[int, tuple[int, int]]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.assignments = list(_JS_ASSIGNMENT.finditer(self.text))
        self.functions = list(_JS_FUNCTION.finditer(self.text))
        self.decode_starts = [start for start, _ in self.decodes]
        self.assignment_starts = [m.start() for m in self.assignments]
        self.function_starts = [m.start() for m in self.functions]
        self.statement_ends: dict[int, int] = {}

    def _statement_end(self, assignment: re.Match[str]) -> int:
        at = assignment.start()
        if at not in self.statement_ends:
            self.statement_ends[at] = _balanced_end(self.text, assignment.end(), statement=True)
        return self.statement_ends[at]

    def _function_at(self, offset: int) -> tuple[str, int, int] | None:
        """The named function whose body holds ``offset``: its name and parameter list span."""
        k = bisect.bisect_right(self.function_starts, offset) - 1
        if k < 0:
            return None
        head = self.functions[k]
        close = _balanced_end(self.text, head.end())
        body = _JS_FUNCTION_BODY.match(self.text, close + 1)
        if body is None:
            return None
        if body.group(2):
            start, end = body.end(2), _balanced_end(self.text, body.end(2))
        elif body.group(1):
            start, end = body.end(), _balanced_end(self.text, body.end(), statement=True)
        else:
            return None
        if not start <= offset < end:
            return None
        return head.group(1) or head.group(2), head.end(), close

    def _holder(self, offset: int) -> tuple[str, int] | None:
        """The name the value at ``offset`` lands in, and the offset it holds it from."""
        k = bisect.bisect_right(self.assignment_starts, offset) - 1
        if k >= 0:
            assignment = self.assignments[k]
            if assignment.end() <= offset:
                end = self._statement_end(assignment)
                if offset < end:
                    return assignment.group(1), end
        # `function decode(s) { return atob(s); }`: the function's name now yields decoded text.
        returned = self.text.rfind("return", max(0, offset - 200), offset)
        if returned >= 0 and ";" not in self.text[returned:offset]:
            function = self._function_at(offset)
            if function is not None:
                return function[0], -1
        return None

    def follow(self) -> None:
        """Fill ``names`` from every decode, then from every use of a name that holds one."""
        queue = [(start, (start, end)) for start, end in self.decodes]
        while queue and len(self.names) < _MAX_FLOW_NAMES:
            offset, origin = queue.pop()
            held = self._holder(offset)
            if held is None or held[0] in self.names:
                continue
            name, since = held
            self.names[name] = (since, origin)
            uses = re.finditer(rf"(?<![\w$.]){re.escape(name)}(?![\w$])", self.text)
            for use in islice(uses, _MAX_NAME_USES):
                if use.start() > since:
                    queue.append((use.start(), origin))

    def decoded_in(self, start: int, end: int, before: int) -> tuple[int, int] | None:
        """The decode behind a value read in ``text[start:end]`` by code at offset ``before``."""
        k = bisect.bisect_left(self.decode_starts, start)
        if k < len(self.decodes) and self.decode_starts[k] < end:
            return self.decodes[k]
        for name in _expression_names(self.text[start:end]):
            found = self.names.get(name)
            if found is not None and found[0] < before:
                return found[1]
        return None

    def reaches_launch(self, launch: int, args: int) -> tuple[int, int] | None:
        """The decode whose value is in the arguments of this launch (they start at ``args``),
        directly or through a parameter of the function around it: `function run(code) {
        spawn(..., code) }` called as `run(atob(blob))`."""
        text = self.text
        close = _balanced_end(text, args)
        found = self.decoded_in(args, close, launch)
        if found is not None:
            return found
        function = self._function_at(launch)
        if function is None:
            return None
        name, params, params_close = function
        if not _expression_names(text[params:params_close]) & _expression_names(text[args:close]):
            return None
        calls = re.finditer(rf"(?<![\w$.]){re.escape(name)}\s*\(", text)
        for call in islice(calls, _MAX_NAME_USES):
            if call.end() != params:  # the declaration itself
                found = self.decoded_in(call.end(), _balanced_end(text, call.end()), call.start())
                if found is not None:
                    return found
        return None

    def runs_written_file(self) -> tuple[tuple[int, int], tuple[int, int]] | None:
        """A decoded value written to a file that is run later: the decode, then the launch."""
        text = self.text
        written: dict[str, tuple[int, tuple[int, int]]] = {}
        for call in _JS_WRITE_FILE.finditer(text):
            close = _balanced_end(text, call.end())
            target, comma, _ = text[call.end() : close].partition(",")
            content = call.end() + len(target) + len(comma)
            origin = self.decoded_in(content, close, call.start()) if comma else None
            if origin is not None:
                written[target.strip().strip("'\"`")] = (call.start(), origin)
        for launch in _JS_LAUNCH.finditer(text) if written else ():
            args = text[launch.end() : _balanced_end(text, launch.end())]
            for path, (at, origin) in written.items():
                run = _JS_RUN_FILE_PREFIX + re.escape(path) + r"(?![\w$.])"
                if launch.start() > at and re.match(run, args):
                    if self._unpacks_shipped_program(origin, args, path):
                        continue
                    return origin, (launch.start(), launch.end())
        return None

    def _unpacks_shipped_program(self, origin: tuple[int, int], args: str, path: str) -> bool:
        """True if the decode decompresses a file the package ships (`brotliDecompressSync(
        fs.readFileSync(...))`) and the written file is then run as the program itself.

        A launcher unpacking its own compressed native binary hides nothing a binary shipped
        uncompressed would not, and this rule does not read binaries either way. A blob embedded in
        the source, a base64 or hex decode, or a decompressed file handed to an interpreter (a
        script that would otherwise be read in the clear) still counts.
        """
        decoder = self.text[origin[0] : origin[1]]
        if not _JS_DECOMPRESS.match(decoder):
            return False
        if not _JS_READ_FILE_ARG.match(self.text, origin[1]):
            return False
        return re.match(rf"[\s\"'`,\[+]*{re.escape(path)}(?![\w$.])", args) is not None


def _in_template_value(text: str, at: int) -> bool:
    """True if ``at`` sits in the ``${...}`` of a template literal: a string, but code."""
    opened = text.rfind("${", max(0, at - 200), at)
    return opened >= 0 and "}" not in text[opened:at]


def _js_decodes(f: IndexedFile) -> list[tuple[int, int]]:
    """The spans of the decode calls in ``f`` that are code."""
    decodes = []
    for m in islice(_JS_DECODE_SOURCE.finditer(f.text), _MAX_CODE_TRIES):
        at = m.start()
        if (
            f.in_comment(at) or f.in_c_comment(at) or f.in_string(at)
            or (f.in_c_string(at) and not _in_template_value(f.text, at))
        ):
            continue
        if m.group().startswith("Buffer"):
            args = f.text[m.end() : _balanced_end(f.text, m.end())]
            if not _JS_DECODE_ENCODING.search(args):
                continue
        decodes.append((m.start(), m.end()))
    return decodes


def _decoded_reaches_spawn(f: IndexedFile) -> tuple[tuple[int, int], tuple[int, int]] | None:
    """The decode and the launch of one file when the decoded value gets there, decode first: in
    the launch's own arguments, through variables assigned from the decode, through a function that
    returns it or takes it as an argument, or through a file it was written to."""
    decodes = _js_decodes(f)
    if not decodes:
        return None
    sinks = list(_matches_in_code(f, _JS_SPAWN_EVAL))
    # Most bundles that decode something launch nothing: they stop here, before any flow is built.
    if not sinks and "writeFile" not in f.text:
        return None
    flow = _DecodeFlow(f.text, decodes)
    flow.follow()
    for sink in sinks:
        origin = flow.reaches_launch(sink.start(), f.text.index("(", sink.start()) + 1)
        if origin is not None:
            return origin, (sink.start(), sink.end())
    return flow.runs_written_file()


def _decrypted_reaches_sink(f: IndexedFile) -> tuple[tuple[int, int], tuple[int, int]] | None:
    """The decryption and the dynamic-code sink of one file when they belong together.

    Python files are read as a pair, as they are not bundled. In JavaScript the decrypted value
    must get to the sink, or the two must sit within ``_FLOW_REACH`` of each other: that keeps a
    loader whose value leaves through a stream callback, which the name flow does not follow.
    """
    decrypts = [m.span() for m in _matches_in_code(f, _DECRYPT_CONSTRUCT)]
    sinks = list(_matches_in_code(f, _EXEC_SINK)) if decrypts else []
    if not sinks:
        return None
    if f.suffix in _PY_SUFFIXES:
        return decrypts[0], sinks[0].span()
    for sink in sinks:
        for decrypt in decrypts:
            if abs(sink.start() - decrypt[0]) < _FLOW_REACH:
                return decrypt, sink.span()
    flow = _DecodeFlow(f.text, decrypts)
    flow.follow()
    for sink in sinks:
        origin = flow.reaches_launch(sink.start(), sink.end())
        if origin is not None:
            return origin, sink.span()
    return None


_BASE64_BLOB =re.compile(r"[A-Za-z0-9+/]{160,}={0,2}")
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){10,}")
_MINIFIED_LINE_CHARS = 2000

# Build artifacts where a single very long line is the *expected* format, not an
# obfuscation signal: source maps (single-line JSON), pre-minified bundles, TypeScript
# declaration files, and lockfiles. Other rules still scan these files normally — only
# the minified-line note skips them.
_EXPECTED_LONG_LINE_SUFFIXES = (
    ".map", ".min.js", ".min.mjs", ".min.cjs", ".min.css",
    ".d.ts", ".d.mts", ".d.cts",
)
_EXPECTED_LONG_LINE_NAMES = {"package-lock.json"}
_MINIFIED_EXAMPLES_SHOWN = 8


def _is_expected_long_line_file(relpath: str) -> bool:
    name = relpath.rsplit("/", 1)[-1].lower()
    return name in _EXPECTED_LONG_LINE_NAMES or name.endswith(_EXPECTED_LONG_LINE_SUFFIXES)


class ObfuscationScanner(Scanner):
    name = "obfuscation"
    rules = [
        RuleSpec(
            id="ST-OBF-DECODE-EXEC",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Decode-and-execute (obfuscated execution)",
            description=(
                "A pattern that decodes data and executes it was detected "
                "(e.g. eval(atob(...)), new Function(Buffer.from(x, 'hex').toString()) or "
                "exec(b64decode(...)), directly or through a variable that holds the decoded text)."
            ),
            recommendation=(
                "Decoding and executing data hides behavior from review. Decode the payload "
                "manually and inspect what it does before trusting this component."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            # A real decode-and-exec is code; the same text inside a string or comment -- in ANY
            # language -- is a pattern literal, a doc example or another scanner's message, not
            # behavior. Unlike a credential path, `eval(atob(...))` inside a string literal can
            # never execute, so the C-family string demotion (`_all`) is safe here: a `demos.js`
            # carrying `description: 'eval(atob("…"))'` and a security auditor listing the pattern
            # in a message both scored as obfuscated execution without it.
            code_context="strings_and_comments_all",
            pattern=_DECODE_EXEC,
        ),
        RuleSpec(
            id="ST-OBF-DYNAMIC-DECODE-EXEC",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Dynamically-resolved decode-and-execute (scanner-evasion variant)",
            description=(
                "A decode function (b64decode/atob/fromhex) is resolved through getattr(), "
                "__dict__ or vars() instead of a literal attribute, and the result is "
                "immediately executed. This evades a plain decode-exec scanner, which looks for "
                "the function name written right after exec(/eval(."
            ),
            recommendation=(
                "Decode the payload manually and inspect what it does before trusting this "
                "component. Resolving a decode function dynamically has no honest purpose here; "
                "it exists to dodge static scanners."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            # Same reasoning as ST-OBF-DECODE-EXEC: a match inside a string/comment is a pattern
            # literal or doc example, never live behavior.
            code_context="strings_and_comments_all",
            pattern=_DYNAMIC_DECODE_EXEC,
        ),
        RuleSpec(
            id="ST-OBF-DECRYPT-EXEC",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Decrypt-and-execute (encrypted payload run at runtime)",
            description=(
                "A file decrypts data with a symmetric cipher (e.g. AES via "
                "crypto.createDecipheriv / PyCryptodome / Fernet) and, in the same file, feeds "
                "code to a dynamic-execution sink (new Function / eval / vm.runInThisContext). "
                "Decrypting a payload to run it keeps the real behavior opaque to static "
                "review until runtime."
            ),
            recommendation=(
                "Decrypt the payload offline and inspect what it does before trusting this "
                "component. Running encrypted code at runtime has no honest purpose that cannot "
                "be met by shipping the code in the clear."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            # A match inside a string/comment is a pattern literal or doc example, never live
            # behavior — same reasoning as ST-OBF-DECODE-EXEC.
            code_context="strings_and_comments_all",
        ),
        RuleSpec(
            id="ST-OBF-DECODE-SPAWN",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Decode-and-spawn (obfuscated payload run as a subprocess)",
            description=(
                "A file decodes an embedded blob (gzip/brotli/base64/hex) and passes the result "
                "to a child process with an inline-code flag (e.g. spawn(execPath, ['-e', stage]) "
                "or node -e / python -c), or writes it to a file it then runs. Running decoded "
                "text as a spawned interpreter hides behavior from review exactly like "
                "eval(atob(...)), with the execution moved out of process."
            ),
            recommendation=(
                "Decode the payload offline and inspect what it does before trusting this "
                "component. Shipping code only as a decoded blob run through a spawned "
                "interpreter has no honest purpose that shipping it in the clear cannot meet."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            # A match inside a string/comment is a pattern literal or doc example, never live
            # behavior — same reasoning as ST-OBF-DECODE-EXEC.
            code_context="strings_and_comments_all",
        ),
        # The following are listed for `rules list`; they emit needs_review only.
        RuleSpec(
            id="ST-OBF-BASE64-BLOB",
            category=CATEGORY,
            severity=Severity.LOW,
            title="Large base64 blob",
            description="A large base64-looking blob was detected.",
            recommendation="Decode and inspect the blob to confirm it is benign data.",
            capability=None,
        ),
        RuleSpec(
            id="ST-OBF-HEX",
            category=CATEGORY,
            severity=Severity.LOW,
            title="Excessive hex escaping",
            description="A run of many hex escape sequences was detected.",
            recommendation="Decode the escaped sequence to confirm intent.",
            capability=None,
        ),
        RuleSpec(
            id="ST-OBF-MINIFIED",
            category=CATEGORY,
            severity=Severity.LOW,
            title="Heavily minified / very long line",
            description="A file contains an extremely long line (possible minification).",
            recommendation="Review whether the file should be minified in source form.",
            capability=None,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        scored_ids = {"ST-OBF-DECODE-EXEC", "ST-OBF-DYNAMIC-DECODE-EXEC"}
        findings = findings_from_rules(index, [r for r in self.rules if r.id in scored_ids])
        flow = _decoded_then_executed(index)
        if flow:
            rule = self.rules[0]
            direct = next((f for f in findings if f.id == rule.id), None)
            seen: set[tuple[str, int, int]] = set()
            evidence: list[Evidence] = []
            for ev in [*(direct.evidence if direct else ()), *flow]:
                if (ev.file, ev.line_start, ev.line_end) not in seen:
                    seen.add((ev.file, ev.line_start, ev.line_end))
                    evidence.append(ev)
            findings = [f for f in findings if f.id != rule.id]
            findings.insert(0, _finding_from_rule(rule, evidence[:MAX_EVIDENCE_SCANNED]))

        decode_spawn = self._decode_spawn(index)
        if decode_spawn:
            rule = next(r for r in self.rules if r.id == "ST-OBF-DECODE-SPAWN")
            findings.append(
                Finding(
                    id=rule.id, severity=rule.severity, category=rule.category,
                    title=rule.title, description=rule.description,
                    evidence=decode_spawn[:MAX_EVIDENCE_SCANNED],
                    recommendation=rule.recommendation,
                    threat_class=rule.threat_class,
                )
            )

        decrypt_exec = self._decrypt_exec(index)
        if decrypt_exec:
            rule = next(r for r in self.rules if r.id == "ST-OBF-DECRYPT-EXEC")
            findings.append(
                Finding(
                    id=rule.id, severity=rule.severity, category=rule.category,
                    title=rule.title, description=rule.description,
                    evidence=decrypt_exec[:MAX_EVIDENCE_SCANNED],
                    recommendation=rule.recommendation,
                    threat_class=rule.threat_class,
                )
            )

        needs_review: list[NeedsReview] = []
        self._heuristic(index, _BASE64_BLOB, "ST-OBF-BASE64-BLOB",
                        "Large base64 blob", "large base64-looking blob(s)", needs_review)
        self._heuristic(index, _HEX_ESCAPES, "ST-OBF-HEX",
                        "Excessive hex escaping", "run(s) of hex escape sequences", needs_review)
        self._minified(index, needs_review)
        return ScanResult(findings=findings, needs_review=needs_review)

    @staticmethod
    def _decode_spawn(index: FileIndex) -> list[Evidence]:
        """Evidence when one JS/TS file decodes a blob and spawns an interpreter on it.

        Both halves must be code (a decode a comment mentions decodes nothing; a spawn in a string
        literal runs nothing) and the decoded value must reach the spawn: decoding and spawning
        that merely share a file, a test helper or a polyfill next to a build script, are no
        decode-and-execute.
        """
        evidence: list[Evidence] = []
        for f in index.select(suffixes=_DECODE_SPAWN_SUFFIXES):
            link = _decoded_reaches_spawn(f)
            if link is None:
                continue
            for start, end in link:
                evidence.append(f.evidence_for_span(start, end))
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
        return evidence

    @staticmethod
    def _decrypt_exec(index: FileIndex) -> list[Evidence]:
        """Evidence when one code file both decrypts data and runs code through a dynamic sink.

        Requires BOTH signals in the same file (the staged loader decrypts, then executes the
        plaintext). In JavaScript the two must also be linked, since a bundle holds a schema
        validator's `new Function` and the app's own decrypt helper thousands of lines apart.
        Engine-level string/comment demotion (code_context) drops matches that are only pattern
        literals or doc examples, so a security tool listing these patterns in a message is not
        flagged.
        """
        evidence: list[Evidence] = []
        for f in index.select(suffixes=_DECRYPT_EXEC_SUFFIXES):
            # Each half must be code: a decryption a comment mentions decrypts nothing, so it does
            # not pair with an unrelated `eval` elsewhere in the file.
            pair = _decrypted_reaches_sink(f)
            if pair is None:
                continue
            for start, end in pair:
                evidence.append(f.evidence_for_span(start, end))
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
        return evidence

    def _heuristic(self, index, pattern, _rule_id, title, what, needs_review) -> None:
        """One aggregated note per heuristic (it used to be one per line, up to 75)."""
        places: list[tuple[str, int | None]] = []
        seen: set[tuple[str, int]] = set()
        capped = False
        for _f, _m, ev in index.search(pattern):
            key = (ev.file, ev.line_start)
            if key in seen:
                continue
            if len(places) >= MAX_EVIDENCE_SCANNED:
                capped = True
                break
            seen.add(key)
            places.append(key)
        if places:
            needs_review.append(aggregated_review(
                category=CATEGORY,
                title=title,
                places=places,
                what=what,
                advice="Malicious intent cannot be confirmed without decoding them.",
                capped=capped,
            ))

    def _minified(self, index: FileIndex, needs_review: list[NeedsReview]) -> None:
        """One aggregated note per report (not per file), skipping expected formats.

        Source maps / .d.ts / lockfiles are long-line *by design*; flagging each one
        floods a legitimate SDK's report with dozens of identical rows. Files that
        remain are summarized in a single entry listing a few examples.
        """
        minified: list[str] = []
        for f in index.files:
            if _is_expected_long_line_file(f.relpath):
                continue
            if any(len(line) > _MINIFIED_LINE_CHARS for line in f.text.splitlines()):
                minified.append(f.relpath)
        if not minified:
            return
        examples = ", ".join(minified[:_MINIFIED_EXAMPLES_SHOWN])
        more = len(minified) - _MINIFIED_EXAMPLES_SHOWN
        if more > 0:
            examples += f", and {more} more"
        needs_review.append(
            NeedsReview(
                category=CATEGORY,
                title=f"Heavily minified files ({len(minified)})",
                reason=(
                    f"{len(minified)} file(s) contain lines over {_MINIFIED_LINE_CHARS} "
                    f"characters (possible minification); not analyzable line-by-line: "
                    f"{examples}."
                ),
                file=minified[0],
            )
        )
