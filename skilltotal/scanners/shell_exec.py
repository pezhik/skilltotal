"""Shell / command execution detection for Node.js.

Python shell execution is handled by the AST scanner (:mod:`skilltotal.scanners.python_ast`).

A bare ``exec(`` is not evidence of anything on its own: ``RegExp.prototype.exec``,
better-sqlite3's ``db.exec`` and mongoose's ``query.exec()`` are all spelled the same way, and
matching the name alone flagged ordinary regex code as shell execution. A call site therefore
counts only where it can be tied to ``child_process``:

* ``child_process.exec(...)`` spelled out, anywhere;
* in a file that imports ``child_process``, a bare ``exec(...)`` / ``spawn(...)`` (the destructured
  import) or a call through the alias that file bound (``const cp = require("child_process")`` then
  ``cp.exec(...)``).

Importing ``child_process`` or a process-spawning library is itself evidence, and ``Bun.spawn`` is
matched explicitly; the member-call exclusion above would otherwise have dropped it.
"""

from __future__ import annotations

import re

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
from skilltotal.scanners.shell_script import REMOTE_EXEC

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


def _call_prefixes(f: IndexedFile) -> list[str]:
    """Where an exec/spawn call counts in this file (regex prefixes before the call name)."""
    prefixes = [r"child_process\."]
    if _IMPORTS_CP.search(f.text):
        prefixes.append(_BARE)
        aliases = _aliases(f.text)
        if aliases:
            prefixes.append(_BARE + "(?:" + "|".join(re.escape(a) for a in aliases) + r")\.")
    return prefixes


def exec_call_pattern(f: IndexedFile) -> re.Pattern[str]:
    """The process-running call sites ST-SHELL-NODE counts in this file (imports left out)."""
    prefixes = "|".join(f"(?:{p})" for p in _call_prefixes(f))
    return alternation(rf"(?:{prefixes}){_CALLS}\s*\(", *_ANYWHERE_CALLS, flags=re.MULTILINE)


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
        "`execSync(\"curl ... | bash\")`. The component runs whatever the host serves at that "
        "moment, which no review of the component can see."
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
            prefixes = "|".join(f"(?:{p})" for p in _call_prefixes(f))
            calls = re.compile(rf"(?:{prefixes}){_CALLS}\s*\(", re.MULTILINE)
            injections = re.compile(
                "|".join(rf"(?:(?:{prefixes})exec(?:Sync)?\s*\({t})" for t in _INJECTION_TAILS),
                re.MULTILINE,
            )
            _collect(f, (_ANYWHERE, calls), shell, seen_shell)
            _collect(f, (injections,), cmdi, seen_cmdi)
            if len(pipe) < MAX_EVIDENCE_SCANNED and ("curl" in f.text or "wget" in f.text):
                pipe_calls = re.compile(rf"(?:{prefixes}){_PIPE_CALLS}\s*\(", re.MULTILINE)
                for m in pipe_calls.finditer(f.text):
                    end = _call_end(f.text, m.end())
                    command = " ".join(_string_literals(f.text, m.end(), end))
                    if REMOTE_EXEC.search(command):
                        pipe.append(f.evidence_for_span(m.start(), end))
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


def _collect(
    f: IndexedFile,
    patterns: tuple[re.Pattern[str], ...],
    out: list[Evidence],
    seen: set[tuple[str, int, int]],
) -> None:
    """Add this file's matches in line order, the order a single alternation used to yield."""
    found: list[Evidence] = []
    for pattern in patterns:
        for _m, ev in f.finditer(pattern):
            key = (ev.file, ev.line_start, ev.line_end)
            if key not in seen:
                seen.add(key)
                found.append(ev)
    found.sort(key=lambda ev: (ev.line_start, ev.line_end))
    out.extend(found[: max(0, MAX_EVIDENCE_SCANNED - len(out))])
