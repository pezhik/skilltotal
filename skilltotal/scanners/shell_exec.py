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

NODE_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

CATEGORY = "shell_execution"

_CP = r"['\"](?:node:)?child_process['\"]"
_SPAWN_LIBS = r"['\"](?:execa|zx|shelljs|cross-spawn|spawn-rx|tinyexec|node-pty)['\"]"
_IDENT = r"[A-Za-z_$][\w$]*"
# Not preceded by an identifier character or a dot: a bare call, never a method on something else.
_BARE = r"(?<![\w$.])"
_CALLS = r"(?:exec|execSync|spawn|spawnSync)"

# Evidence that holds in any file, whatever it imports.
_ANYWHERE = alternation(
    r"child_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(",
    rf"require\(\s*{_CP}\s*\)",
    rf"from\s+{_CP}",
    rf"require\(\s*{_SPAWN_LIBS}\s*\)",
    rf"from\s+{_SPAWN_LIBS}",
    r"\bBun\.spawn(?:Sync)?\s*\(",
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
    suffixes=NODE_SUFFIXES,
    # Metadata only (rules list / docs): the effective pattern is built per file.
    pattern=alternation(
        *(r"child_process\.exec(?:Sync)?\s*\(" + tail for tail in _INJECTION_TAILS),
        flags=re.MULTILINE,
    ),
)


class ShellExecScanner(Scanner):
    name = "shell_exec"
    rules = [SHELL_RULE, CMDI_RULE]

    def scan(self, index: FileIndex) -> ScanResult:
        shell: list[Evidence] = []
        cmdi: list[Evidence] = []
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
        findings = []
        if shell:
            findings.append(_finding_from_rule(SHELL_RULE, shell))
        if cmdi:
            findings.append(_finding_from_rule(CMDI_RULE, cmdi))
        return ScanResult(findings=findings)


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
