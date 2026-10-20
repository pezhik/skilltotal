"""A Python file named after a standard-library module that runs code when it is imported.

An attacker lures an agent into writing its own decoder and running it inside a folder that also
ships a ``.py`` file whose name collides with a standard-library module -- ``struct.py``,
``json.py``, ``base64.py`` -- next to the data the agent is told to process (embracethered,
"Breaking Claude Code", Aug/Sep 2026). Python searches the script's own directory first, so when
the agent's decoder imports ``base64`` (which imports ``struct``), it loads the planted module,
which runs its code at import time and then re-exports the real functionality so the output still
looks correct. An auto-mode classifier that reviewed only the harmless decoder sees nothing.

The precise, low-false-positive signal is the collision PLUS import-time side effects: a module
whose name shadows a stdlib module and that runs a shell / network / dynamic-exec call, or
rebinds ``sys.modules``, at module top level. A legitimately-named local helper that only defines
functions and constants (no top-level dangerous call) is left clean, even if its name happens to
match a stdlib module.

Detection parses the AST and inspects only top-level statements; nothing is executed.
"""

from __future__ import annotations

import ast
import sys

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
)

R_STDLIB_SHADOW = "ST-PY-STDLIB-SHADOW"

# Top-level standard-library module names (3.10+ provides this set directly).
_STDLIB = frozenset(getattr(sys, "stdlib_module_names", frozenset()))

# Callables whose top-level invocation is an unambiguously dangerous import-time side effect.
# Deliberately narrow: generic names (compile, run, call, get, post, connect, request) match
# benign code -- re.compile, a .run() method -- so they are excluded. The builtins exec/eval and
# a concrete shell/network/dynamic-import call are what mark import-time code execution.
_DANGER_NAMES = frozenset({"exec", "eval", "__import__"})  # resolved as a bare builtin call
_DANGER_ATTRS = frozenset({
    "system", "popen", "Popen", "check_call", "check_output", "import_module", "urlopen",
})
_PY_SUFFIXES = (".py", ".pyw")


def _module_name(relpath: str) -> str:
    return relpath.replace("\\", "/").rsplit("/", 1)[-1].rsplit(".", 1)[0]


def _is_danger_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr in _DANGER_ATTRS
    if isinstance(func, ast.Name):
        return func.id in _DANGER_NAMES
    return False


def _rebinds_sys_modules(node: ast.AST) -> bool:
    """A statement that writes to or reads ``sys.modules`` -- the re-export tell of a shadow."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Attribute):
            if sub.value.attr == "modules" and isinstance(sub.value.value, ast.Name) \
                    and sub.value.value.id == "sys":
                return True
    return False


def _toplevel_danger(tree: ast.Module) -> ast.AST | None:
    """The first top-level statement that runs a dangerous call (or rebinds ``sys.modules``).

    Descends through control-flow statements (``if``/``for``/``with``/``try``) but never into a
    function or class body, so only code that runs at import time counts.
    """
    stack: list[ast.AST] = list(tree.body)
    while stack:
        stmt = stack.pop(0)
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Call) and _is_danger_call(sub):
                return stmt
        if _rebinds_sys_modules(stmt):
            return stmt
    return None


class StdlibShadowScanner(Scanner):
    name = "stdlib_shadow"
    rules = [
        RuleSpec(
            id=R_STDLIB_SHADOW,
            category="obfuscation",
            severity=Severity.HIGH,
            title="Python module shadows a standard-library module and runs code on import",
            description=(
                "A Python file is named after a standard-library module (e.g. struct.py, "
                "json.py, base64.py) and executes a shell, network or dynamic-exec call - or "
                "rebinds sys.modules to re-export the real module - at import time. Python "
                "searches a script's own directory first, so a script run from this folder that "
                "imports that stdlib module loads this file instead and runs its code, while the "
                "re-export keeps the output looking correct. A module-name collision alone is a "
                "mistake; the collision plus import-time execution is the shadowing attack."
            ),
            recommendation=(
                "Do not run scripts inside this folder. Rename the colliding module and inspect "
                "what it runs at import; a legitimate helper does not need to shadow a "
                "standard-library name or execute on import."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        for f in index.select(suffixes=_PY_SUFFIXES):
            name = _module_name(f.relpath)
            if name not in _STDLIB or name == "":
                continue
            try:
                tree = ast.parse(f.text)
            except (SyntaxError, ValueError):
                continue
            stmt = _toplevel_danger(tree)
            if stmt is not None:
                evidence.append(_node_evidence(f, stmt))
                if len(evidence) >= MAX_EVIDENCE_SCANNED:
                    break
        if evidence:
            return ScanResult(findings=[_finding_from_rule(self.rules[0], evidence)])
        return ScanResult()


def _node_evidence(f: IndexedFile, node: ast.AST) -> Evidence:
    line_start = getattr(node, "lineno", 1)
    line_end = getattr(node, "end_lineno", line_start) or line_start
    return f.evidence_for_lines(line_start, line_end)
