"""AST-based Python scanner.

Replaces regex matching for Python with a real ``ast`` walk: it resolves call targets
(including ``import ... as`` aliases and ``from ... import`` names), distinguishes
``open(path, 'w')`` (write) from ``open(path)`` (read), and never matches an API name that
merely appears inside a string or comment. Files that fail to parse fall back to the regex
patterns declared on each rule and are flagged in ``needs_review``.
"""

from __future__ import annotations

import ast
import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity
from skilltotal.scanners.base import (
    MAX_EVIDENCE_PER_FINDING,
    RuleSpec,
    Scanner,
    ScanResult,
    alternation,
)

PY_SUFFIXES = (".py", ".pyw")

# --- call-target classification ------------------------------------------------------
SHELL_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "os.system",
        "os.popen",
        # asyncio process creation is shell execution too.
        "asyncio.create_subprocess_shell",
        "asyncio.create_subprocess_exec",
    }
)
# Third-party libraries whose whole purpose is running OS processes; importing one is a
# shell-execution signal even without a direct subprocess call.
SHELL_MODULES = frozenset({"sh", "plumbum", "pexpect", "invoke", "fabric"})
# True arbitrary-code execution: a confirmed finding.
DYNAMIC_CALLS = frozenset({"eval", "exec", "compile"})
# Dynamic *module import* by name. Extremely common in legitimate code (optional
# dependencies, plugin loaders) and a much weaker signal than eval/exec, so it is routed to
# needs_review rather than a high-severity finding.
DYNAMIC_IMPORT_CALLS = frozenset({"__import__", "importlib.import_module"})
FS_READ_SUFFIXES = ("read_text", "read_bytes")
FS_WRITE_SUFFIXES = ("write_text", "write_bytes")
FS_WRITE_PREFIXES = ("shutil.copy", "shutil.move", "shutil.rmtree", "os.remove", "os.unlink")
NETWORK_HEADS = frozenset({"requests", "aiohttp", "httpx"})
WRITE_MODE_CHARS = frozenset("wax+")

# Rule ids
R_SHELL = "ST-SHELL-PY"
R_FS_READ = "ST-FS-PY-READ"
R_FS_WRITE = "ST-FS-PY-WRITE"
R_NET = "ST-NET-PY"
R_DYN = "ST-DYN-PY"


class PythonAstScanner(Scanner):
    name = "python_ast"
    rules = [
        RuleSpec(
            id=R_SHELL,
            category="shell_execution",
            severity=Severity.HIGH,
            title="Python shell/command execution",
            description=(
                "Python APIs that spawn OS processes were detected "
                "(subprocess / os.system / os.popen)."
            ),
            recommendation=(
                "Confirm the command and its arguments are fully controlled and not "
                "derived from untrusted input; avoid shell=True."
            ),
            capability=Capability.SHELL_EXECUTION,
            suffixes=PY_SUFFIXES,
            pattern=alternation(
                r"subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(",
                r"os\.system\s*\(",
                r"os\.popen\s*\(",
                r"asyncio\.create_subprocess_(?:shell|exec)\s*\(",
                r"\bimport\s+(?:sh|plumbum|pexpect|invoke|fabric)\b",
                r"\bfrom\s+(?:sh|plumbum|pexpect|invoke|fabric)\b",
            ),
        ),
        RuleSpec(
            id=R_FS_READ,
            category="filesystem",
            severity=Severity.MEDIUM,
            title="Python filesystem read",
            description="Python filesystem read APIs were detected (open / read_text).",
            recommendation=(
                "Confirm which files are read and that paths cannot be influenced by "
                "untrusted input to reach sensitive locations."
            ),
            capability=Capability.FILESYSTEM_READ,
            suffixes=PY_SUFFIXES,
            pattern=alternation(r"\bopen\s*\(", r"\.read_text\s*\(", r"\.read_bytes\s*\("),
        ),
        RuleSpec(
            id=R_FS_WRITE,
            category="filesystem",
            severity=Severity.MEDIUM,
            title="Python filesystem write/delete",
            description=(
                "Python filesystem write/delete APIs were detected "
                "(write_text / shutil / os.remove)."
            ),
            recommendation=(
                "Confirm which files are written/deleted and that paths cannot be "
                "influenced by untrusted input."
            ),
            capability=Capability.FILESYSTEM_WRITE,
            suffixes=PY_SUFFIXES,
            pattern=alternation(
                r"\.write_text\s*\(",
                r"\.write_bytes\s*\(",
                r"\bos\.remove\s*\(",
                r"\bos\.unlink\s*\(",
                r"\bshutil\.(?:copy\w*|move|rmtree)\s*\(",
            ),
        ),
        RuleSpec(
            id=R_NET,
            category="network_egress",
            severity=Severity.MEDIUM,
            title="Python network egress",
            description=(
                "Python HTTP/network client usage was detected "
                "(requests / urllib / aiohttp / http.client)."
            ),
            recommendation=(
                "Confirm the destination hosts are expected and that no sensitive data "
                "is sent off-host."
            ),
            capability=Capability.NETWORK_EGRESS,
            suffixes=PY_SUFFIXES,
            pattern=alternation(
                r"\bimport\s+requests\b",
                r"\bfrom\s+requests\b",
                r"\brequests\.\w+",
                r"\bimport\s+urllib\b",
                r"\burllib\.request\b",
                r"\bimport\s+aiohttp\b",
                r"\bimport\s+http\.client\b",
                flags=re.MULTILINE,
            ),
        ),
        RuleSpec(
            id=R_DYN,
            category="dynamic_code_execution",
            severity=Severity.HIGH,
            title="Python dynamic code execution",
            description=(
                "Python dynamic execution primitives were detected "
                "(eval / exec / compile)."
            ),
            recommendation=(
                "Avoid evaluating dynamically constructed code; if unavoidable, ensure "
                "the input is a trusted constant and never derived from external data."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            suffixes=PY_SUFFIXES,
            pattern=alternation(
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"\bcompile\s*\(",
            ),
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        acc: dict[str, list[Evidence]] = {}
        needs_review: list[NeedsReview] = []

        for f in index.select(suffixes=PY_SUFFIXES):
            try:
                tree = ast.parse(f.text, filename=f.relpath)
            except SyntaxError:
                self._regex_fallback(f, acc)
                needs_review.append(
                    NeedsReview(
                        category="python",
                        title="Unparseable Python file",
                        reason=(
                            "File could not be parsed as Python (AST); analyzed with "
                            "regex fallback, results may be incomplete."
                        ),
                        file=f.relpath,
                    )
                )
                continue
            visitor = _CallVisitor(f)
            visitor.visit(tree)
            for rid, evidence in visitor.hits.items():
                acc.setdefault(rid, []).extend(evidence)
            for ev in visitor.dynamic_imports:
                if len(needs_review) >= MAX_EVIDENCE_PER_FINDING:
                    break
                needs_review.append(
                    NeedsReview(
                        category="dynamic_code_execution",
                        title="Dynamic module import",
                        reason=(
                            f"Dynamic import by name at line {ev.line_start} "
                            "(__import__ / importlib.import_module); common for optional "
                            "dependencies or plugins, but verify the module name is not "
                            "attacker-controlled."
                        ),
                        file=ev.file,
                    )
                )

        return ScanResult(findings=self._build_findings(acc), needs_review=needs_review)

    # ------------------------------------------------------------------ helpers
    def _rules_by_id(self) -> dict[str, RuleSpec]:
        return {r.id: r for r in self.rules}

    def _build_findings(self, acc: dict[str, list[Evidence]]) -> list[Finding]:
        rules = self._rules_by_id()
        findings: list[Finding] = []
        for rid, evidence in acc.items():
            rule = rules[rid]
            evidence = _dedupe(evidence)[:MAX_EVIDENCE_PER_FINDING]
            description = rule.description
            if len(evidence) > 1:
                description = f"{description} ({len(evidence)} occurrence(s) shown as evidence)."
            findings.append(
                Finding(
                    id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    title=rule.title,
                    description=description,
                    evidence=evidence,
                    recommendation=rule.recommendation,
                )
            )
        return findings

    def _regex_fallback(self, f: IndexedFile, acc: dict[str, list[Evidence]]) -> None:
        for rule in self.rules:
            if rule.pattern is None:
                continue
            for _m, ev in f.finditer(rule.pattern):
                acc.setdefault(rule.id, []).append(ev)


class _CallVisitor(ast.NodeVisitor):
    """Collects rule hits from a parsed Python module, resolving import aliases."""

    def __init__(self, file: IndexedFile):
        self.file = file
        self.hits: dict[str, list[Evidence]] = {}
        self.dynamic_imports: list[Evidence] = []  # __import__ / importlib.import_module
        self.aliases: dict[str, str] = {}  # local name -> top-level module
        self.from_imports: dict[str, str] = {}  # local name -> module.attr

    # -- imports -----------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.aliases[local] = alias.name
            if _is_network_module(alias.name):
                self._add(R_NET, node)
            if alias.name.split(".")[0] in SHELL_MODULES:
                self._add(R_SHELL, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.from_imports[local] = f"{module}.{alias.name}" if module else alias.name
        if _is_network_module(module):
            self._add(R_NET, node)
        if module.split(".")[0] in SHELL_MODULES:
            self._add(R_SHELL, node)
        self.generic_visit(node)

    # -- calls -------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        name = self._dotted(node.func)
        if name is not None:
            self._classify_call(name, node)
        self.generic_visit(node)

    def _classify_call(self, name: str, node: ast.Call) -> None:
        if name in SHELL_CALLS:
            self._add(R_SHELL, node)
        elif name in DYNAMIC_CALLS:
            self._add(R_DYN, node)
        elif name in DYNAMIC_IMPORT_CALLS:
            self._add_dynamic_import(node)
        elif name == "open":
            self._add(R_FS_WRITE if _open_is_write(node) else R_FS_READ, node)
        elif name.endswith(FS_WRITE_SUFFIXES):
            self._add(R_FS_WRITE, node)
        elif name.endswith(FS_READ_SUFFIXES):
            self._add(R_FS_READ, node)
        elif name.startswith(FS_WRITE_PREFIXES):
            self._add(R_FS_WRITE, node)
        elif _is_network_call(name):
            self._add(R_NET, node)

    # -- internals ---------------------------------------------------------
    def _dotted(self, func: ast.expr) -> str | None:
        """Resolve a call target to a canonical dotted name, applying import aliases."""
        if isinstance(func, ast.Name):
            return self.from_imports.get(func.id, func.id)
        if isinstance(func, ast.Attribute):
            base = self._dotted(func.value)
            if base is None:
                return func.attr
            parts = base.split(".")
            if parts[0] in self.aliases:
                parts[0] = self.aliases[parts[0]]
                base = ".".join(parts)
            return f"{base}.{func.attr}"
        return None

    def _add(self, rule_id: str, node: ast.AST) -> None:
        bucket = self.hits.setdefault(rule_id, [])
        if len(bucket) >= MAX_EVIDENCE_PER_FINDING:
            return
        bucket.append(self._evidence(node))

    def _add_dynamic_import(self, node: ast.AST) -> None:
        if len(self.dynamic_imports) >= MAX_EVIDENCE_PER_FINDING:
            return
        self.dynamic_imports.append(self._evidence(node))

    def _evidence(self, node: ast.AST) -> Evidence:
        line_start = getattr(node, "lineno", 1)
        line_end = getattr(node, "end_lineno", line_start) or line_start
        return self.file.evidence_for_lines(line_start, line_end)


def _open_is_write(node: ast.Call) -> bool:
    mode: ast.expr | None = None
    if len(node.args) >= 2:
        mode = node.args[1]
    for kw in node.keywords:
        if kw.arg == "mode":
            mode = kw.value
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return any(ch in WRITE_MODE_CHARS for ch in mode.value)
    return False


def _is_network_module(module: str) -> bool:
    if not module:
        return False
    head = module.split(".")[0]
    return head in NETWORK_HEADS or module.startswith(("urllib", "http.client"))


def _is_network_call(name: str) -> bool:
    head = name.split(".")[0]
    return head in NETWORK_HEADS or name.startswith(("urllib", "http.client"))


def _dedupe(evidence: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, int, int]] = set()
    out: list[Evidence] = []
    for e in evidence:
        key = (e.file, e.line_start, e.line_end)
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out
