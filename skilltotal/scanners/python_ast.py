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
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_PER_FINDING,
    RuleSpec,
    Scanner,
    ScanResult,
    alternation,
)
from skilltotal.scanners.sensitive_paths import _STRONG_PATHS  # reuse the credential-path set

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

# Calls that always run through a shell (so a dynamic command is injectable).
ALWAYS_SHELL_CALLS = frozenset({"os.system", "os.popen", "asyncio.create_subprocess_shell"})

# Deserializers that execute / instantiate arbitrary objects from their input.
UNSAFE_DESERIALIZE_CALLS = frozenset(
    {
        "pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load",
        "_pickle.loads", "_pickle.load", "marshal.loads", "marshal.load",
        "dill.loads", "dill.load", "jsonpickle.decode", "jsonpickle.loads",
        "shelve.open",
    }
)

# Rule ids
R_SHELL = "ST-SHELL-PY"
R_CMDI = "ST-CMDI-PY"
R_DESERIAL = "ST-DESERIALIZE-PY"
R_FS_READ = "ST-FS-PY-READ"
R_FS_WRITE = "ST-FS-PY-WRITE"
R_NET = "ST-NET-PY"
R_DYN = "ST-DYN-PY"
R_SENS_PY = "ST-SENS-PATH-PY"

# Calls that *use* a path/command/URL — a sensitive path passed here is a real read/exec/send,
# not a mere mention. Excludes regex builders / metadata constructors, so a detector matching its
# own pattern literals (or a docstring example) is not flagged.
_PATH_CONSUMER_NAMES = frozenset(
    {"open", "io.open", "codecs.open", "os.open", "Path", "pathlib.Path", "PosixPath"}
)
_PATH_CONSUMER_PREFIXES = ("os.path.", "shutil.", "pathlib.")


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
            id=R_CMDI,
            category="command_injection",
            severity=Severity.HIGH,
            title="Possible command injection (shell + dynamic command)",
            description=(
                "A shell command is built from a non-constant value (f-string, "
                "concatenation, .format, or a variable) and run through a shell "
                "(os.system/os.popen or subprocess with shell=True). If any part comes from "
                "untrusted input, this is a command-injection vector."
            ),
            recommendation=(
                "Pass arguments as a list without shell=True (e.g. "
                "subprocess.run(['git', 'checkout', branch])); never build a shell string "
                "from external input. If a shell is unavoidable, quote with shlex.quote."
            ),
            capability=None,  # the shell capability is already covered by ST-SHELL-PY
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            suffixes=PY_SUFFIXES,
        ),
        RuleSpec(
            id=R_DESERIAL,
            category="unsafe_deserialization",
            severity=Severity.HIGH,
            title="Unsafe deserialization",
            description=(
                "A deserializer that can execute or instantiate arbitrary objects from its "
                "input was detected (pickle/cPickle/dill/marshal/jsonpickle/shelve, or "
                "yaml.load without SafeLoader). Loading such data from an untrusted source "
                "allows arbitrary code execution."
            ),
            recommendation=(
                "Deserialize untrusted data with a safe format/loader: JSON, or "
                "yaml.safe_load / Loader=SafeLoader. Reserve pickle/marshal for data you "
                "fully control."
            ),
            capability=None,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            suffixes=PY_SUFFIXES,
            pattern=alternation(
                r"\b(?:c?[Pp]ickle|_pickle|dill|marshal)\.loads?\s*\(",
                r"\bjsonpickle\.(?:decode|loads)\s*\(",
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
        RuleSpec(
            id=R_SENS_PY,
            category="sensitive_path",
            severity=Severity.HIGH,
            title="Sensitive path / secret-location access",
            description=(
                "A credential/secret location (e.g. ~/.ssh, ~/.aws/credentials, id_rsa) is "
                "passed to a filesystem, process, or network call — the code reads or ships a "
                "secret location, not merely mentions it."
            ),
            recommendation=(
                "Verify why the component accesses credential locations; reading these is a "
                "common precursor to secret exfiltration."
            ),
            capability=Capability.FILESYSTEM_READ,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            suffixes=PY_SUFFIXES,
            # AST-only (no regex pattern): matched structurally via call arguments, so a
            # credential path that merely appears in a string literal / docstring / regex
            # pattern is never flagged here.
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        acc: dict[str, list[Evidence]] = {}
        needs_review: list[NeedsReview] = []

        for f in index.select(suffixes=PY_SUFFIXES):
            try:
                tree = ast.parse(f.text, filename=f.relpath)
            except SyntaxError as exc:
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
                        line=exc.lineno,
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
                        line=ev.line_start,
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
                    threat_class=rule.threat_class,
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
            if _is_command_injection(name, node):
                self._add(R_CMDI, node)
        elif name in UNSAFE_DESERIALIZE_CALLS:
            self._add(R_DESERIAL, node)
        elif name in ("yaml.load", "yaml.load_all") and _yaml_load_is_unsafe(node):
            self._add(R_DESERIAL, node)
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

        # Independent of the classification above: a credential path passed to a path/IO/process/
        # network call is a real sensitive-data access (e.g. open("~/.aws/credentials"),
        # expanduser("~/.ssh/id_rsa"), subprocess.run(["cat", "~/.ssh/id_rsa"])).
        if _is_path_consumer(name) and any(
            _STRONG_PATHS.search(s) for s in _iter_string_consts(node)
        ):
            self._add(R_SENS_PY, node)

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


def _is_path_consumer(name: str) -> bool:
    """True if a string argument to ``name`` is used as a path/command/URL (not metadata)."""
    if name in _PATH_CONSUMER_NAMES or name in SHELL_CALLS or _is_network_call(name):
        return True
    if name.endswith(FS_READ_SUFFIXES) or name.endswith(FS_WRITE_SUFFIXES):
        return True
    return name.startswith(_PATH_CONSUMER_PREFIXES)


def _iter_string_consts(node: ast.Call):
    """Yield string-constant values among a call's positional/keyword args (recursing lists)."""
    for arg in node.args:
        yield from _strings_in(arg)
    for kw in node.keywords:
        yield from _strings_in(kw.value)


def _strings_in(expr: ast.expr):
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        yield expr.value
    elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        for element in expr.elts:
            yield from _strings_in(element)


def _shell_true(node: ast.Call) -> bool:
    """True if the call passes shell=True (a literal True)."""
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _command_arg(node: ast.Call) -> ast.expr | None:
    """The command/argv argument: first positional, else args=/cmd= keyword."""
    if node.args:
        return node.args[0]
    for kw in node.keywords:
        if kw.arg in ("args", "cmd", "command"):
            return kw.value
    return None


def _is_dynamic_command(arg: ast.expr | None) -> bool:
    """True if the command is built from anything other than pure constants."""
    if arg is None:
        return False
    if isinstance(arg, ast.Constant):
        return False
    if isinstance(arg, ast.JoinedStr):  # f-string: dynamic only if it interpolates
        return any(isinstance(v, ast.FormattedValue) for v in arg.values)
    if isinstance(arg, ast.BinOp):  # "a " + x  or  "fmt %s" % x
        return isinstance(arg.op, (ast.Add, ast.Mod))
    if isinstance(arg, (ast.List, ast.Tuple)):  # argv form: dynamic if any element is
        return any(_is_dynamic_command(e) for e in arg.elts)
    if isinstance(arg, ast.Constant):
        return False
    # Name / Attribute / Subscript / Call (e.g. .format(), or any variable) -> dynamic.
    return isinstance(arg, (ast.Name, ast.Attribute, ast.Subscript, ast.Call))


def _is_command_injection(name: str, node: ast.Call) -> bool:
    """Shell call + dynamic command = injectable. Excludes argv-without-shell (safe)."""
    uses_shell = name in ALWAYS_SHELL_CALLS or (
        name.startswith("subprocess.") and _shell_true(node)
    )
    if not uses_shell:
        return False
    return _is_dynamic_command(_command_arg(node))


def _yaml_load_is_unsafe(node: ast.Call) -> bool:
    """yaml.load(...) is unsafe unless a Safe loader is passed (positional or Loader=)."""
    loader: ast.expr | None = None
    if len(node.args) >= 2:
        loader = node.args[1]
    for kw in node.keywords:
        if kw.arg == "Loader":
            loader = kw.value
    if loader is None:
        return True  # no loader -> historically the unsafe full loader
    tail = loader.attr if isinstance(loader, ast.Attribute) else getattr(loader, "id", "")
    return "Safe" not in tail  # SafeLoader / CSafeLoader are safe


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
