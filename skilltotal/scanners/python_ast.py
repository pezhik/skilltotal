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
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from skilltotal.file_index import FileIndex, IndexedFile, is_test_path
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_PER_FINDING,
    MAX_EVIDENCE_SCANNED,
    TACTIC_PERSISTENCE,
    RuleSpec,
    Scanner,
    ScanResult,
    aggregated_review,
    alternation,
)
from skilltotal.scanners.sensitive_paths import (  # reuse the credential-path set
    _STRONG_PATHS,
    is_metadata_without_credentials,
)
from skilltotal.scanners.shell_script import REMOTE_EXEC

PY_SUFFIXES = (".py", ".pyw")

# --- deep nesting ----------------------------------------------------------------------------
# The visitors recurse once per level of the tree, and a file can nest an expression deeper than
# the default recursion limit lets them go: `x = 1+1+...+1` with a thousand terms compiles and
# runs, and was read only by the regex fallback (security review, 2026-10-15). Such a tree is
# walked again in a thread with a large stack under a raised limit. Python frames have used no C
# stack since 3.11, and since 3.12 the C code's own recursion has a limit of its own, so raising
# the Python limit there cannot let another thread overflow its stack; before 3.12 the walk is
# not retried.
_DEEP_STACK_BYTES = 64 * 1024 * 1024
_DEEP_RECURSION_LIMIT = 100_000
_deep_lock = threading.Lock()
_T = TypeVar("_T")


def walk_deep(walk: Callable[[], _T]) -> _T:
    """``walk()``; when it runs out of recursion, ``walk()`` again with room for a deep tree.
    Raises RecursionError when even that is not enough."""
    try:
        return walk()
    except RecursionError:
        if sys.version_info < (3, 12):
            raise
    result: list[_T] = []
    error: list[BaseException] = []

    def run() -> None:
        try:
            result.append(walk())
        except BaseException as exc:  # handed to the caller's thread
            error.append(exc)

    with _deep_lock:
        limit = sys.getrecursionlimit()
        try:
            stack = threading.stack_size(_DEEP_STACK_BYTES)
        except (ValueError, RuntimeError):  # a platform that cannot size thread stacks
            raise RecursionError("nested too deeply to walk") from None
        try:
            thread = threading.Thread(target=run, name="skilltotal-deep-ast", daemon=True)
            sys.setrecursionlimit(max(limit, _DEEP_RECURSION_LIMIT))
            thread.start()
            thread.join()
        finally:
            sys.setrecursionlimit(limit)
            threading.stack_size(stack)
    if error:
        raise error[0]
    return result[0]

# --- call-target classification ------------------------------------------------------
# Process creation without subprocess: the exec*/spawn* families replace or fork the interpreter
# with another program, and getoutput()/getstatusoutput() run a command through the shell.
_PROCESS_CALLS = frozenset(
    {
        f"os.{fn}"
        for fn in (
            "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
            "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp",
            "spawnvpe", "posix_spawn", "posix_spawnp", "startfile",
        )
    }
    | {"subprocess.getoutput", "subprocess.getstatusoutput", "pty.spawn"}
)
SHELL_CALLS = (
    frozenset(
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
    | _PROCESS_CALLS
)
# Third-party libraries whose whole purpose is running OS processes; importing one is a
# shell-execution signal even without a direct subprocess call. `git` is GitPython: every
# `repo.git.<command>(...)` runs the git binary, with arguments the caller supplies (the official
# git MCP server checks out, resets and logs through it and reported no capability at all).
SHELL_MODULES = frozenset({"sh", "plumbum", "pexpect", "invoke", "fabric", "git"})
# True arbitrary-code execution: a confirmed finding.
DYNAMIC_CALLS = frozenset({"eval", "exec", "compile"})
# The same primitives reached through the builtins module (`builtins.exec`, or `b.exec` for a
# module bound by name): `builtins.exec` IS exec, so it is dynamic execution like the bare name.
_BUILTINS_DYNAMIC = frozenset(f"builtins.{name}" for name in DYNAMIC_CALLS)
# Dynamic *module import* by name. Extremely common in legitimate code (optional
# dependencies, plugin loaders) and a much weaker signal than eval/exec, so it is routed to
# needs_review rather than a high-severity finding.
DYNAMIC_IMPORT_CALLS = frozenset({"__import__", "importlib.import_module"})
FS_READ_SUFFIXES = ("read_text", "read_bytes")
FS_WRITE_SUFFIXES = ("write_text", "write_bytes")
FS_WRITE_PREFIXES = ("shutil.copy", "shutil.move", "shutil.rmtree", "os.remove", "os.unlink")
# smtplib included: e-mail is an egress channel too (read a secret + e-mail it out is exfil).
NETWORK_HEADS = frozenset({"requests", "aiohttp", "httpx", "smtplib"})
WRITE_MODE_CHARS = frozenset("wax+")

# Calls that always run through a shell (so a dynamic command is injectable).
ALWAYS_SHELL_CALLS = frozenset(
    {
        "os.system", "os.popen", "asyncio.create_subprocess_shell",
        "subprocess.getoutput", "subprocess.getstatusoutput",
    }
)

# Deserializers that execute / instantiate arbitrary objects from their input.
UNSAFE_DESERIALIZE_CALLS = frozenset(
    {
        "pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load",
        "_pickle.loads", "_pickle.load", "marshal.loads", "marshal.load",
        "dill.loads", "dill.load", "jsonpickle.decode", "jsonpickle.loads",
        "shelve.open",
    }
)
# Their serializing counterparts: bytes made by one of these in the same module are the
# module's own state, not outside input (see _CallVisitor._loads_own_state).
_SERIALIZE_CALLS = frozenset(
    {
        "pickle.dumps", "cPickle.dumps", "_pickle.dumps", "marshal.dumps", "dill.dumps",
    }
)

# What a pickle __reduce__/__reduce_ex__ may hand back as the callable to run on load. Pickle
# calls whatever comes first in the returned tuple, so a shell or code-execution function there
# runs the moment the object is unpickled (the classic gadget in poisoned ML model files): process
# creation, eval/exec, the runners that execute a path or a statement string, and a second
# unpickle (a nested payload).
REDUCE_GADGET_CALLS = (
    SHELL_CALLS
    | DYNAMIC_CALLS
    | frozenset(
        {
            "__import__", "builtins.eval", "builtins.exec", "builtins.compile",
            "builtins.__import__", "runpy.run_path", "runpy.run_module", "timeit.timeit",
            "timeit.repeat", "pdb.run", "profile.run", "cProfile.run", "pickle.loads",
            "_pickle.loads", "cPickle.loads", "dill.loads",
        }
    )
)
_REDUCE_METHODS = frozenset({"__reduce__", "__reduce_ex__"})
# copyreg.pickle(cls, reducer) registers a reducer function: the same gadget, defined elsewhere.
_COPYREG_PICKLE = frozenset({"copyreg.pickle", "copy_reg.pickle"})
# Looking a module function up by name hides it from a name match: `getattr(os, "system")`,
# `__import__("os").system`, `getattr(__import__("os"), "sys" + "tem")`. These resolve when the
# module and the name are constants (so `getattr(self, name)` stays unresolved).
_IMPORT_BY_NAME = frozenset({"__import__", "builtins.__import__", "importlib.import_module"})
_GETATTR = frozenset({"getattr", "builtins.getattr"})

# Rule ids
R_SHELL = "ST-SHELL-PY"
R_CMDI = "ST-CMDI-PY"
R_DESERIAL = "ST-DESERIALIZE-PY"
R_FS_READ = "ST-FS-PY-READ"
R_FS_WRITE = "ST-FS-PY-WRITE"
R_NET = "ST-NET-PY"
R_DYN = "ST-DYN-PY"
# Deserialize-and-execute: exec/eval/compile(pickle|marshal|dill|jsonpickle.load[s](...)). The
# serializer variant of ST-OBF-DECODE-EXEC; Python-specific because it needs alias resolution.
R_DECODE_EXEC_PY = "ST-OBF-DECODE-EXEC-PY"
R_SENS_PY = "ST-SENS-PATH-PY"
R_PICKLE_REDUCE = "ST-PICKLE-REDUCE"
# A shell call whose command downloads code and runs it (`os.system("curl … | bash")`).
R_PIPE_EXEC_PY = "ST-SHELL-PIPE-EXEC-PY"
# The shells an argv list can hand a command string to (`["bash", "-c", "…"]`).
_SHELL_PROGRAMS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})

# Calls that *use* a path/command/URL — a sensitive path passed here is a real read/exec/send,
# not a mere mention. Excludes regex builders / metadata constructors, so a detector matching its
# own pattern literals (or a docstring example) is not flagged.
_PATH_CONSUMER_NAMES = frozenset(
    {"open", "io.open", "codecs.open", "os.open", "Path", "pathlib.Path", "PosixPath"}
)
_PATH_CONSUMER_PREFIXES = ("os.path.", "shutil.", "pathlib.")

# A credential path built from segments instead of written out: joined onto the home directory
# (`os.path.join(os.path.expanduser("~"), ".aws", "credentials")`,
# `Path.home() / ".aws" / "credentials"`, `Path.home().joinpath(...)`), concatenated to it
# (`expanduser("~") + "/.aws/config"`) or interpolated (`f"{Path.home()}/.npmrc"`). The expression
# is read as the path it builds -- the home directory as `~`, strings as written, anything else as
# a segment no rule matches -- and judged like the written path. Only the outermost expression is
# judged: `Path.home() / ".ssh"` inside `Path.home() / ".ssh" / "known_hosts"` is part of a
# public-key path, not a path of its own.
_PATH_JOIN_CALLS = frozenset({"os.path.join", "posixpath.join", "ntpath.join"})
_PATH_TYPES = frozenset(
    {"Path", "PurePath", "PosixPath", "PurePosixPath", "WindowsPath", "PureWindowsPath"}
)
# Calls and methods that hand back the path they are given (expanded or normalized).
_PATH_PASSTHROUGH_CALLS = frozenset(
    {"os.path.expanduser", "os.path.abspath", "os.path.realpath", "os.path.normpath",
     "os.fspath", "str"}
)
_PATH_PASSTHROUGH_METHODS = frozenset({"expanduser", "resolve", "absolute"})
_HOME_ENV_NAMES = frozenset({"HOME", "USERPROFILE"})
_ENV_GETTERS = frozenset({"os.getenv", "os.environ.get"})
_UNKNOWN_SEGMENT = "\x00"

# --- taint analysis (intra-procedural) -----------------------------------------------
# A .pth file imports a module of the same component whose top level spawns a process.
R_PTH_IMPORT_EXEC = "ST-PTH-IMPORT-EXEC"
R_TAINT_EXEC = "ST-TAINT-EXEC-PY"
R_TAINT_SHELL = "ST-TAINT-SHELL-PY"
R_TAINT_DESERIAL = "ST-TAINT-DESERIAL-PY"

# Untrusted-input SOURCES — conservative, high-confidence set for v1.
_SOURCE_CALLS = frozenset({"os.getenv", "os.environ.get", "input"})
_SOURCE_ATTRS = frozenset({"os.environ", "sys.argv"})
# Attributes exposing a network response body (requests/httpx/aiohttp .text/.content/.json()).
_NET_BODY_ATTRS = frozenset({"text", "content", "json"})
# Calls that neutralize taint before a shell/exec sink.
_SANITIZERS = frozenset({"shlex.quote", "shlex.join", "int", "float"})
# str methods that carry taint from the receiver or arguments (x.format(...), sep.join(x), ...).
_STR_TAINT_METHODS = frozenset(
    {
        "format", "format_map", "join", "strip", "lstrip", "rstrip",
        "replace", "lower", "upper", "title", "encode", "decode",
    }
)
# A function decorated with `@*.tool` is treated as an MCP tool handler whose params are
# agent/attacker-controlled (the decorator's leaf attribute is "tool": mcp.tool/server.tool/...).
_MCP_TOOL_DECORATOR_LEAF = "tool"
_COMPOUND_STMTS = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)


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
            id=R_PIPE_EXEC_PY,
            category="shell_execution",
            severity=Severity.HIGH,
            title="Remote pipe-to-shell execution (Python)",
            description=(
                "A Python shell call (os.system / os.popen, subprocess with shell=True, or an "
                "argv list that runs `sh -c`) is given a command that downloads code and pipes it "
                "into a shell or interpreter, e.g. `os.system(\"curl ... | bash\")`. The component "
                "runs whatever the host serves at that moment, which no review of the component "
                "can see."
            ),
            recommendation=(
                "Ship the code instead, or download a pinned artifact, verify its checksum, and "
                "run that copy; never pipe a network response straight into a shell."
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
            id=R_PICKLE_REDUCE,
            category="unsafe_deserialization",
            severity=Severity.HIGH,
            title="Pickle __reduce__ returns a code-execution callable",
            description=(
                "A class defines __reduce__/__reduce_ex__ that returns a shell or "
                "code-execution function (os.system, subprocess, eval, exec, ...) as the callable "
                "pickle invokes on load, so unpickling the object runs it. This is the construct "
                "pickle code-execution gadgets are built from."
            ),
            recommendation=(
                "A __reduce__ normally returns the class (or a factory) and its constructor "
                "arguments, not a shell or exec function. Do not unpickle data this component "
                "produces unless that behavior is intended and understood."
            ),
            capability=None,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            suffixes=PY_SUFFIXES,
            # No regex fallback: a real gadget is valid Python and always parses, and a regex
            # cannot see which callable the tuple returns -- it would only add false positives.
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
                "Python HTTP/network/email client usage was detected "
                "(requests / urllib / aiohttp / http.client / smtplib)."
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
                r"\bimport\s+urllib\b(?!\s*\.\s*(?:parse|error))",
                r"\bfrom\s+urllib\.request\b",
                r"\burllib\.request\b",
                r"\bimport\s+aiohttp\b",
                r"\bimport\s+http\.client\b",
                r"\bimport\s+smtplib\b",
                r"\bsmtplib\.",
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
            id=R_DECODE_EXEC_PY,
            category="obfuscation",
            severity=Severity.HIGH,
            title="Deserialize-and-execute (obfuscated execution)",
            description=(
                "A value is deserialized with pickle/marshal/dill/jsonpickle and immediately "
                "executed (e.g. exec(marshal.loads(...))). Deserializing then executing data "
                "hides behavior from review and is a common second-stage dropper; if the data "
                "is untrusted this is arbitrary code execution."
            ),
            recommendation=(
                "Decode/deserialize the payload manually and inspect what it does before "
                "trusting this component. Never exec/eval the result of pickle/marshal/dill on "
                "data you do not fully control."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            suffixes=PY_SUFFIXES,
            # AST-anchored; the regex is only the fallback for files that fail to parse.
            pattern=alternation(
                r"(?:eval|exec|compile)\s*\(\s*(?:c?[Pp]ickle|_pickle|dill|marshal)\.loads?\s*\(",
                r"(?:eval|exec|compile)\s*\(\s*jsonpickle\.(?:decode|loads)\s*\(",
            ),
        ),
        RuleSpec(
            id=R_SENS_PY,
            category="sensitive_path",
            severity=Severity.HIGH,
            title="Sensitive path / secret-location access",
            description=(
                "A credential/secret location (e.g. ~/.ssh, ~/.aws/credentials, id_rsa) is "
                "passed to a filesystem, process, or network call - the code reads or ships a "
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
        RuleSpec(
            id=R_PTH_IMPORT_EXEC,
            category="shell_execution",
            severity=Severity.HIGH,
            title="A .pth file runs a module that spawns a process at import",
            description=(
                "A .pth file imports a module shipped in this component, and that module spawns "
                "an OS process at its top level, outside any function. Python runs a .pth file's "
                "import lines at every interpreter start, so the process starts each time Python "
                "does, without the package ever being used."
            ),
            recommendation=(
                "A legitimate .pth file adds import paths or imports a module that only defines "
                "things. Treat a process started from a .pth import as malicious; remove the "
                "package and check what the command ran."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            suffixes=(*PY_SUFFIXES, ".pth"),
            # AST-only: the .pth import line and the module-level spawn are matched structurally.
            tactic=TACTIC_PERSISTENCE,
        ),
        RuleSpec(
            id=R_TAINT_EXEC,
            category="dynamic_code_execution",
            severity=Severity.HIGH,
            title="Untrusted input flows to dynamic code execution",
            description=(
                "A value derived from an untrusted source (environment, command-line "
                "arguments, input(), a network response body, or an MCP tool argument) reaches "
                "eval / exec / compile. If the source is attacker-controlled this is remote "
                "code execution."
            ),
            recommendation=(
                "Never evaluate data built from external input. Remove the dynamic execution "
                "or restrict the input to a trusted, validated allow-list of constants."
            ),
            capability=None,  # the exec capability is already covered by ST-DYN-PY
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            suffixes=PY_SUFFIXES,
        ),
        RuleSpec(
            id=R_TAINT_SHELL,
            category="command_injection",
            severity=Severity.HIGH,
            title="Untrusted input flows to a shell command",
            description=(
                "A value derived from an untrusted source (environment, command-line "
                "arguments, input(), a network response body, or an MCP tool argument) is run "
                "through a shell (os.system / os.popen or subprocess with shell=True). If the "
                "source is attacker-controlled this is command injection."
            ),
            recommendation=(
                "Pass arguments as a list without shell=True; never build a shell string from "
                "external input. If a shell is unavoidable, quote every external value with "
                "shlex.quote."
            ),
            capability=None,  # shell capability already covered by ST-SHELL-PY
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            suffixes=PY_SUFFIXES,
        ),
        RuleSpec(
            id=R_TAINT_DESERIAL,
            category="unsafe_deserialization",
            severity=Severity.HIGH,
            title="Untrusted input flows to unsafe deserialization",
            description=(
                "A value derived from an untrusted source (environment, command-line "
                "arguments, input(), a network response body, or an MCP tool argument) is "
                "passed to a deserializer that can execute arbitrary objects "
                "(pickle/marshal/dill/jsonpickle, or yaml.load without SafeLoader)."
            ),
            recommendation=(
                "Deserialize untrusted data only with a safe format/loader (JSON, "
                "yaml.safe_load). Reserve pickle/marshal for data you fully control."
            ),
            capability=None,  # already covered by ST-DESERIALIZE-PY
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            suffixes=PY_SUFFIXES,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        acc: dict[str, list[Evidence]] = {}
        needs_review: list[NeedsReview] = []
        unparseable: list[tuple[str, int | None]] = []
        dynamic_imports: list[tuple[str, int | None]] = []
        # Shipped modules whose top level spawns a process, by path (see ST-PTH-IMPORT-EXEC).
        module_spawns: dict[str, list[Evidence]] = {}

        too_deep: list[tuple[str, int | None]] = []

        for f in index.select(suffixes=PY_SUFFIXES):
            try:
                tree = ast.parse(f.text, filename=f.relpath)
            # RecursionError / MemoryError: nesting deeper than the parser's own stack
            # (`x = 1+1+...`), which a file can force.
            except (RecursionError, MemoryError):
                self._regex_fallback(f, acc)
                too_deep.append((f.relpath, None))
                continue
            # ValueError: a NUL byte on older Pythons.
            except (SyntaxError, ValueError) as exc:
                self._regex_fallback(f, acc)
                unparseable.append((f.relpath, getattr(exc, "lineno", None)))
                continue
            try:
                visitor, taint = walk_deep(lambda f=f, tree=tree: _walk(f, tree))
            except RecursionError:
                # Parsed, but nested deeper than the visitors can walk even with a raised limit:
                # read like unparseable source, so nothing half-visited is reported.
                self._regex_fallback(f, acc)
                too_deep.append((f.relpath, None))
                continue
            for rid, evidence in visitor.hits.items():
                acc.setdefault(rid, []).extend(evidence)
            if visitor.module_spawns and not is_test_path(f.relpath):
                module_spawns[f.relpath] = visitor.module_spawns
            dynamic_imports.extend((ev.file, ev.line_start) for ev in visitor.dynamic_imports)
            for rid, evidence in taint.hits.items():
                acc.setdefault(rid, []).extend(evidence)

        # One note per heuristic, not one per file or call site (see aggregated_review).
        if unparseable:
            needs_review.append(aggregated_review(
                category="python",
                title="Unparseable Python file",
                places=unparseable,
                what="Python file(s) could not be parsed (AST)",
                advice="They were analyzed with the regex fallback, so results for them may "
                       "be incomplete.",
            ))
        if too_deep:
            needs_review.append(aggregated_review(
                category="python",
                title="Python file too deeply nested to analyze",
                places=too_deep,
                what="Python file(s) nest an expression or statement deeper than the analysis "
                     "can follow",
                advice="They were analyzed with the regex fallback, matches inside strings "
                       "included, so results for them may be incomplete. Deep nesting is rare "
                       "in hand-written code; read the file.",
            ))
        if dynamic_imports:
            needs_review.append(aggregated_review(
                category="dynamic_code_execution",
                title="Dynamic module import",
                places=dynamic_imports,
                what="dynamic import(s) by name (__import__ / importlib.import_module)",
                advice="Common for optional dependencies or plugins, but verify the module "
                       "names are not attacker-controlled.",
            ))

        if module_spawns:
            for evidence in _pth_import_chains(index, module_spawns):
                acc.setdefault(R_PTH_IMPORT_EXEC, []).extend(evidence)
        _suppress_cmdi_covered_by_taint(acc)
        return ScanResult(findings=self._build_findings(acc), needs_review=needs_review,
                          regex_only_files=[path for path, _ in too_deep])

    # ------------------------------------------------------------------ helpers
    def _rules_by_id(self) -> dict[str, RuleSpec]:
        return {r.id: r for r in self.rules}

    def _build_findings(self, acc: dict[str, list[Evidence]]) -> list[Finding]:
        rules = self._rules_by_id()
        findings: list[Finding] = []
        for rid, evidence in acc.items():
            rule = rules[rid]
            evidence = _dedupe(evidence)[:MAX_EVIDENCE_SCANNED]
            description = rule.description
            if len(evidence) > 1:
                shown = min(len(evidence), MAX_EVIDENCE_PER_FINDING)
                description = f"{description} ({shown} occurrence(s) shown as evidence)."
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


def _walk(f: IndexedFile, tree: ast.Module) -> tuple[_CallVisitor, _TaintVisitor]:
    visitor = _CallVisitor(f)
    visitor.visit(tree)
    taint = _TaintVisitor(f)
    taint.analyze(tree)
    return visitor, taint


def _is_main_guard(test: ast.expr) -> bool:
    """`__name__ == "__main__"`, either way round: its body does not run on import."""
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)):
        return False
    sides = (test.left, test.comparators[0])
    return (any(isinstance(s, ast.Name) and s.id == "__name__" for s in sides)
            and any(isinstance(s, ast.Constant) and s.value == "__main__" for s in sides))


def _pth_imported_modules(line: str) -> set[str]:
    """Module names one executed .pth line imports: `import a, b.c`, `from a import b`,
    `__import__('a')`, `importlib.import_module('a')`, and the same inside exec("...")."""
    try:
        tree = ast.parse(line)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str):
            func = node.func
            called = func.id if isinstance(func, ast.Name) else (
                func.attr if isinstance(func, ast.Attribute) else "")
            if called in ("__import__", "import_module"):
                names.add(node.args[0].value)
            elif called in ("exec", "eval") and len(node.args[0].value) < 2000:
                names |= _pth_imported_modules(node.args[0].value)
    return names


def _pth_import_chains(
    index: FileIndex, module_spawns: dict[str, list[Evidence]]
) -> list[list[Evidence]]:
    """Evidence for each .pth import line that runs a shipped module with a top-level spawn.

    Python's site module executes a .pth line only when it starts with `import ` or `import\t`;
    every other line is a path. A module counts when its file ends the path of the dotted name
    (`pkg/boot.py`, `pkg/boot/__init__.py`), wherever the package sits (`src/`, the root).
    """
    chains: list[list[Evidence]] = []
    for f in index.select(suffixes=(".pth",)):
        if is_test_path(f.relpath):
            continue
        for lineno, line in enumerate(f.text.splitlines(), start=1):
            if not line.startswith(("import ", "import\t")):
                continue
            spawns: list[Evidence] = []
            for module in sorted(_pth_imported_modules(line)):
                stem = module.replace(".", "/")
                for target in (f"{stem}.py", f"{stem}/__init__.py"):
                    for relpath, evidence in module_spawns.items():
                        if relpath == target or relpath.endswith("/" + target):
                            spawns.extend(evidence)
            if spawns:
                chains.append([f.evidence_for_lines(lineno, lineno), *spawns])
    return chains


class _CallVisitor(ast.NodeVisitor):
    """Collects rule hits from a parsed Python module, resolving import aliases."""

    def __init__(self, file: IndexedFile):
        self.file = file
        self.hits: dict[str, list[Evidence]] = {}
        self.dynamic_imports: list[Evidence] = []  # __import__ / importlib.import_module
        self.aliases: dict[str, str] = {}  # local name -> top-level module
        self.from_imports: dict[str, str] = {}  # local name -> module.attr
        # ids of deserialize calls nested directly inside an exec/eval/compile (decode-and-execute),
        # so the weaker ST-DESERIALIZE-PY is not also raised on the same node (scored once).
        self._decode_exec_inner: set[int] = set()
        # Functions seen so far by name, for copyreg.pickle(cls, reducer_function).
        self._functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        # Loop variables that can only hold one of the literal strings of their loop, while the
        # loop body is visited: `for cmd in ["npx.cmd", "npx"]: subprocess.run([cmd, ...])`.
        self._loop_constants: list[str] = []
        # Credential paths built from segments (see _PATH_JOIN_CALLS): the module's imports as a
        # whole, the names that only ever hold the home directory, and the nodes already read as
        # part of a larger path expression.
        self._module_aliases: dict[str, str] = {}
        self._module_from: dict[str, str] = {}
        self._home_names: frozenset[str] = frozenset()
        self._path_parts: set[int] = set()
        # Process spawns that run when the module is imported: outside any function or lambda,
        # and outside an `if __name__ == "__main__":` block. A .pth import runs exactly these.
        self.module_spawns: list[Evidence] = []
        self._deferred = 0  # > 0 while visiting code an import does not run
        # Attributes every assignment of which (in this module) is this module's own serialized
        # state: computed on the first deserialize call, see _loads_own_state.
        self._module: ast.Module | None = None
        self._own_state_attrs: frozenset[str] | None = None

    def visit_Module(self, node: ast.Module) -> None:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Import):
                for alias in sub.names:
                    local = alias.asname or alias.name.split(".")[0]
                    self._module_aliases[local] = alias.name
                    # Hoist imports into the resolution maps up front, so a name bound to a
                    # getattr/__import__ result (see _value_bindings) can resolve the module even
                    # when the binding is read before the visitor reaches the import statement.
                    self.aliases.setdefault(local, alias.name)
            elif isinstance(sub, ast.ImportFrom) and sub.level == 0 and sub.module:
                for alias in sub.names:
                    local = alias.asname or alias.name
                    self._module_from[local] = f"{sub.module}.{alias.name}"
                    self.from_imports.setdefault(local, f"{sub.module}.{alias.name}")
        self._home_names = self._home_variables(node)
        self._module = node
        # Module-scope bindings apply everywhere (module globals are visible in functions), so they
        # are merged in without being popped.
        self.aliases, self.from_imports = _with_bindings(
            node.body, self.aliases, self.from_imports
        )
        self.generic_visit(node)

    # -- credential paths built from segments -------------------------------
    def _home_variables(self, tree: ast.Module) -> frozenset[str]:
        """Names every assignment of which is the home directory (`home = Path.home()`)."""
        values: dict[str, list[ast.expr]] = {}
        for sub in ast.walk(tree):
            if isinstance(sub, ast.Assign) and len(sub.targets) == 1:
                target, value = sub.targets[0], sub.value
            elif isinstance(sub, ast.AnnAssign) and sub.value is not None:
                target, value = sub.target, sub.value
            else:
                continue
            if isinstance(target, ast.Name):
                values.setdefault(target.id, []).append(value)
        return frozenset(
            name for name, assigned in values.items()
            if all(self._path_part(v, set()).rstrip("/") == "~" for v in assigned)
        )

    def _fold_name(self, func: ast.expr) -> str:
        return _resolve_dotted(func, self._module_aliases, self._module_from) or ""

    def _path_part(self, node: ast.expr, parts: set[int]) -> str:
        """The text ``node`` contributes to a path: a string as written, ``~`` for the home
        directory, a built path, or a segment nothing matches."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in self._home_names:
            return "~"
        if isinstance(node, ast.Subscript) and self._fold_name(node.value) == "os.environ":
            key = node.slice
            if isinstance(key, ast.Constant) and key.value in _HOME_ENV_NAMES:
                return "~"
        if isinstance(node, ast.Call):
            name = self._fold_name(node.func)
            if name.endswith("Path.home") and name.split(".")[-2] in _PATH_TYPES:
                return "~"
            if name in _ENV_GETTERS and node.args:
                key = node.args[0]
                if isinstance(key, ast.Constant) and key.value in _HOME_ENV_NAMES:
                    return "~"
        built = self._built_path(node, parts)
        return _UNKNOWN_SEGMENT if built is None else built

    def _built_path(self, node: ast.expr, parts: set[int]) -> str | None:
        """The path ``node`` builds when it is a path expression (a join, a ``Path(...)``, a ``/``
        or ``+`` chain, an f-string, or a call that passes a path through), else None. Every node
        read on the way is added to ``parts``."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
            # Walked down the left-leaning chain in a loop: `a + b + ... + z` nests as deep as it
            # is long, and a recursive walk would stop on a long generated one.
            chain: list[ast.BinOp] = []
            current: ast.expr = node
            while isinstance(current, ast.BinOp) and isinstance(current.op, (ast.Div, ast.Add)):
                parts.add(id(current))
                chain.append(current)
                current = current.left
            text = self._path_part(current, parts)
            for link in reversed(chain):
                sep = "/" if isinstance(link.op, ast.Div) else ""
                text += sep + self._path_part(link.right, parts)
            return text
        if isinstance(node, ast.JoinedStr):
            parts.add(id(node))
            text = []
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    text.append(self._path_part(value.value, parts))
                elif isinstance(value, ast.Constant) and isinstance(value.value, str):
                    text.append(value.value)
            return "".join(text)
        if not isinstance(node, ast.Call):
            return None
        name = self._fold_name(node.func)
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if (name in _PATH_JOIN_CALLS or name.split(".")[-1] in _PATH_TYPES) and node.args:
            parts.add(id(node))
            return "/".join(self._path_part(a, parts) for a in node.args)
        if method == "joinpath":
            parts.add(id(node))
            segments = [node.func.value, *node.args]  # type: ignore[union-attr]
            return "/".join(self._path_part(s, parts) for s in segments)
        if method in _PATH_PASSTHROUGH_METHODS and not node.args:
            parts.add(id(node))
            return self._path_part(node.func.value, parts)  # type: ignore[union-attr]
        if name in _PATH_PASSTHROUGH_CALLS and len(node.args) == 1:
            parts.add(id(node))
            return self._path_part(node.args[0], parts)
        return None

    def _check_built_path(self, node: ast.expr) -> None:
        """Flag ``node`` when it is the outermost expression of a credential path built from
        segments: rooted at the home directory (as `~/…` is), or holding a credential path written
        whole in one of its strings. Its sub-expressions are not judged again on their own."""
        if id(node) in self._path_parts:
            return
        parts: set[int] = set()
        built = self._built_path(node, parts)
        self._path_parts |= parts
        if built is None or not _is_credential_path(re.sub(r"/{2,}", "/", built)):
            return
        if built.startswith("~") or any(
            isinstance(sub, ast.Constant)
            and isinstance(sub.value, str)
            and _is_credential_path(sub.value)
            for sub in ast.walk(node)
        ):
            self._add(R_SENS_PY, node)

    def _starts_at_home(self, node: ast.JoinedStr) -> bool:
        first = node.values[0] if node.values else None
        return isinstance(first, ast.FormattedValue) and (
            self._path_part(first.value, set()).rstrip("/") == "~"
        )

    def _is_path_builder(self, node: ast.Call) -> bool:
        """A call that joins path segments: os.path.join(...), Path(...), p.joinpath(...)."""
        if not node.args:
            return False
        name = self._fold_name(node.func)
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        return name in _PATH_JOIN_CALLS or name.split(".")[-1] in _PATH_TYPES or (
            method == "joinpath"
        )

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        if self._starts_at_home(node):
            self._check_built_path(node)
        self.generic_visit(node)

    # -- imports -----------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.aliases[local] = alias.name
            if _is_network_import(alias.name):
                self._add(R_NET, node)
            if alias.name.split(".")[0] in SHELL_MODULES:
                self._add(R_SHELL, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        # A relative import names the package's own module: `from .requests import Request` is
        # the package's requests.py, not the requests library. Its names keep their leading dots,
        # so no check below mistakes them for the library that shares the name.
        prefix = "." * node.level
        for alias in node.names:
            local = alias.asname or alias.name
            self.from_imports[local] = (
                f"{prefix}{module}.{alias.name}" if module else f"{prefix}{alias.name}"
            )
        if node.level == 0 and _is_network_import(module):
            self._add(R_NET, node)
        # Only an absolute import names the library: `from .git import x` is the package's own
        # module, which happens to share the name.
        if node.level == 0 and module.split(".")[0] in SHELL_MODULES:
            self._add(R_SHELL, node)
        self.generic_visit(node)

    # -- loops -------------------------------------------------------------
    def visit_For(self, node: ast.For) -> None:
        self._visit_loop(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_loop(node)

    def _visit_loop(self, node: ast.For | ast.AsyncFor) -> None:
        name = _literal_loop_variable(node)
        if name is None:
            self.generic_visit(node)
            return
        self.visit(node.target)
        self.visit(node.iter)
        self._loop_constants.append(name)
        try:
            for stmt in node.body:
                self.visit(stmt)
        finally:
            self._loop_constants.pop()
        for stmt in node.orelse:
            self.visit(stmt)

    # -- calls -------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        name = self._dotted(node.func)
        if name is not None:
            self._classify_call(name, node)
        if self._is_path_builder(node):
            self._check_built_path(node)
        self.generic_visit(node)

    def _classify_call(self, name: str, node: ast.Call) -> None:
        if name in SHELL_CALLS:
            self._add(R_SHELL, node)
            if not self._deferred and len(self.module_spawns) < MAX_EVIDENCE_SCANNED:
                self.module_spawns.append(self._evidence(node))
            if _is_command_injection(name, node, frozenset(self._loop_constants)):
                self._add(R_CMDI, node)
            command = _shell_command_text(name, node)
            if command is not None and REMOTE_EXEC.search(command):
                self._add(R_PIPE_EXEC_PY, node)
        elif name in UNSAFE_DESERIALIZE_CALLS:
            # Skip if this call is the payload of an enclosing exec/eval/compile — that's the
            # malicious decode-and-execute, already raised as ST-OBF-DECODE-EXEC-PY. Skip too an
            # attribute that only ever holds what this module serialized itself.
            if id(node) not in self._decode_exec_inner and not self._loads_own_state(node):
                self._add(R_DESERIAL, node)
        elif name in ("yaml.load", "yaml.load_all") and _yaml_load_is_unsafe(node):
            self._add(R_DESERIAL, node)
        elif name in DYNAMIC_CALLS or name in _BUILTINS_DYNAMIC:
            self._add(R_DYN, node)
            inner = self._decode_exec_inner_call(node)
            if inner is not None:
                self._decode_exec_inner.add(id(inner))
                self._add(R_DECODE_EXEC_PY, node)
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
        elif _is_network_call(name) and self._root_is_imported(node.func):
            self._add(R_NET, node)
        elif name in _COPYREG_PICKLE and len(node.args) >= 2:
            self._check_copyreg_reducer(node, node.args[1])

        # Independent of the classification above: a credential path passed to a path/IO/process/
        # network call is a real sensitive-data access (e.g. open("~/.aws/credentials"),
        # expanduser("~/.ssh/id_rsa"), subprocess.run(["cat", "~/.ssh/id_rsa"])).
        if _is_path_consumer(name) and any(
            _is_credential_path(s) for s in _iter_string_consts(node)
        ):
            self._add(R_SENS_PY, node)
        # The same for a path an f-string builds: open(f"{base}/.aws/credentials").
        if _is_path_consumer(name):
            for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                if isinstance(arg, ast.JoinedStr):
                    self._check_built_path(arg)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        # A credential path built by string concatenation — e.g.
        # ``os.path.expanduser('~') + '/.aws/credentials'`` or ``os.environ['HOME'] + '/.ssh/...'``
        # — evades the literal-arg check above (the path is never a single open() argument). Flag a
        # strong credential-path string literal used as an operand of ``+``. A bare literal, a list
        # element, or a comparison is NOT a BinOp, so the denylist/guardrail cases stay clean.
        if isinstance(node.op, ast.Add):
            for operand in (node.left, node.right):
                if (
                    isinstance(operand, ast.Constant)
                    and isinstance(operand.value, str)
                    and _is_credential_path(operand.value)
                ):
                    self._add(R_SENS_PY, node)
                    break
        # A path split across operands or joined with `/` onto a Path (see _PATH_JOIN_CALLS).
        if isinstance(node.op, (ast.Add, ast.Div)):
            self._check_built_path(node)
        self.generic_visit(node)

    # -- pickle gadgets ----------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._functions[node.name] = node
        self._check_reduce_gadget(node)
        saved = self._enter_scope(node.body)
        self._deferred += 1
        try:
            self.generic_visit(node)
        finally:
            self._deferred -= 1
            self._restore_scope(saved)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._functions[node.name] = node
        self._check_reduce_gadget(node)
        saved = self._enter_scope(node.body)
        self._deferred += 1
        try:
            self.generic_visit(node)
        finally:
            self._deferred -= 1
            self._restore_scope(saved)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._deferred += 1
        try:
            self.generic_visit(node)
        finally:
            self._deferred -= 1

    def visit_If(self, node: ast.If) -> None:
        if not _is_main_guard(node.test):
            self.generic_visit(node)
            return
        self.visit(node.test)
        self._deferred += 1
        try:
            for stmt in node.body:
                self.visit(stmt)
        finally:
            self._deferred -= 1
        for stmt in node.orelse:
            self.visit(stmt)

    # -- names bound to a module / dangerous callable (resolved within one scope) ----------
    def _enter_scope(self, body: list[ast.stmt]) -> tuple[dict[str, str], dict[str, str]]:
        """Merge this scope's value bindings over the current view and return the previous view,
        so a name bound to a lookup result inside one function does not leak into another."""
        saved = (self.aliases, self.from_imports)
        self.aliases, self.from_imports = _with_bindings(body, self.aliases, self.from_imports)
        return saved

    def _restore_scope(self, saved: tuple[dict[str, str], dict[str, str]]) -> None:
        self.aliases, self.from_imports = saved

    def visit_Assign(self, node: ast.Assign) -> None:
        # `__reduce__ = lambda self: (os.system, (...,))` in a class body: the same gadget.
        if (
            any(isinstance(t, ast.Name) and t.id in _REDUCE_METHODS for t in node.targets)
            and isinstance(node.value, ast.Lambda)
            and self._is_gadget(node.value.body)
        ):
            self._add(R_PICKLE_REDUCE, node)
        self.generic_visit(node)

    def _check_reduce_gadget(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Flag a __reduce__/__reduce_ex__ that returns (<shell/exec callable>, args).

        Pickle calls the first element of the returned tuple when the object is loaded, so
        ``return (os.system, ("...",))`` runs a command on unpickling. A normal __reduce__ returns
        the class or a factory (``(self.__class__, (...))``), which resolves to no dangerous name.
        """
        if node.name in _REDUCE_METHODS:
            self._flag_gadget_return(node)

    def _check_copyreg_reducer(self, call: ast.Call, reducer: ast.expr) -> None:
        """``copyreg.pickle(cls, reducer)``: the reducer runs on pickling and its returned tuple is
        what the loader calls, exactly like a __reduce__ method."""
        if isinstance(reducer, ast.Lambda):
            if self._is_gadget(reducer.body):
                self._add(R_PICKLE_REDUCE, call)
        elif isinstance(reducer, ast.Name) and reducer.id in self._functions:
            self._flag_gadget_return(self._functions[reducer.id])

    def _flag_gadget_return(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        local = _local_assignments(func)
        for sub in ast.walk(func):
            if isinstance(sub, ast.Return) and sub.value is not None:
                if self._is_gadget(sub.value, local):
                    self._add(R_PICKLE_REDUCE, sub)
                    return

    def _is_gadget(self, value: ast.expr, local: dict[str, ast.expr] | None = None) -> bool:
        """``(callable, args)`` whose callable resolves to a REDUCE_GADGET_CALLS name. A name
        assigned in the same function (``f = os.system`` / ``t = (os.system, …)``) is followed
        one step, since aliasing the callable first changes nothing for pickle."""
        local = local or {}
        if isinstance(value, ast.Name) and value.id in local:
            value = local[value.id]
        if not (isinstance(value, ast.Tuple) and value.elts):
            return False
        target = value.elts[0]
        if isinstance(target, ast.Name) and target.id in local:
            target = local[target.id]
        return _resolve_dotted(target, self.aliases, self.from_imports) in REDUCE_GADGET_CALLS

    def _decode_exec_inner_call(self, node: ast.Call) -> ast.Call | None:
        """If ``node`` is exec/eval/compile(<deserialize>(<non-literal>)), return the inner
        deserialize call (the decode-and-execute payload); otherwise None."""
        arg = _first_arg(node)
        if not isinstance(arg, ast.Call):
            return None
        inner = _resolve_dotted(arg.func, self.aliases, self.from_imports)
        if inner not in UNSAFE_DESERIALIZE_CALLS:
            return None
        if not _has_nonliteral_arg(arg):
            return None  # a constant payload is not a dropper (false-positive guard)
        return arg

    def _loads_own_state(self, node: ast.Call) -> bool:
        """True for ``loads(x.attr)`` where every assignment to ``.attr`` in this module stores
        this module's own serialization (``self._meta = dumps(meta)``), ``None`` or the same
        attribute of another object, and at least one stores a ``dumps``: an object reading back
        bytes it pickled itself (rich's ``Style.meta``). An attribute filled anywhere from
        anything else (a socket, a file) keeps the finding, as does any other argument."""
        arg = node.args[0] if node.args else None
        if not isinstance(arg, ast.Attribute) or self._module is None:
            return False
        if self._own_state_attrs is None:
            self._own_state_attrs = self._own_state_attributes(self._module)
        return arg.attr in self._own_state_attrs

    def _own_state_attributes(self, tree: ast.Module) -> frozenset[str]:
        values: dict[str, list[ast.expr | None]] = {}
        for sub in ast.walk(tree):
            if isinstance(sub, ast.Assign):
                targets, value = sub.targets, sub.value
            elif isinstance(sub, (ast.AnnAssign, ast.AugAssign)):
                targets = [sub.target]
                value = None if isinstance(sub, ast.AugAssign) else sub.value
                if value is None and isinstance(sub, ast.AnnAssign):
                    continue  # a bare annotation assigns nothing
            elif (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                  and sub.func.id == "setattr" and len(sub.args) >= 2):
                attr = _const_str(sub.args[1])
                if attr is None:
                    return frozenset()  # sets an attribute it does not name: could be any
                values.setdefault(attr, []).append(None)
                continue
            else:
                continue
            for target in targets:
                for element in ast.walk(target):
                    if isinstance(element, ast.Attribute) and isinstance(element.ctx, ast.Store):
                        direct = element is target
                        values.setdefault(element.attr, []).append(value if direct else None)
        return frozenset(
            attr for attr, assigned in values.items()
            if all(v is not None and self._own_state_value(v, attr) for v in assigned)
            and any(self._is_serializer_call(v) for v in assigned)
        )

    def _own_state_value(self, value: ast.expr, attr: str) -> bool:
        if isinstance(value, ast.Constant) and value.value is None:
            return True
        if isinstance(value, ast.Attribute) and value.attr == attr:
            return True
        if isinstance(value, ast.IfExp):
            return (self._own_state_value(value.body, attr)
                    and self._own_state_value(value.orelse, attr))
        if isinstance(value, ast.BoolOp):
            return all(self._own_state_value(v, attr) for v in value.values)
        return self._is_serializer_call(value)

    def _is_serializer_call(self, value: ast.expr | None) -> bool:
        if isinstance(value, ast.IfExp):
            return self._is_serializer_call(value.body) or self._is_serializer_call(value.orelse)
        if not isinstance(value, ast.Call):
            return False
        return self._dotted(value.func) in _SERIALIZE_CALLS

    # -- internals ---------------------------------------------------------
    def _dotted(self, func: ast.expr) -> str | None:
        """Resolve a call target to a canonical dotted name, applying import aliases."""
        return _resolve_dotted(func, self.aliases, self.from_imports)

    def _root_is_imported(self, func: ast.expr) -> bool:
        """Whether a call's leftmost name was bound by an import in this module.

        `requests.items()` on a parameter called requests is a dict, not the library."""
        root = func
        while isinstance(root, ast.Attribute):
            root = root.value
        if not isinstance(root, ast.Name):
            return True  # a resolved lookup: __import__("requests").get(...)
        return root.id in self.aliases or root.id in self.from_imports

    def _add(self, rule_id: str, node: ast.AST) -> None:
        bucket = self.hits.setdefault(rule_id, [])
        if len(bucket) >= MAX_EVIDENCE_SCANNED:
            return
        bucket.append(self._evidence(node))

    def _add_dynamic_import(self, node: ast.AST) -> None:
        if len(self.dynamic_imports) >= MAX_EVIDENCE_SCANNED:
            return
        self.dynamic_imports.append(self._evidence(node))

    def _evidence(self, node: ast.AST) -> Evidence:
        line_start = getattr(node, "lineno", 1)
        line_end = getattr(node, "end_lineno", line_start) or line_start
        return self.file.evidence_for_lines(line_start, line_end)


# How many attributes and calls deep a target is resolved. Every rule names a short path
# (`os.system`, `getattr(os, "system")`); a chain thousands of links long resolved again from
# each link took time cubic in its length.
_MAX_RESOLVE_DEPTH = 64


def _resolve_dotted(
    func: ast.expr, aliases: dict[str, str], from_imports: dict[str, str], depth: int = 0
) -> str | None:
    """Resolve a call/attribute target to a canonical dotted name, applying import aliases."""
    if isinstance(func, ast.Name):
        return from_imports.get(func.id, func.id)
    if depth >= _MAX_RESOLVE_DEPTH:
        return None
    if isinstance(func, ast.Attribute):
        base = _resolve_dotted(func.value, aliases, from_imports, depth + 1)
        if base is None:
            return func.attr
        parts = base.split(".")
        if parts[0] in aliases:
            parts[0] = aliases[parts[0]]
            base = ".".join(parts)
        return f"{base}.{func.attr}"
    if isinstance(func, ast.Call):
        return _resolve_lookup_call(func, aliases, from_imports, depth + 1)
    return None


def _resolve_lookup_call(
    call: ast.Call, aliases: dict[str, str], from_imports: dict[str, str], depth: int = 0
) -> str | None:
    """``__import__("os")`` -> ``os``; ``getattr(os, "sys" + "tem")`` -> ``os.system``.

    Only for a constant name looked up on a module (imported, or imported right there by name), so
    ``getattr(self, name)`` and ``getattr(obj, "x")`` stay unresolved.
    """
    name = _resolve_dotted(call.func, aliases, from_imports, depth)
    if name in _IMPORT_BY_NAME and call.args:
        return _const_str(call.args[0])
    if name not in _GETATTR or len(call.args) < 2:
        return None
    attr = _const_str(call.args[1])
    owner = call.args[0]
    if attr is None:
        return None
    is_module = isinstance(owner, ast.Call) or (
        isinstance(owner, (ast.Name, ast.Attribute))
        and _root_name(owner) in aliases.keys() | from_imports.keys()
    )
    base = _resolve_dotted(owner, aliases, from_imports, depth) if is_module else None
    if not base:
        return None
    parts = base.split(".")
    if parts[0] in aliases:
        parts[0] = aliases[parts[0]]
    return ".".join([*parts, attr])


def _root_name(node: ast.expr) -> str | None:
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _const_str(node: ast.expr) -> str | None:
    """A string spelled out in constants: ``"system"``, ``"sys" + "tem"``, ``f"sys{'tem'}"``."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _const_str(node.left), _const_str(node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                value = value.value
            part = _const_str(value)
            if part is None:
                return None
            parts.append(part)
        return "".join(parts)
    return None


def _with_bindings(
    body: list[ast.stmt], aliases: dict[str, str], from_imports: dict[str, str]
) -> tuple[dict[str, str], dict[str, str]]:
    """``aliases`` / ``from_imports`` extended with the value bindings of one scope (new dicts
    only when there are bindings, so the caller can keep the old ones to restore)."""
    module_binds, call_binds = _value_bindings(body, aliases, from_imports)
    if module_binds:
        aliases = {**aliases, **module_binds}
    if call_binds:
        from_imports = {**from_imports, **call_binds}
    return aliases, from_imports


def _value_bindings(
    body: list[ast.stmt], aliases: dict[str, str], from_imports: dict[str, str]
) -> tuple[dict[str, str], dict[str, str]]:
    """Plain ``name = <call>`` bindings in a scope that make ``name`` an alias for a module
    (``__import__("os")`` / ``importlib.import_module("os")``) or for a dangerous dotted callable
    (``getattr(<module>, <literal>)``). A name assigned more than once in the scope is ambiguous
    and is not bound (``f = getattr(os, "system"); f = print`` stays unresolved). Module bindings
    are resolved first so a later ``getattr(m, ...)`` in the same scope sees them."""
    assigns: dict[str, list[ast.expr]] = {}
    for value, names in _scope_assignments(body):
        for name in names:
            assigns.setdefault(name, []).append(value)
    module_binds: dict[str, str] = {}
    for name, values in assigns.items():
        if len(values) == 1:
            module = _bound_module(values[0], aliases, from_imports)
            if module is not None:
                module_binds[name] = module
    view = {**aliases, **module_binds} if module_binds else aliases
    call_binds: dict[str, str] = {}
    for name, values in assigns.items():
        if len(values) == 1 and name not in module_binds:
            dotted = _bound_callable(values[0], view, from_imports)
            if dotted is not None:
                call_binds[name] = dotted
    return module_binds, call_binds


def _bound_module(
    value: ast.expr, aliases: dict[str, str], from_imports: dict[str, str]
) -> str | None:
    """The module a ``__import__`` / ``importlib.import_module`` call imports, when it is spelled
    out as a constant (so a dynamic ``__import__(pkg)`` does not bind)."""
    if not isinstance(value, ast.Call):
        return None
    name = _resolve_dotted(value.func, aliases, from_imports)
    if name in _IMPORT_BY_NAME and value.args:
        return _const_str(value.args[0])
    return None


def _bound_callable(
    value: ast.expr, view: dict[str, str], from_imports: dict[str, str]
) -> str | None:
    """The dotted callable a ``getattr(<module>, <literal>)`` resolves to, or None."""
    if not isinstance(value, ast.Call):
        return None
    if _resolve_dotted(value.func, view, from_imports) not in _GETATTR:
        return None
    return _resolve_lookup_call(value, view, from_imports)


def _scope_assignments(body: list[ast.stmt]):
    """Yield ``(value, [names])`` for each ``name = value`` / ``name: T = value`` with only plain
    Name targets in a scope, descending into its compound statements (if/for/while/with/try) but
    not into nested function or class bodies, which are scopes of their own."""
    stack = list(reversed(body))
    while stack:
        stmt = stack.pop()
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, ast.Assign) and stmt.targets and all(
            isinstance(t, ast.Name) for t in stmt.targets
        ):
            yield stmt.value, [t.id for t in stmt.targets]  # type: ignore[attr-defined]
        elif (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and stmt.value is not None
        ):
            yield stmt.value, [stmt.target.id]
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                stack.append(child)


def _local_assignments(func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, ast.expr]:
    """``name = value`` assignments in a function body (the last one wins)."""
    local: dict[str, ast.expr] = {}
    for sub in ast.walk(func):
        if isinstance(sub, ast.Assign) and len(sub.targets) == 1:
            target = sub.targets[0]
            if isinstance(target, ast.Name):
                local[target.id] = sub.value
    return local


def _first_arg(node: ast.Call) -> ast.expr | None:
    return node.args[0] if node.args else None


def _has_nonliteral_arg(call: ast.Call) -> bool:
    """True if the call has at least one positional argument that is not a bare literal."""
    return any(not isinstance(a, ast.Constant) for a in call.args)


def _target_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for elt in target.elts:
            names.extend(_target_names(elt))
        return names
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []


def _suppress_cmdi_covered_by_taint(acc: dict[str, list[Evidence]]) -> None:
    """When ST-TAINT-SHELL-PY fires on a call, drop the weaker ST-CMDI-PY evidence on the same
    node so the same injection is scored once (the more specific taint finding wins)."""
    taint_shell = acc.get(R_TAINT_SHELL)
    cmdi = acc.get(R_CMDI)
    if not taint_shell or not cmdi:
        return
    spans = {(e.file, e.line_start, e.line_end) for e in taint_shell}
    kept = [e for e in cmdi if (e.file, e.line_start, e.line_end) not in spans]
    if kept:
        acc[R_CMDI] = kept
    else:
        acc.pop(R_CMDI, None)


class _TaintVisitor:
    """Conservative intra-procedural taint: flags an untrusted SOURCE reaching a dangerous SINK
    within a single function body. Per-function scope, default-deny propagation, sanitizers clear
    taint. Inter-procedural flow, attribute/container aliasing and closures are intentionally not
    tracked (false-positive control)."""

    def __init__(self, file: IndexedFile):
        self.file = file
        self.hits: dict[str, list[Evidence]] = {}
        self.aliases: dict[str, str] = {}
        self.from_imports: dict[str, str] = {}

    def analyze(self, tree: ast.Module) -> None:
        self._collect_imports(tree)
        # Names bound to a module / dangerous callable resolve here exactly as in _CallVisitor, so
        # a tainted value reaching `f(...)` for `f = getattr(os, "system")` is the same sink.
        self.aliases, self.from_imports = _with_bindings(
            tree.body, self.aliases, self.from_imports
        )
        self._walk_scope(tree.body, set())

    # -- imports (resolution only) ----------------------------------------
    def _collect_imports(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    local = alias.asname or alias.name
                    self.from_imports[local] = (
                        f"{module}.{alias.name}" if module else alias.name
                    )

    # -- scope walk -------------------------------------------------------
    def _walk_scope(self, body: list[ast.stmt], tainted: set[str]) -> None:
        for stmt in body:
            self._walk_stmt(stmt, tainted)

    def _walk_stmt(self, stmt: ast.stmt, tainted: set[str]) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            inner: set[str] = set()
            self._seed_mcp_params(stmt, inner)
            saved = (self.aliases, self.from_imports)
            self.aliases, self.from_imports = _with_bindings(
                stmt.body, self.aliases, self.from_imports
            )
            try:
                self._walk_scope(stmt.body, inner)
            finally:
                self.aliases, self.from_imports = saved
            return
        if isinstance(stmt, ast.ClassDef):
            self._walk_scope(stmt.body, set())
            return
        if isinstance(stmt, _COMPOUND_STMTS):
            for expr in self._header_exprs(stmt):
                self._check_exprs_for_sinks(expr, tainted)
            for sub in self._child_bodies(stmt):
                self._walk_scope(sub, tainted)
            return
        # Simple statement: a sink in it evaluates with the CURRENT taint, then the target binds.
        self._check_exprs_for_sinks(stmt, tainted)
        self._apply_assignment(stmt, tainted)

    def _check_exprs_for_sinks(self, root: ast.AST, tainted: set[str]) -> None:
        for node in ast.walk(root):
            if isinstance(node, ast.Call):
                self._check_sink(node, tainted)

    # -- taint propagation ------------------------------------------------
    def _apply_assignment(self, stmt: ast.stmt, tainted: set[str]) -> None:
        if isinstance(stmt, ast.Assign):
            t = self._is_tainted(stmt.value, tainted)
            for tgt in stmt.targets:
                for name in _target_names(tgt):
                    tainted.add(name) if t else tainted.discard(name)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            t = self._is_tainted(stmt.value, tainted)
            for name in _target_names(stmt.target):
                tainted.add(name) if t else tainted.discard(name)
        elif isinstance(stmt, ast.AugAssign):
            if self._is_tainted(stmt.value, tainted) or (
                isinstance(stmt.target, ast.Name) and stmt.target.id in tainted
            ):
                for name in _target_names(stmt.target):
                    tainted.add(name)

    def _is_tainted(self, expr: ast.expr | None, tainted: set[str]) -> bool:
        if expr is None:
            return False
        if isinstance(expr, ast.Name):
            return expr.id in tainted
        if self._is_source_expr(expr):
            return True
        if isinstance(expr, ast.JoinedStr):
            return any(
                self._is_tainted(v.value, tainted)
                for v in expr.values
                if isinstance(v, ast.FormattedValue)
            )
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
            return self._is_tainted(expr.left, tainted) or self._is_tainted(expr.right, tainted)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_tainted(e, tainted) for e in expr.elts)
        if isinstance(expr, ast.Starred):
            return self._is_tainted(expr.value, tainted)
        if isinstance(expr, ast.IfExp):
            return self._is_tainted(expr.body, tainted) or self._is_tainted(expr.orelse, tainted)
        if isinstance(expr, ast.Subscript):
            return self._is_tainted(expr.value, tainted)
        if isinstance(expr, ast.Call):
            name = _resolve_dotted(expr.func, self.aliases, self.from_imports)
            if name in _SANITIZERS:
                return False
            if isinstance(expr.func, ast.Attribute) and expr.func.attr in _STR_TAINT_METHODS:
                if self._is_tainted(expr.func.value, tainted):
                    return True
                return any(self._is_tainted(a, tainted) for a in expr.args)
            return False
        if isinstance(expr, ast.Attribute):
            return self._is_tainted(expr.value, tainted)
        return False

    def _is_source_expr(self, expr: ast.expr) -> bool:
        if isinstance(expr, ast.Attribute):
            dotted = _resolve_dotted(expr, self.aliases, self.from_imports)
            if dotted in _SOURCE_ATTRS:
                return True
            return expr.attr in _NET_BODY_ATTRS and self._is_network_result(expr.value)
        if isinstance(expr, ast.Call):
            name = _resolve_dotted(expr.func, self.aliases, self.from_imports)
            if name in _SOURCE_CALLS:
                return True
            if (
                isinstance(expr.func, ast.Attribute)
                and expr.func.attr in _NET_BODY_ATTRS
                and self._is_network_result(expr.func.value)
            ):
                return True
        return False

    def _is_network_result(self, expr: ast.expr) -> bool:
        if isinstance(expr, ast.Call):
            name = _resolve_dotted(expr.func, self.aliases, self.from_imports)
            return bool(name) and _is_network_call(name)
        return False

    # -- sinks ------------------------------------------------------------
    def _check_sink(self, node: ast.Call, tainted: set[str]) -> None:
        name = _resolve_dotted(node.func, self.aliases, self.from_imports)
        if name is None:
            return
        if name in DYNAMIC_CALLS or name in _BUILTINS_DYNAMIC:
            if self._is_tainted(_first_arg(node), tainted):
                self._add(R_TAINT_EXEC, node)
        elif name in UNSAFE_DESERIALIZE_CALLS:
            if self._is_tainted(_first_arg(node), tainted):
                self._add(R_TAINT_DESERIAL, node)
        elif name in ("yaml.load", "yaml.load_all") and _yaml_load_is_unsafe(node):
            if self._is_tainted(_first_arg(node), tainted):
                self._add(R_TAINT_DESERIAL, node)
        elif self._is_shell_sink(name, node):
            if self._is_tainted(_command_arg(node), tainted):
                self._add(R_TAINT_SHELL, node)

    def _is_shell_sink(self, name: str, node: ast.Call) -> bool:
        return name in ALWAYS_SHELL_CALLS or (
            name.startswith("subprocess.") and _shell_true(node)
        )

    # -- MCP tool handler parameters -------------------------------------
    def _seed_mcp_params(
        self, fn: ast.FunctionDef | ast.AsyncFunctionDef, tainted: set[str]
    ) -> None:
        if not self._is_mcp_tool(fn):
            return
        a = fn.args
        for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs]:
            tainted.add(arg.arg)
        if a.vararg:
            tainted.add(a.vararg.arg)
        if a.kwarg:
            tainted.add(a.kwarg.arg)

    def _is_mcp_tool(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for dec in fn.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            dotted = _resolve_dotted(target, self.aliases, self.from_imports)
            if dotted and dotted.split(".")[-1] == _MCP_TOOL_DECORATOR_LEAF:
                return True
        return False

    # -- helpers ----------------------------------------------------------
    def _header_exprs(self, stmt: ast.stmt) -> list[ast.expr]:
        if isinstance(stmt, (ast.If, ast.While)):
            return [stmt.test]
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            return [stmt.iter]
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            return [item.context_expr for item in stmt.items]
        return []

    def _child_bodies(self, stmt: ast.stmt) -> list[list[ast.stmt]]:
        bodies: list[list[ast.stmt]] = [list(getattr(stmt, "body", []))]
        if isinstance(stmt, ast.Try):
            for handler in stmt.handlers:
                bodies.append(handler.body)
            bodies.append(stmt.finalbody)
        bodies.append(list(getattr(stmt, "orelse", [])))
        return [b for b in bodies if b]

    def _add(self, rule_id: str, node: ast.AST) -> None:
        bucket = self.hits.setdefault(rule_id, [])
        line_start = getattr(node, "lineno", 1)
        line_end = getattr(node, "end_lineno", line_start) or line_start
        ev = self.file.evidence_for_lines(line_start, line_end)
        span = (ev.file, ev.line_start, ev.line_end)
        if len(bucket) >= MAX_EVIDENCE_SCANNED:
            return
        if all((e.file, e.line_start, e.line_end) != span for e in bucket):
            bucket.append(ev)


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
        if "\n" not in expr.value:
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


def _is_dynamic_command(arg: ast.expr | None, constants: frozenset[str] = frozenset()) -> bool:
    """True if the command is built from anything other than pure constants.

    ``constants`` are names that can only hold literal strings here (the variable of a loop over a
    literal list of strings, inside that loop)."""
    if arg is None:
        return False
    if isinstance(arg, ast.Constant):
        return False
    if isinstance(arg, ast.Name) and arg.id in constants:
        return False
    if isinstance(arg, ast.JoinedStr):  # f-string: dynamic only if it interpolates a non-constant
        return any(
            isinstance(v, ast.FormattedValue) and _is_dynamic_command(v.value, constants)
            for v in arg.values
        )
    if isinstance(arg, ast.BinOp):  # "a " + x  or  "fmt %s" % x
        if not isinstance(arg.op, (ast.Add, ast.Mod)):
            return False
        if constants:
            return _is_dynamic_command(arg.left, constants) or _is_dynamic_command(
                arg.right, constants
            )
        return True
    if isinstance(arg, (ast.List, ast.Tuple)):  # argv form: dynamic if any element is
        return any(_is_dynamic_command(e, constants) for e in arg.elts)
    # Name / Attribute / Subscript / Call (e.g. .format(), or any variable) -> dynamic.
    return isinstance(arg, (ast.Name, ast.Attribute, ast.Subscript, ast.Call))


def _literal_loop_variable(node: ast.For | ast.AsyncFor) -> str | None:
    """The variable of ``for x in ["a", "b"]`` when the loop body never rebinds it, else None."""
    if not isinstance(node.target, ast.Name):
        return None
    elts = node.iter.elts if isinstance(node.iter, (ast.List, ast.Tuple, ast.Set)) else []
    if not elts or not all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in elts):
        return None
    name = node.target.id
    for stmt in node.body:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Name) and sub.id == name and not isinstance(sub.ctx, ast.Load):
                return None
    return name


def _is_command_injection(
    name: str, node: ast.Call, constants: frozenset[str] = frozenset()
) -> bool:
    """Shell call + dynamic command = injectable. Excludes argv-without-shell (safe)."""
    uses_shell = name in ALWAYS_SHELL_CALLS or (
        name.startswith("subprocess.") and _shell_true(node)
    )
    if not uses_shell:
        return False
    return _is_dynamic_command(_command_arg(node), constants)


def _shell_command_text(name: str, node: ast.Call) -> str | None:
    """The command a shell receives from this call, as far as it is written in the source: the
    command string of a call that runs through a shell, or the string after ``-c`` in an argv list
    that starts a shell (``["bash", "-c", "…"]``). A part computed at run time (an f-string field,
    a concatenated variable) reads as ``X``, so ``f"curl {url} | bash"`` is still a download piped
    into a shell. None when the call hands no command to a shell."""
    arg = _command_arg(node)
    if arg is None:
        return None
    if name in ALWAYS_SHELL_CALLS or (name.startswith("subprocess.") and _shell_true(node)):
        return _literal_text(arg)
    if isinstance(arg, (ast.List, ast.Tuple)) and len(arg.elts) >= 3:
        program = _literal_text(arg.elts[0]) or ""
        flag = _literal_text(arg.elts[1]) or ""
        if program.rsplit("/", 1)[-1] in _SHELL_PROGRAMS and flag.startswith("-") and "c" in flag:
            return _literal_text(arg.elts[2])
    return None


def _literal_text(expr: ast.expr) -> str | None:
    """The text of a string expression with its run-time parts as ``X``: a literal, an f-string,
    or a ``+`` concatenation that holds at least one literal. None for anything else."""
    if isinstance(expr, ast.Constant):
        return expr.value if isinstance(expr.value, str) else None
    if isinstance(expr, ast.JoinedStr):
        return "".join(
            v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else "X"
            for v in expr.values
        )
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left, right = _literal_text(expr.left), _literal_text(expr.right)
        if left is None and right is None:
            return None
        return (left if left is not None else "X") + (right if right is not None else "X")
    return None


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


# --- paths a module writes (read by the agent-configuration check) ----------------------------
# Calls that write the file named by one of their arguments: (call, index of the target argument).
_COPY_CALLS = {
    "shutil.copy": 1, "shutil.copy2": 1, "shutil.copyfile": 1, "shutil.move": 1,
    "os.rename": 1, "os.replace": 1,
}
_OPEN_CALLS = frozenset({"open", "io.open", "codecs.open"})
_MODULE_OPENS = frozenset({"io.open", "codecs.open", "os.open"})


@dataclass(frozen=True)
class PathWrite:
    """A call that writes a file, the path it writes (``~`` for the home directory, ``\x00`` for
    a segment that cannot be named) and whether it runs when the module is imported."""

    evidence: Evidence
    path: str
    top_level: bool


def python_path_writes(f: IndexedFile) -> list[PathWrite]:
    """Every file write in a Python module, with the path it writes as far as it can be read:
    ``open(p, "w")``, ``p.write_text()``, ``p.open("a")``, ``shutil.copy(src, p)``. A name the
    path was assigned to is followed (``target = Path.home() / ".x"; target.write_text(...)``).
    Parsing only: nothing is run."""
    try:
        tree = ast.parse(f.text, filename=f.relpath)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    def walk() -> list[PathWrite]:
        visitor = _WriteVisitor(f)
        visitor.visit(tree)
        return visitor.writes

    try:
        return walk_deep(walk)
    except RecursionError:
        return []


class _WriteVisitor(_CallVisitor):
    """The import resolution, home-directory folding and import-time tracking of _CallVisitor,
    collecting file writes instead of rule hits."""

    def __init__(self, file: IndexedFile):
        super().__init__(file)
        self.writes: list[PathWrite] = []
        self._assigned: dict[str, ast.expr] = {}
        self._resolving: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            self._assigned[node.targets[0].id] = node.value
        super().visit_Assign(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self._assigned[node.target.id] = node.value
        self.generic_visit(node)

    def _path_part(self, node: ast.expr, parts: set[int]) -> str:
        # One name deep per hop, and never round a cycle (`p = p / "x"`).
        if (isinstance(node, ast.Name) and node.id not in self._home_names
                and node.id in self._assigned and node.id not in self._resolving):
            self._resolving.add(node.id)
            try:
                return super()._path_part(self._assigned[node.id], parts)
            finally:
                self._resolving.discard(node.id)
        return super()._path_part(node, parts)

    def visit_Call(self, node: ast.Call) -> None:
        target = self._write_target(node)
        if target is not None and len(self.writes) < MAX_EVIDENCE_SCANNED:
            path = re.sub(r"/{2,}", "/", self._path_part(target, set()).replace("\\", "/"))
            self.writes.append(PathWrite(self._evidence(node), path, not self._deferred))
        self.generic_visit(node)

    def _write_target(self, node: ast.Call) -> ast.expr | None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in FS_WRITE_SUFFIXES:
            return func.value
        name = self._dotted(func) or ""
        if isinstance(func, ast.Attribute) and func.attr == "open" and name not in _MODULE_OPENS:
            # pathlib: p.open("w"). A receiver the resolver cannot name may read as plain "open".
            mode = node.args[0] if node.args else next(
                (kw.value for kw in node.keywords if kw.arg == "mode"), None)
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(
                ch in WRITE_MODE_CHARS for ch in mode.value
            ):
                return func.value
            return None
        if name in _OPEN_CALLS and _open_is_write(node):
            return node.args[0] if node.args else next(
                (kw.value for kw in node.keywords if kw.arg == "file"), None)
        if name in _COPY_CALLS and len(node.args) > _COPY_CALLS[name]:
            return node.args[_COPY_CALLS[name]]
        return None


# --- what each call does (read by the MCP tool-annotation check) ------------------------------
EFFECT_WRITE = "write"
EFFECT_DELETE = "delete"
EFFECT_EXEC = "exec"
EFFECT_NETWORK = "network"
_RULE_EFFECTS = {R_FS_WRITE: EFFECT_WRITE, R_SHELL: EFFECT_EXEC, R_NET: EFFECT_NETWORK}
_DELETE_CALLS = frozenset({"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "shutil.rmtree"})
# pathlib's Path.unlink() / Path.rmdir(), on whatever receiver holds the path.
_DELETE_METHODS = frozenset({"unlink", "rmdir"})


@dataclass(frozen=True)
class CallEffect:
    """A call that writes or deletes a file, runs a process or reaches the network, as the rules
    above classify it, with its target resolved through the module's imports."""

    call: ast.Call
    name: str
    effects: frozenset[str]


def python_call_effects(f: IndexedFile, tree: ast.Module) -> list[CallEffect]:
    """Every call in ``tree`` that ST-FS-PY-WRITE, ST-SHELL-PY or ST-NET-PY counts, plus file
    deletes (``os.remove``, ``shutil.rmtree``, ``Path.unlink``), in visiting order. The same
    classification as the rules, so a caller scoping it to one function sees what they see."""

    def walk() -> list[CallEffect]:
        visitor = _EffectVisitor(f)
        visitor.visit(tree)
        return [
            CallEffect(call, visitor.names[key], frozenset(kinds))
            for key, (call, kinds) in visitor.effects.items()
        ]

    try:
        return walk_deep(walk)
    except RecursionError:
        return []


class _EffectVisitor(_CallVisitor):
    """_CallVisitor, noting which calls its rule hits land on."""

    def __init__(self, file: IndexedFile):
        super().__init__(file)
        self.effects: dict[int, tuple[ast.Call, set[str]]] = {}
        self.names: dict[int, str] = {}

    def _classify_call(self, name: str, node: ast.Call) -> None:
        self.names[id(node)] = name
        super()._classify_call(name, node)
        if name in _DELETE_CALLS or (
            isinstance(node.func, ast.Attribute) and node.func.attr in _DELETE_METHODS
        ):
            self._note(node, EFFECT_DELETE)

    def _add(self, rule_id: str, node: ast.AST) -> None:
        super()._add(rule_id, node)
        effect = _RULE_EFFECTS.get(rule_id)
        if effect is not None and isinstance(node, ast.Call):
            self._note(node, effect)

    def _note(self, node: ast.Call, effect: str) -> None:
        self.names.setdefault(id(node), self._dotted(node.func) or "")
        self.effects.setdefault(id(node), (node, set()))[1].add(effect)


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


# `urllib.parse` splits and joins URLs and `urllib.error` holds its exceptions; neither opens a
# connection. Only `urllib.request` (and the aliases pointing at it) is egress.
_NON_NETWORK_MODULES = ("urllib.parse", "urllib.error", "urllib.robotparser")


def _is_credential_path(value: str) -> bool:
    """A strong credential path, except an instance-metadata URL that asks for no credentials.

    Regex text that names a credential path is a detector's pattern, not a path: a path never holds
    a regex group opener, and a pattern built by concatenation (``r"(?i)~/\\.aws|" + rest``) read as
    a path built from segments made a security tool's own rules a credential read."""
    if "(?" in value:
        return False
    m = _STRONG_PATHS.search(value)
    return bool(m) and not is_metadata_without_credentials(m.group(0), value)


def _is_network_module(module: str) -> bool:
    if not module or module.startswith(_NON_NETWORK_MODULES):
        return False
    head = module.split(".")[0]
    # Whole names only: `urllib3_version_list.append` is a list, not urllib.
    return (
        head in NETWORK_HEADS or head in ("urllib", "urllib3") or _is_under(module, "http.client")
    )


def _is_network_import(module: str) -> bool:
    """Importing ``module`` counts as network access. Not ``http.client`` by itself: its status
    table (``http.client.responses``) is read for reason phrases; a connection is a call."""
    return _is_network_module(module) and module != "http.client"


def _is_network_call(name: str) -> bool:
    return _is_network_module(name)


def _is_under(name: str, module: str) -> bool:
    return name == module or name.startswith(module + ".")


def _dedupe(evidence: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, int, int]] = set()
    out: list[Evidence] = []
    for e in evidence:
        key = (e.file, e.line_start, e.line_end)
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out
