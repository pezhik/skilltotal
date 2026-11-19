"""Four shapes of remote-code and remote-access setup that the generic network rules do not join.

* A Python function that downloads a script from an address and runs the text it got back
  (``exec(urlopen(url).read())``). Fetching JSON, or running a local file, is not this.
* A file that starts an SSH server AND a public tunnel client:
  together they publish a login on the machine to the internet. Either alone is ordinary.
* An npm package named for one platform (``-linux-x64``) that has an install hook running a file
  that downloads from the network. An honest platform package ships its binary in the tarball.
  ``platform_fetch_evidence`` feeds ``ST-INSTALL-NPM-REMOTE-EXEC`` (install_scripts.py).
* An agent launcher that sends the model API to another host AND turns approvals off, or adds a
  Defender exclusion, in the same file.

Detection is parsing and pattern matching only; nothing here runs.
"""

from __future__ import annotations

import ast
import json
import posixpath
import re
from collections.abc import Callable

from skilltotal import bounded_json
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.loaded_code import _module_paths
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.agent_approval import _elsewhere
from skilltotal.scanners.base import (
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    searched_for,
)
from skilltotal.scanners.node_fetch_exec import NODE_SUFFIXES, code_sink_heads, fetched_text_sinks
from skilltotal.scanners.py_download_run import RUN_TEXT, download_runs
from skilltotal.scanners.python_ast import _DOWNLOAD_RUN_REACH, _resolve_dotted

R_PY_FETCH_EXEC = "ST-PY-FETCH-EXEC"
R_NODE_FETCH_EXEC = "ST-NODE-FETCH-EXEC"
R_SSH_TUNNEL = "ST-SSH-TUNNEL-BACKDOOR"
R_LAUNCHER_HIJACK = "ST-AGENT-LAUNCHER-HIJACK"

_PY_SUFFIXES = (".py", ".pyw")
_CODE_SUFFIXES = (".py", ".pyw", ".js", ".cjs", ".mjs", ".ts", ".sh", ".bash", ".ps1")
_NODE_SUFFIXES = (".js", ".cjs", ".mjs", ".ts")

# --- Python: fetched text reaches exec / eval / compile -------------------------------------
_FETCH_FUNCS = frozenset({"urlopen", "urlretrieve"})
_HTTP_VERBS = frozenset({"get", "post", "request", "fetch"})
_HTTP_MODULES = frozenset({"requests", "httpx", "session", "client", "http", "urllib3", "aiohttp"})
_RUNNERS = frozenset({"exec", "eval"})
_BODY_ATTRS = frozenset({"read", "text", "content", "decode", "json", "body", "data", "strip"})


def _is_fetch_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    fn = node.func
    if isinstance(fn, ast.Name):
        return fn.id == "urlopen"
    if isinstance(fn, ast.Attribute):
        if fn.attr == "urlopen":
            return True
        base = fn.value
        return fn.attr in _HTTP_VERBS and isinstance(base, ast.Name) and base.id in _HTTP_MODULES
    return False


_Remote = Callable[[ast.Call], bool]


def _tainted(node: ast.AST, names: set[str], remote: _Remote | None = None) -> bool:
    """True if the expression is (derived from) a fetched response. ``remote`` says whether a call
    is to a function of another module of the component that returns one."""
    if isinstance(node, ast.Name):
        return node.id in names
    if _is_fetch_call(node):
        return True
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr in _BODY_ATTRS | {"encode", "decode"}:
            if _tainted(fn.value, names, remote):
                return True
        if isinstance(fn, ast.Name) and fn.id in ("str", "bytes", "compile", "bytearray"):
            return any(_tainted(a, names, remote) for a in node.args)
        return remote is not None and remote(node)
    if isinstance(node, ast.Attribute):
        return node.attr in _BODY_ATTRS and _tainted(node.value, names, remote)
    if isinstance(node, ast.Subscript):
        return _tainted(node.value, names, remote)
    return False


def _fetched_flow(
    scope: ast.AST, remote: _Remote | None, *, returned: bool = False
) -> ast.AST | None:
    """The first exec / eval call of ``scope`` that is given a fetched response or, with
    ``returned``, the first ``return`` of one."""
    names: set[str] = set()
    nodes = sorted(
        (n for n in ast.walk(scope) if hasattr(n, "lineno")),
        key=lambda n: (n.lineno, n.col_offset),
    )
    for node in nodes:
        if isinstance(node, ast.Assign) and _tainted(node.value, names, remote):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.optional_vars, ast.Name) and _tainted(
                    item.context_expr, names, remote
                ):
                    names.add(item.optional_vars.id)
        elif returned:
            if isinstance(node, ast.Return) and node.value is not None and _tainted(
                node.value, names, remote
            ):
                return node
        elif isinstance(node, ast.Call) and node.args and _is_runner(node.func) \
                and _tainted(node.args[0], names, remote):
            return node
    return None


# --- a fetched response returned by a function of another module of the component -------------
# `exec(bridge.staged())`, where `bridge.staged` returns `download.payload()` and that returns
# `requests.get(url).text`: the fetch and the exec are in different files. A call is followed only
# into a module the file imports that is a file of the component, a few modules deep.
_MAX_HOPS = 3
_MAX_MODULE_CHARS = 400_000
_MAX_MODULES_PARSED = 40


class _Modules:
    """The Python modules of one component, for calls from one of them into another."""

    def __init__(self, index: FileIndex) -> None:
        self._index = index
        self._files: dict[str, IndexedFile] | None = None
        self._trees: dict[str, ast.Module | None] = {}
        self._imports: dict[str, dict[str, tuple[str, str | None]]] = {}
        self._returns: dict[tuple[str, str], bool] = {}

    def _file(self, relpath: str) -> IndexedFile | None:
        if self._files is None:
            self._files = {f.relpath: f for f in self._index.select(suffixes=_PY_SUFFIXES)}
        return self._files.get(relpath)

    def tree(self, f: IndexedFile) -> ast.Module | None:
        if f.relpath not in self._trees:
            tree = None
            if len(f.text) <= _MAX_MODULE_CHARS and len(self._trees) < _MAX_MODULES_PARSED:
                try:
                    tree = ast.parse(f.text)
                except (SyntaxError, ValueError, RecursionError, MemoryError):
                    tree = None
            self._trees[f.relpath] = tree
        return self._trees[f.relpath]

    def _module_file(self, bases: list[str], parts: list[str]) -> str | None:
        for base in bases:
            for candidate in _module_paths(base, parts):
                if self._file(candidate) is not None:
                    return candidate
        return None

    def _bindings(self, f: IndexedFile) -> dict[str, tuple[str, str | None]]:
        """Local name -> (module file, function name), or (module file, None) for a name bound
        to the module itself, for the imports of ``f`` that are files of the component."""
        if f.relpath in self._imports:
            return self._imports[f.relpath]
        bound: dict[str, tuple[str, str | None]] = {}
        self._imports[f.relpath] = bound
        tree = self.tree(f)
        if tree is None:
            return bound
        package = posixpath.dirname(f.relpath)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    parts = alias.name.split(".")
                    if alias.asname is None and len(parts) > 1:
                        continue
                    module = self._module_file([package, ""], parts)
                    if module is not None:
                        bound[alias.asname or alias.name] = (module, None)
            elif isinstance(node, ast.ImportFrom):
                base = package
                for _ in range(max(node.level - 1, 0)):
                    base = posixpath.dirname(base)
                bases = [base] if node.level else [package, ""]
                parts = node.module.split(".") if node.module else []
                for alias in node.names:
                    local = alias.asname or alias.name
                    submodule = self._module_file(bases, [*parts, alias.name])
                    if submodule is not None:
                        bound[local] = (submodule, None)
                        continue
                    module = self._module_file(bases, parts) if parts else None
                    if module is not None:
                        bound[local] = (module, alias.name)
        return bound

    def returns_fetched(self, f: IndexedFile, call: ast.Call, hops: int = 0) -> bool:
        """True if ``call`` in ``f`` is to a function of another module of the component that
        returns a fetched response, itself or through a function of a further module."""
        fn = call.func
        target: tuple[str, str | None] | None = None
        if isinstance(fn, ast.Name):
            target = self._bindings(f).get(fn.id)
            if target is not None and target[1] is None:
                target = None
        elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
            module = self._bindings(f).get(fn.value.id)
            if module is not None and module[1] is None:
                target = (module[0], fn.attr)
        if target is None or target[1] is None or hops >= _MAX_HOPS:
            return False
        key = (target[0], target[1])
        if key not in self._returns:
            self._returns[key] = False  # a cycle of calls returns nothing fetched
            defined = self._file(target[0])
            tree = self.tree(defined) if defined is not None else None
            for node in tree.body if tree is not None and defined is not None else ():
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                        and node.name == target[1]:
                    inner = defined

                    def remote(c: ast.Call, inner: IndexedFile = inner) -> bool:
                        return self.returns_fetched(inner, c, hops + 1)

                    self._returns[key] = _fetched_flow(node, remote, returned=True) is not None
                    break
        return self._returns[key]


_BUILTINS_ALIASES = {"builtins": "builtins"}
_RUNNER_NAMES = _RUNNERS | {f"builtins.{name}" for name in _RUNNERS}


def _is_runner(func: ast.expr) -> bool:
    """exec / eval, written out or looked up on the builtins module: ``builtins.exec``,
    ``getattr(builtins, "ex" + "ec")``, ``__builtins__.__dict__["exec"]``,
    ``vars(builtins)["exec"]`` (see python_ast: a lookup resolves only for a name spelled out in
    constants)."""
    if isinstance(func, ast.Name):
        return func.id in _RUNNERS
    if not isinstance(func, (ast.Attribute, ast.Call, ast.Subscript)):
        return False
    return _resolve_dotted(func, _BUILTINS_ALIASES, {}) in _RUNNER_NAMES


_RUNNER_WORD = re.compile(r"\b(?:exec|eval)\b")


def _could_run_text(text: str) -> bool:
    """False only when no call to exec or eval can be in the file. A runner is a bare name, so in
    ASCII source it is spelled out as a whole word; elsewhere Python folds look-alike letters
    (NFKC) into it, so a file with any non-ASCII text is parsed whatever it spells. Most files hold
    neither name, and parsing and walking them for this rule cost as much as the whole Python
    scanner (2026-11-07 profile)."""
    return (not text.isascii() or _RUNNER_WORD.search(text) is not None
            or "builtins" in text)


def _py_fetch_exec(f: IndexedFile, modules: _Modules | None = None) -> Evidence | None:
    if not _could_run_text(f.text):
        return None
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    scopes: list[ast.AST] = [tree] + [
        n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    remote: _Remote | None = None
    if modules is not None:
        def remote(call: ast.Call) -> bool:
            return modules.returns_fetched(f, call)
    for scope in scopes:
        try:
            hit = _fetched_flow(scope, remote)
        except RecursionError:
            return None
        if hit is not None:
            end = getattr(hit, "end_lineno", hit.lineno) or hit.lineno
            return f.evidence_for_lines(hit.lineno, end)
    return None


# --- SSH server + public tunnel --------------------------------------------------------------
# Written with one-letter classes so the patterns do not match their own source text.
_SSH_SERVER = re.compile(
    r"[\"'/ ]s[s]hd[\"' ]|\bPermitEmpt[y]Passwords\b|\bcheck_auth_[n]one\b"
    r"|\basyncssh\.(?:listen|create_server)\b|\bparamiko\.ServerInterface\b|\bdropbea[r]\b"
)
_TUNNEL_CLIENT = re.compile(
    r"\b(?:n[g]rok|pyn[g]rok|[l]ocaltunnel|serve[o]|localhost\.run|cloudflare[d]|bore\.pub)\b"
)


# A keyword list handed to a rule or matcher (`keywords=("a", ...)`) names tools; it starts none.
_LIST_KEYWORDS = frozenset({"keywords", "patterns", "pattern", "names", "indicators", "terms"})


def _listed_lines(f: IndexedFile) -> set[int]:
    if f.suffix not in _PY_SUFFIXES:
        return set()
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return set()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg in _LIST_KEYWORDS:
            end = getattr(node.value, "end_lineno", node.value.lineno) or node.value.lineno
            lines.update(range(node.value.lineno, end + 1))
    return lines


def _ssh_tunnel(f: IndexedFile) -> list[Evidence]:
    text = f.text
    # Both patterns must match outside a comment before the keyword lists matter: parsing every
    # Python file for them cost more than the patterns themselves.
    if not all(any(not f.in_comment(m.start()) for m in p.finditer(text))
               for p in (_SSH_SERVER, _TUNNEL_CLIENT)):
        return []
    listed = _listed_lines(f)

    def first(pattern: re.Pattern[str]) -> re.Match[str] | None:
        # A name a log query looks for (`message CONTAINS 'sshd'`) starts nothing either.
        return next((m for m in pattern.finditer(text)
                     if not f.in_comment(m.start()) and f.line_of_offset(m.start()) not in listed
                     and not searched_for(text, m.start() + (text[m.start()] in "\"'/ "))),
                    None)

    ssh, tun = first(_SSH_SERVER), first(_TUNNEL_CLIENT)
    if ssh is None or tun is None:
        return []
    return [f.evidence_for_span(ssh.start(), ssh.end()),
            f.evidence_for_span(tun.start(), tun.end())]


# --- platform-named npm package with a downloading install hook ------------------------------
_PLATFORM_NAME = re.compile(
    r"-(?:darwin|linux|win32|freebsd|android)-(?:x64|arm64|arm|ia32|x86)(?:-(?:gnu|musl|msvc))?$"
)
_NET_FETCH = re.compile(
    r"\b(?:https?|axios|got|needle|node-fetch)\.(?:get|request)\s*\(|\bfetch\s*\(\s*[\"'`]https?:"
    r"|\b(?:curl|wget)\s|\.(?:downloadFile|download)\s*\(|\bInvoke-WebRequest\b"
)
_NPM_NAME = re.compile(r'"name"\s*:\s*"([^"\n]{1,214})"')


# --- agent launcher: model API redirect + approvals off / Defender exclusion ------------------
_BASE_URL_ASSIGN = re.compile(
    r"""\b(?:OPENROUTER|OPENAI|ANTHROPIC|GEMINI|MISTRAL|GROQ|DEEPSEEK)_(?:BASE_URL|API_BASE)\b"""
    r"""[\"'\]]{0,2}\s{0,3}[=:]\s{0,3}[\"'`](https?://[^\"'`\s]{1,200})[\"'`]"""
)
_APPROVALS_OFF = re.compile(
    r"""approval(?:Mode|_mode|Policy)?[\"']?\s{0,3}[:=]\s{0,3}[\"'](?:yolo|never)[\"']"""
    r"""|--dangerously-skip-permissions|\bbypassPermissions\b""",
    re.IGNORECASE,
)
_DEFENDER_TAMPER = re.compile(
    r"\bAdd-MpPreference\b[^\n]{0,80}-Exclusion|\bSet-MpPreference\b[^\n]{0,80}-DisableRealtime"
    r"|\bSet-ExecutionPolicy\s{1,4}(?:-\w+\s{1,4}){0,2}Bypass\b",
    re.IGNORECASE,
)


def _launcher_hijack(f: IndexedFile) -> list[Evidence]:
    redirect = next(
        (m for m in _BASE_URL_ASSIGN.finditer(f.text)
         if _elsewhere(m.group(1)) and not f.in_comment(m.start())),
        None,
    )
    if redirect is None:
        return []
    second = next(
        (m for pat in (_APPROVALS_OFF, _DEFENDER_TAMPER) for m in pat.finditer(f.text)
         if not f.in_comment(m.start())),
        None,
    )
    if second is None:
        return []
    return [f.evidence_for_span(redirect.start(), redirect.end()),
            f.evidence_for_span(second.start(), second.end())]


class FetchTunnelLauncherScanner(Scanner):
    name = "fetch_tunnel_launcher"
    rules = [
        RuleSpec(
            id=R_PY_FETCH_EXEC,
            category="dynamic_code",
            severity=Severity.HIGH,
            title="Python execs fetched code",
            description=(
                "A Python function fetches a response (urlopen, requests, httpx) and passes the "
                "text it got to exec or eval, directly, through a function of another module of "
                "the component that returns it, or by saving it to a file and reading that file "
                "back into exec; or the file saves a download under a hidden name (or in a "
                "temporary folder, detached) and starts it with its output discarded. What runs "
                "is whatever the remote host serves when the function is called; it is not in "
                "the package for review."
            ),
            recommendation=(
                "Ship the code that runs, or download a pinned artifact and verify its checksum "
                "before using it. Do not call exec on a response body."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_NODE_FETCH_EXEC,
            category="dynamic_code",
            severity=Severity.HIGH,
            title="Node.js runs fetched code",
            description=(
                "A JavaScript file requests a URL (fetch, http(s).get, axios, got) and the "
                "response reaches a call that runs text as code: eval, the Function constructor "
                "or the vm module, written out or reached indirectly (`(0, eval)(t)`, "
                "`globalThis[k](t)`, a renamed eval). What runs is whatever the remote host "
                "serves when the file is run; it is not in the package for review."
            ),
            recommendation=(
                "Ship the code that runs, or download a pinned artifact and verify its checksum "
                "before using it. Do not evaluate a response body."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            # The request and the sink are both checked to be code, not text in a string or a
            # comment; the declaration keeps the engine's own demotion in step.
            code_context="strings_and_comments_all",
        ),
        RuleSpec(
            id=R_SSH_TUNNEL,
            category="remote_access",
            severity=Severity.HIGH,
            title="SSH server behind a tunnel",
            description=(
                "One file starts an SSH server (the OpenSSH daemon, an SSH server library, or a "
                "no-password setting) and a public tunnel client (a reverse-tunnel service). "
                "Together they publish a login on this machine to the internet."
            ),
            recommendation=(
                "Do not run this component. A tunnel client for a web preview does not start an "
                "SSH server; remote login belongs in the user's own configuration."
            ),
            capability=Capability.NETWORK_EGRESS,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_LAUNCHER_HIJACK,
            category="agent_config",
            severity=Severity.HIGH,
            title="Launcher hijacks API",
            description=(
                "One file sets a model API base URL (OPENROUTER_BASE_URL, OPENAI_BASE_URL, ...) "
                "to a host that is neither the vendor's nor this machine, and also turns tool "
                "approvals off or adds a Defender exclusion / execution-policy bypass. The agent "
                "then sends its key and prompts to that host and runs tools unasked."
            ),
            recommendation=(
                "Do not run this launcher. Keep the vendor's API address and the default "
                "approval mode unless the user chooses otherwise."
            ),
            capability=Capability.NETWORK_EGRESS,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        found: dict[str, list[Evidence]] = {r.id: [] for r in self.rules}
        modules = _Modules(index)
        for f in index.select(suffixes=NODE_SUFFIXES):
            for request, sink in fetched_text_sinks(f, code_sink_heads):
                found[R_NODE_FETCH_EXEC] += [
                    f.evidence_for_span(*span) for span in (request, sink)
                ]
        for f in index.select(suffixes=_CODE_SUFFIXES):
            if f.suffix in _PY_SUFFIXES:
                ev = _py_fetch_exec(f, modules)
                if ev is not None:
                    found[R_PY_FETCH_EXEC].append(ev)
                for hit in download_runs(f, reach=_DOWNLOAD_RUN_REACH):
                    if hit.kind == RUN_TEXT or hit.concealed:
                        found[R_PY_FETCH_EXEC] += [
                            f.evidence_for_span(*span) for span in (hit.download, hit.run)
                        ]
            found[R_SSH_TUNNEL].extend(_ssh_tunnel(f))
            if f.suffix in _NODE_SUFFIXES or f.suffix in (".ps1", ".sh", ".bash"):
                found[R_LAUNCHER_HIJACK].extend(_launcher_hijack(f))
        findings = [
            _finding_from_rule(r, _one_per_line(found[r.id])[:6]) for r in self.rules if found[r.id]
        ]
        return ScanResult(findings=findings)


def _one_per_line(evidence: list[Evidence]) -> list[Evidence]:
    """A request and the sink it reaches are often on one line: that line is shown once."""
    seen: set[tuple[str, int, int]] = set()
    kept: list[Evidence] = []
    for ev in evidence:
        key = (ev.file, ev.line_start, ev.line_end)
        if key not in seen:
            seen.add(key)
            kept.append(ev)
    return kept


def platform_fetch_evidence(index: FileIndex) -> list[Evidence]:
    out: list[Evidence] = []
    for pkg in index.select(names=("package.json",)):
        m = _NPM_NAME.search(pkg.text)
        if m is None or not _PLATFORM_NAME.search(m.group(1)):
            continue
        try:
            data = bounded_json.loads(pkg.text)
        except (ValueError, json.JSONDecodeError):
            continue
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if not isinstance(scripts, dict) or not any(
            isinstance(scripts.get(k), str) for k in ("preinstall", "install", "postinstall")
        ):
            continue
        folder = pkg.relpath.rsplit("/", 1)[0] + "/" if "/" in pkg.relpath else ""
        for f in index.files:
            if f.relpath not in index.install_scripts or not f.relpath.startswith(folder):
                continue
            hit = next(
                (h for h in _NET_FETCH.finditer(f.text) if not f.in_comment(h.start())), None)
            if hit is not None:
                out.append(f.evidence_for_span(hit.start(), hit.end()))
                break
    return out
