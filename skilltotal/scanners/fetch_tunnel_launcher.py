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
import re

from skilltotal import bounded_json
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.agent_approval import _elsewhere
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule

R_PY_FETCH_EXEC = "ST-PY-FETCH-EXEC"
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


def _tainted(node: ast.AST, names: set[str]) -> bool:
    """True if the expression is (derived from) a fetched response."""
    if isinstance(node, ast.Name):
        return node.id in names
    if _is_fetch_call(node):
        return True
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr in _BODY_ATTRS | {"encode", "decode"}:
            return _tainted(fn.value, names)
        if isinstance(fn, ast.Name) and fn.id in ("str", "bytes", "compile", "bytearray"):
            return any(_tainted(a, names) for a in node.args)
        return False
    if isinstance(node, ast.Attribute):
        return node.attr in _BODY_ATTRS and _tainted(node.value, names)
    if isinstance(node, ast.Subscript):
        return _tainted(node.value, names)
    return False


def _scope_fetch_exec(scope: ast.AST) -> ast.Call | None:
    names: set[str] = set()
    nodes = sorted(
        (n for n in ast.walk(scope) if hasattr(n, "lineno")),
        key=lambda n: (n.lineno, n.col_offset),
    )
    for node in nodes:
        if isinstance(node, ast.Assign) and _tainted(node.value, names):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.optional_vars, ast.Name) and _tainted(item.context_expr, names):
                    names.add(item.optional_vars.id)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in _RUNNERS and node.args and _tainted(node.args[0], names):
            return node
    return None


_RUNNER_WORD = re.compile(r"\b(?:exec|eval)\b")


def _could_run_text(text: str) -> bool:
    """False only when no call to exec or eval can be in the file. A runner is a bare name, so in
    ASCII source it is spelled out as a whole word; elsewhere Python folds look-alike letters
    (NFKC) into it, so a file with any non-ASCII text is parsed whatever it spells. Most files hold
    neither name, and parsing and walking them for this rule cost as much as the whole Python
    scanner (2026-11-07 profile)."""
    return not text.isascii() or _RUNNER_WORD.search(text) is not None


def _py_fetch_exec(f: IndexedFile) -> Evidence | None:
    if not _could_run_text(f.text):
        return None
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    scopes: list[ast.AST] = [tree] + [
        n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    for scope in scopes:
        try:
            hit = _scope_fetch_exec(scope)
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
        return next((m for m in pattern.finditer(text)
                     if not f.in_comment(m.start()) and f.line_of_offset(m.start()) not in listed),
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
                "text it got to exec or eval. What runs is whatever the remote host serves when "
                "the function is called; it is not in the package for review."
            ),
            recommendation=(
                "Ship the code that runs, or download a pinned artifact and verify its checksum "
                "before using it. Do not call exec on a response body."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
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
        for f in index.select(suffixes=_CODE_SUFFIXES):
            if f.suffix in _PY_SUFFIXES:
                ev = _py_fetch_exec(f)
                if ev is not None:
                    found[R_PY_FETCH_EXEC].append(ev)
            found[R_SSH_TUNNEL].extend(_ssh_tunnel(f))
            if f.suffix in _NODE_SUFFIXES or f.suffix in (".ps1", ".sh", ".bash"):
                found[R_LAUNCHER_HIJACK].extend(_launcher_hijack(f))
        findings = [_finding_from_rule(r, found[r.id][:6]) for r in self.rules if found[r.id]]
        return ScanResult(findings=findings)


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
