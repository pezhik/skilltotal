"""Shell-script detection (.sh / .bash / .zsh and shebang scripts, composite-action steps).

Shell install/bootstrap scripts are a common dropper surface that the language scanners
(Python AST, Node regex) miss: a decode-and-execute idiom (``… base64 -d | bash``) or a
remote pipe-to-shell (``curl … | sh``). Detection is regex over shell files, selected by
suffix or by a shell shebang on the first line, and over the ``run:`` steps of a composite
GitHub Action (``action.yml``), which execute on the runner of whoever uses the action.
"""

from __future__ import annotations

import re
import string

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    alternation,
)

SHELL_SUFFIXES = (".sh", ".bash", ".zsh")
_SHEBANG_RE = re.compile(r"^#!.*\b(?:bash|zsh|sh|dash|ksh)\b")
# A shell that the decoded/fetched payload is piped or fed into.
_TO_SHELL = r"\|\s*(?:sudo\s+)?\b(?:bash|zsh|sh)\b"

# Fetch-and-run or decode-and-run, in a shell command or in the source of a script (shared by
# the agent-configuration, npm lifecycle-script and shell-call checks): a download
# piped into a shell (or into an interpreter reading its program from stdin), a download run through
# `sh -c "$(...)"`, `eval "$(...)"` or a process substitution, PowerShell's download-then-iex in
# either order, an encoded PowerShell command, and the same in JavaScript or Python.
# The gaps between the parts are bounded: an unbounded `[^\n]*` after each `curl` of a crafted
# line rescanned the rest of the line from every one of them (quadratic).
_FETCH = r"(?:curl|wget)\b"
_GAP = r"[^\n]{0,1000}?"
REMOTE_EXEC = re.compile(
    rf"{_FETCH}{_GAP}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
    rf"|{_FETCH}[^\n|]{{0,1000}}\|\s*(?:sudo\s+)?(?:python[0-9.]*|node|perl|ruby)(?:\s+-)?\s*"
    r"(?=$|[;&|)\n\"'])"
    rf"|base64\s+(?:-d|-D|--decode)\b{_GAP}\|\s*(?:ba|z)?sh\b"
    rf"|\b(?:ba|z|da|k)?sh\s+-c\s+[\"']?\$\(\s*{_FETCH}"
    rf"|\beval\s+[\"']?\$\(\s*{_FETCH}"
    rf"|(?:\bsource|(?<![\w.])\.|\b(?:ba|z|da|k)?sh)\s+<\(\s*{_FETCH}"
    rf"|\b(?:iex|Invoke-Expression)\b{_GAP}\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|"
    r"DownloadString)\b"
    r"|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,1000}\|\s*(?:iex|Invoke-Expression)\b"
    rf"|\bpowershell(?:\.exe)?\b{_GAP}\s-(?:e|enc|encodedcommand)\s"
    r"|\beval\s*\(\s*(?:await\s+)?(?:\(\s*)?(?:await\s+)?fetch\s*\("
    r"|\bexec\s*\(\s*(?:urllib\.request\.)?urlopen\s*\(",
    re.IGNORECASE,
)

# Decode data, then run it in a shell (also read in npm lifecycle scripts).
# Bounded gaps: an unbounded `[^\n]*` rescanned the rest of a crafted line from every `eval` or
# `base64 -d` on it (quadratic). `base64(?<!\wbase64)` is `\bbase64` written so that the gap is
# followed by a literal, which the regex engine skips ahead to instead of trying every position.
DECODE_EXEC_SH = alternation(
    rf"base64\s+(?:-d|-D|--decode)\b[^\n]{{0,1000}}{_TO_SHELL}",
    r"\beval\b[^\n]{0,1000}base64(?<!\wbase64)\s+(?:-d|-D|--decode)\b",
)

R_DECODE_EXEC_SH = "ST-OBF-DECODE-EXEC-SH"
R_PIPE_EXEC = "ST-SHELL-PIPE-EXEC"
R_PASSWORD_ARCHIVE = "ST-ARCHIVE-PASSWORD-EXTRACT"  # nosec B105 - a rule id, not a password
R_ACTION_SECRET_EXFIL = "ST-ACTION-SECRET-EXFIL"  # nosec B105 - a rule id, not a secret

# --- CI-token exfiltration from a composite action run step --------------------------------
# A continuous-integration secret the runner holds: the workflow token, the artifact/OIDC tokens,
# or any `${{ secrets.* }}` / `${{ github.token }}` expression interpolated into the step.
_CI_SECRET = re.compile(
    r"\bGITHUB_TOKEN\b"
    r"|\bACTIONS_RUNTIME_TOKEN\b"
    r"|\bACTIONS_ID_TOKEN_REQUEST_TOKEN\b"
    r"|\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}"
    r"|\$\{\{\s*github\.token\s*\}\}",
    re.IGNORECASE,
)
# A generic network client (not `gh` / `git`, which speak to GitHub legitimately).
_NET_CLIENT = re.compile(
    r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|ncat|nc|telnet|httpie)\b",
    re.IGNORECASE,
)
# A GitHub / Actions-infrastructure destination, named by host or by its documented URL env var.
# A command segment carrying one of these is talking to GitHub, where the token belongs.
_GITHUB_DEST = re.compile(
    r"github\.com"
    r"|githubusercontent\.com"
    r"|ghcr\.io"
    r"|\.pkg\.github\.com"
    r"|GITHUB_(?:API|SERVER|GRAPHQL)_URL"
    r"|ACTIONS_(?:RESULTS|CACHE|ID_TOKEN_REQUEST|RUNTIME)_URL",
    re.IGNORECASE,
)
# A shell metacharacter that ends one command in a pipeline / list.
_SEGMENT_BREAK = frozenset(";&|\n")


def _command_segments(command: str) -> list[tuple[int, int]]:
    """``(start, end)`` ranges of the separate commands in ``command``, split on unquoted ``;`` /
    ``&`` / ``|`` / newline. Quotes are honored (a separator inside a quoted string does not split),
    and a backslash before a newline is a line continuation, not a break -- so a single ``curl``
    written across several lines stays one segment with its host and its token together."""
    segments: list[tuple[int, int]] = []
    quote: str | None = None
    start = 0
    i = 0
    n = len(command)
    while i < n:
        c = command[i]
        if quote == "'":
            if c == "'":
                quote = None
        elif quote == '"':
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == '"':
                quote = None
        elif c == "\\":
            i += 2  # an escaped char (incl. a line-continuation newline) is part of this segment
            continue
        elif c in "'\"":
            quote = c
        elif c in _SEGMENT_BREAK:
            if start < i:
                segments.append((start, i))
            start = i + 1
        i += 1
    if start < n:
        segments.append((start, n))
    return segments
# Markdown whose fenced shell blocks are commands for a person or an agent to run. The ClawHavoc
# skills (ClawHub, early 2026) put `echo '<base64>' | base64 -D | bash` under "Prerequisites".
_MARKDOWN = (".md", ".mdx")
# Fence info strings that mean "run this in a shell". A ```typescript block showing
# `sandbox.exec('curl ... | sh')` is a code sample, not a command (FP: a Cloudflare skill's
# reference file raised a registry MCP server from medium to high).
_SHELL_FENCES = frozenset(
    {"", "bash", "sh", "shell", "zsh", "console", "terminal", "shell-session"}
)
_FENCE_INFO = re.compile(r" {0,3}(?:`{3,}|~{3,})\s*([\w+-]*)")
# Rules that apply inside markdown. A pipe-to-shell there is an install instruction in prose docs
# far more often than anything else, so it stays a script-only signal; decoding-then-executing
# and extracting a downloaded archive with a password have no honest documentation reading.
_MARKDOWN_RULES = frozenset({R_DECODE_EXEC_SH, R_PASSWORD_ARCHIVE})
_DOWNLOAD = re.compile(r"\b(?:curl|wget|Invoke-WebRequest|iwr)\b", re.IGNORECASE)

# Composite GitHub Actions. The `run:` steps of an `action.yml` execute on the runner of whoever
# `uses:` the action -- the consumer, like an install-time hook -- so the shell rules apply to them
# (a composite action piping `curl` into `bash` used to produce no finding at all). An action under
# `.github/` is usually the project's own CI helper (`./.github/actions/x`); it is scanned too, and
# file_index.is_ci_path demotes it to needs_review (shown, not scored) rather than dropping it,
# because such an action can still be used remotely (`owner/repo/.github/actions/x@ref`).
_ACTION_NAMES = frozenset({"action.yml", "action.yaml"})
# `run` as a mapping key: at the start of a line (optionally a list item `- `) or after `{` / `,`
# in a flow mapping, plain or quoted. `runs:` is not it.
_RUN_KEY = re.compile(
    r"""(?:^[ \t]*(?:-[ \t]+)*|[{,][ \t]*)(["']?)run\1[ \t]*:(?=[ \t\r\n]|$)""", re.MULTILINE
)
# A block-scalar header (`|`, `|-`, `>+`, `|2`, ...): the command is on the following lines.
_BLOCK_HEADER = re.compile(r"^[|>][0-9+-]*[ \t]*(?:#.*)?$")
_TRAILING_COMMENT = re.compile(r"[ \t]#")
# A following line that opens a nested mapping or list: the key holds a structure, not a command.
_NESTED_START = re.compile(r"""(?:-(?:[ \t]|$)|["']?[\w.-]{1,200}["']?[ \t]*:(?:[ \t]|$))""")
_ALIAS_NAME = re.compile(r"[*&]([\w.-]+)")
# YAML double-quoted escapes that stand for one character.
_DQ_ESCAPES = {
    '"': '"', "\\": "\\", "/": "/", "n": "\n", "t": "\t", " ": " ", "0": "\0", "a": "\a",
    "b": "\b", "e": "\x1b", "f": "\f", "r": "\r", "v": "\v", "N": "\x85", "_": "\xa0",
    "L": " ", "P": " ",
}
_DQ_HEX = {"x": 2, "u": 4, "U": 8}
# A `#` starts a shell comment only at the start of a word.
_WORD_BREAK = " \t\n;&|()"

_Text = tuple[list[str], list[int]]  # characters, and each one's offset in the action file


def _indent(text: str, line_start: int) -> int:
    end = line_start
    while end < len(text) and text[end] in " \t":
        end += 1
    return end - line_start


def _line_end(text: str, pos: int) -> int:
    end = text.find("\n", pos)
    return len(text) if end == -1 else end


def _next_content_line(text: str, pos: int) -> int | None:
    """Start of the first line at or after ``pos`` that is neither blank nor a comment."""
    while pos < len(text):
        stripped = text[pos:_line_end(text, pos)].strip()
        if stripped and not stripped.startswith("#"):
            return pos
        pos = _line_end(text, pos) + 1
    return None


def _yaml_value(text: str, pos: int, key_indent: int, depth: int = 0) -> _Text:
    """The string the runner gets for the YAML value that starts at ``pos`` (after ``key:``).

    No YAML library (the engine is stdlib-only), but the scalar forms are decoded the way YAML does
    it -- plain (folded, `` #`` ends it), double-quoted (escapes, so ``\\u007C`` is a ``|``),
    single-quoted, block ``|``/``>`` and an alias to an anchored value -- because a reader that
    sees less than the runner is a way around the rules. A nested mapping or list yields nothing.
    """
    while pos < len(text) and text[pos] in " \t":
        pos += 1
    head = text[pos:_line_end(text, pos)].rstrip("\r")
    if head.startswith("&"):  # `run: &cmd …`: the anchor itself, then the value
        name = _ALIAS_NAME.match(head)
        if name is not None:
            return _yaml_value(text, pos + name.end(), key_indent, depth)
    if head.startswith("*"):
        name = _ALIAS_NAME.match(head)
        if name is None or depth >= 3:
            return [], []
        anchor = re.search(rf"&{re.escape(name.group(1))}(?=[\s,\]}}]|$)", text)
        if anchor is None:
            return [], []
        anchor_line = text.rfind("\n", 0, anchor.start()) + 1
        return _yaml_value(text, anchor.end(), _indent(text, anchor_line), depth + 1)
    if _BLOCK_HEADER.match(head):
        return _block_scalar(text, _line_end(text, pos) + 1, key_indent, head[0] == ">")
    if head.startswith('"'):
        return _double_quoted(text, pos + 1)
    if head.startswith("'"):
        return _single_quoted(text, pos + 1)
    if head and not head.startswith("#"):
        return _plain_scalar(text, pos, key_indent)
    # Nothing on the key line: the value, if any, starts on a following, deeper line.
    nxt = _next_content_line(text, _line_end(text, pos) + 1)
    if nxt is None or _indent(text, nxt) <= key_indent:
        return [], []
    first = nxt + _indent(text, nxt)
    if _NESTED_START.match(text, first):
        return [], []
    return _yaml_value(text, first, key_indent, depth)


def _plain_scalar(text: str, pos: int, key_indent: int) -> _Text:
    """A plain scalar: its lines fold into one with spaces; a `` #`` comment or a line no deeper
    than the key ends it."""
    chars: list[str] = []
    idx: list[int] = []
    while True:
        end = _line_end(text, pos)
        line = text[pos:end].rstrip("\r")
        cut = _TRAILING_COMMENT.search(line)
        segment = (line[: cut.start()] if cut else line).rstrip()
        if segment:
            if chars:
                chars.append(" ")
                idx.append(pos)
            chars.extend(segment)
            idx.extend(range(pos, pos + len(segment)))
        if cut is not None:
            break
        nxt = _next_content_line(text, end + 1)
        if nxt is None or _indent(text, nxt) <= key_indent:
            break
        if text[end + 1:nxt].lstrip(" \t\r\n").startswith("#"):
            break  # a comment line ends a plain scalar
        pos = nxt + _indent(text, nxt)
    return chars, idx


def _quoted_fold(text: str, i: int, chars: list[str], idx: list[int]) -> int:
    """Fold a line break inside a quoted scalar (YAML: a space) and skip the next line's indent."""
    chars.append(" ")
    idx.append(i)
    i += 1
    while i < len(text) and text[i] in " \t\r":
        i += 1
    return i


def _double_quoted(text: str, i: int) -> _Text:
    chars: list[str] = []
    idx: list[int] = []
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            break
        if c == "\\" and i + 1 < n:
            e = text[i + 1]
            if e in _DQ_ESCAPES:
                chars.append(_DQ_ESCAPES[e])
                idx.append(i)
                i += 2
                continue
            width = _DQ_HEX.get(e)
            digits = text[i + 2:i + 2 + width] if width else ""
            if width and len(digits) == width and all(d in string.hexdigits for d in digits):
                code = int(digits, 16)
                if code <= 0x10FFFF:
                    chars.append(chr(code))
                    idx.append(i)
                    i += 2 + width
                    continue
            if e in "\r\n":  # an escaped line break joins the lines with nothing between
                i += 2
                while i < n and text[i] in " \t\r\n":
                    i += 1
                continue
        if c == "\n":
            i = _quoted_fold(text, i, chars, idx)
            continue
        if c != "\r":
            chars.append(c)
            idx.append(i)
        i += 1
    return chars, idx


def _single_quoted(text: str, i: int) -> _Text:
    chars: list[str] = []
    idx: list[int] = []
    while i < len(text):
        c = text[i]
        if c == "'":
            if text.startswith("''", i):
                chars.append("'")
                idx.append(i)
                i += 2
                continue
            break
        if c == "\n":
            i = _quoted_fold(text, i, chars, idx)
            continue
        if c != "\r":
            chars.append(c)
            idx.append(i)
        i += 1
    return chars, idx


def _block_scalar(text: str, pos: int, key_indent: int, folded: bool) -> _Text:
    """``|`` keeps the lines; ``>`` folds them into one. The block holds the lines indented at
    least as far as its first line, which must be deeper than the key."""
    chars: list[str] = []
    idx: list[int] = []
    content_indent: int | None = None
    while pos < len(text):
        end = _line_end(text, pos)
        line = text[pos:end].rstrip("\r")
        if line.strip():
            indent = _indent(text, pos)
            if content_indent is None:
                if indent <= key_indent:
                    break  # an empty block: the next key is not the command
                content_indent = indent
            elif indent < content_indent:
                break
            body = line[content_indent:]
            if chars:
                chars.append(" " if folded else "\n")
                idx.append(pos)
            chars.extend(body)
            idx.extend(range(pos + content_indent, pos + content_indent + len(body)))
        pos = end + 1
    return chars, idx


def _without_shell_comments(value: _Text) -> _Text:
    """``value`` minus its shell comments: a word starting with ``#`` outside quotes, to the end of
    the line. Quotes are tracked across lines, as the shell does, so a ``#`` inside a quoted string
    does not hide the rest of the line."""
    chars, idx = value
    out_chars: list[str] = []
    out_idx: list[int] = []
    quote: str | None = None
    i = 0
    while i < len(chars):
        c = chars[i]
        step = 1
        if quote == "'":
            if c == "'":
                quote = None
        elif c == "\\":
            step = 2  # an escaped character never opens, closes or comments
        elif quote == '"':
            if c == '"':
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or chars[i - 1] in _WORD_BREAK):
            while i < len(chars) and chars[i] != "\n":
                i += 1
            continue
        out_chars.extend(chars[i:i + step])
        out_idx.extend(idx[i:i + step])
        i += step
    return out_chars, out_idx


def _secret_exfil_spans(command: str) -> list[tuple[int, int]]:
    """Spans (in ``command``) of a network client that carries a CI secret to a non-GitHub host.

    Each pipeline/``;``/``&&`` segment is judged on its own: it must invoke a network client and
    hold a CI secret, and must not name a GitHub destination (where the token legitimately goes).
    The span returned is the network-client token, so the evidence points at the exfiltrating
    call."""
    spans: list[tuple[int, int]] = []
    for start, end in _command_segments(command):
        piece = command[start:end]
        client = _NET_CLIENT.search(piece)
        if client is None or not _CI_SECRET.search(piece):
            continue
        if _GITHUB_DEST.search(piece):
            continue  # the secret is being sent to GitHub, which is legitimate
        spans.append((start + client.start(), start + client.end()))
    return spans


def _action_commands(text: str) -> list[tuple[str, list[int]]]:
    """The shell command of each ``run:`` step of a composite action, as the runner's shell
    receives it, with every character's offset in ``text`` (so evidence points at the file)."""
    commands: list[tuple[str, list[int]]] = []
    for m in _RUN_KEY.finditer(text):
        key_line = text.rfind("\n", 0, m.start()) + 1
        chars, idx = _without_shell_comments(_yaml_value(text, m.end(), _indent(text, key_line)))
        command = "".join(chars)
        if command.strip():
            commands.append((command, idx))
    return commands


class ShellScriptScanner(Scanner):
    """Custom scanner: regex rules over shell files (suffix or shebang)."""

    name = "shell_script"
    rules = [
        RuleSpec(
            id=R_DECODE_EXEC_SH,
            category="obfuscation",
            severity=Severity.HIGH,
            title="Shell decode-and-execute (obfuscated execution)",
            description=(
                "A shell command decodes data and immediately executes it "
                "(e.g. `... base64 -d | bash` or `eval \"$(... base64 -d)\"`). Decoding then "
                "executing hides behaviour from review and is a common dropper idiom."
            ),
            recommendation=(
                "Decode the payload manually and inspect what it runs before trusting this "
                "component. Never pipe decoded data into a shell."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            suffixes=SHELL_SUFFIXES,
            pattern=DECODE_EXEC_SH,
        ),
        RuleSpec(
            id=R_PIPE_EXEC,
            category="shell_execution",
            severity=Severity.HIGH,
            title="Remote pipe-to-shell execution",
            description=(
                "A remotely fetched payload is piped straight into a shell "
                "(e.g. `curl ... | bash`). The component runs code downloaded at runtime, which "
                "is unreviewable and a common second-stage delivery vector."
            ),
            recommendation=(
                "Download to a file, inspect it, and run a pinned/verified copy instead of "
                "piping a network response directly into a shell."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            suffixes=SHELL_SUFFIXES,
            # A `# Usage: curl … | bash` line documents the install command; it is a comment, not
            # a runnable pipe-to-shell. Demote matches inside shell comments (engine code-context).
            code_context="comments",
            # Bounded gap, as in REMOTE_EXEC: unbounded, it rescanned the rest of a crafted line
            # from every `curl` on it (quadratic).
            pattern=alternation(
                rf"(?:curl|wget)\b[^\n]{{0,1000}}{_TO_SHELL}",
            ),
        ),
        RuleSpec(
            id=R_PASSWORD_ARCHIVE,
            category="obfuscation",
            severity=Severity.HIGH,
            title="Downloaded archive extracted with a password",
            description=(
                "A script or setup instruction downloads an archive and extracts it with a "
                "password (`unzip -P ...`, `7z x -p...`). The password exists to keep the contents "
                "away from scanners on the way in; malicious agent skills (ToxicSkills, 2026) "
                "delivered their binaries this way."
            ),
            recommendation=(
                "Do not run it. Download the archive in isolation and inspect what it contains."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            suffixes=SHELL_SUFFIXES,
            code_context="comments",
            # Bounded gaps: an unbounded `[^\n]*` from each `unzip` of a crafted line was quadratic.
            pattern=alternation(
                r"\bunzip\b[^\n]{0,1000}\s-P\s*\S+",
                r"\b7za?\s+[xe]\b[^\n]{0,1000}\s-p\S+",
                r"\bunrar\s+[xe]\b[^\n]{0,1000}\s-p\S+",
            ),
        ),
        RuleSpec(
            id=R_ACTION_SECRET_EXFIL,
            category="exfiltration_path",
            severity=Severity.HIGH,
            title="CI token sent off GitHub from a composite action",
            description=(
                "A composite GitHub Action's run step sends a continuous-integration secret "
                "(GITHUB_TOKEN, an Actions OIDC/runtime token, or a ${{ secrets.* }} / "
                "${{ github.token }} expression) to a non-GitHub host through a network client "
                "(curl / wget / Invoke-WebRequest / nc). The step runs on the runner of whoever "
                "uses the action, so the token and secrets of every consumer are exfiltrated. "
                "Handing the token to gh / git against GitHub, or to the documented Actions "
                "service URLs, is not matched."
            ),
            recommendation=(
                "Never send a CI token or repository secret to a host you do not control. If a "
                "third-party service needs a credential, use its own scoped secret and send it "
                "only to that service's documented endpoint."
            ),
            capability=None,  # egress of a credential; capability chips come from other rules
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            # Custom matching (see _secret_exfil_spans); applied only to composite-action run steps.
            # No regex pattern / fallback: it needs client + secret + host co-occurrence in a step.
            names=("action.yml", "action.yaml"),
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        files = [
            f
            for f in index.files
            if self._is_shell(f) or f.suffix in _MARKDOWN or self._is_action(f)
        ]
        # A composite action's commands are matched as the runner's shell receives them (decoded
        # from YAML), with each match mapped back to the file for its evidence.
        actions = {f.relpath: _action_commands(f.text) for f in files if self._is_action(f)}
        findings = []
        for rule in self.rules:
            # ST-ACTION-SECRET-EXFIL has no regex (custom co-occurrence match) and applies only to
            # composite-action run steps; every other rule needs a pattern.
            is_action_secret = rule.id == R_ACTION_SECRET_EXFIL
            if rule.pattern is None and not is_action_secret:
                continue
            seen: set[tuple[str, int, int]] = set()
            evidence = []
            for f in files:
                if f.suffix in _MARKDOWN and rule.id not in _MARKDOWN_RULES:
                    continue
                if f.relpath in actions:
                    for command, idx in actions[f.relpath]:
                        if is_action_secret:
                            spans = _secret_exfil_spans(command)
                        elif rule.id == R_PASSWORD_ARCHIVE and not _DOWNLOAD.search(command):
                            continue
                        else:
                            spans = [
                                (m.start(), m.end())
                                for m in rule.pattern.finditer(command)
                                if m.end() > m.start()
                            ]
                        for s, e in spans:
                            ev = f.evidence_for_span(idx[s], idx[e - 1] + 1)
                            key = (ev.file, ev.line_start, ev.line_end)
                            if key not in seen and len(evidence) < MAX_EVIDENCE_SCANNED:
                                seen.add(key)
                                evidence.append(ev)
                    continue
                if is_action_secret:
                    continue  # this rule is scoped to composite-action run steps only
                regions = self._regions(f)
                for m, ev in f.finditer(rule.pattern):
                    region = next((r for r in regions if r[0] <= m.start() < r[1]), None)
                    if region is None:
                        continue
                    if rule.id == R_PASSWORD_ARCHIVE and not _DOWNLOAD.search(
                        f.text, region[0], region[1]
                    ):
                        continue
                    key = (ev.file, ev.line_start, ev.line_end)
                    if key in seen:
                        continue
                    seen.add(key)
                    evidence.append(ev)
                    if len(evidence) >= MAX_EVIDENCE_SCANNED:
                        break
            if evidence:
                findings.append(_finding_from_rule(rule, evidence))
        return ScanResult(findings=findings)

    @staticmethod
    def _regions(f) -> list[tuple[int, int]]:
        """Where shell commands live: the whole script, or each fenced block of a markdown file.
        (A composite action's ``run:`` steps are decoded by :func:`_action_commands` instead.)"""
        if f.suffix in _MARKDOWN:
            spans = []
            for start, end in f.markdown_code_spans():
                info = _FENCE_INFO.match(f.text, start)
                if info is not None and info.group(1).lower() in _SHELL_FENCES:
                    spans.append((start, end))
            return spans
        return [(0, len(f.text))]

    @staticmethod
    def _is_action(f) -> bool:
        """A GitHub Action's metadata file (one under `.github/` is demoted by is_ci_path)."""
        return f.relpath.lower().split("/")[-1] in _ACTION_NAMES

    @staticmethod
    def _is_shell(f) -> bool:
        if f.suffix in SHELL_SUFFIXES:
            return True
        first = f.text[:200].splitlines()[0] if f.text else ""
        return bool(_SHEBANG_RE.match(first))
