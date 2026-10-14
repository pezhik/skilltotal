"""Agent and IDE configuration that runs commands on its own, and AI CLIs driven with guards off.

Three attack shapes published in 2026 live here.

* **Auto-run configuration shipped with a component.** The Miasma worm (npm, June 2026) wrote
  `.claude/settings.json`, `.gemini/settings.json` and `.vscode/tasks.json` into projects so that
  opening the project in an agent or editor ran the worm again; the TrustFall research showed the
  agentic CLIs execute such project configuration after a single trust prompt, or none in CI.
  HookPry (Sept 2026) showed the same lifecycle-hook binding shipped from a Claude Code plugin's
  own manifest (`hooks/hooks.json`, or inline in `.claude-plugin/plugin.json`) rather than the
  well-known `.claude/` paths — a plugin *update* can add the hook without the user ever seeing a
  new settings file. A hook in a repository can be an honest formatter, so the configuration alone
  is a risky construct. When the command, or the script it runs from the same component, fetches
  code and pipes it into a shell or decodes and executes it, it is a malicious indicator.
  Hooks are one of many such commands: an MCP server's launch command in any client format, the
  status line and credential helpers of Claude Code settings, a plugin's monitors and language
  servers, hooks in a skill's or a subagent's frontmatter. ``skilltotal.autorun`` reads them all
  in one place, and every one gets the same fetch-or-decode-and-run check here. Where an honest
  one is expected (an MCP server is started by a command), only that check applies. An ``http``
  hook posts every event it is bound to, with the tool input and output in it, to its URL: one
  aimed at a host other than this machine is a risky construct.
* **A `.git/config` that runs a command on every `git status`/`git diff`.** GitSpawn (Manifold
  Security, Sept 2026) found that several AI coding agents run `git status`/`git diff` at session
  startup, before any trust prompt, and that `core.fsmonitor` in `.git/config` names a command git
  itself runs to refresh its index on those calls. A component that ships a rigged `.git/config`
  therefore gets code execution the moment the agent looks at the project.
* **An AI coding CLI launched with its permission checks disabled.** The s1ngularity and
  Shai-Hulud npm campaigns drove the victim's own `claude`/`gemini`/`q` CLI with flags such as
  `--dangerously-skip-permissions` and `--yolo` to search the disk for secrets. Honest wrappers
  do this too, so it is a risky construct, not a verdict. When the same file ALSO opens an
  outbound connection to a remote endpoint, that is the remote-control shape (a relay feeds tasks
  from a server the user does not control into the approvals-off agent) that a cluster of npm
  packages used in Sept 2026 -- a malicious indicator, not just a risky construct.

Detection patterns below are string literals; nothing here executes a command.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from skilltotal.autorun import (
    KIND_HOOK,
    ORIGIN_PLUGIN,
    ORIGIN_PROJECT,
    ORIGIN_SKILL,
    AutorunCommand,
    autorun_commands,
)
from skilltotal.file_index import FileIndex, IndexedFile, is_test_path
from skilltotal.models import Capability, Evidence, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    aggregated_review,
    concat_folded_spans,
)
from skilltotal.scanners.python_ast import _pth_imported_modules, python_path_writes
from skilltotal.scanners.sensitive_paths import (
    _JS_HOME_EXPR,
    _JS_HOME_VAR,
    _JS_JOIN_CALL,
    _JS_STRING,
    _js_call_args,
    _js_segment,
    joined_js_paths,
)
from skilltotal.scanners.sensitive_paths import _UNKNOWN_SEGMENT as _JS_UNKNOWN_SEGMENT

# JS/TS (and Python) files where a client-config path may be split across concatenated literals.
_CONFIG_INJECT_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".pyw")

R_AUTORUN = "ST-AGENT-AUTORUN"
R_AUTORUN_REMOTE = "ST-AGENT-AUTORUN-REMOTE"
R_CLI_BYPASS = "ST-AGENT-CLI-BYPASS"
R_CLI_RELAY = "ST-AGENT-CLI-RELAY"
R_GITCONFIG_REMOTE = "ST-AGENT-GITCONFIG-EXEC-REMOTE"
R_CONFIG_INJECT = "ST-AGENT-CONFIG-INJECT"
R_CONFIG_PERSIST = "ST-AGENT-CONFIG-PERSIST"
R_GIT_PERSIST = "ST-GIT-HOOK-PERSIST"
R_SKILL_EXEC = "ST-SKILL-DYNAMIC-EXEC"

# Where an honest auto-run command is a finding: configuration of the project itself (agent hook
# files, Claude Code settings commands, VS Code folder-open tasks) runs when someone merely opens
# the project, and a published package has no reason to ship it. A Claude Code plugin's own hooks
# (HookPry, 2026) and the hooks of a skill or subagent are what the user installs them for, and what
# HookPry abuses is an *update* adding one, which a single snapshot cannot see: an honest hook there
# is listed for review and never scored. An MCP server is started by a command by design, and a
# plugin's monitors and language servers are what it ships, so nothing is said about honest ones.
# Every origin gets the fetch-or-decode-and-run check (and, in secret_exfil, the credential check).
# Host names compared against, never bound to.
_HTTP_HOOK_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})  # nosec B104

# `.git/config`'s `core.fsmonitor` (GitSpawn, 2026): file_index.py reads this one path despite
# the general `.git` skip, because its content is itself an auto-exec surface, and hands it only
# to this check (`index.git_config`, never `index.files`). A boolean value
# (git's own built-in daemon) is the honest, overwhelmingly common case and is never flagged. A
# bare local hook path (e.g. a large monorepo's watchman integration) is not a malware verdict on
# its own -- it is a command git will run automatically, so it is surfaced for review, not
# flagged. Only a fetch-and-run / decode-and-run value is a malicious indicator.
_FSMONITOR = re.compile(r"^[ \t]*fsmonitor[ \t]*=[ \t]*(.+?)[ \t]*$", re.MULTILINE | re.IGNORECASE)
_GIT_BOOL_VALUES = frozenset({"true", "false", "yes", "no", "on", "off", "1", "0"})

# Fetch-and-run or decode-and-run, in a shell command or in the source of a script: a download
# piped into a shell (or into an interpreter reading its program from stdin), a download run through
# `sh -c "$(...)"`, `eval "$(...)"` or a process substitution, PowerShell's download-then-iex in
# either order, an encoded PowerShell command, and the same in JavaScript or Python.
# The gaps between the parts are bounded: an unbounded `[^\n]*` after each `curl` of a crafted
# line rescanned the rest of the line from every one of them (quadratic).
_FETCH = r"(?:curl|wget)\b"
_GAP = r"[^\n]{0,1000}?"
_REMOTE_EXEC = re.compile(
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
    r"|\beval\s*\(\s*(?:await\s+)?\(?\s*(?:await\s+)?fetch\s*\("
    r"|\bexec\s*\(\s*(?:urllib\.request\.)?urlopen\s*\(",
    re.IGNORECASE,
)

_AI_CLIS = r"(?:claude|gemini|codex|kiro(?:-cli)?|opencode|aider|cursor-agent|qwen|amp|q\s+chat)"
_BYPASS_FLAGS = (
    r"(?:--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|"
    r"--trust-all-tools|--allow-all-tools|--approval-mode[= ]yolo)"
)
_CLI_BYPASS = re.compile(rf"\b{_AI_CLIS}\b[^\n]{{0,160}}?({_BYPASS_FLAGS})", re.IGNORECASE)
_CODE_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".sh", ".bash", ".zsh", ".ps1")


def _flag_in_inline_code(f: IndexedFile, m: re.Match[str]) -> bool:
    """True if the matched bypass flag is a markdown inline-code span inside Python text.

    Python has no backtick syntax, so `` `--dangerously-skip-permissions` `` in a .py file is
    formatting in text written for a reader -- the prompt of a security-review hook describing the
    flag as a vulnerability (anthropics/claude-code), or help text -- not an argument handed to a
    process. A real launch passes the flag as its own string or inside a command string.
    """
    if f.suffix not in (".py", ".pyw"):
        return False
    start, end = m.start(1), m.end(1)
    return start > 0 and f.text[start - 1] == "`" and end < len(f.text) and f.text[end] == "`"


# --- MCP-client config injection (SANDWORM_MODE "McpInject", 2026) ---------------------------
# Writing an attacker server into ANOTHER AI client's config loads it on that client's next
# session, from a package the user installed for something else. These are the config files of the
# common AI clients; a third-party component has no honest reason to write to them. `.claude/`
# settings are already covered by the auto-run rule above, so they are left out here.
_CLIENT_CONFIG_PATHS = re.compile(
    r"(?:claude_desktop_config\.json"
    r"|\.cursor[/\\]mcp\.json"
    r"|\.vscode[/\\]mcp\.json"
    r"|\.continue[/\\]config\.(?:json|yaml|yml)"
    r"|windsurf[/\\]mcp_config\.json"
    r"|\.codeium[/\\][^\s\"']{0,64}mcp[^\s\"']{0,64}\.json"
    r"|(?<![\w.])\.claude\.json)",
    re.IGNORECASE,
)
# A file-writing sink, in any of the languages we see. Reading these configs can be benign
# (a tool that lists / health-checks your installed servers); only WRITING one is the injection.
_WRITE_SINK = re.compile(
    r"\b(?:writeFileSync|writeFile|appendFileSync|appendFile|outputFile(?:Sync)?|createWriteStream"
    r"|write_text|write_bytes|Out-File|Set-Content|Add-Content)\b"
    r"|\bjson\.dump\s*\("
    r"|\bopen\s*\([^)]{0,200},\s*['\"][rbt]*[wa]\+?[rbt]*['\"]",
    re.IGNORECASE,
)
# The config path must be the TARGET of a write, not merely mentioned in the same file. A health
# check that reads ~/.claude.json and writes its OWN state file elsewhere (e.g. ECC's
# mcp-health-check.js) is not injection. This matches when a write sink opens its argument list and
# the config path appears inside it, on the same statement (bounded so a crafted line cannot
# backtrack). The config path (built from the shared alternation) is appended by the scanner.
_WRITE_CALL_OPEN = (
    r"(?:writeFileSync|writeFile|appendFileSync|appendFile|outputFile(?:Sync)?|createWriteStream"
    r"|Out-File|Set-Content|Add-Content|json\.dump|open)\s*\("
)
_WRITE_BEFORE = re.compile(_WRITE_CALL_OPEN + r"[^;\n]{0,200}$", re.IGNORECASE)
# Python `Path(...).write_text(...)` / `.write_bytes(...)`: the path precedes the write method.
_WRITE_METHOD_AFTER = re.compile(r"^[^;\n]{0,120}?\.write_(?:text|bytes)\s*\(", re.IGNORECASE)
# The variable a statement assigns the config path to, so a one-hop write through it is caught
# (`const target = home + '/.cursor/mcp.json'; writeFileSync(target, data)`). A health check that
# returns the paths in a list (`return [path.join(cwd, '.claude.json'), …]`) has no such
# assignment head, so it is not matched — closing the injection bypass without re-flagging reads.
_ASSIGN_HEAD = re.compile(r"^(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=(?!=)")


def _is_write_target(text: str, start: int, end: int) -> bool:
    """True if the config-path span [start,end) is (or flows one hop to) a write sink's target."""
    line_start = text.rfind("\n", 0, start) + 1
    stmt_start = max(line_start, text.rfind(";", line_start, start) + 1)
    before = text[max(stmt_start, start - 200):start]
    if _WRITE_BEFORE.search(before):
        return True
    if _WRITE_METHOD_AFTER.match(text[end:end + 120]):
        return True
    # One-hop: the path is assigned to a variable that is then written.
    m = _ASSIGN_HEAD.match(before)
    if m:
        var = re.escape(m.group(1))
        if re.search(_WRITE_CALL_OPEN + r"[^;\n]{0,200}\b" + var + r"\b", text, re.IGNORECASE):
            return True
        method = r"\b" + var + r"\b[^;\n]{0,80}\.write_(?:text|bytes)\s*\("
        if re.search(method, text, re.IGNORECASE):
            return True
    return False


# --- writes into an AI agent's own configuration, instructions or memory --------------------
# Beyond the MCP client configs above: the agent's settings (hooks, permissions, status line),
# its skills/agents/commands folders, and the instruction and memory files it reads at every
# session start. What is written there steers the agent in every later session. A CLI's own `init`
# command honestly writes AGENTS.md or CLAUDE.md into the project, so a project-relative write is
# listed for review; one into the user's home directory is a risky construct; one made at install
# or import time is a malicious indicator (ST-AGENT-CONFIG-PERSIST).
_AGENT_SETTINGS_PATHS = re.compile(
    r"\.claude[/\\](?:settings(?:\.local)?\.json|(?:skills|agents|commands)(?![\w.-]))"
    r"|\.codex[/\\]config\.toml"
    r"|\.gemini[/\\]settings\.json"
    r"|\.vscode[/\\]settings\.json"
    r"|\.cursor[/\\]rules(?![\w.-])"
)
_AGENT_INSTRUCTION_PATHS = re.compile(
    r"(?<![\w.-])(?:CLAUDE|AGENTS|GEMINI|SOUL|MEMORY)\.md(?![\w.-])"
    r"|\.github[/\\]copilot-instructions\.md"
)
_AGENT_TARGETS = re.compile(
    _AGENT_SETTINGS_PATHS.pattern + "|" + _AGENT_INSTRUCTION_PATHS.pattern
)
# A file names one of the targets only when it holds one of these (a path split into join
# segments still holds the folder name); every other file is skipped for free.
_AGENT_TOKENS = (
    ".claude", ".codex", ".gemini", ".cursor", ".vscode", ".continue", ".codeium", "windsurf",
    "copilot-instructions", "CLAUDE.md", "AGENTS.md", "GEMINI.md", "SOUL.md", "MEMORY.md",
)
_KIND_CLIENT, _KIND_SETTINGS, _KIND_INSTRUCTIONS = "client", "settings", "instructions"
# A write that adds an auto-run command or an approval: a hook, a permission rule, an MCP
# server's auto-approve list, a status line or credential helper command.
_HOOK_KEYS = re.compile(
    r"[\"']?\b(?:hooks|PreToolUse|PostToolUse|SessionStart|UserPromptSubmit|permissions"
    r"|autoApprove|alwaysAllow|statusLine|apiKeyHelper)\b[\"']?\s*[:=]"
)
# The user's home directory (or the per-user application data folder), however it is named.
_HOME_MARKER = re.compile(
    r"~[/\\]|\$\{?(?:HOME|USERPROFILE|APPDATA)\b|%(?:USERPROFILE|APPDATA)%"
    r"|\$env:(?:USERPROFILE|APPDATA)"
    r"|\bhomedir\s*\)?\s*\(|process\.env(?:\.|\[\s*['\"])(?:HOME|USERPROFILE|APPDATA)\b"
    r"|\bPath\.home\s*\(|\bexpanduser\s*\("
    r"|\b(?:environ(?:\.get\s*\(|\s*\[)|getenv\s*\()\s*['\"](?:HOME|USERPROFILE|APPDATA)['\"]",
    re.IGNORECASE,
)
# Calls whose first argument is the file they write, and calls that write their second (copy,
# move, link). `open` writes only with a write mode, read from the call itself.
_WRITE_CALLS = frozenset({
    "writeFileSync", "writeFile", "appendFileSync", "appendFile", "outputFile", "outputFileSync",
    "outputJson", "outputJsonSync", "writeJson", "writeJsonSync", "createWriteStream",
})
_COPY_CALLS = frozenset({
    "copyFileSync", "copyFile", "cpSync", "renameSync", "rename", "copy", "copySync", "move",
    "moveSync", "symlinkSync", "symlink", "linkSync", "ensureSymlink",
})
_OPEN_CALLS = frozenset({"open", "openSync"})
_CALLEE = re.compile(r"([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*$")
_OPEN_WRITE_MODE = re.compile(
    r",\s*(?:mode\s*=\s*)?['\"][rbt]*[wax]\+?[rbt]*['\"]|flags\s*:\s*['\"][wa]"
)
# Shell writes: a redirect, tee, PowerShell's file cmdlets, and cp/mv/install/ln (destination
# last). `=>`, `->` and an HTML tag's `>` are not redirects.
_SHELL_WRITE_BEFORE = re.compile(
    r"(?:(?<![=<>\-\w])>>?\s*|\btee\s+(?:-a\s+)?"
    r"|\b(?:Out-File|Set-Content|Add-Content|Copy-Item|Move-Item)\b[^\n|;]{0,160}?\s"
    r"|\b(?:cp|mv|install|ln)\b[^\n;|&]{1,300}?\s)"
    r"[\"']?[^\s\"'<>|;&]*$",
    re.IGNORECASE,
)
_SHELL_COPY_BEFORE = re.compile(r"\b(?:cp|mv|install|ln|Copy-Item|Move-Item)\b", re.IGNORECASE)
_SHELL_REDIRECT_BEFORE = re.compile(r"(?:(?<![=<>\-\w])>>?|\btee)\s*(?:-a\s+)?[\"']?\S*$")
_SHELL_ARG_END = re.compile(r"[^\s\"';|&]*[\"']?[ \t]*(?:[;|&)#].*)?")
_SHELL_SUFFIXES = (".sh", ".bash", ".zsh", ".ps1")
# A line of another language that runs a shell command, where a redirect inside a string counts.
_PROCESS_CALL = re.compile(r"\b(?:exec\w*|spawn\w*|system|Popen|check_call|check_output|run)\s*\(")
_JS_ASSIGN = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]{0,60})\s*=\s*")
_PY_SHELL_ASSIGN = re.compile(r"^[ \t]*(?:export[ \t]+)?([A-Za-z_]\w{0,60})[ \t]*=[ \t]*")
_JS_TEMPLATE_VAR = re.compile(
    r"`\$\{\s*([A-Za-z_$][\w$]{0,60})\s*\}((?:[^`\\$]|\\.|\$(?!\{)){1,200})`"
)
_JS_PLUS_VAR = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]{0,60})\s*\+\s*(['\"])((?:(?!\2)[^\\\n]|\\.){1,300})\2"
)
_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
# A package.json install hook, whose command runs at every install of the package.
_NPM_INSTALL_HOOK_LINE = re.compile(
    r"\"(?:preinstall|install|postinstall)\"\s*:\s*\"((?:[^\"\\\n]|\\.){1,2000})\""
)
_MAX_TARGETS_PER_FILE = 2000
# Python files an import runs at the top level: a package's `__init__`, and the start-up hooks.
_PY_IMPORT_HOOK_NAMES = frozenset({"__init__.py", "sitecustomize.py", "usercustomize.py"})


def _target_kind(path: str) -> str | None:
    if _CLIENT_CONFIG_PATHS.search(path):
        return _KIND_CLIENT
    if _AGENT_SETTINGS_PATHS.search(path):
        return _KIND_SETTINGS
    if _AGENT_INSTRUCTION_PATHS.search(path):
        return _KIND_INSTRUCTIONS
    return None


# How far around a match the checks below look: a statement, never a whole minified line.
_WINDOW = 400


def _line_start(text: str, pos: int) -> int:
    lo = max(0, pos - _WINDOW)
    return max(lo, text.rfind("\n", lo, pos) + 1)


def _line_end(text: str, pos: int) -> int:
    hi = min(len(text), pos + _WINDOW)
    end = text.find("\n", pos, hi)
    return hi if end < 0 else end


def _statement_start(text: str, start: int) -> int:
    line_start = _line_start(text, start)
    return max(line_start, text.rfind(";", line_start, start) + 1)


def _call_args_text(text: str, open_at: int) -> str:
    """The argument text of the call whose ``(`` is at ``open_at`` (bounded, best effort)."""
    depth = 0
    for i in range(open_at, min(len(text), open_at + 400)):
        if text[i] in "([{":
            depth += 1
        elif text[i] in ")]}":
            depth -= 1
            if depth == 0:
                return text[open_at:i]
    return text[open_at:open_at + 400]


def _in_write_call(text: str, pos: int) -> bool:
    """True if ``pos`` lies in the argument a write call writes: the first of ``writeFileSync``
    and its kin (also inside a nested ``path.join``), the second of a copy or move, the first of
    ``open`` with a write mode. Walks outwards through the enclosing brackets of the statement;
    a function body's ``{`` ends the walk."""
    depth, commas = 0, 0
    lo = max(0, pos - _WINDOW)
    i = pos - 1
    while i >= lo:
        ch = text[i]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth:
                depth -= 1
            elif ch == "{" and text[lo:i].rstrip()[-1:] in (")", ">", ""):
                return False
            else:
                if ch == "(":
                    m = _CALLEE.search(text, max(lo, i - 80), i)
                    name = re.sub(r"\s+", "", m.group(1)) if m else ""
                    last = name.rsplit(".", 1)[-1]
                    if last in _WRITE_CALLS and commas == 0:
                        return True
                    if last in _COPY_CALLS and commas >= 1 and (
                        "." in name or last.endswith("Sync")
                    ):
                        return True
                    if last in _OPEN_CALLS and commas == 0 and _OPEN_WRITE_MODE.search(
                        _call_args_text(text, i)
                    ):
                        return True
                commas = 0
        elif ch == "," and not depth:
            commas += 1
        elif ch == ";" and not depth:
            return False
        i -= 1
    return False


def _shell_writes(text: str, start: int, end: int, stop: int | None = None) -> bool:
    """True if a shell redirect, ``tee``, a PowerShell file cmdlet or the destination of
    ``cp``/``mv``/``install``/``ln`` writes the path at ``[start, end)``. ``stop`` ends the
    command early (a command held in a JSON string)."""
    before = text[_line_start(text, start):start]
    m = _SHELL_WRITE_BEFORE.search(before)
    if m is None:
        return False
    if _SHELL_COPY_BEFORE.search(m.group(0)) and not _SHELL_REDIRECT_BEFORE.search(before):
        line_end = _line_end(text, end)
        rest = text[end:line_end if stop is None else min(stop, line_end)]
        return _SHELL_ARG_END.fullmatch(rest) is not None  # the destination is the last word
    return True


class _WriteChecker:
    """Whether a path span in one file is the target of a write, directly or one name away."""

    def __init__(self, f: IndexedFile, shell_file: bool):
        self.f = f
        self.shell_file = shell_file

    def _shell_ok(self, start: int) -> bool:
        if self.shell_file:
            return True
        text = self.f.text
        return bool(_PROCESS_CALL.search(text, _line_start(text, start), _line_end(text, start)))

    def direct(self, start: int, end: int) -> bool:
        text = self.f.text
        if _in_write_call(text, start) or _WRITE_METHOD_AFTER.match(text[end:end + 120]):
            return True
        return self._shell_ok(start) and _shell_writes(text, start, end)

    def writes(self, start: int, end: int) -> bool:
        if self.direct(start, end):
            return True
        # One hop: the path is assigned to a name that a write then targets.
        text = self.f.text
        head = text[_statement_start(text, start):start].lstrip()
        m = _ASSIGN_HEAD.match(head) or _PY_SHELL_ASSIGN.match(head)
        if m is None:
            return False
        name = re.escape(m.group(1))
        use = re.compile(rf"(?<![\w$.])\$?\{{?{name}\}}?(?![\w$])")
        for count, occurrence in enumerate(use.finditer(text, end)):
            if count >= 50:
                break
            if self.direct(occurrence.start(), occurrence.end()):
                return True
        return False


def _js_home_pattern(text: str) -> re.Pattern[str]:
    names = {m.group(1) for m in _JS_HOME_VAR.finditer(text)}
    alts = [_JS_HOME_EXPR] + [rf"(?<![\w$.]){re.escape(n)}(?![\w$])" for n in sorted(names)]
    return re.compile("|".join(f"(?:{a})" for a in alts))


def _js_built_paths(f: IndexedFile) -> list[tuple[int, int, str]]:
    """``(start, end, path)`` for each path a JS/TS file builds from segments: joined onto the
    home directory (see ``joined_js_paths``), or joined from strings and names that hold a path
    built earlier in the file (``const dir = path.join(os.homedir(), '.claude');
    path.join(dir, 'settings.json')``). The home directory reads as ``~``."""
    text = f.text
    out = list(joined_js_paths(f))
    home = _js_home_pattern(text)
    path_vars: dict[str, str] = {}

    def segment(arg: str) -> str:
        value = _js_segment(arg, home)
        if value == _JS_UNKNOWN_SEGMENT:
            return path_vars.get(arg, value)
        return value

    def joined(pos: int) -> tuple[int, int, str] | None:
        m = _JS_JOIN_CALL.match(text, pos)
        if m is None:
            return None
        call = _js_call_args(text, m.end() - 1)
        if call is None or not call[0]:
            return None
        segments = [segment(a) for a in call[0]]
        if all(s == _JS_UNKNOWN_SEGMENT for s in segments):
            return None
        return m.start(), call[1], re.sub(r"/{2,}", "/", "/".join(segments))

    for m in _JS_ASSIGN.finditer(text):
        built = joined(m.end())
        if built is not None:
            path_vars[m.group(1)] = built[2]
            continue
        literal = _JS_STRING.match(text, m.end())
        if literal and re.match(r"\s*[;\n]", text[literal.end():literal.end() + 2]):
            path_vars[m.group(1)] = literal.group(2) if literal.group(1) else literal.group(3)
    for m in _JS_JOIN_CALL.finditer(text):
        built = joined(m.start())
        if built is not None:
            out.append(built)
    for m in _JS_TEMPLATE_VAR.finditer(text):
        if m.group(1) in path_vars:
            out.append((m.start(), m.end(), path_vars[m.group(1)] + m.group(2)))
    for m in _JS_PLUS_VAR.finditer(text):
        if m.group(1) in path_vars:
            out.append((m.start(), m.end(), path_vars[m.group(1)] + m.group(3)))
    return out


# --- git-hook persistence (SANDWORM_MODE / supply-chain worms, 2026) -------------------------
# Repointing git's GLOBAL template dir makes a hook run for every repository the victim creates
# or clones. `init.templateDir` is rare and essentially never benign. `core.hooksPath` is NOT a
# reliable signal on its own: husky/lefthook/pre-commit all set it LOCALLY to a repo directory,
# so it is flagged only when set `--global`/`--system` (reaching outside the current repo).
# `core.fsmonitor` is handled by the .git/config rule above (git runs it directly).
_GIT_PERSIST = re.compile(
    r"\bgit\b[^\n]{0,40}?\bconfig\b[^\n]{0,80}?\binit\.templateDir\b"
    r"|\bgit\b[^\n]{0,40}?\bconfig\b(?=[^\n]{0,200}?\bcore\.hooksPath\b)[^\n]{0,200}?--(?:global|system)\b"
    r"|\bgit\b[^\n]{0,40}?\bconfig\b(?=[^\n]{0,200}?--(?:global|system)\b)[^\n]{0,200}?\bcore\.hooksPath\b",
    re.IGNORECASE,
)
# Reading or clearing the config is not installing persistence: `git config --global --get
# core.hooksPath`, or the value-less `git config --global core.hooksPath` (then `|| true` / end of
# command), just reads the current value — ECC's codex tooling does this to save/restore it.
_GIT_CONFIG_READ = re.compile(r"--(?:get|get-all|get-regexp|list|unset|unset-all|null)\b", re.I)
# core.hooksPath followed by an actual value (a SET), vs. nothing / a shell terminator (a READ).
_HOOKSPATH_SET = re.compile(r"core\.hooksPath\b[ \t]+[\"']?[^\s|&;)>\"']", re.I)
# Note on restore-instruction help text (`echo "to undo: git config --global core.hooksPath …"`):
# a line that merely PRINTS the command is demoted uniformly for every rule by the engine's
# ``IndexedFile.in_printed_command`` (echo/printf/console.log), so this scanner does not redo it.
# A command that actually RUNS -- `eval "…"`, `echo x; git config …`, a user-defined `log`
# function -- is not a print builtin and stays detected.

# --- auto-executed command in an Agent Skill (Clawsights dynamic context, Datadog 2026) ------
# A Claude Code skill may embed a "dynamic context" command with a leading `!` (bare or wrapped
# in backticks). It runs when the skill loads, before the model reads the skill, so `allowed-tools`
# refusals do not help. A benign skill uses this for `!`git status``; a malicious one hides a
# credential grab or a fetch-and-run in it. Only the dangerous bodies are flagged.
_SKILL_DYNAMIC_CMD = re.compile(r"(?m)^[ \t>]*!\s*(\S[^\n]*)")
# A credential source piped/joined to a network sink (exfil), or a fetch-and-run. `gh auth token`,
# an SSH/AWS/keychain read, or a kube/npm credential, reaching curl/wget/nc or an http(s) URL.
_SKILL_CRED_SOURCE = re.compile(
    r"\bgh\s+auth\s+(?:token|status\s+[^\n]{0,80}--show-token)"
    r"|security\s+find-(?:generic|internet)-password"
    r"|~/\.ssh\b|~/\.aws\b|\.aws/credentials|\bid_rsa\b|\.kube/config|~/\.npmrc|\.git-credentials",
    re.IGNORECASE,
)
_SKILL_NET_SINK = re.compile(
    r"\b(?:curl|wget|nc|ncat|http|https)\b|https?://", re.IGNORECASE
)

# A path-looking token in a command that may name a script shipped in the component. Bounded: an
# unbounded run before the extension backtracked from every start of a long token (40,000
# characters took 15 s); no real script path is longer.
_PATH_TOKEN = re.compile(r"[\w.${}/\\-]{1,300}\.(?:m?js|cjs|ts|py|sh|bash|ps1)\b")

# An outbound network client: a connection the component itself opens to a remote endpoint.
# Used ONLY as the second half of the remote-control shape below (never a finding on its own),
# so a broad idiom list is safe here -- the rare CLI-bypass anchor is what makes a match specific.
# A relay package (a cluster of npm packages, Sept 2026)
# opens a socket to a hardcoded host, reads task objects from it, and drives the victim's own
# agent CLI with approvals off. Local automation that disables approvals operates on the checkout
# in front of it and does not also phone a remote host.
_NET_CLIENT = re.compile(
    r"\bnew\s+WebSocket\s*\("
    r"|\brequire\(\s*['\"]ws['\"]\s*\)"
    r"|\bimport\b[^\n]{0,60}?['\"]ws['\"]"
    r"|\b(?:https?|net|tls|dgram)\.(?:request|get|connect|createConnection)\s*\("
    r"|\bfetch\s*\("
    r"|\baxios\b"
    r"|\bwebsockets?\.(?:connect|ClientConnection)\s*\("
    r"|\bsocket\.(?:connect|create_connection)\s*\("
    r"|\brequests\.(?:get|post|put|request)\s*\("
    r"|\bhttpx\.(?:get|post|stream|Client|AsyncClient)\b"
    r"|\burllib\.request\.urlopen\s*\(",
    re.IGNORECASE,
)


class AgentConfigScanner(Scanner):
    name = "agent_config"
    rules = [
        RuleSpec(
            id=R_AUTORUN,
            category="agent_config",
            severity=Severity.MEDIUM,
            title="Agent or editor configuration runs a command or sends data automatically",
            description=(
                "The component ships agent or IDE configuration that acts without a separate "
                "step: a Claude Code / Gemini CLI / Cursor hook, a Claude Code status line or "
                "credential helper command, or a VS Code task that runs when the folder opens. "
                "Opening the project in that tool runs it with the developer's privileges. An "
                "`http` hook (here or in a plugin or skill) posts each event it is bound to, tool "
                "input and output included, to a server that is not this machine."
            ),
            recommendation=(
                "Read the command and anything it runs, or the URL a hook posts to, before "
                "opening this project in an agent or editor. A published package has no reason "
                "to ship project auto-run config."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
        # Seen in the wild: the Miasma npm worm re-infected projects through .claude/, .gemini/
        # and .vscode/ configuration (June 2026). Rule texts describe behavior, never a campaign.
        RuleSpec(
            id=R_AUTORUN_REMOTE,
            category="agent_config",
            severity=Severity.HIGH,
            title="Auto-run agent configuration fetches or decodes code and executes it",
            description=(
                "A command an agent or editor runs on its own -- a hook or task, an MCP server's "
                "launch command, a status line or credential helper, a plugin's monitor or "
                "language server, or a hook in a skill's or subagent's frontmatter -- or the "
                "script it runs from this component, downloads code and pipes it into a shell or "
                "decodes and runs it. Opening the project, installing the plugin or starting the "
                "server runs it without a prompt."
            ),
            recommendation=(
                "Do not open the project, install the plugin or add the server. Remove the "
                "configuration and treat a machine that already ran it as exposed."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_CLI_BYPASS,
            category="agent_config",
            severity=Severity.HIGH,
            title="Code launches an AI coding CLI with its permission checks disabled",
            description=(
                "Code runs a local AI coding agent (claude, gemini, codex, q …) with a flag that "
                "turns off its approval prompts. The agent then acts with the user's credentials "
                "and file access, and nobody confirms what it does."
            ),
            recommendation=(
                "Confirm why the component drives an AI agent unattended and what prompt it "
                "sends. Prefer explicit, narrow tool allowlists over disabling approvals."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            # A launch passes the flag as a value-string; a comment or a docstring that names it
            # documents the flag. (Inline-code mentions in Python text are set aside in scan().)
            code_context="comments_and_docstrings",
        ),
        RuleSpec(
            id=R_CLI_RELAY,
            category="agent_config",
            severity=Severity.HIGH,
            title="A remote connection drives an AI coding CLI with its permission checks disabled",
            description=(
                "The same file opens an outbound connection to a remote endpoint and launches a "
                "local AI coding agent (claude, gemini, codex, q ...) with a flag that turns off "
                "its approval prompts. A relay of this shape can feed tasks from a remote server "
                "to the user's own agent, which then acts with the user's credentials and file "
                "access without asking. Local automation that disables approvals runs against "
                "the checkout in front of it and does not also connect to a remote host."
            ),
            recommendation=(
                "Do not install this component. A package has no reason to pipe instructions from "
                "a remote server into an AI agent running with approvals off; treat a machine that "
                "already ran it as exposed."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            code_context="comments",
        ),
        RuleSpec(
            id=R_GITCONFIG_REMOTE,
            category="agent_config",
            severity=Severity.HIGH,
            title="A shipped .git/config fetches or decodes code and runs it on git status/diff",
            description=(
                "This component's own `.git/config` sets `core.fsmonitor` to a command that "
                "fetches code and pipes it into a shell, or decodes and runs it. Git runs that "
                "command on ordinary operations (`git status`, `git diff`) to refresh its index -- "
                "several AI coding agents run exactly those commands at session startup, before "
                "any trust prompt (GitSpawn, 2026)."
            ),
            recommendation=(
                "Do not open this project in an agent, editor, or run git commands in it. Remove "
                "`core.fsmonitor` from .git/config and treat a machine that already opened it as "
                "exposed."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_CONFIG_INJECT,
            category="agent_config",
            severity=Severity.HIGH,
            title="Code writes to an AI agent's MCP configuration, settings or instruction files",
            description=(
                "The component writes to a config file of a separate AI client (Claude Desktop, "
                "Cursor, VS Code, Continue, Windsurf), or, in the user's home directory, to an "
                "AI agent's settings, skills, subagents, commands or instruction and memory files "
                "(Claude Code, Codex, Gemini CLI, Cursor rules, AGENTS.md, CLAUDE.md). A server, "
                "hook or instruction added there loads in the agent's next session. That is "
                "expected from a command the user runs to set the agent up, and unexpected from "
                "code that runs on install or import."
            ),
            recommendation=(
                "Confirm why the component edits an agent's configuration or instructions. A tool "
                "that registers itself should ask the user and write only what it says it writes."
            ),
            capability=Capability.FILESYSTEM_WRITE,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            # A comment that names the write does not write anything.
            code_context="comments",
        ),
        RuleSpec(
            id=R_CONFIG_PERSIST,
            category="agent_config",
            severity=Severity.HIGH,
            title="Install- or import-time code writes into the user's AI agent configuration",
            description=(
                "Code that runs when the package is installed or imported (a script an npm "
                "install hook runs, a .pth line, setup.py, or the top level of a package module) "
                "writes into an AI agent's configuration in the user's home directory (settings, "
                "MCP servers, skills, instruction or memory files such as ~/.claude/CLAUDE.md, "
                "~/.codex/AGENTS.md, ~/.gemini/GEMINI.md), or adds a hook or permission entry to "
                "agent settings. Every later agent session then loads what was written, without "
                "the user having run or seen anything."
            ),
            recommendation=(
                "Do not install this version. Inspect and restore the named agent files on any "
                "machine that installed it, and remove hooks, servers and instructions it added."
            ),
            capability=Capability.FILESYSTEM_WRITE,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            code_context="comments",
        ),
        RuleSpec(
            id=R_GIT_PERSIST,
            category="agent_config",
            severity=Severity.HIGH,
            title="Code installs a global git hook / template for persistence",
            description=(
                "The component runs `git config` to point git's global template directory or "
                "hooks path at its own files, so a hook runs for every repository the user "
                "creates or clones afterwards."
            ),
            recommendation=(
                "Do not install the component. A package has no legitimate reason to repoint the "
                "user's global git template or hooks path."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            code_context="comments",
        ),
        RuleSpec(
            id=R_SKILL_EXEC,
            category="agent_config",
            severity=Severity.HIGH,
            title="Agent skill auto-runs a command that steals credentials or fetches code",
            description=(
                "An Agent Skill embeds a `!` dynamic-context command that runs when the skill "
                "loads — before the model reads the skill, so its tool restrictions do not apply "
                "— and that command reads a credential and sends it off-host, or downloads code "
                "and runs it. This is the malicious-skill pattern Datadog documented (Clawsights)."
            ),
            recommendation=(
                "Do not install the skill. Remove any `!` dynamic-context command that touches "
                "credentials or the network; it executes without the user's confirmation."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        by_path = {f.relpath: f for f in index.files}
        autorun: list[Evidence] = []
        remote: list[Evidence] = []
        scan = autorun_commands(index)
        needs_review: list[NeedsReview] = list(scan.reviews)
        # Honest hooks of a plugin, a skill or a subagent, per file, for one review note each.
        honest: dict[tuple[str, str], list[AutorunCommand]] = {}
        for command in scan.commands:
            if command.is_http:
                if _is_remote_url(command.text):
                    autorun.append(command.evidence())
                continue
            text = command.text
            m = _REMOTE_EXEC.search(text)
            if m:
                ev = command.evidence(command.piece_at(m.start()))
                autorun.append(ev)
                remote.append(ev)
                continue
            script = self._referenced_script(text, by_path, command.file.relpath)
            m = _REMOTE_EXEC.search(script.text) if script is not None else None
            if m and script is not None:
                ev = command.evidence()
                autorun.append(ev)
                remote.extend([ev, script.evidence_for_span(m.start(), m.end())])
            elif command.origin == ORIGIN_PROJECT:
                autorun.append(command.evidence())
            elif command.origin in (ORIGIN_PLUGIN, ORIGIN_SKILL) and command.kind == KIND_HOOK:
                honest.setdefault((command.file.relpath, command.origin), []).append(command)
        for (relpath, origin), commands in honest.items():
            texts = "; ".join(c.text[:120] for c in commands[:5])
            if origin == ORIGIN_PLUGIN:
                title = "Plugin binds lifecycle hooks"
                reason = (
                    f"This plugin runs these commands on agent lifecycle events: {texts}. Confirm "
                    "they do what the plugin says, and re-check after updates: an update can add "
                    "a hook without the user seeing it (HookPry, 2026)."
                )
            else:
                title = "Skill or subagent binds lifecycle hooks"
                reason = (
                    f"This skill or subagent's frontmatter runs these commands on agent lifecycle "
                    f"events once it is used: {texts}. Confirm they do what it says."
                )
            needs_review.append(NeedsReview(
                category="agent_config", title=title, reason=reason, file=relpath,
                line=commands[0].evidence().line_start,
            ))

        bypass: list[Evidence] = []
        bypass_described: list[str] = []
        config_inject: list[Evidence] = []
        git_persist: list[Evidence] = []
        relay: list[Evidence] = []
        for f in index.select(suffixes=_CODE_SUFFIXES):
            file_bypass: list[Evidence] = []
            for _m, ev in f.finditer(_CLI_BYPASS):
                if _flag_in_inline_code(f, _m):
                    if f.relpath not in bypass_described:
                        bypass_described.append(f.relpath)
                    continue
                file_bypass.append(ev)
            if file_bypass and len(bypass) + len(relay) < MAX_EVIDENCE_SCANNED:
                net = next((ev for _m, ev in f.finditer(_NET_CLIENT)), None)
                if net is not None:
                    # Remote-control shape: approvals-off CLI and an outbound connection, one file.
                    relay.extend(file_bypass)
                    relay.append(net)
                else:
                    bypass.extend(file_bypass)
            for _m, ev in f.finditer(_GIT_PERSIST):
                line = f.line_text(ev.line_start)
                # A read (`--get`/`--list`/`--unset`, or value-less `core.hooksPath`) is not
                # persistence. (Printed restore-help is demoted later by in_printed_command.)
                if _GIT_CONFIG_READ.search(line):
                    continue
                lower = line.lower()
                reads_hookspath = (
                    "core.hookspath" in lower
                    and "templatedir" not in lower
                    and not _HOOKSPATH_SET.search(line)
                )
                if reads_hookspath:
                    continue
                git_persist.append(ev)
                if len(git_persist) >= MAX_EVIDENCE_SCANNED:
                    break
            # Writing to another client's config is the injection; reading or health-checking one
            # is benign, so the config path must be the TARGET of a write sink, not just present.
            if _WRITE_SINK.search(f.text):
                for m, ev in f.finditer(_CLIENT_CONFIG_PATHS):
                    if _is_write_target(f.text, m.start(), m.end()):
                        config_inject.append(ev)
                        if len(config_inject) >= MAX_EVIDENCE_SCANNED:
                            break

        # Folded view: catch a client-config path split across string literals
        # (``"~/.cursor/" + "mcp.json"``). Same rule — it must be a write target.
        config_inject_lines = {(e.file, e.line_start) for e in config_inject}
        for f, start, end in concat_folded_spans(
            index, _CLIENT_CONFIG_PATHS, suffixes=_CONFIG_INJECT_SUFFIXES
        ):
            if len(config_inject) >= MAX_EVIDENCE_SCANNED:
                break
            if not _WRITE_SINK.search(f.text) or not _is_write_target(f.text, start, end):
                continue
            ev = f.evidence_for_span(start, end)
            if (ev.file, ev.line_start) not in config_inject_lines:
                config_inject_lines.add((ev.file, ev.line_start))
                config_inject.append(ev)

        # Agent settings, instructions and memory, and any agent config written at install or
        # import time. A line written at install time is reported once, as the stronger rule.
        more_inject, config_persist, write_review = self._agent_config_writes(index)
        persist_lines = {(e.file, e.line_start) for e in config_persist}
        for ev in more_inject:
            if (ev.file, ev.line_start) not in config_inject_lines:
                config_inject_lines.add((ev.file, ev.line_start))
                config_inject.append(ev)
        config_inject = [e for e in config_inject if (e.file, e.line_start) not in persist_lines]
        write_review = [p for p in write_review if p not in config_inject_lines | persist_lines]
        if write_review:
            needs_review.append(aggregated_review(
                category="agent_config",
                title="Code writes an AI agent instruction or settings file in the project",
                places=sorted(set(write_review)),
                what="write(s) to an agent instruction or settings file (AGENTS.md, CLAUDE.md, "
                     ".claude/settings.json, .cursor/rules, ...) in a folder the code is given",
                advice="A CLI's own init or setup command does this honestly. Confirm it runs "
                       "only when the user asks, and that what it writes is what it says.",
            ))

        skill_exec: list[Evidence] = []
        for f in index.files:
            if not self._is_skill_file(f):
                continue
            for m in _SKILL_DYNAMIC_CMD.finditer(f.text):
                body = m.group(1).strip().strip("`").strip()
                dangerous = _REMOTE_EXEC.search(body) or (
                    _SKILL_CRED_SOURCE.search(body) and _SKILL_NET_SINK.search(body)
                )
                if dangerous:
                    skill_exec.append(f.evidence_for_span(m.start(1), m.end(1)))
                    if len(skill_exec) >= MAX_EVIDENCE_SCANNED:
                        break

        gitconfig_remote: list[Evidence] = []
        gitconfig = index.git_config
        if gitconfig is not None:
            self._scan_git_config(gitconfig, gitconfig_remote, needs_review)

        if bypass_described:
            needs_review.append(NeedsReview(
                category="agent_config",
                title="AI CLI permission-bypass flag named in text",
                reason=(
                    "A flag that turns off an AI coding CLI's approval prompts appears as inline "
                    "code in text (a prompt, help or documentation string), not as an argument "
                    f"to a process: {', '.join(bypass_described[:5])}. Confirm nothing launches "
                    "the CLI with it."
                ),
                file=bypass_described[0],
            ))

        findings = []
        if remote:
            findings.append(_finding_from_rule(self._rule(R_AUTORUN_REMOTE), remote))
        elif autorun:
            findings.append(_finding_from_rule(self._rule(R_AUTORUN), autorun))
        if relay:
            findings.append(_finding_from_rule(self._rule(R_CLI_RELAY), relay))
        if bypass:
            findings.append(_finding_from_rule(self._rule(R_CLI_BYPASS), bypass))
        if config_inject:
            findings.append(_finding_from_rule(self._rule(R_CONFIG_INJECT), config_inject))
        if config_persist:
            findings.append(_finding_from_rule(self._rule(R_CONFIG_PERSIST), config_persist))
        if git_persist:
            findings.append(_finding_from_rule(self._rule(R_GIT_PERSIST), git_persist))
        if skill_exec:
            findings.append(_finding_from_rule(self._rule(R_SKILL_EXEC), skill_exec))
        if gitconfig_remote:
            findings.append(_finding_from_rule(self._rule(R_GITCONFIG_REMOTE), gitconfig_remote))
        return ScanResult(findings=findings, needs_review=needs_review)

    @staticmethod
    def _agent_config_writes(
        index: FileIndex,
    ) -> tuple[list[Evidence], list[Evidence], list[tuple[str, int | None]]]:
        """Writes into an agent's configuration, instructions or memory, as (risky, written at
        install or import time, project-relative for review)."""
        inject: list[Evidence] = []
        persist: list[Evidence] = []
        review: list[tuple[str, int | None]] = []
        seen: set[tuple[str, int, bool]] = set()
        relpaths = {f.relpath for f in index.files}
        pth_modules: set[str] = set()
        for f in index.select(suffixes=(".pth",)):
            for line in f.text.splitlines():
                if line.startswith(("import ", "import\t")):
                    pth_modules |= _pth_imported_modules(line)

        def record(f: IndexedFile, ev: Evidence, kind: str, home: bool, install: bool) -> None:
            if install and (home or (kind != _KIND_INSTRUCTIONS and _HOOK_KEYS.search(f.text))):
                bucket = persist
            elif home or kind == _KIND_CLIENT:
                bucket = inject
            else:
                if not is_test_path(f.relpath):
                    review.append((ev.file, ev.line_start))
                return
            key = (ev.file, ev.line_start, bucket is persist)
            if key not in seen and len(bucket) < MAX_EVIDENCE_SCANNED:
                seen.add(key)
                bucket.append(ev)

        for f in index.files:
            suffix = f.suffix
            if f.relpath == "package.json":
                AgentConfigScanner._npm_install_hook_writes(f, record)
                continue
            if suffix not in _CODE_SUFFIXES and suffix != ".pth":
                continue
            if not any(token in f.text for token in _AGENT_TOKENS):
                continue
            text = f.text
            checker = _WriteChecker(f, shell_file=suffix in _SHELL_SUFFIXES)
            spans = [(m.start(), m.end(), m.group(0)) for m in _AGENT_TARGETS.finditer(text)]
            spans += [(m.start(), m.end(), m.group(0)) for m in _CLIENT_CONFIG_PATHS.finditer(text)]
            if suffix in _JS_SUFFIXES:
                spans += _js_built_paths(f)
            # One verdict per line, and a bounded number of checks per file: a crafted line that
            # repeats a target thousands of times costs no more than an honest one.
            lines_done: set[int] = set()
            targets = [(s, e, p, k) for s, e, p in spans if (k := _target_kind(p)) is not None]
            for start, end, path, kind in targets[:_MAX_TARGETS_PER_FILE]:
                if f.line_of_offset(start) in lines_done:
                    continue
                if not checker.writes(start, end):
                    continue
                lines_done.add(f.line_of_offset(start))
                home = path.startswith("~") or bool(
                    _HOME_MARKER.search(text, _statement_start(text, start), end)
                )
                if suffix == ".pth":
                    line = text[_line_start(text, start):start]
                    install = line.startswith(("import ", "import\t"))
                else:
                    install = f.relpath in index.install_scripts
                record(f, f.evidence_for_span(start, end), kind, home, install)
            if suffix in (".py", ".pyw"):
                when = AgentConfigScanner._python_import_time(f, relpaths, pth_modules)
                for write in python_path_writes(f):
                    kind = _target_kind(write.path)
                    if kind is None:
                        continue
                    install = when == "always" or (when == "top level" and write.top_level)
                    record(f, write.evidence, kind, write.path.startswith("~"), install)
        return inject, persist, review

    @staticmethod
    def _npm_install_hook_writes(f: IndexedFile, record) -> None:
        """An agent file written by the command of a package.json install hook itself."""
        for hook in _NPM_INSTALL_HOOK_LINE.finditer(f.text):
            command = hook.group(1)
            for m in _AGENT_TARGETS.finditer(command):
                start, end = hook.start(1) + m.start(), hook.start(1) + m.end()
                if not (_shell_writes(f.text, start, end, stop=hook.end(1))
                        or _in_write_call(f.text, start)):
                    continue
                home = bool(_HOME_MARKER.search(command, 0, m.end()))
                record(f, f.evidence_for_span(start, end), _target_kind(m.group(0)), home, True)
            for m in _CLIENT_CONFIG_PATHS.finditer(command):
                start, end = hook.start(1) + m.start(), hook.start(1) + m.end()
                if _shell_writes(f.text, start, end, stop=hook.end(1)) or _in_write_call(
                    f.text, start
                ):
                    home = bool(_HOME_MARKER.search(command, 0, m.end()))
                    record(f, f.evidence_for_span(start, end), _KIND_CLIENT, home, True)

    @staticmethod
    def _python_import_time(f: IndexedFile, relpaths: set[str], pth_modules: set[str]) -> str:
        """When a Python file's writes run on install or import: ``always`` for setup.py (its
        command classes run during the install too), ``top level`` for a module an import runs
        (a package's modules, the start-up hooks, a module a .pth line imports), else ``never``.
        A standalone script someone runs by hand is not imported by anything."""
        name = f.relpath.rsplit("/", 1)[-1]
        if name == "setup.py":
            return "always"
        folder = f.relpath.rsplit("/", 1)[0] if "/" in f.relpath else ""
        if name in _PY_IMPORT_HOOK_NAMES or (folder and f"{folder}/__init__.py" in relpaths):
            return "top level"
        stem = f.relpath.rsplit(".", 1)[0]
        for module in pth_modules:
            path = module.replace(".", "/")
            if stem == path or stem.endswith("/" + path):
                return "top level"
        return "never"

    # A Claude Code / agent skill file: the well-known name, or a markdown file whose YAML
    # frontmatter declares `allowed-tools` (the skill marker) or a skill `name:` + `description:`.
    @staticmethod
    def _is_skill_file(f: IndexedFile) -> bool:
        name = f.relpath.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if name in ("skill.md", "agents.md"):
            return True
        if not name.endswith((".md", ".mdx")):
            return False
        head = f.text[:600]
        return bool(re.search(r"(?mi)^\s*allowed-tools\s*:", head))

    @staticmethod
    def _scan_git_config(
        f: IndexedFile, remote: list[Evidence], needs_review: list[NeedsReview]
    ) -> None:
        m = _FSMONITOR.search(f.text)
        if m is None:
            return
        value = m.group(1).strip().strip("\"'")
        if not value or value.lower() in _GIT_BOOL_VALUES:
            return  # unset, or the built-in daemon toggle -- not an external command
        if _REMOTE_EXEC.search(value):
            remote.append(f.evidence_for_span(m.start(1), m.end(1)))
            return
        needs_review.append(
            NeedsReview(
                category="agent_config",
                title="git config core.fsmonitor names an external command",
                reason=(
                    "core.fsmonitor is set to a command rather than a boolean, so git runs it "
                    "automatically on `status`/`diff`. Large repositories legitimately point this "
                    "at a local watchman hook script -- confirm this one is trusted before running "
                    "git commands or opening the project in an agent."
                ),
                file=f.relpath,
                line=f.evidence_for_span(m.start(1), m.end(1)).line_start,
            )
        )

    def _rule(self, rule_id: str) -> RuleSpec:
        return next(r for r in self.rules if r.id == rule_id)

    @staticmethod
    def _referenced_script(
        command: str, by_path: dict[str, IndexedFile], near: str = ""
    ) -> IndexedFile | None:
        """A script shipped in the component that ``command`` runs (``node hooks/setup.mjs``,
        ``"${CLAUDE_PLUGIN_ROOT}"/scripts/x.sh``): looked up from the component root, then from
        each folder above ``near`` (the file that declares the command, e.g. a plugin nested in a
        marketplace repository, whose paths are relative to the plugin)."""
        folders = [""]
        parts = near.replace("\\", "/").split("/")[:-1]
        while parts:
            folders.append("/".join(parts))
            parts.pop()
        for token in _PATH_TOKEN.findall(command):
            cleaned = re.sub(r"^[\"']?(?:\$\{?\w+\}?[\"']?[/\\])+", "", token)
            cleaned = re.sub(r"^(?:\.[/\\])+", "", cleaned).replace("\\", "/").lstrip("/")
            for folder in folders:
                candidate = f"{folder}/{cleaned}" if folder else cleaned
                if candidate in by_path:
                    return by_path[candidate]
        return None


def _is_remote_url(url: str) -> bool:
    """True for an ``http(s)`` URL whose host is written out and is not this machine. A host
    left to a variable (``${OTEL_ENDPOINT}``) cannot be judged, so it is not called remote."""
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        return False
    if parts.scheme.lower() not in ("http", "https") or not host or "$" in url[: url.find(host)]:
        return False
    if any(ch in host for ch in "${}%"):
        return False
    return not (
        host in _HTTP_HOOK_LOCAL_HOSTS or host.endswith(".localhost") or host.startswith("127.")
    )
