"""Install-time execution detection (npm lifecycle hooks, Python build hooks).

Install-time hooks run automatically when a user installs a package — a classic supply
chain execution vector. npm hooks are matched directly on ``package.json``; Python's
``setup.py`` is only flagged when it contains execution-y constructs (a bare ``setup()``
call is not, by itself, suspicious).
"""

from __future__ import annotations

import posixpath
import re

from skilltotal import bounded_json
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.loaded_code import install_time_scripts
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    PatternScanner,
    RuleSpec,
    ScanResult,
    _finding_from_rule,
    alternation,
)
from skilltotal.scanners.fetch_tunnel_launcher import platform_fetch_evidence
from skilltotal.scanners.obfuscation import _DECODE_EXEC
from skilltotal.scanners.shell_script import DECODE_EXEC_SH, REMOTE_EXEC

CATEGORY = "install_time_execution"
R_NPM_REMOTE_EXEC = "ST-INSTALL-NPM-REMOTE-EXEC"
# The scripts npm runs on its own: on every install of the package (preinstall / install /
# postinstall), and on a git or local install (prepare).
_NPM_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")


# JavaScript that collects a response body into a variable: `res.on("data", c => body += c)`,
# `fetch(u).then(r => r.text()).then(body => ...)`, `const body = await (await fetch(u)).text()`.
_JS_BODY_INTO = re.compile(
    r"\.on\(\s*['\"]data['\"]\s*,\s*(?:async\s+)?(?:function\s*)?\(?\s*([\w$]{1,40})\s*\)?\s*"
    r"(?:=>)?\s*\{?\s*\(?\s*([\w$]{1,40})\s*\+=\s*\1\b"
    r"|\.text\(\s*\)\s*\)?\s*\.then\(\s*(?:async\s+)?(?:function\s*)?\(?\s*([\w$]{1,40})\s*\)?"
    r"|(?:const|let|var)\s+([\w$]{1,40})\s*=\s*await\s+[^;\n]{0,160}?\.text\(\s*\)"
)
# A request through Node's http/https module or fetch, before the body is collected.
_JS_REQUEST = re.compile(
    r"\bhttps?\s*\.\s*(?:get|request)\s*\("
    r"|['\"](?:node:)?https?['\"]\s*\)\s*\.\s*(?:get|request)\s*\("
    r"|\bfetch\s*\("
)
_CHILD_PROCESS_NAME = re.compile(
    r"(?:const|let|var)\s+([\w$]{1,40})\s*=\s*require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)"
)
_JS_FLOW_REACH = 3000


def _js_runs_body(name: str, cp_names: list[str]) -> re.Pattern[str]:
    """A sink that runs the variable ``name`` as code or as a shell command. A bare ``exec`` counts
    only as a plain function or a member of a ``child_process`` binding: ``/re/.exec(body)`` is a
    regular expression."""
    v = re.escape(name)
    owners = "|".join(re.escape(n) for n in cp_names) or "(?!)"
    return re.compile(
        rf"(?<![\w$])(?:eval|Function|execSync|runInThisContext|runInNewContext|Script)\s*\("
        rf"\s*(?:[^()\n]{{0,80}},\s*)?{v}\s*(?:\.toString\(\s*\))?\s*[,)]"
        rf"|(?:(?<![\w$.])|\b(?:{owners})\s*\.\s*|['\"]child_process['\"]\s*\)\s*\.\s*)"
        rf"exec\s*\(\s*{v}\s*[,)]"
        rf"|(?<![\w$])(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*['\"](?:sh|bash|node)['\"]\s*,"
        rf"\s*\[\s*['\"]-[ce]['\"]\s*,\s*{v}\b"
    )


def js_runs_fetched_body(text: str) -> tuple[int, int] | None:
    """The span from a JavaScript response body collected into a variable to the sink that runs
    that same variable (``eval``, ``new Function``, ``execSync``, ``vm``), when a request
    (http/https ``get``/``request`` or ``fetch``) comes before it; None otherwise. A body that is
    only parsed, printed or written to a file is not run."""
    if "+=" not in text and ".text(" not in text:
        return None
    cp_names = [m.group(1) for m in _CHILD_PROCESS_NAME.finditer(text)]
    for body in _JS_BODY_INTO.finditer(text):
        name = body.group(2) or body.group(3) or body.group(4)
        if not _JS_REQUEST.search(text, max(0, body.start() - _JS_FLOW_REACH), body.end()):
            continue
        sink = _js_runs_body(name, cp_names).search(
            text, body.end(), body.end() + _JS_FLOW_REACH
        )
        if sink is not None:
            return body.start(), sink.end()
    return None


def runs_fetched_or_decoded_code(command: str) -> bool:
    """True if a command downloads code and runs it, or decodes data and runs it: the shell forms
    (`curl … | sh`, `sh -c "$(curl …)"`, `… base64 -d | sh`) and inline JavaScript or Python
    (`node -e "eval(Buffer.from(…, 'base64').toString())"`, or a `node -e` whose `https.get`
    response body reaches `eval`)."""
    return bool(
        REMOTE_EXEC.search(command) or DECODE_EXEC_SH.search(command)
        or _DECODE_EXEC.search(command) or js_runs_fetched_body(command)
    )


def npm_install_commands(
    f: IndexedFile, lifecycle: tuple[str, ...]
) -> list[tuple[str, str, int, int]]:
    """``(name, command, start, end)`` of each script of ``f`` (a package.json) that npm runs at
    install: the ``lifecycle`` scripts and the scripts they start with ``npm run``. Values are read
    as npm reads them (JSON-decoded); the span is the script's key, or the ``scripts`` key when
    the key itself is written with escapes."""
    try:
        data = bounded_json.loads(f.text)
    except ValueError:
        return []
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    block = re.search(r'"scripts"\s*:', f.text)
    out: list[tuple[str, str, int, int]] = []
    for name, command in install_time_scripts(scripts, lifecycle):
        key = (
            re.compile(rf'"{re.escape(name)}"\s*:').search(f.text, block.end() if block else 0)
            or block
        )
        start, end = (key.start(), key.end()) if key else (0, 1)
        out.append((name, command, start, end))
    return out


# `sh ./scripts/bootstrap`, `bash -e setup`, `node ./scripts/update.data`: the interpreter an
# install command starts on a file, whatever the file is named.
_RUNS_FILE = re.compile(
    r"(?<![\w/.$-])(sh|bash|zsh|dash|node)(?:\.exe)?\s{1,4}"
    r"((?:-{1,2}[\w-]{1,30}(?:=[^\s\"']{0,100})?\s{1,4}){0,4})[\"']?([\w./@+-]{1,200})"
)
# Options after which the next word is inline code, not a file (`sh -c "..."`, `node -e "..."`).
_SHELL_INLINE = frozenset({"-c"})
_NODE_INLINE = frozenset({"-e", "-p", "--eval", "--print"})


def install_run_interpreters(index: FileIndex) -> tuple[set[str], set[str]]:
    """Relative paths of the install-run files (``index.install_scripts``) that an install command
    starts with a shell, and those it starts with node. The command names the language, so the
    file is read as that language whatever its suffix or first line."""
    shell: set[str] = set()
    node: set[str] = set()
    if not index.install_scripts:
        return shell, node
    for f in index.select(names=("package.json",)):
        folder = posixpath.dirname(f.relpath)
        for _name, command, _start, _end in npm_install_commands(f, _NPM_LIFECYCLE_SCRIPTS):
            for m in _RUNS_FILE.finditer(command):
                inline = _NODE_INLINE if m.group(1) == "node" else _SHELL_INLINE
                if inline & set(m.group(2).split()):
                    continue
                target = posixpath.normpath(posixpath.join(folder, m.group(3)))
                if target in index.install_scripts:
                    (node if m.group(1) == "node" else shell).add(target)
    return shell, node


class InstallScriptsScanner(PatternScanner):
    name = "install_scripts"
    rules = [
        RuleSpec(
            id="ST-INSTALL-NPM",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="npm install-time lifecycle hook",
            description=(
                "package.json declares install-time lifecycle scripts "
                "(preinstall / install / postinstall) that run automatically when the "
                "package is installed by a consumer."
            ),
            recommendation=(
                "Inspect the hook command. Install-time scripts are a common supply chain "
                "execution vector; ensure they do nothing beyond a documented build step."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            names=("package.json",),
            pattern=re.compile(r'"(?:preinstall|install|postinstall)"\s*:'),
        ),
        RuleSpec(
            id="ST-INSTALL-NPM-PREPARE",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            title="npm prepare hook",
            description=(
                "package.json declares a 'prepare' script. It runs on local/git installs "
                "and before publish (typically a build step), but not for consumers "
                "installing the published package from the registry."
            ),
            recommendation=(
                "Usually a legitimate build step; confirm it only builds and does not fetch "
                "or execute remote code."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            names=("package.json",),
            pattern=re.compile(r'"prepare"\s*:'),
        ),
        RuleSpec(
            id=R_NPM_REMOTE_EXEC,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="npm install script downloads or decodes code and runs it",
            description=(
                "A package.json lifecycle script that npm runs on its own (preinstall / install / "
                "postinstall, or prepare on a git or local install), a script one of them starts "
                "with `npm run`, or a file one of them runs "
                "(`\"postinstall\": \"bash install.sh\"`, `node ./scripts/update.data`), "
                "downloads code and pipes it into a shell, runs "
                "a downloaded response body (`eval`, `execSync`), or decodes data and executes "
                "it, for example `curl -fsSL https://... | bash` or "
                "`node -e \"eval(Buffer.from(..., 'base64')...)\"`. "
                "What runs is whatever the host serves, or the decoded text, on every install; "
                "neither is in the package for review."
            ),
            recommendation=(
                "Do not install this version. An honest package ships the code its install step "
                "runs, or downloads a pinned artifact and verifies its checksum before using it."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            # Custom matching (InstallScriptsScanner.scan): the parsed script values of each
            # package.json, so a JSON escape (`|` for `|`) is read as npm reads it.
            names=("package.json",),
        ),
        RuleSpec(
            id="ST-INSTALL-GYP",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="binding.gyp runs a hidden command at install time",
            description=(
                "binding.gyp uses node-gyp command substitution (`<!(...)`) to run a script with "
                "its output discarded, fetch from the network, pipe into a shell, or decode "
                "data; or a target's `actions` / `rules` command list fetches from the network, "
                "pipes into a shell or decodes data. "
                "node-gyp runs both during `npm install` even when package.json "
                "declares no install script, so install-script checks never see it, for example "
                "`<!(node index.js > /dev/null 2>&1 && echo stub.c)` or "
                "`\"action\": [\"sh\", \"-c\", \"curl ... | sh\"]`."
            ),
            recommendation=(
                "Do not install this version. Honest bindings use substitution only to print "
                "include paths (`node -p \"require('node-addon-api').include\"`)."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            names=("binding.gyp",),
            pattern=re.compile(
                r"<!@?\(\s*(?:"
                r"[^)\"']*?\b(?:curl|wget)\b"
                r"|[^)\"']*?https?://"
                r"|[^)\"']*?\|\s*(?:ba|z)?sh\b"
                r"|[^)\"']*?\bbase64\b"
                r"|node\s+(?!-[pe]\b)[^\s)\"']+\.[cm]?js\b[^)\"']*?(?:>\s*/dev/null|2>&1|>\s*nul\b)"
                r")",
                re.IGNORECASE,
            ),
        ),
        RuleSpec(
            id="ST-INSTALL-PY",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Python install/build-time execution hook",
            description=(
                "setup.py / pyproject build configuration contains execution constructs "
                "(custom cmdclass, command-class override, subprocess/os.system, eval/exec, "
                "or network access) that run at build/install time."
            ),
            recommendation=(
                "Verify the build hook performs only a legitimate build step and does not "
                "execute commands or reach the network during installation."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            names=("setup.py", "pyproject.toml"),
            pattern=alternation(
                r"\bcmdclass\b",
                r"class\s+\w*(?:Install|Develop|EggInfo|BuildPy|Build)\b",
                r"\bos\.system\s*\(",
                r"\bsubprocess\.",
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"\bimport\s+(?:urllib|requests|socket|http)\b",
                flags=re.MULTILINE,
            ),
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        result = super().scan(index)
        evidence = [
            f.evidence_for_span(start, end)
            for f in index.select(names=("package.json",))
            for _name, command, start, end in npm_install_commands(f, _NPM_LIFECYCLE_SCRIPTS)
            if runs_fetched_or_decoded_code(command)
        ]
        shell_run, node_run = install_run_interpreters(index)
        for f in index.files:
            if f.relpath not in index.install_scripts:
                continue
            if f.is_shell_like or f.relpath in shell_run:
                evidence += _remote_exec_lines(f)
            elif f.suffix in (".js", ".cjs", ".mjs") or f.relpath in node_run:
                span = js_runs_fetched_body(f.text)
                if span is not None and not f.in_c_comment(span[1] - 1):
                    evidence.append(f.evidence_for_span(*span))
        evidence += platform_fetch_evidence(index)
        if evidence:
            rule = next(r for r in self.rules if r.id == R_NPM_REMOTE_EXEC)
            result.findings.append(_finding_from_rule(rule, evidence))
        gyp = [ev for f in index.select(names=("binding.gyp",)) for ev in _gyp_action_commands(f)]
        if gyp:
            rule = next(r for r in self.rules if r.id == "ST-INSTALL-GYP")
            known = next((x for x in result.findings if x.id == rule.id), None)
            if known is not None:
                result.findings.remove(known)
                gyp = known.evidence + gyp
            result.findings.append(_finding_from_rule(rule, gyp))
        return result


# A command node-gyp runs for a target: `"action": ["sh", "-c", "..."]` in an `actions` or `rules`
# entry. The same tells as the `<!(...)` branch of ST-INSTALL-GYP, read over the list's strings.
_GYP_ACTION = re.compile(r"""["']action["']\s*:\s*\[""")
_GYP_STRING = re.compile(r""""((?:[^"\\\n]|\\.){0,2000})"|'((?:[^'\\\n]|\\.){0,2000})'""")
_GYP_ACTION_TELL = re.compile(
    r"\b(?:curl|wget)\b|https?://|\|\s*(?:ba|z)?sh\b|\bbase64\b", re.IGNORECASE
)


def _gyp_action_commands(f: IndexedFile) -> list[Evidence]:
    """Evidence for each ``action`` command list of a binding.gyp that fetches, pipes into a shell
    or decodes. Honest actions run the project's own build tools (``python tools/js2c.py``)."""
    found: list[Evidence] = []
    for m in _GYP_ACTION.finditer(f.text):
        end = f.text.find("]", m.end(), m.end() + 4000)
        if end < 0:
            continue
        words = " ".join(
            a or b for a, b in _GYP_STRING.findall(f.text, m.end(), end)
        )
        if _GYP_ACTION_TELL.search(words):
            found.append(f.evidence_for_span(m.start(), end + 1))
    return found


def _remote_exec_lines(f: IndexedFile) -> list[Evidence]:
    """Evidence for each line of ``f``, a shell script an npm install script runs
    (``"postinstall": "bash install.sh"``), that downloads code and pipes it into a shell or decodes
    data and runs it. A comment, a printed hint or a hint kept in a variable that is only printed
    is not run, so it does not count. A file the install starts with a shell is read as one even
    without a shell suffix or first line; its ``#`` lines are comments all the same."""
    found: list[Evidence] = []
    for pattern in (REMOTE_EXEC, DECODE_EXEC_SH):
        for match in pattern.finditer(f.text):
            at = match.start()
            if (f.in_shell_comment(at) or f.in_printed_command(at)
                    or f.in_shell_assigned_hint(at) or _after_hash(f.text, at)):
                continue
            found.append(f.evidence_for_span(match.start(), match.end()))
    return found


def _after_hash(text: str, at: int) -> bool:
    """True if a ``#`` opens the line before ``at`` (a whole-line shell comment)."""
    return text[text.rfind("\n", 0, at) + 1:at].lstrip().startswith("#")
