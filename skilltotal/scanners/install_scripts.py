"""Install-time execution detection (npm lifecycle hooks, Python build hooks).

Install-time hooks run automatically when a user installs a package — a classic supply
chain execution vector. npm hooks are matched directly on ``package.json``; Python's
``setup.py`` is only flagged when it contains execution-y constructs (a bare ``setup()``
call is not, by itself, suspicious).
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Sequence
from itertools import islice
from pathlib import Path

from skilltotal import bounded_json
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.loaded_code import NPM_LIFECYCLE_SCRIPTS, install_time_scripts
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
from skilltotal.scanners.shell_script import (
    DECODE_EXEC_SH,
    REMOTE_EXEC,
    decode_then_run_spans,
    download_then_run_spans,
)
from skilltotal.text_normalize import js_unescaped

CATEGORY = "install_time_execution"
R_NPM_REMOTE_EXEC = "ST-INSTALL-NPM-REMOTE-EXEC"
# The scripts npm runs on its own (loaded_code.NPM_LIFECYCLE_SCRIPTS): on every install of the
# package (preinstall / install / postinstall), and on a local or git install the prepare family
# (prepublish, preprepare, prepare, postprepare) and prepack.
_NPM_LIFECYCLE_SCRIPTS = NPM_LIFECYCLE_SCRIPTS


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


# More ways an install command runs code that is not in the package, next to the shared shell
# forms (REMOTE_EXEC, DECODE_EXEC_SH): text decoded inside a command substitution that a shell
# runs, text reversed or un-hexed into a shell, Python that executes a response body, and a
# package runner pointed at a web address.
_INSTALL_FETCH_RUN = re.compile(
    r"\b(?:ba|z|da|k)?sh\s+-c\s+[\"']?(?:\$\(|`)[^)`\n]{0,600}\bbase64\s+(?:-d|-D|--decode)\b"
    r"|\b(?:rev|xxd\s+-r)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
    r"|\bpython[0-9.]*\s+-c\b[^\n]{0,600}?\b(?:exec|eval)\s*\([^\n]{0,200}?"
    r"\b(?:urlopen|urlretrieve|requests\s*\.\s*get)\b"
    # The address is what the runner is given to run (after its own flags), not an address
    # that appears later in the line (a printed "run npx tool ... docs: https://...").
    r"|(?<![\w.-])(?:npx|bunx|npm\s+exec|pnpm\s+dlx|yarn\s+dlx)\s+(?:--?[\w-]+(?:=\S+)?\s+){0,4}"
    r"(?:--\s+)?[\"']?https?://",
    re.IGNORECASE,
)

# A download saved to a file that a later part of the same script starts (`curl -o /tmp/p URL &&
# /tmp/p`), and data decoded into a variable or a file that a later command runs, are read by
# shell_script.download_then_run_spans / decode_then_run_spans, shared with the shell-file rules.

# `c=curl; s=sh; $c -s URL | $s`: the tools named through variables set in the same script.
_SHELL_TOOL_ASSIGNMENT = re.compile(
    r"(?:^|[;&\n]|\bexport)\s*([A-Za-z_]\w{0,40})=[\"']?(?:[\w./-]{0,60}/)?"
    r"(curl|wget|sh|bash|zsh|dash|ksh)[\"']?(?=\s*(?:[;&\n]|$))",
    re.MULTILINE,
)


def indirect_remote_exec_spans(text: str) -> list[tuple[int, int]]:
    """Spans of a download piped into a shell where the downloader, the shell or both are named
    through a variable the script sets to that tool (``c=curl; $c URL | sh``)."""
    fetchers: list[str] = []
    shells: list[str] = []
    for m in _SHELL_TOOL_ASSIGNMENT.finditer(text):
        (fetchers if m.group(2) in ("curl", "wget") else shells).append(re.escape(m.group(1)))
    if not fetchers and not shells:
        return []
    fetch = r"(?:\b(?:curl|wget)\b" + (
        rf"|\$\{{?(?:{'|'.join(fetchers)})\}}?(?![\w])" if fetchers else "") + ")"
    shell = r"(?:(?:sudo\s+)?(?:ba|z|da|k)?sh\b" + (
        rf"|\$\{{?(?:{'|'.join(shells)})\}}?(?![\w])" if shells else "") + ")"
    piped = re.compile(rf"{fetch}[^\n|]{{0,1000}}\|\s*{shell}")
    return [
        (m.start(), m.end()) for m in piped.finditer(text)
        if "$" in m.group(0)[:1] or re.search(r"\|\s*\$", m.group(0))
    ]


def _shell_fetch_run_spans(f: IndexedFile) -> list[tuple[int, int]]:
    """Spans of shell text in ``f`` that download code and run it or decode data and run it. A
    comment, a printed hint or a hint kept in a variable that is only printed is not run."""
    spans = [
        (m.start(), m.end())
        for pattern in (REMOTE_EXEC, DECODE_EXEC_SH, _INSTALL_FETCH_RUN)
        for m in pattern.finditer(f.text)
    ]
    spans += download_then_run_spans(f.text) + indirect_remote_exec_spans(f.text)
    spans += decode_then_run_spans(f.text)
    return sorted(
        (start, end) for start, end in set(spans)
        if not (f.in_shell_comment(start) or f.in_printed_command(start)
                or f.in_shell_assigned_hint(start) or _after_hash(f.text, start))
    )


def _command_as_file(command: str) -> IndexedFile:
    """An install command as a one-off shell file, so that the same reading of comments and of
    printed text applies to it as to a script on disk."""
    return IndexedFile(
        path=Path("install-command.sh"), relpath="install-command.sh", text=command,
        _line_starts=FileIndex._compute_line_starts(command),
    )


def runs_fetched_or_decoded_code(command: str) -> bool:
    """True if a command downloads code and runs it, or decodes data and runs it: the shell forms
    (`curl … | sh`, `sh -c "$(curl …)"`, `… base64 -d | sh`, a download saved and then started)
    and inline JavaScript or Python (`node -e "eval(Buffer.from(…, 'base64').toString())"`, or a
    `node -e` whose `https.get` response body reaches `eval`). A command that only prints such a
    line for the person to run (`echo "Then run: curl … | sh"`) does not run it."""
    return bool(
        _shell_fetch_run_spans(_command_as_file(command))
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


# npm puts the `config` object of package.json into the environment of every script it runs, as
# `npm_package_config_<key>` (nested keys joined with `_`). An install command that is only
# `$npm_package_config_cmd`, or install code that runs `process.env.npm_package_config_cmd`, keeps
# the command text out of the line and the file the install rules read. The value is in the same
# package.json, so it is looked up there and judged as the command it is.
_CONFIG_MARK = "npm_package_config_"
_CONFIG_REF = re.compile(
    r"\bprocess\s{0,3}\.\s{0,3}env\s{0,3}(?:\.\s{0,3}|\[\s{0,3}['\"`])npm_package_config_(\w{1,100})"
    r"(?:['\"`]\s{0,3}\])?"
    r"|\$\{?npm_package_config_(\w{1,100})\}?"
    r"|%npm_package_config_(\w{1,100})%"
)
_MAX_CONFIG_KEYS = 200
_MAX_CONFIG_DEPTH = 4
_MAX_CONFIG_VALUE = 4000
_MAX_CONFIG_REFS = 50
_NOT_ENV_NAME = re.compile(r"[^A-Za-z0-9_]")
_JS_PRINTED = re.compile(r"\bconsole\s*\.\s*\w+\s*\([^\n;]{0,300}$")


def npm_package_config(f: IndexedFile) -> dict[str, str]:
    """The string values of the ``config`` object of ``f`` (a package.json), keyed as npm names
    them in a script's environment after ``npm_package_config_``."""
    if '"config"' not in f.text:
        return {}
    try:
        data = bounded_json.loads(f.text)
    except ValueError:
        return {}
    config = data.get("config") if isinstance(data, dict) else None
    out: dict[str, str] = {}
    stack: list[tuple[str, object, int]] = [("", config, 0)]
    while stack and len(out) < _MAX_CONFIG_KEYS:
        prefix, node, depth = stack.pop()
        if isinstance(node, str):
            if prefix and len(node) <= _MAX_CONFIG_VALUE:
                out[prefix] = node
            continue
        if depth >= _MAX_CONFIG_DEPTH:
            continue
        items = (
            node.items() if isinstance(node, dict)
            else enumerate(node) if isinstance(node, list) else ()
        )
        for key, value in islice(items, _MAX_CONFIG_KEYS):
            name = _NOT_ENV_NAME.sub("_", str(key))
            stack.append((f"{prefix}_{name}" if prefix else name, value, depth + 1))
    return out


def _with_package_config(command: str, config: dict[str, str]) -> str | None:
    """``command`` with each ``npm_package_config_*`` reference replaced by its value from
    ``config``: as shell text where the shell expands it, as a string literal where JavaScript
    reads it. None when the command has no reference that resolves."""
    resolved = False

    def value(m: re.Match[str]) -> str:
        nonlocal resolved
        found = config.get(m.group(1) or m.group(2) or m.group(3))
        if found is None:
            return m.group(0)
        resolved = True
        return json.dumps(found) if m.group(1) else found

    out = _CONFIG_REF.sub(value, command, count=_MAX_CONFIG_REFS)
    return out if resolved else None


def _config_value_evidence(f: IndexedFile, value: str) -> Evidence | None:
    """Where package.json ``f`` writes the config ``value`` (None when written with escapes that
    ``json.dumps`` does not reproduce)."""
    at = f.text.find(json.dumps(value, ensure_ascii=False))
    return f.evidence_for_span(at, at + len(value) + 2) if at >= 0 else None


def _config_command_evidence(f: IndexedFile, manifest: IndexedFile) -> list[Evidence]:
    """Evidence for an install-run file ``f`` that reads a ``npm_package_config_*`` variable whose
    value in ``manifest`` (the package.json it belongs to) downloads code and runs it or decodes
    data and runs it: the reference, then the value. A reference in a comment or in printed text
    is not a command."""
    config = npm_package_config(manifest)
    if not config:
        return []
    shell = f.is_shell_like
    found: list[Evidence] = []
    judged: dict[str, bool] = {}
    for m in islice(_CONFIG_REF.finditer(f.text), _MAX_CONFIG_REFS):
        key = m.group(1) or m.group(2) or m.group(3)
        value = config.get(key)
        if value is None:
            continue
        if key not in judged:
            judged[key] = runs_fetched_or_decoded_code(value)
        if not judged[key]:
            continue
        if shell:
            if f.in_shell_comment(m.start()) or f.in_printed_command(m.start()):
                continue
        elif f.in_c_comment(m.start()) or _JS_PRINTED.search(
            f.text, f.text.rfind("\n", 0, m.start()) + 1, m.start()
        ):
            continue
        found.append(f.evidence_for_span(m.start(), m.end()))
        where = _config_value_evidence(manifest, value)
        if where is not None:
            found.append(where)
        break
    return found


def _owning_manifest(relpath: str, manifests: dict[str, IndexedFile]) -> IndexedFile | None:
    """The package.json of the nearest folder above ``relpath``."""
    folder = posixpath.dirname(relpath)
    while True:
        if folder in manifests:
            return manifests[folder]
        if not folder:
            return None
        folder = posixpath.dirname(folder)


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


# A shell command a JavaScript install script runs: the string is an argument of a
# `child_process` call (`execSync("…")`, `cp["exec"]("…")`, `spawn("sh", ["-c", "…"])`).
_JS_RUNS_COMMAND = re.compile(
    r"(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)[\"'`]?\s{0,10}\]?\s{0,10}\(\s{0,40}"
    r"(?:[\"'`][\w./-]{0,20}[\"'`]\s{0,10},\s{0,10}\[?\s{0,10}"
    r"(?:[\"'`]-c[\"'`]\s{0,10},\s{0,10})?)?[\"'`][^\"'`\n]{0,300}$"
)
_JS_COMMAND_REACH = 400


def _js_command_evidence(f: IndexedFile) -> list[Evidence]:
    """Evidence for each shell command a JavaScript install script runs that downloads code and
    runs it or decodes data and runs it. The file is read as written, with split string literals
    joined (``"cu" + "rl"``) and with character escapes written out (``"\\x63url"``): none of
    these changes what the script runs. A string that is only printed or kept is not a command."""
    views: list[tuple[str, Sequence[int] | None]] = [(f.text, None)]
    folded = f.concat_folded_or_none()
    if folded is not None:
        views.append((folded[0], folded[1]))
    for text, origin in list(views):
        plain = js_unescaped(text, origin)
        if plain is not None:
            views.append(plain)
    found: list[Evidence] = []
    lines: set[int] = set()
    for text, origin in views:
        spans = [
            (m.start(), m.end())
            for pattern in (REMOTE_EXEC, DECODE_EXEC_SH, _INSTALL_FETCH_RUN)
            for m in pattern.finditer(text)
        ] + download_then_run_spans(text)
        for start, end in sorted(set(spans)):
            if not _JS_RUNS_COMMAND.search(text, max(0, start - _JS_COMMAND_REACH), start):
                continue
            first, last = (start, end) if origin is None else (origin[start], origin[end - 1] + 1)
            if f.in_c_comment(first):
                continue
            ev = f.evidence_for_span(first, last)
            if ev.line_start not in lines:
                lines.add(ev.line_start)
                found.append(ev)
    return found


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
            title="npm prepare-time hook",
            description=(
                "package.json declares a script of the prepare family (prepublish, preprepare, "
                "prepare, postprepare) or prepack. npm runs these on a local install (`npm "
                "install` or `npm ci` in the package's folder), when the package is installed "
                "from a git address, and before publish (typically a build step), but not for "
                "consumers installing the published package from the registry."
            ),
            recommendation=(
                "Usually a legitimate build step; confirm it only builds and does not fetch "
                "or execute remote code."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            names=("package.json",),
            pattern=re.compile(r'"(?:prepublish|preprepare|prepare|postprepare|prepack)"\s*:'),
        ),
        RuleSpec(
            id=R_NPM_REMOTE_EXEC,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="npm install script downloads or decodes code and runs it",
            description=(
                "A package.json lifecycle script that npm runs on its own (preinstall / install / "
                "postinstall, or the prepare family and prepack on a git or local install), a "
                "script one of them starts with `npm run`, or a file one of them runs or reaches "
                "through another file "
                "(`\"postinstall\": \"bash install.sh\"`, `node ./scripts/update.data`, "
                "`setup.js` that starts `payload.sh`), "
                "downloads code and pipes it into a shell, saves a download and then starts it, "
                "runs a downloaded response body (`eval`, `execSync`), or decodes data and "
                "executes it, for example `curl -fsSL https://... | bash`, "
                "`curl -o /tmp/p https://... && /tmp/p` or "
                "`node -e \"eval(Buffer.from(..., 'base64')...)\"`. "
                "A command the script takes from the package's own `config` block "
                "(`$npm_package_config_cmd`, `process.env.npm_package_config_cmd`) is read with "
                "the value written there. "
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
        evidence: list[Evidence] = []
        manifests: dict[str, IndexedFile] = {}
        for f in index.select(names=("package.json",)):
            manifests[posixpath.dirname(f.relpath)] = f
            for _name, command, start, end in npm_install_commands(f, _NPM_LIFECYCLE_SCRIPTS):
                if runs_fetched_or_decoded_code(command):
                    evidence.append(f.evidence_for_span(start, end))
                elif _CONFIG_MARK in command:
                    # The command is in the `config` block (see `_CONFIG_REF`).
                    config = npm_package_config(f)
                    resolved = _with_package_config(command, config)
                    if resolved is None or not runs_fetched_or_decoded_code(resolved):
                        continue
                    evidence.append(f.evidence_for_span(start, end))
                    for ref in islice(_CONFIG_REF.finditer(command), _MAX_CONFIG_REFS):
                        value = config.get(ref.group(1) or ref.group(2) or ref.group(3))
                        where = _config_value_evidence(f, value) if value else None
                        if where is not None:
                            evidence.append(where)
        shell_run, node_run = install_run_interpreters(index)
        for f in index.files:
            if f.relpath not in index.install_scripts:
                continue
            if _CONFIG_MARK in f.text:
                manifest = _owning_manifest(f.relpath, manifests)
                if manifest is not None:
                    evidence += _config_command_evidence(f, manifest)
            if f.is_shell_like or f.relpath in shell_run:
                evidence += _remote_exec_lines(f)
            elif f.suffix in (".js", ".cjs", ".mjs") or f.relpath in node_run:
                span = js_runs_fetched_body(f.text)
                if span is not None and not f.in_c_comment(span[1] - 1):
                    evidence.append(f.evidence_for_span(*span))
                evidence += _js_command_evidence(f)
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
    return [f.evidence_for_span(start, end) for start, end in _shell_fetch_run_spans(f)]


def _after_hash(text: str, at: int) -> bool:
    """True if a ``#`` opens the line before ``at`` (a whole-line shell comment)."""
    return text[text.rfind("\n", 0, at) + 1:at].lstrip().startswith("#")
