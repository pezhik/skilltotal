"""Network-exposure posture: a component that listens on all interfaces or runs a debug
server. Not malware — a ``risky_construct`` that widens the attack surface (often combined
with missing auth), e.g. an MCP/agent server bound to 0.0.0.0 or a Flask app with debug=True.
"""

from __future__ import annotations

import ast
import bisect
import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    alternation,
    findings_from_rules,
)

CODE_SUFFIXES = (".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

CATEGORY = "network_exposure"

# The all-interfaces address: a quoted literal (0.0.0.0, optionally with a port as in gunicorn's
# `bind = "0.0.0.0:8000"`, or the IPv6 `::` / `[::]`), or a bare 0.0.0.0 / [::] after a CLI flag.
_ANY_ADDR = re.compile(
    r"""['"](?:0\.0\.0\.0(?::\d{1,5})?|::|\[::\](?::\d{1,5})?)['"]"""
    r"""|(?<![\w.:\[])(?:0\.0\.0\.0|\[::\])(?![\w.])"""
)
# A quoted 0.0.0.0 is a bind address only in a bind context; elsewhere it is a value being compared,
# listed or rewritten (axios: `new Set(['localhost', '0.0.0.0'])`; playwright:
# `url.replace("0.0.0.0", "localhost")`; psycopg: `__version__ = "0.0.0.0"`; scapy: a route table's
# `gw = "0.0.0.0"`). Each context below is matched against the text right before the literal.
#
# A name that holds the address a server listens on: host / hostname / bind / listen, alone or in a
# compound (HOST, DEFAULT_HOST, bind_addr, listenAddress, server_host). A bare `addr` / `ip` / `gw`
# is not one: those name a gateway, a peer, a client's source address or a display string as
# often as a bind address.
_BIND_NAME = r"""\b\w*(?:host|hostname|bind|listen)\w*"""
_BIND_BEFORE = re.compile(
    r"(?i)(?:"
    # host="0.0.0.0", host: '0.0.0.0', HOST = "0.0.0.0", "host": "0.0.0.0", host: str = "0.0.0.0"
    + _BIND_NAME + r"""['"]?\s*(?::\s*(?:[A-Za-z_][\w.\[\]| ]{0,40}?=(?!=)\s*)?|=(?!=)\s*)"""
    # host: str = typer.Option("0.0.0.0", ...), HOST = resolve_host("0.0.0.0")
    + r"|" + _BIND_NAME + r"""\s*(?::[^=\n]{0,40})?=(?!=)\s*[\w.]{1,60}\(\s*"""
    # process.env.HOST || '0.0.0.0', options.host ?? "0.0.0.0", args.host or "0.0.0.0"
    + r"|" + _BIND_NAME + r"""\s*(?:\|\||\?\?|\bor\b)\s*"""
    # os.getenv("HOST", "0.0.0.0"), os.environ.get('BIND_ADDR', '0.0.0.0')
    + r"""|\b(?:getenv|get|setdefault)\s*\(\s*['"]""" + _BIND_NAME + r"""['"]\s*,\s*"""
    # HOST, PORT = "0.0.0.0", 8080
    + r"|" + _BIND_NAME + r"""\s*,\s*\w+\s*=\s*"""
    # app.listen(3000, '0.0.0.0'), make_server('0.0.0.0', 8000, app), HTTPServer(('0.0.0.0', p), H)
    + r"""|\b(?:listen|bind|serve|run|run_app|run_simple|start_server|\w*server)\s*\(\s*"""
    r"""(?:[^'"\n;]{0,80}?,\s*)?\(?\s*"""
    # A --host option's value: an argv list ("--host", "0.0.0.0"), an argparse / click default
    # (add_argument("--host", default="0.0.0.0")) or commander's default argument.
    + r"""|--(?:host|hostname|bind|listen|ip|addr|address)\b[^)\n]{0,120}?"""
    r"""(?:\bdefault\s*[=:]\s*|,\s*)"""
    + r"""|(?<![\w-])-[hHb]['"]\s*,\s*"""
    + r")$"
)
# A (host, port) socket address with a real port, not a call's argument list: ("0.0.0.0", 8080) /
# ('::', PORT). Port 0 asks for "any port": a client's source address, not a service.
_TUPLE_BEFORE = re.compile(r"(?<![\w$.])\(\s*$")
_TUPLE_AFTER = re.compile(r"\s*,\s*(?:[1-9]\d{0,4}|[A-Za-z_][\w.]*)\s*\)")
# The address followed by a literal port number in the same argument list is a socket address in
# any call: web.TCPSite(runner, "0.0.0.0", 8080).
_PORT_AFTER = re.compile(r"\s*,\s*[1-9]\d{0,4}\b(?!\.)")
# The literal is the first argument of a string method: "::" and "0.0.0.0" there are text being
# split, searched or replaced (pytest's `nodeid.split("::", 1)` read as an address and a port, and
# `host = url.replace("0.0.0.0", ...)` as an assignment to a host), never a bind.
_STRING_METHOD_BEFORE = re.compile(
    r"\.(?:r?split|r?partition|join|replace|(?:starts|ends)with|r?find|r?index|count"
    r"|[lr]?strip|remove(?:prefix|suffix))\s*\(\s*$"
)
# CLI launchers: --host 0.0.0.0, --bind=0.0.0.0:8000, -b 0.0.0.0 (flask run -h, gunicorn -b).
_FLAG_BEFORE = re.compile(
    r"(?:--(?:host|hostname|bind|listen|ip|addr|address)|(?<![\w-])-[hHb])(?:=|\s+)$"
)
_CONTEXT_CHARS = 160

# The address reaching a bind through a name that does not say "host": `ADDR = "0.0.0.0"` then
# `app.run(host=ADDR)`, `ANY = "::"` then `sock.bind((ANY, 9000))`, `const ip = '0.0.0.0';` then
# `server.listen(3000, ip)`. A name assigned exactly the address literal, then passed in the same
# file to a bind / listen / run / *server call (or as a host / bind / listen keyword or key). The
# name alone is not a bind: a constant compared, listed or split on stays clean.
_ADDR_VALUE = re.compile(r"(?:0\.0\.0\.0|::|\[::\])(?::\d{1,5})?")
_BIND_CALLS = frozenset(
    {"listen", "bind", "serve", "run", "run_app", "run_simple", "start_server", "TCPSite"}
)
# Searched in a keyword argument's name (an identifier, all word characters): the same test as a
# fullmatch of `\w*(?:host|...)\w*`, which backtracked quadratically over a long name.
_BIND_KEYWORD = re.compile(r"(?i)host|bind|listen")
_JS_ADDR_NAME = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]{0,60})\s*=\s*(['\"])"
    r"(?:0\.0\.0\.0|::|\[::\])(?::\d{1,5})?\2"
)
_JS_BIND_CALL = re.compile(r"\b(?:listen|bind|serve|run|run_app|start_server|\w*[Ss]erver)\s*\(")
_JS_HOST_KEY = re.compile(r"\b(?:host|hostname|bind|listen)\s*:\s*([A-Za-z_$][\w$]{0,60})\b")
# A bare name passed as an argument: not a call, a member, a property or part of a string.
_JS_PLAIN_NAME = re.compile(r"(?<![\w$.'\"`])([A-Za-z_$][\w$]{0,60})(?![\w$(.'\"`])")
_JS_ARGS_WINDOW = 200


# An all-interfaces address literal that sits inside a format/template string whose own literal
# text carries whitespace is prose, not a bind: a warning or log line such as
# ``f"WARNING: binding {host or '0.0.0.0'} with no api-key..."``. A real bind string is a bare
# address or a ``host:port`` and never contains a space, so a bind f-string like
# ``f"{host or '0.0.0.0'}:{port}"`` (constant text ``":"``) keeps flagging.
_ADDR_CONST = re.compile(r"""(?:0\.0\.0\.0|::|\[::\])(?::\d{1,5})?""")
_WHITESPACE = re.compile(r"\s")
_JS_INTERPOLATION = re.compile(r"\$\{[^{}]*\}")


def _python_prose_fstring_lines(tree: ast.Module) -> set[int]:
    """Lines spanned by an f-string that is prose (a constant text segment has whitespace) and
    contains an all-interfaces address literal. Matches on those lines are suppressed. Keyed on
    the f-string node's own line span, which is reliable on every supported Python."""
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        prose = any(
            isinstance(v, ast.Constant)
            and isinstance(v.value, str)
            and _WHITESPACE.search(v.value)
            for v in node.values
        )
        if not prose:
            continue
        if any(
            isinstance(s, ast.Constant)
            and isinstance(s.value, str)
            and _ADDR_CONST.fullmatch(s.value)
            for s in ast.walk(node)
        ):
            lines.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return lines


def _js_prose_template_spans(f) -> list[tuple[int, int]]:
    """Character spans (in file order) of JS/TS template literals that are prose -- their literal
    text, outside the ``${...}`` fields, has whitespace -- and hold an address literal: the
    template-literal analog of a warning/log f-string. The templates come from the file's lexer,
    so a backtick inside a comment (a markdown code fence in a JSDoc block) or inside another
    string never starts or ends one and cannot stretch a "template" over real code. A bind
    template (``\\`${host || '0.0.0.0'}:${port}\\``) has no whitespace in its literal text, so it
    is not suppressed."""
    text = f.text
    spans: list[tuple[int, int]] = []
    for start, end in f.c_string_spans():
        if text[start] != "`" or end - start < 2:
            continue
        body = text[start + 1 : end - 1]
        if _ADDR_CONST.search(body) and _WHITESPACE.search(_JS_INTERPOLATION.sub("", body)):
            spans.append((start, end))
    return spans


def _in_spans(spans: list[tuple[int, int]], starts: list[int], offset: int) -> bool:
    """Whether ``offset`` falls in one of ``spans`` (sorted, non-overlapping; ``starts`` holds
    their start offsets), by bisection."""
    k = bisect.bisect_right(starts, offset) - 1
    return k >= 0 and offset < spans[k][1]


def _is_bind_call(func: ast.expr) -> bool:
    leaf = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    return leaf in _BIND_CALLS or leaf.lower().endswith("server")


def _is_service_port(node: ast.expr) -> bool:
    """A real port, as in `_TUPLE_AFTER`: a nonzero number or a name; port 0 is a client's."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, int) and 0 < node.value <= 65535
    return isinstance(node, (ast.Name, ast.Attribute))


def _python_address_binds(f, tree: ast.Module) -> list[Evidence]:
    """Evidence for an any-address literal assigned to a name a bind call then receives."""
    assigned: dict[str, list[ast.Constant]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        else:
            continue
        if (
            isinstance(target, ast.Name)
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and _ADDR_VALUE.fullmatch(value.value)
        ):
            assigned.setdefault(target.id, []).append(value)
    if not assigned:
        return []
    bound: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if (
                kw.arg
                and _BIND_KEYWORD.search(kw.arg)
                and isinstance(kw.value, ast.Name)
                and kw.value.id in assigned
            ):
                bound.add(kw.value.id)
        if not _is_bind_call(node.func):
            continue
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in assigned:
                bound.add(arg.id)
            elif (
                isinstance(arg, ast.Tuple)
                and len(arg.elts) >= 2
                and isinstance(arg.elts[0], ast.Name)
                and arg.elts[0].id in assigned
                and _is_service_port(arg.elts[1])
            ):
                bound.add(arg.elts[0].id)
    return [
        f.evidence_for_lines(literal.lineno, literal.lineno)
        for name in sorted(bound)
        for literal in assigned[name]
    ]


def _js_address_binds(f) -> list[Evidence]:
    """The same for JS/TS: names bound to the address literal, then found among the arguments of
    a bind call or as the value of a `host:` key. One pass over the file for each."""
    text = f.text
    assigned: dict[str, list[re.Match[str]]] = {}
    for m in _JS_ADDR_NAME.finditer(text):
        assigned.setdefault(m.group(1), []).append(m)
    if not assigned:
        return []
    bound = {m.group(1) for m in _JS_HOST_KEY.finditer(text) if m.group(1) in assigned}
    for call in _JS_BIND_CALL.finditer(text):
        args = text[call.end() : call.end() + _JS_ARGS_WINDOW].split(")", 1)[0]
        bound.update(n.group(1) for n in _JS_PLAIN_NAME.finditer(args) if n.group(1) in assigned)
    return [
        f.evidence_for_span(m.start(2), m.end()) for name in sorted(bound) for m in assigned[name]
    ]


def _bind_evidence(index: FileIndex) -> list[Evidence]:
    evidence: list[Evidence] = []
    for f in index.select(suffixes=CODE_SUFFIXES):
        text = f.text
        if not _ANY_ADDR.search(text):
            continue  # nothing to do; avoid parsing files with no address literal at all
        python = f.suffix in (".py", ".pyw")
        tree: ast.Module | None = None
        if python:
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                tree = None
        # An address literal inside a prose format/template string (whitespace in its constant
        # text) is a warning/log message, not a bind: suppress those matches up front.
        prose_lines = _python_prose_fstring_lines(tree) if tree is not None else set()
        prose_spans = [] if python else _js_prose_template_spans(f)
        prose_starts = [s for s, _ in prose_spans]
        for m in _ANY_ADDR.finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            before = text[max(line_start, m.start() - _CONTEXT_CHARS) : m.start()]
            if m.group(0)[0] in "'\"" and (
                f.line_of_offset(m.start()) in prose_lines
                or _in_spans(prose_spans, prose_starts, m.start())
            ):
                bound = None
            elif m.group(0)[0] in "'\"" and _STRING_METHOD_BEFORE.search(before):
                bound = None
            elif m.group(0)[0] in "'\"":
                bound = (
                    _BIND_BEFORE.search(before)
                    or _PORT_AFTER.match(text, m.end())
                    or (_TUPLE_BEFORE.search(before) and _TUPLE_AFTER.match(text, m.end()))
                )
            else:
                bound = _FLAG_BEFORE.search(before)
            if bound:
                evidence.append(f.evidence_for_span(m.start(), m.end()))
                if len(evidence) >= MAX_EVIDENCE_SCANNED:
                    return evidence
        lines = {(e.file, e.line_start) for e in evidence}
        name_binds = _python_address_binds(f, tree) if tree is not None else (
            [] if python else _js_address_binds(f)
        )
        for ev in name_binds:
            if (ev.file, ev.line_start) not in lines:
                evidence.append(ev)
        if len(evidence) >= MAX_EVIDENCE_SCANNED:
            return evidence[:MAX_EVIDENCE_SCANNED]
    return evidence


class ExposureScanner(Scanner):
    name = "exposure"
    rules = [
        RuleSpec(
            id="ST-EXPOSE-BIND",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            title="Server bound to all network interfaces",
            description=(
                "The component binds a server to 0.0.0.0 / :: (all interfaces), exposing it "
                "beyond localhost. Without authentication this lets other hosts reach the "
                "server (a common MCP/agent exposure and DNS-rebinding surface)."
            ),
            recommendation=(
                "Bind to 127.0.0.1 for local-only use, or require authentication and "
                "restrict access if remote exposure is intended."
            ),
            capability=None,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            # Real binds are value-strings (host="0.0.0.0"); the same text in a `#`/`//` comment or
            # a Python docstring (`Set this to '0.0.0.0' to ...`) is an example. Strings stay.
            code_context="comments_and_docstrings",
            suffixes=CODE_SUFFIXES,
            # Metadata only (rules list / docs): matching is done by _bind_evidence, which also
            # requires a bind context around the address.
            pattern=_ANY_ADDR,
        ),
        RuleSpec(
            id="ST-EXPOSE-DEBUG",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            title="Debug server enabled",
            description=(
                "A web framework debug mode was detected (e.g. Flask debug=True). Debug "
                "servers expose interactive consoles / stack traces and must never run in "
                "an exposed or production setting."
            ),
            recommendation=(
                "Disable debug mode for anything reachable beyond local development; it can "
                "allow remote code execution via the debugger."
            ),
            capability=None,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            # Real binds/debug flags are value-strings (host="0.0.0.0", run(debug=True)); the FP
            # is the same text in a comment or docstring example. Strings stay in scope.
            code_context="comments_and_docstrings",
            suffixes=CODE_SUFFIXES,
            pattern=alternation(
                r"\.run\([^)]*\bdebug\s*=\s*True",          # Flask app.run(debug=True)
                r"app\.debug\s*=\s*True",
                flags=re.IGNORECASE,
            ),
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        bind_rule, debug_rule = self.rules
        findings = []
        bind = _bind_evidence(index)
        if bind:
            findings.append(_finding_from_rule(bind_rule, bind))
        findings.extend(findings_from_rules(index, [debug_rule]))
        return ScanResult(findings=findings)
