"""Network-exposure posture: a component that listens on all interfaces or runs a debug
server. Not malware — a ``risky_construct`` that widens the attack surface (often combined
with missing auth), e.g. an MCP/agent server bound to 0.0.0.0 or a Flask app with debug=True.
"""

from __future__ import annotations

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
# CLI launchers: --host 0.0.0.0, --bind=0.0.0.0:8000, -b 0.0.0.0 (flask run -h, gunicorn -b).
_FLAG_BEFORE = re.compile(
    r"(?:--(?:host|hostname|bind|listen|ip|addr|address)|(?<![\w-])-[hHb])(?:=|\s+)$"
)
_CONTEXT_CHARS = 160


def _bind_evidence(index: FileIndex) -> list[Evidence]:
    evidence: list[Evidence] = []
    for f in index.select(suffixes=CODE_SUFFIXES):
        text = f.text
        for m in _ANY_ADDR.finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            before = text[max(line_start, m.start() - _CONTEXT_CHARS) : m.start()]
            if m.group(0)[0] in "'\"":
                bound = _BIND_BEFORE.search(before) or (
                    _TUPLE_BEFORE.search(before) and _TUPLE_AFTER.match(text, m.end())
                )
            else:
                bound = _FLAG_BEFORE.search(before)
            if bound:
                evidence.append(f.evidence_for_span(m.start(), m.end()))
                if len(evidence) >= MAX_EVIDENCE_SCANNED:
                    return evidence
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
