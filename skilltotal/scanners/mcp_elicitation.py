"""An MCP server that asks the user for a secret through elicitation.

Elicitation lets a server put a form in front of the user in the middle of a tool call
(``server.elicitInput(...)`` in the TypeScript SDK, ``ctx.elicit(...)`` in the Python SDK and
FastMCP). The MCP specification says servers must not use it to request sensitive information:
the form appears in the client's own interface, so a request there for a password, an API key, a
wallet's recovery phrase or a card number looks like the client asking. The request's message,
its schema and, in Python, the fields of the model it names are read; nothing is run.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule

R_ELICIT_SECRET = "ST-MCP-ELICIT-SECRET"  # nosec B105 - a rule id, not a secret

_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")
_JS_CALL = re.compile(r"\belicitInput\s*\(")
_PY_CALL = re.compile(r"\.elicit\s*\(")
# `[^\S\n]*`, not `\s*`: from each of many blank lines `^\s*` ran over all the rest (quadratic).
_PY_MCP_IMPORT = re.compile(r"^[^\S\n]*(?:from|import)\s+(?:mcp|fastmcp)\b", re.MULTILINE)
_PY_MODEL_ARG = re.compile(r"\b(?:schema|response_type)\s*=\s*([A-Za-z_]\w*)")
_SENSITIVE = re.compile(
    r"(?<![a-z])(?:pass(?:word|phrase|code)|api[\s_-]?key|access[\s_-]?token|auth[\s_-]?token"
    r"|bearer[\s_-]?token|personal[\s_-]?access[\s_-]?token|secret[\s_-]?key|client[\s_-]?secret"
    r"|private[\s_-]?key|seed[\s_-]?phrase|recovery[\s_-]?phrase|mnemonic|credit[\s_-]?card"
    r"|card[\s_-]?number|cvv|cvc|social[\s_-]?security|ssn|one[\s_-]?time[\s_-]?(?:code|password)"
    r"|otp|2fa|mfa[\s_-]?code|verification[\s_-]?code)(?![a-z])",
    re.IGNORECASE,
)
_ARGS_LIMIT = 4000
_MODEL_LINES = 60


class McpElicitationScanner(Scanner):
    name = "mcp_elicitation"
    rules = [
        RuleSpec(
            id=R_ELICIT_SECRET,
            category="mcp",
            severity=Severity.HIGH,
            title="MCP server asks the user for a secret through elicitation",
            description=(
                "The server puts a form in front of the user that asks for a password, key, "
                "token, recovery phrase, card number or one-time code. The MCP specification "
                "says servers must not request sensitive information this way: the form appears "
                "in the client's own interface, so the request looks like the client asking."
            ),
            recommendation=(
                "Do not enter secrets in a form a server shows. A server that needs a credential "
                "should take it from its configuration or an OAuth flow, never from elicitation."
            ),
            capability=Capability.MCP_TOOLS_DETECTED,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        for f in index.files:
            if f.suffix in _JS_SUFFIXES and "elicitInput" in f.text:
                evidence.extend(_requests(f, _JS_CALL, python=False))
            elif f.suffix == ".py" and ".elicit" in f.text and _PY_MCP_IMPORT.search(f.text):
                evidence.extend(_requests(f, _PY_CALL, python=True))
        if not evidence:
            return ScanResult()
        return ScanResult(findings=[_finding_from_rule(self.rules[0], evidence)])


def _requests(f: IndexedFile, call: re.Pattern[str], *, python: bool) -> list[Evidence]:
    found: list[Evidence] = []
    for m in call.finditer(f.text):
        close = _closing_paren(f.text, m.end() - 1)
        if close is None:
            continue
        args = f.text[m.end():close]
        asked = args
        if python:
            model = _PY_MODEL_ARG.search(args)
            if model:
                asked += "\n" + _model_body(f.text, model.group(1))
        if _SENSITIVE.search(asked):
            found.append(f.evidence_for_span(m.start(), close + 1))
    return found


def _closing_paren(text: str, open_at: int) -> int | None:
    depth, i = 0, open_at
    stop = min(len(text), open_at + _ARGS_LIMIT)
    while i < stop:
        ch = text[i]
        if ch in "'\"`":
            end = text.find(ch, i + 1)
            while end > 0 and text[end - 1] == "\\":
                end = text.find(ch, end + 1)
            if end < 0:
                return None
            i = end + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _model_body(text: str, name: str) -> str:
    """The indented body of ``class name(...):`` in the same file (bounded)."""
    m = re.search(r"^class\s+" + re.escape(name) + r"\b[^\n]*:\s*\n", text, re.MULTILINE)
    if m is None:
        return ""
    lines = []
    for line in text[m.end():].splitlines()[:_MODEL_LINES]:
        if line.strip() and not line[0].isspace():
            break
        lines.append(line)
    return "\n".join(lines)
