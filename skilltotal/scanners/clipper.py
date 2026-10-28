"""Clipboard address swap ("clipper").

A clipper watches the clipboard and, when the text there looks like a cryptocurrency address,
writes its own address in its place: the victim pastes the attacker's address and sends the
payment there. There is no network call and no file is touched, so no other rule sees it.

Flagged only when the three parts meet in one file, and the address the code writes is a
constant: a crypto address written into the code, written to the clipboard (directly, through
the name it is bound to, or as the replacement in ``.replace(...)``), in a file that also
recognizes addresses with a pattern. A wallet or dApp that copies the address a user is looking
at writes a variable, not a constant, and stays clean; so does code that only validates
addresses, or only knows a contract address.

A clipper can also leave the clipboard write to its caller and hand back the swapped text: when
the clipboard text matches an address pattern it returns the fixed address, and otherwise the
text unchanged (``_returned_swap_evidence``). That form is flagged in a file that handles
clipboard text, when a value is tested against an address pattern, the branch taken on a match
returns a fixed address of the shape that pattern looks for, and the tested value itself is what
the other path returns (or the pattern's matches are replaced with the fixed address). A
validator returns a boolean, a formatter returns the address shortened, and a chain selector
returns one fixed address or another: none of them passes the tested text through unchanged
beside a fixed address, so none of them is a swap.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Evidence, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule
from skilltotal.text_normalize import original_span

R_CLIPPER = "ST-CLIPPER"

_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".py")

# A string literal holding a crypto address: Bitcoin bech32 and legacy, Ethereum, Tron.
_ADDRESS = (
    r"(?:bc1[ac-hj-np-z02-9]{25,87}|0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
    r"|T[1-9A-HJ-NP-Za-km-z]{33})"
)
_ADDRESS_LITERAL = re.compile(r"""(?P<q>["'`])(?P<addr>""" + _ADDRESS + r""")(?P=q)""")
# `NAME = "<address>"` (const/let/var or a Python assignment): the name the address is bound to.
# A name starts where no identifier character precedes it: with `\b` a run like `const$const$...`
# began a name after every `$` and read it to the end of the run, quadratic in the line's length.
_BOUND_ADDRESS = re.compile(
    r"""(?:\b(?:const|let|var)\s+)?(?<![\w$])(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*[\w.<>]+\s*)?=\s*"""
    r"""(?P<q>["'`])(?P<addr>""" + _ADDRESS + r""")(?P=q)"""
)
# Code that recognizes an address: a pattern anchored on an address prefix or using the base58
# alphabet, the way a clipper decides what to replace.
_RECOGNIZER = re.compile(
    r"(?:[\^(|]\s*(?:bc1|0x)|0x\\?\[[^\]\n]{1,20}\]\{40\}|1-9A-HJ-NP-Za-km-z|a-km-zA-HJ-NP-Z1-9)"
)
# A write to the clipboard and the argument text that follows it (bounded, same line).
_CLIPBOARD_WRITE = re.compile(
    r"(?:\b(?:clipboardy|ncp)\.(?:write|writeSync|copy)"
    r"|\bnavigator\.clipboard\.write(?:Text)?"
    r"|\bclipboard\.write(?:Text)?"
    r"|\bpyperclip\.copy"
    r"|\bwin32clipboard\.SetClipboard(?:Text|Data)"
    r"|\.clipboard_append)\s*\((?P<arg>[^\n]{0,200})"
)
# `swapped = text.replace(PATTERN, ATTACKER)`: a name holding a replacement, written later.
_REPLACED_INTO = re.compile(
    r"(?<![\w$])(?P<name>[A-Za-z_$][\w$]*)\s*=\s*[^\n=]{0,200}?\.replace\s*\((?P<call>[^\n]{0,200})"
)


class ClipperScanner(Scanner):
    name = "clipper"
    rules = [
        RuleSpec(
            id=R_CLIPPER,
            category="clipboard_hijack",
            severity=Severity.HIGH,
            title="Clipboard address swap (clipper)",
            description=(
                "The code puts a cryptocurrency address fixed in the code in place of an address "
                "it recognized with a pattern: it writes the fixed address to the clipboard, or "
                "returns it for clipboard text that matched while other text passes through "
                "unchanged. This is how a clipper replaces an address the user copied, so the "
                "user pastes the fixed address instead."
            ),
            recommendation=(
                "Code that copies an address should copy the one the user chose, never a fixed "
                "one. Treat a fixed address written over the clipboard as malicious; remove the "
                "component."
            ),
            capability=None,  # theft by redirection: no capability this engine models
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            suffixes=_SUFFIXES,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        for f in index.select(suffixes=_SUFFIXES):
            evidence.extend(_clipper_evidence(f) or _returned_swap_evidence(f))
        if evidence:
            return ScanResult(findings=[_finding_from_rule(self.rules[0], evidence)])
        return ScanResult()


def _clipper_evidence(f: IndexedFile) -> list[Evidence]:
    """The clipboard write and the address it writes, when this file swaps addresses."""
    text = f.text
    writes = list(_CLIPBOARD_WRITE.finditer(text))
    if not writes or not _RECOGNIZER.search(text):
        return []
    # Literals spliced from pieces ("bc1q" + "...") are read joined, mapped back to the source.
    texts: list[tuple[str, Sequence[int] | None]] = [(text, None)]
    folded = f.concat_folded_or_none()
    if folded is not None:
        texts.append(folded)
    constants: dict[str, int] = {}  # address, or a name bound to one -> offset in the source
    for body, idx in texts:
        for m in _BOUND_ADDRESS.finditer(body):
            start = _source_offset(m, idx)
            constants.setdefault(m.group("name"), start)
            constants.setdefault(m.group("addr"), start)
        for m in _ADDRESS_LITERAL.finditer(body):
            constants.setdefault(m.group("addr"), _source_offset(m, idx))
    if not constants:
        return []
    # The swap is tied to the recognizing: a fixed address written within a few lines after an
    # address test, or put in by a replace whose pattern is the test. A "copy contract address"
    # button elsewhere in a file that also validates addresses is not that.
    recognized = [f.line_of_offset(m.start()) for m in _RECOGNIZER.finditer(text)]

    def follows_a_test(offset: int) -> bool:
        line = f.line_of_offset(offset)
        return any(line - _NEAR_LINES <= r <= line for r in recognized)

    swapped: dict[str, int] = {}  # a name holding the result of a replace that puts one in
    for m in _REPLACED_INTO.finditer(text):
        used = _constant_in(m.group("call"), constants)
        if used is not None and (_RECOGNIZER.search(m.group("call")) or follows_a_test(m.start())):
            swapped.setdefault(m.group("name"), constants[used])
    for write in writes:
        argument = _call_argument(write.group("arg"))
        name = _constant_in(argument, swapped)
        if name is not None:
            return _evidence(f, write, swapped[name])
        used = _constant_in(argument, constants)
        if used is not None and (_RECOGNIZER.search(argument) or follows_a_test(write.start())):
            return _evidence(f, write, constants[used])
    return []


# How far after an address test the clipboard write may come and still be its consequence.
_NEAR_LINES = 8


def _evidence(f: IndexedFile, write: re.Match[str], address_at: int) -> list[Evidence]:
    return [f.evidence_for_span(write.start(), write.end()),
            f.evidence_for_span(address_at, address_at + 1)]


def _call_argument(rest: str) -> str:
    """What is inside the call's parentheses: ``rest`` starts after ``(``; text after the
    matching ``)`` belongs to other code (`writeText(address)}>{valid ? address : DONATE}`)."""
    depth = 0
    for i, ch in enumerate(rest):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return rest[:i]
            depth -= 1
    return rest


def _source_offset(m: re.Match[str], idx: Sequence[int] | None) -> int:
    start = m.start("addr")
    return start if idx is None else original_span(idx, start, m.end("addr"))[0]


def _constant_in(code: str, constants: dict[str, int]) -> str | None:
    """The first address constant, or name bound to one, that ``code`` uses as a whole word."""
    for key in constants:
        if re.search(r"(?<![\w$])" + re.escape(key) + r"(?![\w$])", code):
            return key
    return None


# --- The swap handed back to the caller ---------------------------------------------------------

# The file handles clipboard text: a clipboard API, a helper package, or a name for it.
_CLIPBOARD_CONTEXT = re.compile(r"clipboard|pyperclip|\bpbpaste\b|\bxclip\b|\bxsel\b", re.I)
_IDENT = r"[A-Za-z_$][\w$]*"
_JS_REGEX = r"/(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+/[a-z]*"
_PY_STRING = r"""[rRbBuU]{0,2}(?P<q>["'])(?:\\.|(?!(?P=q))[^\\\n])*(?P=q)"""
# The tested value: a name, maybe with a property or a no-argument call (`clip.trim()`).
_SUBJECT = r"(?P<subj>[A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*(?:\(\s*\))?)*"
# A value tested against a pattern: `/re/.test(s)`, `RE.test(s)`, `s.match(/re/)`,
# `re.match(r"re", s)`, `RE.fullmatch(s)`.
_PATTERN_TESTS = (
    re.compile(
        r"(?<![\w$)\]])(?P<pat>" + _JS_REGEX + "|" + _IDENT + r")\s*\.test\s*\(\s*" + _SUBJECT
        + r"\s*\)"
    ),
    re.compile(
        r"(?<![\w$.])" + _SUBJECT + r"\s*\.match\s*\(\s*(?P<pat>" + _JS_REGEX + "|" + _IDENT
        + r")\s*\)"
    ),
    re.compile(
        r"\bre\.(?:match|search|fullmatch)\s*\(\s*(?P<pat>" + _PY_STRING + "|" + _IDENT
        + r")\s*,\s*" + _SUBJECT + r"\s*(?:,[^()\n]*)?\)"
    ),
    re.compile(
        r"(?<![\w$.])(?P<pat>" + _IDENT + r")\.(?:match|search|fullmatch)\s*\(\s*" + _SUBJECT
        + r"\s*\)"
    ),
)
# A fixed value: a name, or an address-length string literal.
_VALUE = r"""(?P<val>[A-Za-z_$][\w$]*|["'`][A-Za-z0-9]{20,90}["'`])"""
# Replacing what a pattern matched: `s.replace(/re/g, ADDR)`, `re.sub(r"re", ADDR, s)`.
_PATTERN_REPLACES = (
    re.compile(
        r"\.replace(?:All)?\s*\(\s*(?P<pat>" + _JS_REGEX + "|" + _IDENT + r")\s*,\s*" + _VALUE
        + r"\s*\)"
    ),
    re.compile(
        r"\bre\.sub\s*\(\s*(?P<pat>" + _PY_STRING + "|" + _IDENT + r")\s*,\s*" + _VALUE
        + r"\s*,"
    ),
    re.compile(r"(?<![\w$.])(?P<pat>" + _IDENT + r")\.sub\s*\(\s*" + _VALUE + r"\s*,"),
)
# `NAME = <pattern>`: a pattern kept under a name and tested through it.
_PATTERN_BINDING = re.compile(
    r"(?<![\w$])(?P<name>" + _IDENT + r")\s*=\s*(?P<rhs>[^\n=][^\n]{0,300})"
)
# `NAME = "<string>"`: a fixed value kept under a name (read with spliced literals joined too).
_BOUND_STRING = re.compile(
    r"""(?:\b(?:const|let|var)\s+)?(?<![\w$])(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*[\w.<>]+\s*)?=\s*"""
    r"""(?P<q>["'`])(?P<value>[A-Za-z0-9]{20,90})(?P=q)"""
)
_ANY_RETURN = re.compile(r"\breturn\b")
_RETURN = re.compile(r"\breturn\s+" + _VALUE + r"\s*(?=[;}#/\r\n]|$)", re.M)
# A Bitcoin-bech32-like value outside the strict alphabet, accepted only against a pattern that
# itself looks for `bc1`: the code calls it an address by its own test.
_LOOSE_BECH32 = re.compile(r"bc1[a-z0-9]{15,87}")
_NULL_ADDRESS = re.compile(r"0x0{40}")  # the null address is a placeholder, not a payee
# How many lines the branch taken on a match may span before its `return`.
_BRANCH_LINES = 3


def _returned_swap_evidence(f: IndexedFile) -> list[Evidence]:
    """The test, the swap and the fixed address, when this file hands back swapped clipboard
    text: a fixed address in place of a value that matched an address pattern."""
    text = f.text
    if not _CLIPBOARD_CONTEXT.search(text) or not _RECOGNIZER.search(text):
        return []
    patterns = {
        m.group("name"): m.group("rhs")
        for m in _PATTERN_BINDING.finditer(text)
        if _RECOGNIZER.search(m.group("rhs"))
    }
    constants = _bound_strings(f)

    def address_pattern(pat: str) -> str | None:
        source = patterns.get(pat, pat)
        return source if _RECOGNIZER.search(source) else None

    def fixed_address(val: str, pattern: str, at: int) -> int | None:
        """Where the fixed address ``val`` (a literal, or a name bound to one) is written."""
        if val[0] in "\"'`":
            value, where = val[1:-1], at
        elif val in constants:
            value, where = constants[val]
        else:
            return None
        if _NULL_ADDRESS.fullmatch(value):
            return None
        if re.fullmatch(_ADDRESS, value) or (
            "bc1" in pattern.lower() and _LOOSE_BECH32.fullmatch(value)
        ):
            return where
        return None

    for regex in _PATTERN_TESTS:
        for test in regex.finditer(text):
            pattern = address_pattern(test.group("pat"))
            swap = _swap_after_test(f, test) if pattern is not None else None
            if pattern is None or swap is None:
                continue
            where = fixed_address(swap[0], pattern, swap[1])
            if where is not None:
                return _swap_evidence(f, (test.start(), swap[1], where))
    for regex in _PATTERN_REPLACES:
        for rep in regex.finditer(text):
            pattern = address_pattern(rep.group("pat"))
            where = (
                fixed_address(rep.group("val"), pattern, rep.start("val"))
                if pattern is not None else None
            )
            if where is not None:
                return _swap_evidence(f, (rep.start(), where))
    return []


def _swap_after_test(f: IndexedFile, test: re.Match[str]) -> tuple[str, int] | None:
    """``(fixed value, its offset)`` when the code returns a fixed value for a value that
    matched the pattern and the value itself when it did not: ``if (RE.test(s)) return ADDR;
    return s``, ``RE.test(s) ? ADDR : s``, ``ADDR if re.match(p, s) else s``."""
    text = f.text
    subject = test.group("subj")
    line_start, line_end = f.line_bounds(test.start(), test.end())
    before = text[line_start : test.start()]
    after = text[test.end() : line_end]
    passthrough = r"\s*(?P<other>[A-Za-z_$][\w$]*)\s*(?:[;)}\]#/\r]|$)"
    # A conditional expression on the test's own line.
    js = re.match(r"\s*\)?\s*\?\s*" + _VALUE + r"\s*:" + passthrough, after)
    if js and js.group("other") == subject:
        return js.group("val"), test.end() + js.start("val")
    py = re.search(_VALUE + r"\s+if\s+(?:\(\s*)?$", before)
    tail = re.match(r"\s*\)?\s*else" + passthrough, after)
    if py and tail and tail.group("other") == subject:
        return py.group("val"), line_start + py.start("val")
    # An `if` whose branch returns a fixed value, followed by `return <the tested value>`.
    if not re.search(r"\b(?:if|elif)\s*\(?\s*$", before):
        return None  # not the whole condition, or a negated one (`if (!RE.test(s))`)
    # The first `return` after the test is the branch's, the next one the other path's.
    first = _ANY_RETURN.search(text, test.end(), _line_end_after(text, test.end(), _BRANCH_LINES))
    swap = _RETURN.match(text, first.start()) if first else None
    if swap is None or swap.group("val") == subject:
        return None
    other = _ANY_RETURN.search(text, swap.end(), _line_end_after(text, swap.end(), _NEAR_LINES))
    passed = _RETURN.match(text, other.start()) if other else None
    if passed is not None and passed.group("val") == subject:
        return swap.group("val"), swap.start("val")
    return None


def _line_end_after(text: str, offset: int, lines: int) -> int:
    """The offset just past the line ``lines`` lines below the one holding ``offset``."""
    end = offset
    for _ in range(lines + 1):
        newline = text.find("\n", end)
        if newline < 0:
            return len(text)
        end = newline + 1
    return end


def _bound_strings(f: IndexedFile) -> dict[str, tuple[str, int]]:
    """Every ``NAME = "<address-length string>"``, as written and with spliced literals joined:
    name -> (value, offset of the value in the source)."""
    texts: list[tuple[str, Sequence[int] | None]] = [(f.text, None)]
    folded = f.concat_folded_or_none()
    if folded is not None:
        texts.append(folded)
    bound: dict[str, tuple[str, int]] = {}
    for body, idx in texts:
        for m in _BOUND_STRING.finditer(body):
            start = m.start("value")
            if idx is not None:
                start = original_span(idx, start, m.end("value"))[0]
            bound.setdefault(m.group("name"), (m.group("value"), start))
    return bound


def _swap_evidence(f: IndexedFile, offsets: tuple[int, ...]) -> list[Evidence]:
    """One evidence line per offset (the test, the swap, the fixed address), each line once."""
    evidence: list[Evidence] = []
    lines: set[int] = set()
    for at in offsets:
        line = f.line_of_offset(at)
        if line not in lines:
            lines.add(line)
            evidence.append(f.evidence_for_span(at, at + 1))
    return evidence
