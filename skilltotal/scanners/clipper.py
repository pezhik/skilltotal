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
_BOUND_ADDRESS = re.compile(
    r"""(?:\b(?:const|let|var)\s+)?\b(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*[\w.<>]+\s*)?=\s*"""
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
    r"\b(?P<name>[A-Za-z_$][\w$]*)\s*=\s*[^\n=]{0,200}?\.replace\s*\((?P<call>[^\n]{0,200})"
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
                "The code writes a cryptocurrency address fixed in the code to the clipboard, in "
                "a file that also recognizes addresses with a pattern. This is how a clipper "
                "replaces an address the user copied, so the user pastes the fixed address "
                "instead."
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
            evidence.extend(_clipper_evidence(f))
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
