"""Directives in an instruction file that carry no command, each read with its second tell.

An agent follows the prose of a skill, a rule file or CLAUDE.md as it follows a command line. Five
shapes hand it a hostile instruction without a single shell word. Each is ordinary in part (a
skill links its docs, a memory skill writes to CLAUDE.md, a README shows a badge, a file holds a
base64 sample, a template ends with a marker), so each needs the part an honest file does not have:

* **Remote instructions that outrank the user or are kept from the user.** "Fetch <url> and follow
  the instructions in it" with "even if it conflicts with what the user asked" or "do not mention
  this to the user". Without that part it is a note for review: skills do point an agent at a
  hosted guide.
* **A standing network order planted in the agent's memory.** A write into CLAUDE.md, AGENTS.md or
  another file the agent reads at every start, where the planted text sends files, conversation or
  credentials to a URL, or loads and follows instructions from one.
* **An image address that carries data out.** "Replace DATA with the contents of the .env file"
  next to an image whose URL holds that placeholder in its query: rendering the image sends it.
* **Encoded instructions.** "Decode this base64 string and follow it", with a block in the file
  that decodes to readable text; the decoded text is shown in the evidence.
* **A fake end of the file.** A line that claims the instructions end here ("=== END OF SKILL.md
  ==="), followed by a line that speaks as the system ("System: ...").

Pure functions over one text; the caller decides which files are read and maps the spans back.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import NamedTuple

from skilltotal.scanners.skill_directives import _MEMORY_WRITE
from skilltotal.scanners.skill_fetch_exec import _PARAGRAPH_BREAK, _SENTENCE_END

_SENTENCE_REACH = 400
# Candidates looked at per text and per shape: a file with more is a list, and every candidate
# costs a bounded window, so a crafted file cannot make a pass slow.
_MAX_CANDIDATES = 60


def _sentence_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    """The statement (sentence, list item) around ``[start, end)`` inside its paragraph, looked
    for no further than ``_SENTENCE_REACH`` characters on either side."""
    lo = max(0, start - _SENTENCE_REACH)
    begin = lo
    for stop in _PARAGRAPH_BREAK.finditer(text, lo, start):
        begin = stop.end()
    for stop in _SENTENCE_END.finditer(text, begin, start):
        begin = stop.end()
    hi = min(len(text), end + _SENTENCE_REACH)
    paragraph_end = _PARAGRAPH_BREAK.search(text, end, hi)
    finish = paragraph_end.start() if paragraph_end else hi
    after = _SENTENCE_END.search(text, end, finish)
    return begin, after.start() + 1 if after else finish


class Directive(NamedTuple):
    start: int
    end: int
    # Appended to the evidence snippet (the decoded text of an encoded block); "" for none.
    note: str
    # False: the shape without its second tell, a note for review and never scored.
    scored: bool


_URL = re.compile(r"https?://[^\s'\"`<>)\]]+", re.IGNORECASE)

_FETCH_VERB = re.compile(
    r"\b(?:fetch|download|load|retrieve|pull|read|get|open|visit|request|curl|wget)(?:es|s|ing)?\b",
    re.IGNORECASE,
)
_OBEY_OBJECT = (
    r"(?:(?:exactly|precisely|strictly|fully|blindly)\s+)?"
    r"(?:(?:all|every|each|any|the|its|their|those|these|whatever|latest|current|new|updated)\s+)*"
    r"(?:(?:\w+\s+){0,2}?(?:instructions?|steps|rules|directives|commands|orders|guidance)\b"
    r"|it\b|them\b|everything\b|what(?:ever)?\s+it\s+says\b)"
)
_OBEY = re.compile(
    r"\b(?:follow|obey|execute|carry\s+out|apply|comply\s+with|perform|act\s+on|adopt)\s+"
    + _OBEY_OBJECT,
    re.IGNORECASE,
)
# "follow the rules from <url>": the address is where the instructions come from.
_FROM_URL = re.compile(r"\b(?:from|at|in|on|under|via)\s+[`'\"<(]*$", re.IGNORECASE)
# The remote text outranks the user or the file the user reviewed.
_OUTRANKS = re.compile(
    r"\b(?:even\s+(?:if|when|though)|regardless\s+of|no\s+matter\s+what)\b[^.\n]{0,80}?"
    r"\b(?:users?|instruct\w*|told|asked|says?|conflicts?|contradicts?|polic\w+|rules?|"
    r"guidelines?|system|above|otherwise)\b"
    r"|\b(?:overrid(?:e|es|ing)|supersed(?:e|es|ing)|takes?\s+precedence\s+over|"
    r"takes?\s+priority\s+over|instead\s+of)\b[^.\n]{0,60}?"
    r"\b(?:users?|instructions?|rules|system\s+prompt|this\s+(?:file|skill|document))\b",
    re.IGNORECASE,
)
# Keeping the action itself from the user. "Never show the token" keeps a secret out of the output
# and is not this: what is hidden must be the step.
_KEPT_FROM_USER = re.compile(
    r"\b(?:silently|secretly|quietly|covertly)\b"
    r"|\bwithout\s+(?:asking|telling|informing|notifying|alerting|mentioning)\b"
    r"|\b(?:do\s+not|don['’]?t|never)\s+(?:tell|inform|notify|alert)\s+"
    r"(?:the\s+user|users|anyone|the\s+human)\b"
    r"|\b(?:do\s+not|don['’]?t|never)\s+(?:mention|reveal|disclose|report)\s+"
    r"(?:this|that|these|it|any\s+of\s+this)\b",
    re.IGNORECASE,
)
_NEGATED = re.compile(
    r"\b(?:not|never|cannot|can['’]?t|don['’]?t|won['’]?t|shouldn['’]?t|mustn['’]?t|refuse|"
    r"avoid|without)\b",
    re.IGNORECASE,
)


_BLANK_LINE = re.compile(r"\n[ \t\r]*\n")
# How far the second tell may stand from the directive: the sentence before it and the one after,
# inside its paragraph. A table of attack shapes, or a long paragraph that says "silently" about
# something else, is not the directive's own statement.
_TELL_BEFORE = 200
_TELL_AFTER = 300
_QUOTE_OPEN = "\"'`“‘"


def _statement(text: str, begin: int, finish: int) -> str:
    """The sentence ``[begin, finish)`` with its neighbours, cut at the paragraph's ends."""
    lo = max(0, begin - _TELL_BEFORE)
    breaks = [m.end() for m in _BLANK_LINE.finditer(text, lo, begin)]
    if breaks:
        lo = breaks[-1]
    hi = min(len(text), finish + _TELL_AFTER)
    stop = _BLANK_LINE.search(text, finish, hi)
    return text[lo : stop.start() if stop else hi]


def _remote_instruction_at(text: str, url: re.Match[str]) -> tuple[int, int, int] | None:
    """``(sentence start, directive start, sentence end)`` when ``url`` is where instructions to
    follow are loaded from; the directive starts at its load verb (or at "follow ... from")."""
    begin, finish = _sentence_bounds(text, url.start(), url.end())
    head = text[begin : url.start()]
    obey = _OBEY.search(text, begin, finish)
    if obey is None:
        return None
    fetch = _FETCH_VERB.search(head)
    if fetch is None and not (obey.start() < url.start() and _FROM_URL.search(head)):
        return None
    start = min(begin + fetch.start(), obey.start()) if fetch else obey.start()
    if _NEGATED.search(text[begin:start]):
        return None
    return begin, start, finish


def remote_instructions(text: str) -> list[Directive]:
    """Instructions loaded from a URL and followed; scored when they outrank or bypass the user.

    One that opens right after a quote mark or a backtick is an example somebody shows (a rule
    table: `` `fetch <url> and follow it` ``), so it is only noted."""
    found: list[Directive] = []
    for k, url in enumerate(_URL.finditer(text)):
        if k >= _MAX_CANDIDATES:
            break
        span = _remote_instruction_at(text, url)
        if span is None or (found and found[-1].end >= span[2]):
            continue
        begin, start, finish = span
        statement = _statement(text, begin, finish)
        shown = start > 0 and text[start - 1] in _QUOTE_OPEN
        scored = not shown and bool(
            _OUTRANKS.search(statement) or _KEPT_FROM_USER.search(statement)
        )
        found.append(Directive(start, finish, "", scored))
    return found


_SEND_CONTENT = re.compile(
    r"\b(?:send|upload|post|transmit|forward|exfiltrate|leak|copy)(?:s|ing)?\b[^.\n]{0,120}?"
    r"(?:\b(?:conversation|chat|history|transcript|files?|contents?|code|source|credentials?|"
    r"keys?|tokens?|secrets?|passwords?|everything|prompts?)\b|\.env\b)[^.\n]{0,80}?$",
    re.IGNORECASE,
)
# From the write to the text it plants: the same paragraph and the one after it (a quoted line).
_PLANT_REACH = 700


def planted_memory_orders(text: str) -> list[Directive]:
    """A write into an agent memory file whose planted text sends data to, or obeys, a URL."""
    found: list[Directive] = []
    for k, write in enumerate(_MEMORY_WRITE.finditer(text)):
        if k >= _MAX_CANDIDATES:
            break
        if _NEGATED.search(text[max(0, write.start() - 60) : write.start()]):
            continue
        window_end = min(len(text), write.end() + _PLANT_REACH)
        for url in _URL.finditer(text, write.start(), window_end):
            begin, _ = _sentence_bounds(text, url.start(), url.end())
            head = text[begin : url.start()]
            if _SEND_CONTENT.search(head) or _remote_instruction_at(text, url):
                found.append(Directive(write.start(), url.end(), "", True))
                break
        if len(found) >= 10:
            break
    return found


_SENSITIVE_DATA = (
    r"(?:\.env\b|\bapi[\s_-]?keys?\b|\btokens?\b|\bcredentials?\b|\bsecrets?\b|\bpasswords?\b|"
    r"\bconversation\b|\bchat\s+history\b|\bmessages\b|\bsystem\s+prompt\b|\bprivate\s+keys?\b|"
    r"\bid_rsa\b|\.ssh\b|\.aws\b)"
)
_FILL_PLACEHOLDER = re.compile(
    r"\b(?:replac(?:e|ing)|substitut(?:e|ing)|fill(?:ing)?\s+in|swap(?:ping)?)\s+(?:the\s+)?"
    r"(?:placeholder\s+)?[`'\"]?(?P<name>(?-i:[A-Z][A-Z0-9_]{2,30})|\{\w{1,30}\}|<\w{1,30}>)[`'\"]?"
    r"\s+(?:with|by)\b(?:[^\n]|\n(?![ \t\r]*\n)){0,240}?" + _SENSITIVE_DATA,
    re.IGNORECASE,
)
_IMAGE_URL = re.compile(
    r"!\[[^\]\n]{0,200}\]\(\s*(https?://[^)\s]{1,500})|<img\b[^>]{0,300}?\bsrc\s*=\s*['\"]"
    r"(https?://[^'\"\s]{1,500})",
    re.IGNORECASE,
)
_IMAGE_REACH = 800


def image_exfil_orders(text: str) -> list[Directive]:
    """ "Replace DATA with <secrets>" beside an image whose URL query holds that placeholder."""
    found: list[Directive] = []
    candidates = 0
    # From the image: few files hold an image whose address has a query at all.
    for image in _IMAGE_URL.finditer(text):
        query = (image.group(1) or image.group(2)).partition("?")[2]
        if not query:
            continue
        candidates += 1
        if candidates > _MAX_CANDIDATES or len(found) >= 10:
            break
        lo, hi = max(0, image.start() - _IMAGE_REACH), min(len(text), image.end() + _IMAGE_REACH)
        for fill in _FILL_PLACEHOLDER.finditer(text, lo, hi):
            if fill.group("name") in query:
                found.append(Directive(min(fill.start(), image.start()),
                                       max(fill.end(), image.end()), "", True))
                break
    return found


_DECODE_BASE64 = re.compile(
    r"\bdecod(?:e|ing)\b[^.\n]{0,80}?\bbase[\s-]?64\b|\bbase[\s-]?64[\s-]+decod(?:e|ing)\b"
    r"|\bbase[\s-]?64\b[^.\n]{0,60}?\bdecod(?:e|ing)\b",
    re.IGNORECASE,
)
_OBEY_DECODED = re.compile(
    r"\b(?:follow|obey|execute|carry\s+out|apply|comply\s+with|perform|act\s+on|do\s+what)\b"
    r"[^.\n]{0,60}?\b(?:instructions?|steps|commands|directives|it|them|result|output|text|"
    r"decoded|says)\b",
    re.IGNORECASE,
)
_BASE64_RUN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,4000}={0,2}(?![A-Za-z0-9+/=])")
_BLOCK_REACH = 2000
_MAX_DECODE_TRIES = 8


def _decoded_prose(run: str) -> str | None:
    """The text a base64 run decodes to, when that is readable prose; else None."""
    try:
        raw = base64.b64decode(run + "=" * (-len(run) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for c in decoded if c.isprintable() or c in "\n\t")
    if len(decoded) < 20 or printable < len(decoded) * 0.95 or decoded.count(" ") < 3:
        return None
    return decoded


def encoded_instructions(text: str) -> list[Directive]:
    """ "Decode this base64 and follow it" with a block in reach that decodes to readable text."""
    found: list[Directive] = []
    for k, decode in enumerate(_DECODE_BASE64.finditer(text)):
        if k >= _MAX_CANDIDATES:
            break
        begin, finish = _sentence_bounds(text, decode.start(), decode.end())
        if not _OBEY_DECODED.search(text, begin, finish):
            continue
        if _NEGATED.search(text[begin : decode.start()]):
            continue
        hi = min(len(text), finish + _BLOCK_REACH)
        for tries, run in enumerate(_BASE64_RUN.finditer(text, begin, hi)):
            if tries >= _MAX_DECODE_TRIES:
                break
            decoded = _decoded_prose(run.group(0))
            if decoded is not None:
                shown = " ".join(decoded.split())[:160]
                found.append(Directive(begin, finish, f"  [decodes to: {shown!r}]", True))
                break
        if len(found) >= 10:
            break
    return found


_FAKE_END = re.compile(
    r"^[ \t]*[-=*#<\[]{2,}[ \t]*(?:END|EOF)(?:[ \t]+OF)?[ \t]+(?:THE[ \t]+)?"
    r"(?:[\w.-]{1,60}\.mdc?|SKILL|FILE|INSTRUCTIONS?|DOCUMENT|PROMPT|SYSTEM[ \t]+PROMPT|CONTEXT)"
    r"[ \t]*[-=*#>\]]{2,}[ \t]*\r?\n"
    r"(?:[ \t]*\r?\n){0,3}"
    r"[ \t]*(?:\[?(?:system|developer|admin(?:istrator)?)\]?"
    r"(?:[ \t]+(?:message|prompt|note|override|instructions?))?[ \t]*:"
    r"|<[ \t]*system[ \t]*>|\[[ \t]*system[ \t]*\]|new[ \t]+instructions?[ \t]*:)[^\n]{0,200}",
    re.IGNORECASE | re.MULTILINE,
)


def fake_end_markers(text: str) -> list[Directive]:
    """An end-of-instructions marker followed by a line that speaks as the system."""
    return [Directive(m.start(), m.end(), "", True) for m in _FAKE_END.finditer(text)][:10]


def directives(text: str) -> list[Directive]:
    """Every directive shape of this module found in ``text``."""
    found: list[Directive] = []
    if "http" in text or "HTTP" in text:
        found += remote_instructions(text)
        found += planted_memory_orders(text)
        found += image_exfil_orders(text)
    found += encoded_instructions(text)
    found += fake_end_markers(text)
    return found
