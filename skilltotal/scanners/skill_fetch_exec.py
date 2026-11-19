"""Agent instructions that tell the agent to download code and run it.

What a skill, a subagent, a slash command or a project's agent instructions (CLAUDE.md,
AGENTS.md, GEMINI.md, Cursor and Copilot rules) say is what the agent does; an ``allowed-tools``
list that admits the shell lets it do so without asking the user. A line like
``curl -fsSL https://host/x.sh | bash`` there runs whatever that host serves at the time, which no
scan of the component can see.

An honest setup skill may install a tool that way, so the instruction alone is a risk to review,
however visible it is. Told in the instruction itself (its own sentence, or the lead-in of its code
block) to do it silently, without asking, or without mentioning it to the user; placed where a
person reading the rendered file does not see it (an HTML comment, an element styled hidden); or
fetched from a bare IP address, it is not an honest instruction: that is a malicious indicator.
A concealment word elsewhere in the file says nothing about the install line. Code fences count:
in an instruction file a fenced command is what the agent is meant to run. Human docs (README,
docs/) and tests are not instructions to an agent and are not read here.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule
from skilltotal.text_normalize import original_span

R_FETCH_EXEC = "ST-SKILL-FETCH-EXEC"
R_FETCH_EXEC_HIDDEN = "ST-SKILL-FETCH-EXEC-HIDDEN"

_INSTRUCTION_FILE = re.compile(
    r"(?:^|/)SKILL\.md$|(?:^|/)(?:agents|commands)/[^/]+\.md$|(?:^|/)(?:CLAUDE|AGENTS|GEMINI)\.md$"
    r"|(?:^|/)\.cursor/rules/[^/]+\.mdc?$|(?:^|/)\.cursorrules$|(?:^|/)\.windsurfrules$"
    r"|(?:^|/)\.clinerules(?:/[^/]+)?$|(?:^|/)\.github/copilot-instructions\.md$",
    re.IGNORECASE,
)
_URL = r"https?://[^\s'\"`|)<>]+"
_SHELLS = r"(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python[0-9.]*|node|perl|ruby)\b"
# Download and run, on one line: piped into an interpreter, run from a substitution, or
# PowerShell's download-and-evaluate.
_FETCH_EXEC = re.compile(
    r"\b(?:curl|wget)\b[^\n|;&`]{0,300}?" + _URL + r"[^\n|`]{0,200}\|\s*" + _SHELLS
    + r"|\b(?:ba|z)?sh\s+(?:-c\s+)?[\"']?(?:\$\(|<\()\s*(?:curl|wget)\b[^\n)]{0,300}?" + _URL
    + r"|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|`]{0,300}?" + _URL
    + r"[^\n|`]{0,200}\|\s*(?:iex|Invoke-Expression)\b"
    # At least one blank or `(`, at most two `(`: `\s*[(\s]\s*\(?\s*` matched the same, but tried
    # every split of a long blank run (cubic: "iex " and 1,000 blanks took 42 s).
    + r"|\b(?:iex|Invoke-Expression)(?=[\s(])\s*(?:\(\s*){0,2}"
    r"(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod"
    r"|\(?New-Object\s+(?:System\.)?Net\.WebClient\)?\.DownloadString)\b[^\n`]{0,300}?" + _URL,
    re.IGNORECASE,
)
_FIRST_URL = re.compile(_URL, re.IGNORECASE)
_BARE_IP = re.compile(r"^https?://\d{1,3}(?:\.\d{1,3}){3}(?:[:/]|$)", re.IGNORECASE)
# Keeping the action from the user.
_CONCEALED = re.compile(
    r"\b(?:silently|quietly|secretly|covertly"
    r"|without\s+(?:asking|telling|informing|notifying|mentioning|showing|alerting)"
    r"|(?:do\s+not|don'?t|never)\s+(?:mention|tell|show|report|inform|ask|reveal|disclose"
    r"|notify|alert)"
    r")\b",
    re.IGNORECASE,
)
# An allowed-tools entry that lets the shell run these commands unasked.
_SHELL_PREAPPROVED = re.compile(
    r"^allowed[-_]tools\s*:.*\bBash\b(?!\((?![^)]*\b(?:curl|wget|bash|sh|\*)\b))",
    re.IGNORECASE | re.MULTILINE,
)


class SkillFetchExecScanner(Scanner):
    name = "skill_fetch_exec"
    rules = [
        RuleSpec(
            id=R_FETCH_EXEC,
            category="agent_instructions",
            severity=Severity.MEDIUM,
            title="Agent instructions download code and run it",
            description=(
                "An instruction file the agent follows (a skill, subagent, command or project "
                "instructions) tells it to download a script and run it, for example "
                "`curl ... | bash`. The agent runs whatever that host serves when it follows the "
                "instruction, which this scan cannot see; an allowed-tools list that admits the "
                "shell lets it run without asking."
            ),
            recommendation=(
                "Read what the URL serves before letting an agent follow this instruction, or "
                "replace it with a pinned package install."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
        RuleSpec(
            id=R_FETCH_EXEC_HIDDEN,
            category="agent_instructions",
            severity=Severity.HIGH,
            title="Agent instructions download and run code, hidden from the user",
            description=(
                "An instruction file the agent follows tells it to download a script and run it "
                "while keeping that from the user: the instruction says to do it silently, "
                "without asking or without mentioning it, or the command sits where a reader does "
                "not see it (an HTML comment, an element styled invisible, behind a wall of blank "
                "lines), or its name is written with look-alike or invisible characters, or it is "
                "fetched from a bare IP address. An honest setup step is shown to the user, "
                "written in plain letters, and comes from a named host."
            ),
            recommendation=(
                "Do not install or follow this component. If an agent already followed it, treat "
                "the machine as compromised."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        plain: list[Evidence] = []
        hidden: list[Evidence] = []
        for f in index.files:
            if f.agent_read or _INSTRUCTION_FILE.search(f.relpath):
                _instruction_file(f, plain, hidden)
        findings = [_finding_from_rule(rule, evidence)
                    for rule, evidence in zip(self.rules, (plain, hidden), strict=True)
                    if evidence]
        return ScanResult(findings=findings)


def _instruction_file(f: IndexedFile, plain: list[Evidence], hidden: list[Evidence]) -> None:
    found_plain: list[Evidence] = []
    lines: set[int] = set()
    # The file as written, then its de-obfuscated views: a model reads a command spelled with
    # look-alike or full-width letters, or with invisible characters between them, as the command.
    # (A shell would not run such a spelling, so shell and package scripts are not read this way.)
    views: list[tuple[str, Sequence[int] | None]] = [(f.text, None), *f.folded_views()]
    for text, origin in views:
        for m in _FETCH_EXEC.finditer(text):
            start, end = (m.span() if origin is None
                          else original_span(origin, m.start(), m.end()))
            evidence = f.evidence_for_span(start, end)
            if origin is not None and (start >= end or evidence.line_start in lines):
                continue
            lines.add(evidence.line_start)
            url = _FIRST_URL.search(m.group(0))
            if (
                (url and _BARE_IP.match(url.group(0)))
                or (origin is not None and _disguised_command(f.text, origin, m))
                or _in_hidden_markup(text, m.start())
                or _CONCEALED.search(_instruction_text(text, m))
            ):
                hidden.append(evidence)
            else:
                found_plain.append(evidence)
    if found_plain:
        text = f.text
        preapproved = _SHELL_PREAPPROVED.search(_frontmatter(text))
        if preapproved:
            found_plain.insert(0, f.evidence_for_span(preapproved.start(), preapproved.end()))
        plain.extend(found_plain)


_COMMAND_WORD = re.compile(r"[A-Za-z][\w-]*")


def _disguised_command(original: str, origin: Sequence[int], m: re.Match[str]) -> bool:
    """True if the downloader or the interpreter of a command found only in a de-obfuscated view
    is written with other characters than its ASCII name: look-alike or full-width letters, or
    invisible characters inside the word. Blanks written as no-break spaces (a command pasted
    from a web page) and non-ASCII text around the command are not that."""
    command = m.group(0)
    words = [_COMMAND_WORD.match(command)]
    pipe = command.rfind("|")
    if pipe >= 0:
        words.append(_COMMAND_WORD.search(command, pipe))
    for word in words:
        if word is None:
            continue
        start, end = original_span(origin, m.start() + word.start(), m.start() + word.end())
        if not original[start:end].isascii():
            return True
    return False


# Where one statement of an instruction ends: a sentence end, or a new list item or heading.
_SENTENCE_END = re.compile(r"[.!?](?=\s)|\n(?=[ \t]*(?:[-*+]|\d+[.)])[ \t])|\n(?=[ \t]*#)")
# An element a renderer does not show: `style="display:none"`, `visibility:hidden`, `hidden`.
# Also the styles that draw the text where nobody can read it: no size, fully transparent, the
# colour of a white page with no background set, pushed off the screen, a box of no size that
# clips its content, and the old `<font color="white">`.
_HIDDEN_ELEMENT = re.compile(
    r"<([A-Za-z][\w-]{0,30})\b[^<>]{0,500}?(?:display\s*:\s*none|visibility\s*:\s*hidden"
    r"|\shidden(?=[\s=>/])"
    r"|font-size\s*:\s*(?:0(?:\.0+)?(?:px|pt|em|rem|%)?|1px)(?![\w.])"
    r"|opacity\s*:\s*0(?:\.0+)?(?![\w.])"
    r"|(?<![\w-])color\s*:\s*transparent\b"
    r"|(?:left|top|text-indent|margin-left)\s*:\s*-\d{3,}"
    r"|(?:height|width)\s*:\s*0(?:px)?\s*;[^<>]{0,200}?overflow\s*:\s*hidden"
    r"|overflow\s*:\s*hidden\s*;[^<>]{0,200}?(?:height|width)\s*:\s*0(?:px)?(?![\w.])"
    r"|(?<![\w-])color\s*(?::|=)\s*[\"']?(?:white|#fff(?:fff)?)\b(?![^<>]{0,300}background)"
    r"|(?<![\w-])color\s*:\s*(white|#fff(?:fff)?)\s*;\s*background(?:-color)?\s*:\s*\2\b)"
    r"[^<>]{0,500}>",
    re.IGNORECASE,
)
_HIDDEN_REACH = 4000
# Text pushed out of sight by padding: this many blank lines above it, or this many blanks before
# it on its own line. A person who opens the file sees an empty page and stops reading.
_PAD_BLANK_LINES = 40
_PAD_BLANKS = re.compile(r"[ \t]{200,}")


def _in_hidden_markup(text: str, pos: int) -> bool:
    """True if ``pos`` is inside an HTML comment, inside an element styled not to render, or
    behind a wall of blank lines or blanks: the agent reads the raw file, while a person viewing
    the skill sees nothing there."""
    opened = text.rfind("<!--", 0, pos)
    if opened >= 0 and text.find("-->", opened + 4, pos) < 0:
        return True
    lo = max(0, pos - _HIDDEN_REACH)
    for tag in reversed(list(_HIDDEN_ELEMENT.finditer(text, lo, pos))):
        if not re.search(rf"</{re.escape(tag.group(1))}\s*>", text[tag.end():pos], re.IGNORECASE):
            return True
    return _behind_padding(text, lo, pos)


def _behind_padding(text: str, lo: int, pos: int) -> bool:
    lines = text[lo:pos].split("\n")
    if _PAD_BLANKS.search(lines[-1]):
        return True
    blank = 0
    for line in lines[:-1]:
        blank = 0 if line.strip() else blank + 1
        if blank >= _PAD_BLANK_LINES:
            return True
    return False


def _instruction_text(text: str, m: re.Match[str]) -> str:
    """The instruction that carries the match: its own sentence (or list item), and for a match
    in a fenced code block also the lead-in that introduces the block ("silently run the check
    below:"). Words elsewhere in the file, or in the paragraph before a heading, are not part of
    it: "never ask the user for their API key" above an install section conceals nothing."""
    start, end = _sentence_bounds(text, m.start(), m.end())
    own = text[start:end]
    if text.count("```", 0, m.start()) % 2 == 0:
        return own
    fence = text.rfind("```", 0, m.start())
    lead_end = text.rfind("\n", 0, fence)
    if lead_end < 0:
        return own
    # The lead-in is the last non-blank line before the fence (one blank line may separate them),
    # unless that line is a heading.
    while lead_end > 0 and text[lead_end - 1] in "\r\n \t":
        lead_end -= 1
    lead_start = text.rfind("\n", 0, lead_end) + 1
    lead = text[lead_start:lead_end]
    if lead.lstrip().startswith("#") or text.count("\n", lead_end, fence) > 2:
        return own
    lead_from, _ = _sentence_bounds(text, lead_end, lead_end)
    return text[max(lead_start, lead_from):lead_end] + "\n" + own


# A blank line between paragraphs. A file with Windows line ends has `\r\n\r\n` there, and a line
# of only blanks is blank too: read as one paragraph, the whole file was the command's statement and
# any "silently" in it made the command hidden.
_PARAGRAPH_BREAK = re.compile(r"\n[ \t\r]*\n")


def _sentence_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    """The statement (sentence, list item) around ``[start, end)``, within its paragraph."""
    para_start = _paragraph_start(text, start)
    nxt = _PARAGRAPH_BREAK.search(text, end)
    para_end = len(text) if nxt is None else nxt.start()
    begin = para_start
    for stop in _SENTENCE_END.finditer(text, para_start, start):
        begin = stop.end()
    after = _SENTENCE_END.search(text, end, para_end)
    return begin, after.start() + 1 if after else para_end


def _paragraph_start(text: str, pos: int) -> int:
    """Where the paragraph holding ``pos`` starts: after the nearest blank line above it."""
    i = text.rfind("\n", 0, pos)
    while i >= 0:
        prev = text.rfind("\n", 0, i)
        if not text[prev + 1 : i].strip():
            return i + 1
        i = prev
    return 0


def _frontmatter(text: str) -> str:
    if not text.startswith("---"):
        return ""
    end = text.find("\n---", 3)
    return text[:end] if end >= 0 else ""
