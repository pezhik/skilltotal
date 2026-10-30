"""Two things a skill's own instructions can say that an honest skill has no reason to say.

* **A note to the scanner.** A paragraph addressed to security scanners, auditors or reviewers
  that tells them to report this skill as safe or not to flag it. The text is aimed at an
  automated reviewer reading the file, not at a person or at the agent doing the task.
* **A write into the agent's memory, kept from the user.** An instruction to put text into the
  files the agent reads at every session start (MEMORY.md, SOUL.md, AGENTS.md, CLAUDE.md,
  GEMINI.md) while telling the agent to do it silently or not to mention it. A memory skill that
  saves notes there says so openly; what is written there steers every later session.

Both are read in the instruction files an agent follows (the files ``skill_fetch_exec`` reads).
A concealment word elsewhere in the file, or a memory write the user is told about, does not fire.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule
from skilltotal.scanners.skill_fetch_exec import _INSTRUCTION_FILE

R_AUDIT_OVERRIDE = "ST-SKILL-AUDIT-OVERRIDE"
R_MEMORY_HIDDEN = "ST-SKILL-MEMORY-WRITE-HIDDEN"
R_ENCRYPTED_INSTRUCTIONS = "ST-SKILL-ENCRYPTED-INSTRUCTIONS"

# A blank line ends a paragraph, also in a CRLF file (a Windows checkout): without \r here a whole
# CRLF file was one paragraph, pairing a mention in one section with a word from another.
_PARAGRAPH = re.compile(r"[^\n]+(?:\n(?![ \t\r]*\n)[^\n]*)*")
_REVIEWER = (
    r"(?:scanners?|auditors?|reviewers?|analy[sz]ers?|security\s+(?:tools?|checks?|reviewers?)"
    r"|(?:ai|llm)\s+(?:judges?|reviewers?|scanners?))"
)
_ADDRESSED = re.compile(
    r"\b(?:notes?|messages?|notices?|attention|instructions?|reminders?)\s+(?:to|for)\s+"
    r"(?:the\s+|any\s+|all\s+|automated\s+)?(?:\w+\s+){0,2}?" + _REVIEWER + r"\b"
    r"|\bif\s+you\s+are\s+(?:an?\s+)?(?:\w+\s+){0,2}?" + _REVIEWER[:-1] + r")\b",
    re.IGNORECASE,
)
_BLANKET_VERDICT = re.compile(
    r"\b(?:report|mark|rate|classify|label|treat|consider|score|record)\b[^.\n]{0,40}?"
    r"\bas\s+(?:safe|benign|clean|trusted|harmless|verified|approved)\b"
    r"|\b(?:do\s+not|don['’]?t|must\s+not|should\s+not)\s+(?:flag|report)\s+"
    r"(?:any(?:thing|\s+\w+)?|this)\b"
    r"|\breport\s+no\s+(?:findings|issues)\b",
    re.IGNORECASE,
)
_THIS_COMPONENT = re.compile(
    r"\bthis\s+(?:skill|package|component|plugin|repo(?:sitory)?|server|code)\b", re.IGNORECASE
)

_MEMORY_FILE = r"(?<![\w.-])(?:MEMORY|SOUL|AGENTS|CLAUDE|GEMINI)\.md(?![\w.-])"
_WRITE_VERB = r"\b(?:append|add|write|save|store|insert|put|persist|inject|plant)\w*\b"
# The file is where the text goes ("append ... to MEMORY.md", "open CLAUDE.md and add"), not a
# file the instructions point the reader at ("see AGENTS.md "Pacing GitHub writes"", "a write loop
# paced by AGENTS.md").
_QUOTE = r"[`'\"*]*"
_MEMORY_WRITE = re.compile(
    _WRITE_VERB + r"[^\n]{0,200}?\b(?:to|into|inside|in)\s+"
    r"(?:(?:the|your|its|each|every|global|local|project(?:['’]s)?|user(?:['’]s)?)\s+)*"
    + _QUOTE + _MEMORY_FILE
    + r"|" + _MEMORY_FILE + _QUOTE + r"(?:\s+file)?\s*(?:,|:|\band\b|\bthen\b)\s*(?:then\s+)?"
    + _WRITE_VERB,
    re.IGNORECASE,
)
_HIDE_FROM_USER = re.compile(
    r"\b(?:silently|secretly|quietly|covertly)\b"
    r"|\bwithout\s+(?:asking|telling|informing|notifying|alerting)\b"
    r"|\b(?:never|do\s+not|don['’]?t)\s+(?:mention|tell|show|reveal|disclose)\s+"
    r"(?:this|it|that|these|the\s+(?:change|edit|update|entry|line|instruction)s?)\b",
    re.IGNORECASE,
)
# Instructions kept encrypted so that no reader of the file sees them: the passage tells the agent
# to decrypt a block with a key taken from an env file or an environment variable and then to
# follow the decrypted text. Decrypting a secrets file for a deploy does not tell the agent to
# obey the plaintext.
_DECRYPT = re.compile(r"\bdecrypt\w*", re.IGNORECASE)
_ENV_KEY_SOURCE = re.compile(
    r"(?<![\w.-])\.env(?:\.[\w-]{1,20})?(?![\w-])"
    r"|\benviron(?:ment)?\s+(?:variable|file)s?\b|\bos\.environ\b|\bprocess\.env\b",
    re.IGNORECASE,
)
_OBEY_PLAINTEXT = re.compile(
    r"\b(?:follow|obey|execute|carry\s+out|perform)\b[^\n.]{0,60}?"
    r"\b(?:decrypted|plaintext|deciphered)\b"
    r"|\b(?:decrypted|deciphered)\s+(?:instructions?|commands?|directives?|steps)\b"
    r"[^\n.]{0,40}?\b(?:exactly|verbatim|immediately|as\s+written)\b",
    re.IGNORECASE,
)


class SkillDirectivesScanner(Scanner):
    name = "skill_directives"
    rules = [
        RuleSpec(
            id=R_AUDIT_OVERRIDE,
            category="agent_instructions",
            severity=Severity.HIGH,
            title="Instruction file addresses security scanners and asks for a safe verdict",
            description=(
                "A paragraph in an instruction file is addressed to scanners, auditors or "
                "reviewers and tells them to report this component as safe or not to flag it. "
                "That text is meant for an automated reviewer, not for a person or for the agent "
                "doing the task; an honest skill has no reason to carry it."
            ),
            recommendation=(
                "Do not rely on the claim. Review the skill's instructions and scripts yourself."
            ),
            capability=Capability.PROMPT_SURFACE_RISK,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_MEMORY_HIDDEN,
            category="agent_instructions",
            severity=Severity.HIGH,
            title="Instruction file writes into the agent's memory and hides it from the user",
            description=(
                "An instruction file tells the agent to write text into a memory or instruction "
                "file it reads at every session start (MEMORY.md, SOUL.md, AGENTS.md, CLAUDE.md, "
                "GEMINI.md) and, in the same passage, to do it silently or not to mention it. "
                "What is written there steers later sessions, out of the user's sight."
            ),
            recommendation=(
                "Do not install this skill. If an agent already followed it, inspect and clean "
                "those files."
            ),
            capability=Capability.PROMPT_SURFACE_RISK,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_ENCRYPTED_INSTRUCTIONS,
            category="agent_instructions",
            severity=Severity.HIGH,
            title="Instruction file has the agent decrypt hidden instructions with an env key",
            description=(
                "A passage in an instruction file tells the agent to decrypt a block with a key "
                "read from an env file or an environment variable and then to follow the "
                "decrypted text. The instructions are not visible to a person or a scanner "
                "reading the file; what they say is only known once the agent runs them."
            ),
            recommendation=(
                "Do not install this skill. A skill's instructions should be readable as "
                "shipped; never let an agent follow text that is decrypted at run time."
            ),
            capability=Capability.PROMPT_SURFACE_RISK,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        override: list[Evidence] = []
        memory: list[Evidence] = []
        encrypted: list[Evidence] = []
        for f in index.files:
            if not _INSTRUCTION_FILE.search(f.relpath):
                continue
            for para in _PARAGRAPH.finditer(f.text):
                text = para.group(0)
                base = para.start()
                addressed = _ADDRESSED.search(text)
                if addressed:
                    verdict = _BLANKET_VERDICT.search(text, addressed.start())
                    if verdict and _THIS_COMPONENT.search(text):
                        override.append(f.evidence_for_span(base + addressed.start(),
                                                            base + verdict.end()))
                write = _MEMORY_WRITE.search(text)
                if write:
                    hide = _HIDE_FROM_USER.search(text)
                    if hide:
                        memory.append(f.evidence_for_span(base + write.start(),
                                                          base + max(write.end(), hide.end())))
                decrypt = _DECRYPT.search(text)
                if decrypt and _ENV_KEY_SOURCE.search(text):
                    obey = _OBEY_PLAINTEXT.search(text)
                    if obey:
                        encrypted.append(f.evidence_for_span(
                            base + min(decrypt.start(), obey.start()),
                            base + max(decrypt.end(), obey.end())))
        findings = [_finding_from_rule(rule, ev)
                    for rule, ev in zip(self.rules, (override, memory, encrypted), strict=True)
                    if ev]
        return ScanResult(findings=findings)
