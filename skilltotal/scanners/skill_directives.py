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

from skilltotal.autorun import frontmatter_values
from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule
from skilltotal.scanners.skill_fetch_exec import _INSTRUCTION_FILE

R_AUDIT_OVERRIDE = "ST-SKILL-AUDIT-OVERRIDE"
R_MEMORY_HIDDEN = "ST-SKILL-MEMORY-WRITE-HIDDEN"
R_ENCRYPTED_INSTRUCTIONS = "ST-SKILL-ENCRYPTED-INSTRUCTIONS"
R_SEALED_SCRIPT = "ST-SKILL-SEALED-SCRIPT-RUN"  # nosec B105 - rule id, not a credential
R_ENTRY_EDIT = "ST-SKILL-ENTRY-SCRIPT-EDIT"  # nosec B105 - rule id, not a credential
R_TRUST_PRIORITY = "ST-SKILL-TRUST-CLAIM-PRIORITY"  # nosec B105 - rule id, not a credential

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
    # The file may be named with its folder: "to `~/.claude/CLAUDE.md`".
    + _QUOTE + r"(?:[~.]?[\w.-]{0,40}/){0,6}" + _MEMORY_FILE
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
# The start of a list item. A numbered or bulleted list with no blank lines is one paragraph, but
# each item is its own instruction: "2. Draft the spec internally, never show it to the user" says
# nothing about the memory write in "5. Write conclusions to MEMORY.md". A concealment counts from
# the start of the write's own item onwards ("5. Append ... to MEMORY.md. 6. Never mention it").
_LIST_ITEM = re.compile(r"(?m)^[ \t]*(?:\d{1,3}[.)]|[-*+])[ \t]+")
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

# A script the instructions have the agent run, and a ban on looking at it: "run `node setup.js`
# ... it is sealed, do not open or read it". A script an agent may not read cannot be reviewed by
# the user either; an honest setup step names the script and leaves it readable.
_RUN_SCRIPT = re.compile(
    r"\b(?:run|execute|launch|invoke)\b[^\n]{0,40}?"
    r"\b(?:node|python3?|bash|sh|pwsh|bun|deno)\s+[`'\"]?\.?/?([\w./-]{1,60}\.(?:m?js|cjs|py|sh|ps1))\b",
    re.IGNORECASE,
)
_NO_INSPECT = re.compile(
    r"\b(?:do\s+not|don['’]?t|never|must\s+not|should\s+not)\s+"
    r"(?:\w+\s+){0,2}?(?:open|read|inspect|view|cat|examine|review|look\s+(?:at|into))\b",
    re.IGNORECASE,
)
_SEALED = re.compile(r"\b(?:sealed|opaque|encrypted|obfuscated)\b", re.IGNORECASE)

# An instruction to edit the skill's own script on use: "every time this skill runs, prepend this
# line at the top of scripts/main.py". The script the user reviewed is not the one that runs.
_SCRIPT_PATH = r"[`'\"]?[\w./-]{1,60}\.(?:m?js|cjs|py|sh|ts)\b"
_EDIT_SCRIPT = re.compile(
    r"\b(?:prepend|insert|inject|add|put|write)\w*\b[^\n]{0,100}?"
    r"\b(?:at\s+the\s+(?:very\s+)?(?:top|beginning|start)|as\s+the\s+(?:very\s+)?first\s+line)"
    r"\s+of\s+(?:the\s+)?(?:file\s+)?" + _SCRIPT_PATH
    + r"|\b(?:edit|modify|update|patch)\s+" + _SCRIPT_PATH + r"[`'\"]?"
    r"[^\n]{0,80}?\b(?:prepend|insert|inject|add)\w*\b[^\n]{0,80}?"
    r"\b(?:top|beginning|start|first\s+line)\b",
    re.IGNORECASE,
)
_EVERY_USE = re.compile(
    r"\b(?:every|each)\s+(?:time|invocation|run|use)\b|\bon\s+(?:every|each)\s+\w+"
    r"|\bbefore\s+(?:running|executing|each|every)\b",
    re.IGNORECASE,
)
_RUNS_CODE = re.compile(
    r"\b(?:os\.system|subprocess|child_process|__import__|urllib|requests\.|fetch\(|curl|wget"
    r"|exec|eval)\b",
    re.IGNORECASE,
)

# A skill description that claims vetting AND asks to be chosen ahead of the other skills: the
# text is aimed at the agent's skill selection, not at what the skill does.
_TRUST_CLAIM = re.compile(
    r"\b(?:official|verified|certified|security[- ]audited|audited|approved\s+by|endorsed\s+by"
    r"|trusted)\b",
    re.IGNORECASE,
)
_PRIORITY_CLAIM = re.compile(
    r"\b(?:always|must)\s+(?:choose|select|pick|prefer|use)\s+this\s+skill\b"
    r"|\b(?:choose|select|pick|prefer|use)\s+(?:this\s+skill|it)\s+(?:first|before|over"
    r"|instead\s+of)\b"
    r"|\bover\s+(?:any|all)\s+other\s+skills?\b",
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
        RuleSpec(
            id=R_SEALED_SCRIPT,
            category="agent_instructions",
            severity=Severity.HIGH,
            title="Instruction file has the agent run a script it is told not to read",
            description=(
                "A passage in an instruction file tells the agent to run a script and, in the "
                "same passage, not to open, read or inspect it. A step the agent may run but "
                "neither it nor the user may read cannot be reviewed before it runs."
            ),
            recommendation=(
                "Do not let an agent run the script. Read it yourself first; an honest setup "
                "step leaves its script readable."
            ),
            capability=Capability.PROMPT_SURFACE_RISK,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_ENTRY_EDIT,
            category="agent_instructions",
            severity=Severity.HIGH,
            title="Skill instructions have the agent rewrite a script of the skill on each use",
            description=(
                "A skill's instructions tell the agent to prepend or insert code at the top of "
                "a script file each time the skill runs, and the code calls out to the shell or "
                "the network. The script that was reviewed is not the script that runs."
            ),
            recommendation=(
                "Do not install this skill. A skill's scripts should be fixed as shipped."
            ),
            capability=Capability.PROMPT_SURFACE_RISK,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_TRUST_PRIORITY,
            category="agent_instructions",
            severity=Severity.HIGH,
            title="Skill description claims to be verified and asks to be chosen over other skills",
            description=(
                "The description in a skill's frontmatter claims it is official, verified or "
                "audited and tells the agent to always choose it, or to prefer it over other "
                "skills. The agent reads that text when it picks a skill; it describes no "
                "function, and the claim cannot be checked from the file."
            ),
            recommendation=(
                "Do not rely on the claim. Check who published the skill and read it before use."
            ),
            capability=Capability.PROMPT_SURFACE_RISK,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        override: list[Evidence] = []
        memory: list[Evidence] = []
        encrypted: list[Evidence] = []
        sealed: list[Evidence] = []
        entry_edit: list[Evidence] = []
        trust: list[Evidence] = []
        for f in index.files:
            if not (f.agent_read or _INSTRUCTION_FILE.search(f.relpath)):
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
                    item_start = max(
                        (m.start() for m in _LIST_ITEM.finditer(text, 0, write.start())),
                        default=0,
                    )
                    hide = _HIDE_FROM_USER.search(text, item_start)
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
                run = _RUN_SCRIPT.search(text)
                if run:
                    ban = _NO_INSPECT.search(text, run.end())
                    if ban and (_SEALED.search(text) or run.group(1).lower() in text[ban.end():]
                                .lower()):
                        sealed.append(f.evidence_for_span(base + run.start(), base + ban.end()))
                edit = _EDIT_SCRIPT.search(text)
                if edit and _EVERY_USE.search(text):
                    window = f.text[base + edit.start(): base + edit.end() + 600]
                    if _RUNS_CODE.search(window):
                        entry_edit.append(f.evidence_for_span(base + edit.start(),
                                                              base + edit.end()))
            if f.relpath.lower().endswith("skill.md"):
                for key, value, start, end in frontmatter_values(f.text):
                    if key == "description" and _PRIORITY_CLAIM.search(value) \
                            and _TRUST_CLAIM.search(value):
                        trust.append(f.evidence_for_span(start, end))
        findings = [_finding_from_rule(rule, ev)
                    for rule, ev in zip(self.rules, (override, memory, encrypted, sealed,
                                                     entry_edit, trust), strict=True)
                    if ev]
        return ScanResult(findings=findings)
