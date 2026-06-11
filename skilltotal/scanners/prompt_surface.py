"""Prompt-injection / instruction-override surface detection.

Strong, unambiguous manipulation phrases become evidence-backed findings. Weak or
ambiguous phrases (e.g. "before answering") are routed to ``needs_review`` so they never
inflate the risk score without a human confirming intent.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_PER_FINDING,
    RuleSpec,
    Scanner,
    ScanResult,
    alternation,
    findings_from_rules,
)

CATEGORY = "prompt_surface"

_STRONG = alternation(
    # Instruction-override imperatives (unambiguous).
    r"ignore\s+(?:all\s+)?(?:the\s+)?previous\s+(?:instructions|prompts|context)",
    r"ignore\s+(?:everything\s+)?above",
    r"disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|above|prior)\s+(?:instructions|prompts)",
    r"(?:reveal|print|show|repeat|expose)\s+(?:your\s+|the\s+)?(?:system|developer)\s+prompt",
    r"override\s+(?:developer|system|previous|prior)\s+(?:instructions|prompt)",
    r"do(?:\s*not|n['’]?t)\s+tell\s+the\s+user",
    r"hidden\s+instruction",
    # Data-theft DIRECTIVES — require an action verb + sensitive target and/or a
    # destination, so security prose ("can't exfiltrate ...", "read credentials from env")
    # does not match. Bare nouns like "exfiltrate" alone are intentionally NOT strong.
    r"exfiltrate\s+[^\n]{0,40}\b(?:to|via|through|into)\b",
    # Unambiguous theft verbs only (NOT "collect", which appears in benign prose).
    r"(?:steal|harvest|grab)\s+(?:the\s+)?(?:user['’]?s?\s+)?"
    r"(?:credentials|secrets|api[\s_-]?keys?|tokens?|private\s+keys?|passwords?)",
    r"send\s+(?:the\s+)?(?:credentials|secrets|api[\s_-]?keys?|tokens?|passwords?|"
    r"env(?:ironment)?\s*(?:variables?|vars?)?|conversation\s+history|system\s+prompt)\s+to\b",
    r"send\s+(?:it|this|them|the\s+data)?\s*to\s+[^\n]{0,40}webhook",
    r"send\s+to\s+webhook",
    flags=re.IGNORECASE | re.MULTILINE,
)

_WEAK = re.compile(
    r"before\s+(?:answering|you\s+answer)",
    re.IGNORECASE | re.MULTILINE,
)

# Markdown image/link exfiltration: an image or link whose URL embeds a template
# placeholder ({{...}} / ${...} / {x}), the channel used to smuggle data out by having
# the agent fill the URL with file contents/secrets (cf. the Invariant Labs GitHub-MCP
# attack). FP guard: a literal badge/shields URL has no '{' or '$' placeholder, so it
# won't match — the placeholder is what makes this an exfiltration template.
_EXFIL_MD = alternation(
    r"!\[[^\]]*\]\(\s*https?://[^)\s]*[{$]",          # ![alt](http://host/?x={{data}})
    r"\[[^\]]*\]\(\s*https?://[^)\s]*[{$][^)\s]*\)",  # [text](http://host/?x=${data})
    flags=re.IGNORECASE,
)


class PromptSurfaceScanner(Scanner):
    name = "prompt_surface"
    rules = [
        RuleSpec(
            id="ST-PROMPT-INJECTION",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            title="Prompt injection / instruction override",
            description=(
                "Phrases associated with prompt injection or instruction override were "
                "detected (e.g. 'ignore previous instructions', 'reveal system prompt', "
                "'do not tell the user', 'exfiltrate')."
            ),
            recommendation=(
                "Treat embedded instructions as untrusted. Review whether this component "
                "attempts to manipulate an agent's behavior or hide actions from users."
            ),
            capability=Capability.PROMPT_SURFACE_RISK,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            pattern=_STRONG,
        ),
        RuleSpec(
            id="ST-PROMPT-EXFIL-MD",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Markdown image/link with a templated exfiltration URL",
            description=(
                "A markdown image or link embeds a template placeholder in its URL "
                "(e.g. ![x](https://host/?d={{file_contents}})). This is a known "
                "data-exfiltration channel: an agent rendering the markdown is steered to "
                "fill the URL with file contents or secrets, sending them off-host."
            ),
            recommendation=(
                "Treat embedded markdown as untrusted. A URL that interpolates agent data "
                "into an image/link is an exfiltration sink — remove it and review intent."
            ),
            capability=Capability.PROMPT_SURFACE_RISK,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            pattern=_EXFIL_MD,
        ),
        # Listed for `rules list`; routed to needs_review, never a confirmed finding.
        RuleSpec(
            id="ST-PROMPT-WEAK",
            category=CATEGORY,
            severity=Severity.LOW,
            title="Ambiguous prompt-control phrasing",
            description="Ambiguous phrasing that may indicate prompt control.",
            recommendation="Manually review the surrounding text for manipulation intent.",
            capability=None,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        pattern_rules = [r for r in self.rules if r.pattern is not None]
        findings = findings_from_rules(index, pattern_rules)

        needs_review: list[NeedsReview] = []
        seen: set[tuple[str, int]] = set()
        for _f, m, ev in index.search(_WEAK):
            key = (ev.file, ev.line_start)
            if key in seen:
                continue
            seen.add(key)
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title="Ambiguous prompt-control phrasing",
                    reason=(
                        f"Phrase '{m.group(0)}' at line {ev.line_start} may indicate "
                        "prompt control but is too ambiguous to confirm as a finding."
                    ),
                    file=ev.file,
                    line=ev.line_start,
                )
            )
            if len(needs_review) >= MAX_EVIDENCE_PER_FINDING:
                break
        return ScanResult(findings=findings, needs_review=needs_review)
