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

# Ambiguous concealment phrasing -> needs_review (never scored). "do not tell the user"
# is a genuine malicious-concealment marker, but it also appears in benign UX guardrails
# (e.g. GitHub's official MCP server: "Do NOT tell the user the issue was updated. The user
# MUST click Submit ...") — too ambiguous to drive a malware verdict on its own. Real
# concealment co-occurs with stronger signals (exfil verbs, fake authority) that stay strong.
_WEAK = alternation(
    r"before\s+(?:answering|you\s+answer)",
    r"do(?:\s*not|n['’]?t)\s+tell\s+the\s+user",
    r"without\s+(?:telling|informing|notifying)\s+the\s+user",
    flags=re.IGNORECASE | re.MULTILINE,
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
