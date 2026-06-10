"""Prompt-injection / instruction-override surface detection.

Strong, unambiguous manipulation phrases become evidence-backed findings. Weak or
ambiguous phrases (e.g. "before answering") are routed to ``needs_review`` so they never
inflate the risk score without a human confirming intent.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, NeedsReview, Severity
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
    r"ignore\s+(?:all\s+)?(?:the\s+)?previous\s+(?:instructions|prompts|context)",
    r"ignore\s+(?:everything\s+)?above",
    r"disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|above|prior)\s+(?:instructions|prompts)",
    r"(?:reveal|print|show|repeat|expose)\s+(?:your\s+|the\s+)?(?:system|developer)\s+prompt",
    r"override\s+(?:developer|system|previous|prior)\s+(?:instructions|prompt)",
    r"do(?:\s*not|n['’]?t)\s+tell\s+the\s+user",
    r"hidden\s+instruction",
    r"\bexfiltrate\b",
    r"send\s+(?:it|this|them|the\s+data)?\s*to\s+[^\n]{0,40}webhook",
    r"send\s+to\s+webhook",
    r"collect\s+(?:the\s+)?tokens",
    r"read\s+credentials",
    flags=re.IGNORECASE | re.MULTILINE,
)

_WEAK = re.compile(
    r"before\s+(?:answering|you\s+answer)",
    re.IGNORECASE | re.MULTILINE,
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
        strong_rule = self.rules[0]
        findings = findings_from_rules(index, [strong_rule])

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
