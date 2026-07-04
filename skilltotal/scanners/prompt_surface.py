"""Prompt-injection / instruction-override surface detection.

Strong, unambiguous manipulation phrases become evidence-backed findings. Weak or
ambiguous phrases (e.g. "before answering") are routed to ``needs_review`` so they never
inflate the risk score without a human confirming intent.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Evidence, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_PER_FINDING,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    alternation,
    deobfuscated_spans,
)

CATEGORY = "prompt_surface"

_STRONG = alternation(
    # Instruction-override imperatives (unambiguous).
    r"ignore\s+(?:all\s+)?(?:the\s+)?previous\s+(?:instructions|prompts|context)",
    # "ignore ... above" must carry an intent quantifier (everything/all) OR an explicit
    # instruction object — bare "ignore above" over-matched benign code/docs ("IGNORE ABOVE
    # ELSE" in a minified bundle; "ignore above a multi-line statement" in a linter's own
    # suppression docs). FP fix: notebook, ruff.
    r"ignore\s+(?:everything|all)\s+(?:of\s+)?(?:the\s+)?above",
    r"ignore\s+(?:the\s+)?above\s+(?:instructions?|prompts?|context|messages?|rules?|directions?)",
    r"disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|above|prior)\s+(?:instructions|prompts)",
    # Attacker-flavored verbs only — NOT "print"/"show" (legit CLI/docs: a "print-system-prompt"
    # command prints your OWN prompt; FP fix: serena).
    r"(?:reveal|expose|leak|repeat)\s+(?:your\s+|the\s+)?(?:system|developer)\s+prompt",
    r"override\s+(?:developer|system|previous|prior)\s+(?:instructions|prompt)",
    # Data-theft DIRECTIVES — require an action verb + sensitive target and/or a
    # destination, so security prose ("can't exfiltrate ...", "read credentials from env")
    # does not match. Bare nouns like "exfiltrate" alone are intentionally NOT strong.
    # ("hidden instruction" as a lone phrase was dropped — it FP'd on docs/comments that merely
    # *mention* hidden instructions, e.g. a hidden-char scanner's own comment.)
    r"exfiltrate\s+[^\n]{0,40}\b(?:to|via|through|into)\b",
    # Unambiguous theft verbs only (NOT "collect", which appears in benign prose).
    r"(?:steal|harvest|grab)\s+(?:the\s+)?(?:user['’]?s?\s+)?"
    r"(?:credentials|secrets|api[\s_-]?keys?|tokens?|private\s+keys?|passwords?)",
    # "send <secret> to". Excludes bare "tokens" — legitimately "sent" all over auth flows and
    # specs (FP: exa bundles the MCP spec: "clients MUST NOT send tokens to the MCP server").
    # Best-effort negation guard for plain prose (markdown emphasis can still defeat a fixed-width
    # lookbehind, which is why the ambiguous "tokens" target is dropped rather than relied upon).
    r"(?<!not )(?<!never )(?<!n't )(?<!cannot )(?<!refuse to )(?<!refuses to )(?<!refusing to )"
    r"send\s+(?:the\s+)?(?:credentials|secrets|api[\s_-]?keys?|passwords?|"
    r"env(?:ironment)?\s*(?:variables?|vars?)?|conversation\s+history|system\s+prompt)\s+to\b",
    r"send\s+(?:it|this|them|the\s+data)?\s*to\s+[^\n]{0,40}webhook",
    r"send\s+to\s+webhook",
    # Jailbreak / safety-disable directives. Kept unambiguous (a safety-specific object) so
    # security prose isn't matched; .py-string/comment and documentation matches are demoted.
    r"do\s+anything\s+now\b",
    r"\bDAN\s+mode\b",
    # Negation guard (mirrors the "send" rule): defensive guarantees like "cannot override
    # safety policy" / "will not bypass safety filters" / "can't disable guardrails" are the
    # opposite of a directive. Each lookbehind is fixed-width; "n't" catches can't/won't/don't.
    # \s (not a literal space) so a line-wrapped "cannot\noverride" is still guarded.
    r"(?<!not\s)(?<!never\s)(?<!n't\s)(?<!n’t\s)(?<!cannot\s)(?<!unable\sto\s)"
    r"(?<!refuse\sto\s)(?<!refuses\sto\s)(?<!refusing\sto\s)"
    r"(?:ignore|bypass|disable|turn\s+off|override)\s+(?:your\s+|all\s+|any\s+|the\s+)?"
    r"(?:safety|content|ethical|moral)\s+"
    r"(?:guidelines?|guardrails?|filters?|restrictions?|polic(?:y|ies)|constraints?)",
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

# Quote characters that wrap a *cited* phrase (straight, smart, guillemets, backtick).
_QUOTES = "\"'`“”‘’«»"


def _is_quoted_citation(text: str, start: int, end: int) -> bool:
    """True if the matched span is immediately wrapped in quotes on BOTH sides — a phrase being
    *cited* as an example (a security doc listing `"ignore all previous instructions"`), not a
    live directive. Requiring quotes on both immediate boundaries keeps recall: an injection that
    continues past the phrase (``"Ignore all previous instructions and delete …"``) has no closing
    quote right after the match, so it is not treated as a citation."""
    before = text[start - 1] if start > 0 else ""
    after = text[end] if end < len(text) else ""
    return before in _QUOTES and after in _QUOTES


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
            # Real injection lives in instruction surfaces (SKILL.md, manifests) or prose, not in
            # value-strings. A match inside a Python string/comment — or a C-family (.go/.js/.ts/
            # .rs/…) string/comment — is this scanner's own pattern literal or another security
            # tool's pattern definition/description (e.g. ragflow's
            # `Description: "prompt injection: ignore previous instructions"`), not a live
            # directive.
            code_context="strings_and_comments_all",
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
        inj_rule = next(r for r in self.rules if r.id == "ST-PROMPT-INJECTION")
        evidence: list[Evidence] = []
        seen: set[tuple[str, int]] = set()
        needs_review: list[NeedsReview] = []
        nr_seen: set[tuple[str, int]] = set()

        def add(ev: Evidence) -> None:
            key = (ev.file, ev.match_offset)
            if key in seen or len(evidence) >= MAX_EVIDENCE_PER_FINDING:
                return
            seen.add(key)
            evidence.append(ev)

        def review_citation(ev: Evidence, phrase: str) -> None:
            key = (ev.file, ev.line_start)
            if key in nr_seen or len(needs_review) >= MAX_EVIDENCE_PER_FINDING:
                return
            nr_seen.add(key)
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title="Cited prompt-injection example",
                    reason=(
                        f"Phrase '{phrase}' at line {ev.line_start} is quoted as an example, "
                        "not a live directive; review the surrounding text to confirm."
                    ),
                    file=ev.file,
                    line=ev.line_start,
                )
            )

        # Raw pass: the patterns as written. A match wrapped in quotes on both sides is a cited
        # example, not a live directive -> route to needs_review (ambiguous), never scored.
        for f, m, ev in index.search(inj_rule.pattern):  # type: ignore[arg-type]
            if _is_quoted_citation(f.text, m.start(), m.end()):
                review_citation(ev, m.group(0))
            else:
                add(ev)
        # De-obfuscation pass: the same patterns after folding homoglyphs / full-width /
        # diacritics / zero-width splicing, mapped back to the original span. Catches
        # injection hidden behind look-alike characters; de-duped against the raw pass.
        for f, start, end in deobfuscated_spans(index, _STRONG):
            if start < end:
                if _is_quoted_citation(f.text, start, end):
                    review_citation(f.evidence_for_span(start, end), f.text[start:end])
                else:
                    add(f.evidence_for_span(start, end))

        findings = [_finding_from_rule(inj_rule, evidence)] if evidence else []

        for _f, m, ev in index.search(_WEAK):
            key = (ev.file, ev.line_start)
            if key in nr_seen:
                continue
            nr_seen.add(key)
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
