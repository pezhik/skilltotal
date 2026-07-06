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

# Negation guards: "not send…", "cannot override…" are defensive prose, not directives.
_NEG_PROSE = ("not ", "never ", "n't ", "cannot ", "refuse to ", "refuses to ", "refusing to ")
_NEG_WS = (
    r"not\s", r"never\s", r"n't\s", r"n’t\s", r"cannot\s", r"unable\sto\s",
    r"refuse\sto\s", r"refuses\sto\s", r"refusing\sto\s",
)


def _neg_guarded(verb: str, negations: tuple[str, ...]) -> str:
    """``verb`` with its fixed-width negation lookbehinds anchored right AFTER the verb.

    Semantically identical to the ``(?<!not )verb`` form (the guarded window is the same
    characters), but an order of magnitude faster: with the lookbehinds FIRST the regex engine
    evaluates every guard at every text position; with the verb literal first it fast-skips to
    actual verb occurrences and only guards those (measured 7x on a 23 MB repo, gemini-cli).
    ``verb`` must be a fixed-width literal (a single word) so each lookbehind stays fixed-width.
    """
    guards = "".join(f"(?<!{neg}{verb})" for neg in negations)
    return f"{verb}{guards}"


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
    _neg_guarded("send", _NEG_PROSE)
    + r"\s+(?:the\s+)?(?:credentials|secrets|api[\s_-]?keys?|passwords?|"
    r"env(?:ironment)?\s*(?:variables?|vars?)?|conversation\s+history|system\s+prompt)\s+to\b",
    # Exfiltration to a webhook. Like the "send <secret> to" rule above, require a SENSITIVE
    # data object between the send verb and "webhook" — the webhook destination adds the
    # specificity that lets us also accept "tokens"/"the data"/"user's data" here. Without
    # this gate, benign field descriptions matched: "Headers to send to the webhook URL" (a
    # real OpenAPI field in firecrawl), "send the payload to your webhook endpoint". FP fix.
    "(?:"
    + "|".join(
        _neg_guarded(v, _NEG_PROSE)
        for v in ("send", "post", "upload", "transmit", "forward", "exfiltrate", "leak")
    )
    + r")\s+"
    r"(?:it|this|them|the|your)?\s*(?:user['’]?s?\s+)?"
    r"(?:credentials|secrets|api[\s_-]?keys?|tokens?|passwords?|"
    r"env(?:ironment)?\s*(?:variables?|vars?)?|conversation\s+history|"
    r"system\s+prompt|data\b)"
    r"[^\n]{0,40}?webhook",
    # Self-replicating prompt (Morris-II / GenAI worm, arXiv:2403.02817): a directive to
    # reproduce the injected instructions in the model's OWN output or pass them to downstream
    # agents/messages, so the payload propagates. Requires a propagation verb + an
    # instructions/prompt object + an output-or-downstream target — NOT generic "copy this text",
    # and NOT "...to the user" (a benign UX instruction), so ordinary docs don't match.
    r"(?:copy|include|repeat|append|embed|insert|propagate|forward|reproduce)\s+"
    r"(?:these|this|the\s+following|the\s+same|the\s+above|my)\s+"
    r"(?:instructions?|prompts?|directives?)\s+"
    r"(?:in(?:to)?|to)\s+"
    r"(?:your\s+(?:next\s+|every\s+|each\s+)?(?:response|reply|answer|output|message)|"
    r"(?:every|each|all|any|the\s+next)\s+"
    r"(?:response|message|email|reply|agent|assistant|model|recipient))",
    # Markdown/HTML image exfiltration (embrace-the-red): an image whose EXTERNAL URL carries a
    # template placeholder in its query string — the agent renders it and thereby leaks whatever
    # it interpolates (conversation, secrets) to the attacker's host. Requires a real
    # interpolation tell ({{…}} / ${…} / %s / <var>) in the query, so ordinary images with static
    # query params (?v=2, ?width=200) do NOT match; a match inside code strings is demoted.
    r"!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*"
    r"(?:\{\{[^}]+\}\}|\$\{[^}]+\}|%s|<[a-zA-Z_][\w]*>)",
    r"<img\b[^>]*\bsrc\s*=\s*['\"]https?://[^'\"]+\?[^'\"]*"
    r"(?:\{\{[^}]+\}\}|\$\{[^}]+\}|%s|<[a-zA-Z_][\w]*>)",
    # Jailbreak / safety-disable directives. Kept unambiguous (a safety-specific object) so
    # security prose isn't matched; .py-string/comment and documentation matches are demoted.
    r"do\s+anything\s+now\b",
    r"\bDAN\s+mode\b",
    # Negation guard (mirrors the "send" rule): defensive guarantees like "cannot override
    # safety policy" / "will not bypass safety filters" / "can't disable guardrails" are the
    # opposite of a directive. Each lookbehind is fixed-width; "n't" catches can't/won't/don't.
    # \s (not a literal space) so a line-wrapped "cannot\noverride" is still guarded. Guards are
    # anchored after each verb's first word (see _neg_guarded) so they only run at verb hits;
    # for "turn off" the guard sits after "turn", before the \s+off tail.
    "(?:"
    + "|".join(
        [
            *(_neg_guarded(v, _NEG_WS) for v in ("ignore", "bypass", "disable", "override")),
            _neg_guarded("turn", _NEG_WS) + r"\s+off",
        ]
    )
    + r")\s+(?:your\s+|all\s+|any\s+|the\s+)?"
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
    # A start/end-of-file boundary is NOT a quote. (Guard the empty string explicitly: `"" in
    # _QUOTES` is True in Python — an empty string is a substring of any string — which would
    # misread a match at the very first/last byte as "quoted" and wrongly demote a live directive.)
    return bool(before) and bool(after) and before in _QUOTES and after in _QUOTES


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
