"""Embedded-secret detection: credentials shipped inside the component itself.

A package that bundles a live API key or private key is a real, exploitable leak regardless
of the author's intent — so this is a ``risky_construct`` (not a malware verdict). Detection
favours **known-prefix tokens** (very low false-positive) plus a conservative
secret-variable assignment rule; placeholder values and test paths are filtered out, and the
secret value is **redacted** in the evidence so the report never re-leaks it.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Evidence, Finding, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import MAX_EVIDENCE_PER_FINDING, RuleSpec, Scanner, ScanResult

CATEGORY = "secret_exposure"

# (label, pattern, value-group). Known providers — the prefix itself is the signal.
_KNOWN: list[tuple[str, re.Pattern[str], int]] = [
    ("AWS access key", re.compile(r"\b((?:AKIA|ASIA|AGPA|AROA|ANPA|ANVA|AIDA)[0-9A-Z]{16})\b"), 1),
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), 1),
    ("GitHub fine-grained PAT", re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,})\b"), 1),
    ("GitLab token", re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"), 1),
    ("Anthropic API key", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"), 1),
    ("OpenAI API key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b"), 1),
    ("Slack token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"), 1),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    ("Stripe live key", re.compile(r"\b([sr]k_live_[A-Za-z0-9]{24,})\b"), 1),
    (
        # Require actual key MATERIAL after the marker, not the bare header. A lone
        # `-----BEGIN PRIVATE KEY-----` string constant is a PEM *format marker* used by auth code
        # to assemble/parse a key (e.g. `const pemHeader = '-----BEGIN PRIVATE KEY-----'`), not a
        # leaked key — the secret is the base64 body. Up to 8 non-base64 chars (newline, quote,
        # `\n` escape) may separate the marker from the body.
        "Private key block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            r"[^A-Za-z0-9+/]{0,8}[A-Za-z0-9+/]{40,}"
        ),
        0,
    ),
]

# Generic: a secret-named variable assigned a long opaque string.
_GENERIC = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|auth[_-]?token|"
    r"client[_-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9+/_\-]{20,})['\"]"
)

# Substrings that mark a value as a placeholder / example, not a real secret. Kept to
# unambiguous placeholder words — NOT generic hex/alpha runs, which occur in real tokens.
_PLACEHOLDER = re.compile(
    r"(?i)example|your[_-]?|changeme|placeholder|dummy|sample|xxxx|<[^>]+>|redacted|"
    r"\bfake\b|insert[_-]?(?:your|here)|\.\.\."
)


def _looks_like_placeholder(value: str) -> bool:
    if _PLACEHOLDER.search(value):
        return True
    # Single repeated character (xxxxxxxx, 00000000) or too few distinct chars.
    return len(set(value)) <= 4


# Algolia DocSearch search-only keys are public by design (shipped in client-side docs search)
# and are not a leak. They are 32 lowercase-hex chars and always sit next to an Algolia app id /
# index name. Recognising that shape avoids flagging every docs site as carrying an embedded secret.
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_DOCSEARCH_CTX = re.compile(r"(?i)algolia|docsearch|app[_-]?id|index[_-]?name")


def _is_public_docsearch_key(value: str, context: str) -> bool:
    """True if ``value`` is a public Algolia DocSearch search key (read-only, safe to embed)."""
    return bool(_HEX32.match(value)) and bool(_DOCSEARCH_CTX.search(context))


def _has_mixed_charset(value: str) -> bool:
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


def _redact(snippet: str, value: str) -> str:
    """Replace the secret value in the snippet with a non-recoverable marker."""
    if not value:
        return snippet
    shown = value[:4]
    return snippet.replace(value, f"{shown}…[redacted, {len(value)} chars]")


class SecretsScanner(Scanner):
    name = "secrets"
    rules = [
        RuleSpec(
            id="ST-SECRET-EMBEDDED",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Embedded secret / credential",
            description=(
                "A hardcoded credential was detected in the component (e.g. a cloud access "
                "key, provider API token, or private key). Shipping a live secret is a "
                "supply-chain leak: anyone with the package can use it."
            ),
            recommendation=(
                "Remove the secret from the code, rotate it immediately, and load credentials "
                "from the environment or a secrets manager at runtime."
            ),
            capability=None,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        seen: set[tuple[str, int]] = set()
        docsearch_files: list[str] = []

        for f in index.files:
            for _label, pattern, grp in _KNOWN:
                for m in pattern.finditer(f.text):
                    value = m.group(grp)
                    if grp != 0 and _looks_like_placeholder(value):
                        continue
                    self._add(f, m, value, evidence, seen)
            for m in _GENERIC.finditer(f.text):
                value = m.group(1)
                if _looks_like_placeholder(value) or not _has_mixed_charset(value):
                    continue
                window = f.text[max(0, m.start() - 200) : m.end() + 200]
                if _is_public_docsearch_key(value, window):
                    if f.relpath not in docsearch_files:
                        docsearch_files.append(f.relpath)
                    continue
                self._add(f, m, value, evidence, seen)

        findings: list[Finding] = []
        if evidence:
            rule = self.rules[0]
            findings.append(
                Finding(
                    id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    title=rule.title,
                    description=rule.description,
                    evidence=evidence[:MAX_EVIDENCE_PER_FINDING],
                    recommendation=rule.recommendation,
                    threat_class=rule.threat_class,
                )
            )

        needs_review: list[NeedsReview] = []
        if docsearch_files:
            shown = ", ".join(docsearch_files[:8])
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title=f"Public DocSearch search key ({len(docsearch_files)})",
                    reason=(
                        "A 32-hex key next to an Algolia app id / index name is a public "
                        "DocSearch search-only key (read-only, safe to embed), not a leaked "
                        f"secret; flagged for review, not scored: {shown}."
                    ),
                    file=docsearch_files[0],
                )
            )
        return ScanResult(findings=findings, needs_review=needs_review)

    @staticmethod
    def _add(f, m, value, evidence: list[Evidence], seen: set[tuple[str, int]]) -> None:
        ev = f.evidence_for_span(m.start(), m.end())
        key = (ev.file, ev.line_start)
        if key in seen:
            return
        seen.add(key)
        evidence.append(
            Evidence(
                file=ev.file,
                line_start=ev.line_start,
                line_end=ev.line_end,
                snippet=_redact(ev.snippet, value),
                # Preserve the match offset (only the snippet is redacted) so code-context and
                # inline-test demotion can locate this secret within the source.
                match_offset=ev.match_offset,
            )
        )
