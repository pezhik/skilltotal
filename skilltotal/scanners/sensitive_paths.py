"""Sensitive path / secret-location reference detection.

Strong, path-like indicators (``~/.ssh``, ``~/.aws``, ``id_rsa``, ``.aws/credentials``, an
``.env`` *file*) are high-severity findings. Bare words ``credentials`` / ``secrets`` are
too ambiguous (often variable or field names) so they are routed to ``needs_review``.

Note the ``.env`` pattern uses a negative lookbehind so it matches the file ``'.env'`` but
**not** ``process.env`` (reading environment variables is not file access).

False-positive calibration: the *bare* ``.env`` token is extremely common in legitimate
documentation (``.rst``/``.md``/``.mdx`` describing dotenv support) and in ignore files
(``.gitignore``/``.dockerignore`` listing ``.env`` precisely so it is **not** committed —
the opposite of accessing it). Those file types are excluded from the ``.env`` signal only;
the strong path-like indicators (``~/.aws``, ``~/.ssh``, ``id_rsa`` …) still fire
everywhere, including documentation, so prompt-injection style instructions to read a
credential file in an ``.md`` are still caught.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_PER_FINDING,
    RuleSpec,
    Scanner,
    ScanResult,
    alternation,
)

CATEGORY = "sensitive_path"

# Strong, path-like credential locations. These are unambiguous enough to flag in any
# file type, including documentation.
_STRONG_PATHS = alternation(
    r"~/\.ssh",
    r"\.ssh/",
    r"~/\.aws",
    r"\.aws/credentials",
    r"~/\.kube",
    r"~/\.config/gcloud",
    r"\bid_rsa\b",
    flags=re.IGNORECASE,
)

# The bare ".env" file token (negative lookbehind so "process.env" is not matched). Common
# in benign docs/ignore files, so it is suppressed there (see _IGNORED_FOR_ENV).
_ENV_FILE = re.compile(r"(?<![\w.])\.env\b", re.IGNORECASE)

# File types where a bare ".env" mention is almost always benign (prose documentation or an
# ignore list), so the ".env" signal is not raised for them.
_DOC_SUFFIXES = frozenset({".md", ".mdx", ".rst", ".txt", ".adoc"})
_IGNORE_FILENAMES = frozenset(
    {".gitignore", ".dockerignore", ".npmignore", ".prettierignore", ".eslintignore"}
)


def _suppresses_env(relpath: str) -> bool:
    """True if a bare ``.env`` mention in this file is too benign to flag."""
    lower = relpath.lower()
    name = lower.rsplit("/", 1)[-1]
    if name in _IGNORE_FILENAMES:
        return True
    dot = name.rfind(".")
    suffix = name[dot:] if dot > 0 else ""
    return suffix in _DOC_SUFFIXES


_WEAK = re.compile(r"\b(?:credentials|secrets)\b", re.IGNORECASE)


class SensitivePathScanner(Scanner):
    name = "sensitive_paths"
    rules = [
        RuleSpec(
            id="ST-SENS-PATH",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Sensitive path / secret-location reference",
            description=(
                "References to credential/secret locations were detected "
                "(e.g. ~/.ssh, ~/.aws, .aws/credentials, id_rsa, an .env file)."
            ),
            recommendation=(
                "Verify why the component references credential locations; reading these "
                "is a common precursor to secret exfiltration."
            ),
            capability=Capability.FILESYSTEM_READ,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            pattern=_STRONG_PATHS,
        ),
        # Listed for `rules list`; bare secret words are routed to needs_review.
        RuleSpec(
            id="ST-SENS-WORD",
            category=CATEGORY,
            severity=Severity.LOW,
            title="Ambiguous secret-related word",
            description="The bare word 'credentials' or 'secrets' was detected.",
            recommendation="Review whether this refers to an actual secret store.",
            capability=None,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        strong_rule = self.rules[0]

        # Collect evidence from the strong path indicators (any file) plus the bare ".env"
        # token (excluding benign doc/ignore files), de-duplicated by location.
        seen_ev: set[tuple[str, int, int]] = set()
        evidence: list[Evidence] = []
        for _f, _m, ev in index.search(_STRONG_PATHS):
            key = (ev.file, ev.line_start, ev.line_end)
            if key not in seen_ev:
                seen_ev.add(key)
                evidence.append(ev)
        for _f, _m, ev in index.search(_ENV_FILE):
            if _suppresses_env(ev.file):
                continue
            key = (ev.file, ev.line_start, ev.line_end)
            if key not in seen_ev:
                seen_ev.add(key)
                evidence.append(ev)
            if len(evidence) >= MAX_EVIDENCE_PER_FINDING:
                break

        evidence = evidence[:MAX_EVIDENCE_PER_FINDING]
        findings: list[Finding] = []
        if evidence:
            description = strong_rule.description
            if len(evidence) > 1:
                description = (
                    f"{description} ({len(evidence)} occurrence(s) shown as evidence)."
                )
            findings.append(
                Finding(
                    id=strong_rule.id,
                    severity=strong_rule.severity,
                    category=strong_rule.category,
                    title=strong_rule.title,
                    description=description,
                    evidence=evidence,
                    recommendation=strong_rule.recommendation,
                )
            )

        # Lines already covered by a strong path match should not also be flagged weak.
        strong_lines: set[tuple[str, int]] = set()
        for f in findings:
            for e in f.evidence:
                strong_lines.add((e.file, e.line_start))

        needs_review: list[NeedsReview] = []
        seen: set[tuple[str, int]] = set()
        for _f, m, ev in index.search(_WEAK):
            key = (ev.file, ev.line_start)
            if key in strong_lines or key in seen:
                continue
            seen.add(key)
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title="Ambiguous secret-related word",
                    reason=(
                        f"Word '{m.group(0)}' at line {ev.line_start} may refer to a "
                        "secret store but is too ambiguous to confirm."
                    ),
                    file=ev.file,
                    line=ev.line_start,
                )
            )
            if len(needs_review) >= MAX_EVIDENCE_PER_FINDING:
                break
        return ScanResult(findings=findings, needs_review=needs_review)
