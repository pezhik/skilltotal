"""Sensitive path / secret-location reference detection.

Strong, path-like indicators (``~/.ssh``, ``~/.aws``, ``id_rsa``, ``.aws/credentials``, an
``.env`` *file*) are high-severity findings. Bare words ``credentials`` / ``secrets`` are
too ambiguous (often variable or field names) so they are routed to ``needs_review``.

Note the ``.env`` pattern uses a negative lookbehind so it matches the file ``'.env'`` but
**not** ``process.env`` (reading environment variables is not file access).
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

CATEGORY = "sensitive_path"

_STRONG = alternation(
    r"~/\.ssh",
    r"\.ssh/",
    r"~/\.aws",
    r"\.aws/credentials",
    r"~/\.kube",
    r"~/\.config/gcloud",
    r"\bid_rsa\b",
    r"(?<![\w.])\.env\b",  # the file ".env", not process.env
    flags=re.IGNORECASE,
)

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
            pattern=_STRONG,
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
        findings = findings_from_rules(index, [strong_rule])

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
                )
            )
            if len(needs_review) >= MAX_EVIDENCE_PER_FINDING:
                break
        return ScanResult(findings=findings, needs_review=needs_review)
