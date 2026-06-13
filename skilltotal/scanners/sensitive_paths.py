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
_SENS_WORD_EXAMPLES = 8


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
            # A real reference is a path value (open("~/.ssh/id_rsa")); the same token inside a
            # .py string/comment is a detector's own pattern literal or a doc example (e.g. this
            # scanner defines `id_rsa`). Demote those so a security tool does not flag itself.
            code_context="strings_and_comments",
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
        needs_review: list[NeedsReview] = []

        # Strong, path-like credential locations (~/.ssh, id_rsa, .aws/credentials, …) are the
        # scored finding. The bare ".env" file token is NOT: legitimate apps load a local .env
        # constantly (dotenv), so a `.env` reference + network would otherwise flag almost every
        # web app as a credential-exfiltration path. It is surfaced for review instead.
        seen_ev: set[tuple[str, int, int]] = set()
        evidence: list[Evidence] = []
        for _f, _m, ev in index.search(_STRONG_PATHS):
            key = (ev.file, ev.line_start, ev.line_end)
            if key not in seen_ev:
                seen_ev.add(key)
                evidence.append(ev)
            if len(evidence) >= MAX_EVIDENCE_PER_FINDING:
                break

        env_files: list[str] = []
        env_seen: set[str] = set()
        for _f, _m, ev in index.search(_ENV_FILE):
            if _suppresses_env(ev.file) or ev.file in env_seen:
                continue
            env_seen.add(ev.file)
            env_files.append(ev.file)
        if env_files:
            shown = ", ".join(env_files[:_SENS_WORD_EXAMPLES])
            more = len(env_files) - _SENS_WORD_EXAMPLES
            if more > 0:
                shown += f", and {more} more"
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title=f"Local .env file reference ({len(env_files)})",
                    reason=(
                        f"A bare '.env' file is referenced in {len(env_files)} file(s); "
                        f"commonly benign (dotenv config), so flagged for review not scored: "
                        f"{shown}."
                    ),
                    file=env_files[0],
                )
            )

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

        # Bare secret-related words are common in legitimate code/docs (a large SDK can
        # mention "credentials"/"secret" dozens of times). One row per hit floods the report,
        # so aggregate distinct hit files into a single informational entry.
        seen: set[tuple[str, int]] = set()
        files: list[str] = []
        words: set[str] = set()
        for _f, m, ev in index.search(_WEAK):
            key = (ev.file, ev.line_start)
            if key in strong_lines or key in seen:
                continue
            seen.add(key)
            words.add(m.group(0).lower())
            if ev.file not in files:
                files.append(ev.file)

        if seen:
            shown = ", ".join(files[:_SENS_WORD_EXAMPLES])
            more = len(files) - _SENS_WORD_EXAMPLES
            if more > 0:
                shown += f", and {more} more"
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title=f"Ambiguous secret-related words ({len(seen)})",
                    reason=(
                        f"{len(seen)} mention(s) of secret-related words "
                        f"({', '.join(sorted(words))}) across {len(files)} file(s) may refer "
                        f"to a secret store but are too ambiguous to confirm: {shown}."
                    ),
                    file=files[0] if files else None,
                )
            )
        return ScanResult(findings=findings, needs_review=needs_review)
