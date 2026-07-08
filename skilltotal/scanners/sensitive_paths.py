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
    # ~/.ssh but NOT `~/.ssh/known_hosts` (public host keys, never a credential — pyzmq reads it
    # for its SSH tunnel). `~/.ssh/config` DOES stay flagged: writing it is a real SSH-config
    # injection vector; a legitimate reader (dulwich's git-over-ssh) is cleared by the provider
    # credential-domain match in scoring, not by dropping detection. Private keys still match.
    r"~/\.ssh(?!/known_hosts\b)",
    r"\.ssh/(?!known_hosts\b)",
    r"~/\.aws",
    r"\.aws/credentials",
    r"~/\.kube",
    r"~/\.config/gcloud",
    r"\bid_rsa\b",
    # Cloud / registry / wallet credential locations seen in real cred-stealers.
    r"\.docker/config\.json",
    r"~/\.azure",
    r"\.git-credentials",
    r"application_default_credentials\.json",
    r"169\.254\.169\.254",  # cloud instance-metadata endpoint (SSRF / token theft)
    r"\bwallet\.dat\b",
    r"\.ethereum/keystore",
    r"~/\.config/solana",
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


# A guardrail/denylist that PROTECTS a credential location is the opposite of accessing it: a
# security tool's policy listing `id_rsa`/`.ssh` as paths to deny is a defensive artifact, not an
# exfiltration precursor. Such matches are routed to needs_review so they neither score nor feed
# the credential-exfiltration combo. Real access (a path passed to open()/readFileSync()) is a
# function argument — not a guard segment, keyword, or bare list element — so it still fires.
_GUARD_PATH_SEGMENTS = frozenset(
    {"policy", "policies", "guard", "guards", "denylist", "allowlist", "blocklist", "blocklists",
     "sandbox", "permission", "permissions", "security", "acl"}
)
_GUARD_KEYWORDS = re.compile(
    r"(?i)\b(?:deny|denied|denylist|block|blocked|blocklist|forbid|forbidden|exclude|excluded|"
    r"reject|protect|protected|sensitive|redact|sanitize|allowlist)\b"
)
# A bare string-literal list element: only a quoted string + optional `.to_string()`/`.into()`
# and a trailing comma (e.g. `"id_rsa".to_string(),`, `"**/.ssh/*",`). Declarative data, not a call.
_BARE_LIST_ELEMENT = re.compile(r"""^\s*["'][^"']*["']\s*(?:\.\w+\(\))?\s*,?\s*$""")
# A bare regex-literal list element: a slash-delimited regex (optional flags) on its own line,
# e.g. `/id_rsa/,`, `/credentials/i,`, `/\.pem$/,`. A regex literal is a PATTERN that matches
# against paths, never a path being accessed — so a credential token inside one is a detector's
# denylist entry (as in a `SENSITIVE_PATHS = [ /id_rsa/, ... ]` array), not exfiltration.
_BARE_REGEX_ELEMENT = re.compile(r"^\s*/(?:[^/\\\n]|\\.)+/[gimsuvy]*\s*,?\s*$")


def _guard_segment(relpath: str) -> bool:
    # Tokenize each path segment on `._-` so guard code is recognized whether it's a directory
    # (policies/) or a filename (net_guard.rs, path_guard.rs, denylist.go).
    for part in relpath.lower().split("/"):
        if any(tok in _GUARD_PATH_SEGMENTS for tok in re.split(r"[._-]", part)):
            return True
    return False


def _is_guardlist_context(relpath: str, line_text: str) -> bool:
    """True if a sensitive-path match is a defensive denylist/guardrail mention, not access."""
    return (
        _guard_segment(relpath)
        or bool(_GUARD_KEYWORDS.search(line_text))
        or bool(_BARE_LIST_ELEMENT.match(line_text))
        or bool(_BARE_REGEX_ELEMENT.match(line_text))
    )


# Markdown files where an inline-code span (`...`) is a *cited example*, not path access. A security
# guide that lists `write to ~/.ssh` / `store credentials` as patterns to detect is describing the
# threat, not performing it. Scoped to markdown ONLY — in code, a backtick is a JS template literal
# (`~/.ssh/${x}`) which IS real path usage, so it must still fire there.
_MD_SUFFIXES = frozenset({".md", ".mdx", ".markdown"})


def _cited_in_markdown_code(relpath: str, line_text: str, matched: str) -> bool:
    """True if ``matched`` falls inside a markdown inline-code span on this line. Splitting on the
    backtick delimiter, odd-indexed segments are inside `` `...` `` spans."""
    name = relpath.lower().rsplit("/", 1)[-1]
    dot = name.rfind(".")
    if (name[dot:] if dot > 0 else "") not in _MD_SUFFIXES:
        return False
    segments = line_text.split("`")
    return any(matched in segments[i] for i in range(1, len(segments), 2))


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
        guard_files: list[str] = []
        cited_files: list[str] = []
        for f, _m, ev in index.search(_STRONG_PATHS):
            key = (ev.file, ev.line_start, ev.line_end)
            if key in seen_ev:
                continue
            seen_ev.add(key)
            line_text = f.line_text(ev.line_start)
            if _is_guardlist_context(ev.file, line_text):
                if ev.file not in guard_files:
                    guard_files.append(ev.file)
                continue
            if _cited_in_markdown_code(ev.file, line_text, _m.group(0)):
                if ev.file not in cited_files:
                    cited_files.append(ev.file)
                continue
            evidence.append(ev)
            if len(evidence) >= MAX_EVIDENCE_PER_FINDING:
                break

        if guard_files:
            shown = ", ".join(guard_files[:_SENS_WORD_EXAMPLES])
            more = len(guard_files) - _SENS_WORD_EXAMPLES
            if more > 0:
                shown += f", and {more} more"
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title=f"Credential path in a denylist/guardrail ({len(guard_files)})",
                    reason=(
                        f"A credential location is referenced in a denylist/guardrail context "
                        f"in {len(guard_files)} file(s) (a policy that PROTECTS the path, not "
                        f"access to it); flagged for review, not scored: {shown}."
                    ),
                    file=guard_files[0],
                )
            )

        if cited_files:
            shown = ", ".join(cited_files[:_SENS_WORD_EXAMPLES])
            more = len(cited_files) - _SENS_WORD_EXAMPLES
            if more > 0:
                shown += f", and {more} more"
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title=f"Credential path cited in markdown example ({len(cited_files)})",
                    reason=(
                        f"A credential location appears inside a markdown inline-code example in "
                        f"{len(cited_files)} file(s) (a security doc describing the path, not "
                        f"accessing it); flagged for review, not scored: {shown}."
                    ),
                    file=cited_files[0],
                )
            )

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
