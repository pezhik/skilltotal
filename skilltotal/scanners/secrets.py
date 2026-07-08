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
    # Real OpenAI keys are a legacy `sk-` + long base62 body, or a prefixed
    # (`sk-proj-` / `sk-svcacct-` / `sk-admin-`) key with a long body. Short `sk-…`
    # tokens are NOT OpenAI secrets: litellm proxy virtual keys (`sk-P1zJMds…`, ~20
    # chars), `sk-1234` doc examples, and `org/sk-model-name` Hugging Face model ids
    # all share the `sk-` prefix. Requiring the real length + prefix shape drops those
    # FPs while the 48-char legacy and long project-key forms still match. An
    # `api_key = "sk-short"` assignment remains covered by the generic rule below.
    (
        "OpenAI API key",
        re.compile(r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|sk-[A-Za-z0-9]{40,})\b"),
        1,
    ),
    ("Slack token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"), 1),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    # Hugging Face access tokens gate model/dataset downloads and (for write tokens) pushes to
    # the Hub — a live one shipped in a component is a real leak (Lasso found 1,500+ exposed).
    # The `hf_` / `api_org_` prefix plus a fixed-length base62 body is highly specific (low FP).
    ("Hugging Face user token", re.compile(r"\b(hf_[A-Za-z0-9]{34,40})\b"), 1),
    ("Hugging Face org token", re.compile(r"\b(api_org_[A-Za-z0-9]{34})\b"), 1),
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


# Google OAuth client secrets ("GOCSPX-…") are NOT confidential for INSTALLED apps (desktop /
# CLI / native): Google's own docs say the secret "is obviously not treated as a secret" in that
# flow, and Google ships one inside gcloud. The same value shape IS sensitive for a web app, so
# demotion requires installed-app flow markers in the SAME file: the loopback redirect, the
# legacy oob URN, the device-code flow, PKCE, or a client_secrets.json "installed" key. A
# GOCSPX secret without those markers stays a scored finding (a leaked web-app secret).
_GOOGLE_OAUTH_PREFIX = "GOCSPX-"
_INSTALLED_APP_CTX = re.compile(
    r"(?i)urn:ietf:wg:oauth:2\.0:oob|device[_/]code|code_verifier|code_challenge|"
    r"http://(?:localhost|127\.0\.0\.1)|loopback|[\"']installed[\"']\s*[:=]"
)


def _is_installed_app_oauth_secret(value: str, file_text: str) -> bool:
    """True if ``value`` is a Google OAuth client secret in an installed-app (native) flow."""
    return value.startswith(_GOOGLE_OAUTH_PREFIX) and bool(_INSTALLED_APP_CTX.search(file_text))


# Test TLS/certificate fixtures: packages ship throwaway dummy certificate + private-key pairs to
# drive their OWN test HTTPS servers (urllib3 `dummyserver/certs/*.key`, grpcio
# `src/core/tsi/test_creds/*.key`). Those PEM blocks are real key MATERIAL but are disposable test
# certificates, never a shipped production secret — the directory path (a test/dummy/fixture marker
# next to a cert/cred/tls/ssl/pki marker) says so. Such a private-key block is routed to
# needs_review, not scored. A private key on a normal path (`id_rsa`, `deploy/prod.pem`) has no test
# marker and still scores, so a genuine leaked key is unaffected.
_TEST_CERT_TESTISH = ("test", "dummy", "fixture", "mock", "example", "sample")
_TEST_CERT_CERTISH = ("cert", "cred", "tls", "ssl", "pki")


def _is_test_certificate(relpath: str) -> bool:
    """True if ``relpath`` is a disposable test-certificate fixture (test-server key material)."""
    dirs = "/".join(relpath.lower().replace("\\", "/").split("/")[:-1])
    return any(t in dirs for t in _TEST_CERT_TESTISH) and any(c in dirs for c in _TEST_CERT_CERTISH)


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
            # A secret inside a comment is commented-out example code, not a live shipped
            # credential (e.g. ragflow's `#     OAuthConfig(client_secret="…")`). Real embedded
            # secrets are in code / value-strings, which are NOT demoted, so recall is preserved.
            code_context="comments",
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        seen: set[tuple[str, int]] = set()
        docsearch_files: list[str] = []
        installed_oauth_files: list[str] = []
        test_cert_files: list[str] = []

        for f in index.files:
            for label, pattern, grp in _KNOWN:
                for m in pattern.finditer(f.text):
                    value = m.group(grp)
                    if grp != 0 and _looks_like_placeholder(value):
                        continue
                    if label == "Private key block" and _is_test_certificate(f.relpath):
                        if f.relpath not in test_cert_files:
                            test_cert_files.append(f.relpath)
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
                if _is_installed_app_oauth_secret(value, f.text):
                    if f.relpath not in installed_oauth_files:
                        installed_oauth_files.append(f.relpath)
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
        if test_cert_files:
            shown = ", ".join(test_cert_files[:8])
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title=f"Test-certificate private key ({len(test_cert_files)})",
                    reason=(
                        "A PEM private-key block in a test-certificate fixture path (a "
                        "test/dummy/fixture directory next to a cert/cred/tls/ssl marker, e.g. "
                        "urllib3 dummyserver/certs, grpcio test_creds). These are disposable test "
                        "certificates for the package's own test server, not a shipped production "
                        f"secret; flagged for review, not scored: {shown}."
                    ),
                    file=test_cert_files[0],
                )
            )
        if installed_oauth_files:
            shown = ", ".join(installed_oauth_files[:8])
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title=(
                        f"Installed-app Google OAuth client secret ({len(installed_oauth_files)})"
                    ),
                    reason=(
                        "A GOCSPX- Google OAuth client secret in a file with installed-app flow "
                        "markers (loopback redirect / device code / PKCE / oob). For native "
                        "apps Google documents this value as not confidential (gcloud ships "
                        "one), so it is flagged for review, not scored — verify it is not a "
                        f"web-application secret: {shown}."
                    ),
                    file=installed_oauth_files[0],
                )
            )
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
