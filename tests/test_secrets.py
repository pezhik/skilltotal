"""Embedded-secret detection: known tokens, redaction, and FP guards."""

from __future__ import annotations

from skilltotal.file_index import FileIndex
from skilltotal.models import ThreatClass
from skilltotal.scanners.secrets import SecretsScanner


def fake_token(prefix: str, body: str) -> str:
    """Build a fake provider token at RUNTIME so no contiguous provider-pattern literal
    (``hf_…``, ``AKIA…``, ``ghp_…``) is committed to this public repo. This repo IS a secret
    scanner, so its fixtures deliberately look like real tokens — which GitHub *push protection*
    (a platform feature on public repos, separate from gitleaks and not disable-able by config)
    reads as a real credential and blocks the push. Assembling from two literals defeats that
    partner-pattern match while the scanned temp file still receives the full value, so detection
    behavior is unchanged. gitleaks/detect-secrets are handled separately by the tests/ allowlist.
    """
    return prefix + body


def _scan(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")
    return SecretsScanner().scan(FileIndex.build(tmp_path))


def _finding(result):
    return next((f for f in result.findings if f.id == "ST-SECRET-EMBEDDED"), None)


def test_aws_example_key_is_filtered_as_placeholder(tmp_path):
    # The canonical AWS docs key contains 'EXAMPLE' -> must be treated as a placeholder.
    res = _scan(tmp_path, "config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE9"\n')
    assert _finding(res) is None


def test_aws_key_detected_and_redacted(tmp_path):
    key = fake_token("AKIA", "1B2C3D4E5F6G7H8I")
    res = _scan(tmp_path, "config.py", f'AWS_KEY = "{key}"\n')
    f = _finding(res)
    assert f is not None and f.threat_class == ThreatClass.RISKY_CONSTRUCT
    # value never re-leaked: redacted, only a short prefix shown
    snippet = f.evidence[0].snippet
    assert key not in snippet
    assert "redacted" in snippet


def test_private_key_block_detected(tmp_path):
    # A real leaked key: BEGIN marker followed by actual base64 key material.
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDabcdefghijkl"
    res = _scan(tmp_path, "id_rsa", f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n")
    assert _finding(res) is not None


def test_test_certificate_private_key_demoted(tmp_path):
    # Disposable test-server TLS keys are not a shipped prod secret. FP: urllib3 flagged
    # ST-SECRET-EMBEDDED (-> ST-COMBO-EXFIL high) on dummyserver/certs/*.key; grpcio on
    # src/core/tsi/test_creds/*.key. A PEM block in a test/dummy/fixture path next to a
    # cert/cred/tls/ssl marker is routed to needs_review, not scored.
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDabcdefghijkl"
    for rel in ("dummyserver/certs/server.key", "src/core/tsi/test_creds/ca.key"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        res = _scan(tmp_path, rel, f"-----BEGIN PRIVATE KEY-----\n{body}\n")
        assert _finding(res) is None, rel
        assert any("Test-certificate private key" in n.title for n in res.needs_review), rel


def test_prod_private_key_still_flagged(tmp_path):
    # Recall guard: the SAME PEM material on a normal path (no test/dummy/fixture marker) is a
    # genuine leaked key and stays scored — the demotion is path-scoped, not content-scoped.
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDabcdefghijkl"
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    res = _scan(tmp_path, "config/deploy.key", f"-----BEGIN PRIVATE KEY-----\n{body}\n")
    assert _finding(res) is not None
    assert not any("Test-certificate private key" in n.title for n in res.needs_review)


def test_pem_header_constant_not_flagged(tmp_path):
    # A PEM format *marker* held as a string constant (auth code assembling/parsing a PEM) is not
    # a leaked key — the secret is the base64 body, which is absent here. FP: @ai-sdk/google-vertex.
    res = _scan(
        tmp_path,
        "auth.ts",
        "const pemHeader = '-----BEGIN PRIVATE KEY-----';\n"
        "const pemFooter = '-----END PRIVATE KEY-----';\n",
    )
    assert _finding(res) is None


def test_huggingface_token_detected_and_redacted(tmp_path):
    # A live Hugging Face access token gates model/dataset access (write tokens can push to the
    # Hub) — shipping one is a real leak. Fake but well-formed: hf_ + 34 base62 chars.
    token = fake_token("hf_", "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpP12")
    res = _scan(tmp_path, "config.py", f'HF_TOKEN = "{token}"\n')
    f = _finding(res)
    assert f is not None
    assert token not in f.evidence[0].snippet  # redacted, not re-leaked


def test_huggingface_org_token_detected(tmp_path):
    token = fake_token("api_org_", "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpP12")
    res = _scan(tmp_path, "config.py", f'HF = "{token}"\n')
    assert _finding(res) is not None


def test_huggingface_placeholder_not_flagged(tmp_path):
    # Well-formed shape but an obvious placeholder body -> filtered, no false positive.
    token = fake_token("hf_", "exampleAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    res = _scan(tmp_path, "config.py", f'HF_TOKEN = "{token}"\n')
    assert _finding(res) is None


def test_generic_secret_assignment_detected(tmp_path):
    res = _scan(tmp_path, "settings.py", 'API_TOKEN = "a1b2c3d4e5f6g7h8i9j0k1l2"\n')
    assert _finding(res) is not None


def test_placeholders_not_flagged(tmp_path):
    for val in (
        'API_KEY = "your_api_key_here"',
        'token = "xxxxxxxxxxxxxxxxxxxx"',
        'secret = "<your-secret>"',
        'password = "changeme123456789012"',
        'OPENAI_API_KEY = "sk-proj-EXAMPLE-REPLACE-ME-1234"',
    ):
        res = _scan(tmp_path, "f.py", val + "\n")
        assert _finding(res) is None, val


def test_secret_in_tests_demoted(tmp_path):
    # A secret only in test code is not shipped to consumers; the engine demotes test-only
    # evidence to needs_review. The scanner still finds it; engine handles demotion (covered
    # in engine tests). Here just assert the scanner anchors to the file.
    key = fake_token("ghp_", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ12")
    res = _scan(tmp_path, "config.py", f'GH = "{key}"\n')
    f = _finding(res)
    assert f is not None
    assert f.evidence[0].line_start == 1


def test_clean_file_no_secrets(tmp_path):
    res = _scan(tmp_path, "app.py", "import os\nprint('hello world')\n")
    assert _finding(res) is None


# --- Google installed-app OAuth client secret (ruleset 31) -----------------------------
# For INSTALLED (native/CLI) apps Google documents the client secret as not confidential —
# gcloud itself ships one. FP: gemini-cli scored critical/100 via ST-SECRET-EMBEDDED +
# ST-COMBO-EXFIL on its own oauth2.ts loopback-flow secret.

def _gocspx() -> str:
    # Assembled at runtime (see fake_token) so no GOCSPX- partner-pattern literal is committed.
    return fake_token("GOCSPX-", "4uHgMPm1o7SkgeV6Cu5clXFsxl9qT")


def test_installed_app_oauth_secret_demoted(tmp_path):
    src = (
        f'const OAUTH_CLIENT_SECRET = "{_gocspx()}";\n'
        'const REDIRECT = "http://localhost:7777/oauth2callback";\n'
    )
    res = _scan(tmp_path, "oauth2.ts", src)
    assert _finding(res) is None
    assert any("Installed-app Google OAuth" in n.title for n in res.needs_review)


def test_web_app_gocspx_secret_still_flagged(tmp_path):
    # Recall guard: the SAME value without installed-app markers (a web-app config with an
    # https redirect) is a real leaked secret and stays scored.
    src = (
        f'client_secret = "{_gocspx()}"\n'
        'redirect_uri = "https://app.example.com/oauth/callback"\n'
    )
    res = _scan(tmp_path, "settings.py", src)
    assert _finding(res) is not None
    assert not any("Installed-app Google OAuth" in n.title for n in res.needs_review)


def test_non_gocspx_secret_with_localhost_still_flagged(tmp_path):
    # Recall guard: installed-app markers do NOT excuse other secret shapes.
    key = fake_token("ghp_", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ12")
    src = f'token = "{key}"\nconst REDIRECT = "http://localhost:1234/cb";\n'
    res = _scan(tmp_path, "cli.py", src)
    assert _finding(res) is not None
