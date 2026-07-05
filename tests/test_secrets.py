"""Embedded-secret detection: known tokens, redaction, and FP guards."""

from __future__ import annotations

from skilltotal.file_index import FileIndex
from skilltotal.models import ThreatClass
from skilltotal.scanners.secrets import SecretsScanner


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
    res = _scan(tmp_path, "config.py", 'AWS_KEY = "AKIA1B2C3D4E5F6G7H8I"\n')
    f = _finding(res)
    assert f is not None and f.threat_class == ThreatClass.RISKY_CONSTRUCT
    # value never re-leaked: redacted, only a short prefix shown
    snippet = f.evidence[0].snippet
    assert "AKIA1B2C3D4E5F6G7H8I" not in snippet
    assert "redacted" in snippet


def test_private_key_block_detected(tmp_path):
    # A real leaked key: BEGIN marker followed by actual base64 key material.
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDabcdefghijkl"
    res = _scan(tmp_path, "id_rsa", f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n")
    assert _finding(res) is not None


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
    # NOTE: the prefix is concatenated at runtime so no contiguous `hf_<34>` literal exists in
    # this source — otherwise GitHub push protection reads our own detection fixture as a real
    # Hugging Face token and blocks the push. The scanned temp file still gets the full value.
    token = "hf_" + "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpP12"
    res = _scan(tmp_path, "config.py", f'HF_TOKEN = "{token}"\n')
    f = _finding(res)
    assert f is not None
    assert token not in f.evidence[0].snippet  # redacted, not re-leaked


def test_huggingface_org_token_detected(tmp_path):
    token = "api_org_" + "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpP12"  # split: avoid push-protection match
    res = _scan(tmp_path, "config.py", f'HF = "{token}"\n')
    assert _finding(res) is not None


def test_huggingface_placeholder_not_flagged(tmp_path):
    # Well-formed shape but an obvious placeholder body -> filtered, no false positive.
    token = "hf_" + "exampleAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # split: avoid push-protection match
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
    res = _scan(tmp_path, "config.py", 'GH = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ12"\n')
    f = _finding(res)
    assert f is not None
    assert f.evidence[0].line_start == 1


def test_clean_file_no_secrets(tmp_path):
    res = _scan(tmp_path, "app.py", "import os\nprint('hello world')\n")
    assert _finding(res) is None
