"""Two mirror-image defects in the embedded-secret rule, found while surveying the MCP registry.

The generic assignment rule keyed on api_key/secret/token/password/... but NOT on `private_key`
-- the most standard name there is for an actual credential -- so those were missed entirely.
Meanwhile a web3 `token = "0x<40 hex>"` matched, because in that ecosystem "token" names an
asset and the value is a public contract ADDRESS, not a credential. The rule was flagging the
harmless identifier and ignoring the real key.
"""

from __future__ import annotations

from skilltotal.engine import analyze_directory
from skilltotal.models import Component

ETH_ADDRESS = "0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9"           # 40 hex: public
ETH_PRIVATE_KEY = "0x4c0883a69102937d6231471b5dbb6204fe512961708279b3b4d2f0c1b8f6b2a1"  # 64 hex


def _ids(tmp_path, code: str, name: str = "index.js") -> set[str]:
    (tmp_path / name).write_text(code, encoding="utf-8")
    report = analyze_directory(
        tmp_path, Component(name="x", type="directory", source=str(tmp_path))
    )
    return {f.id for f in report.findings}


def test_private_key_assignment_is_detected(tmp_path):
    assert "ST-SECRET-EMBEDDED" in _ids(tmp_path, f'const privateKey = "{ETH_PRIVATE_KEY}";')


def test_snake_case_private_key_is_detected(tmp_path):
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ"
    assert "ST-SECRET-EMBEDDED" in _ids(tmp_path, f'private_key = "{body}"', name="app.py")


def test_public_blockchain_address_is_not_a_secret(tmp_path):
    """A 0x + 40-hex value is an address published on-chain; anyone can read it."""
    assert "ST-SECRET-EMBEDDED" not in _ids(tmp_path, f'const token = "{ETH_ADDRESS}";')


def test_a_blockchain_private_key_still_counts(tmp_path):
    """The exclusion is shape-exact, so the 64-hex key form is untouched."""
    assert "ST-SECRET-EMBEDDED" in _ids(tmp_path, f'const secret = "{ETH_PRIVATE_KEY}";')


def test_ordinary_secrets_are_unaffected(tmp_path):
    assert "ST-SECRET-EMBEDDED" in _ids(tmp_path, 'secret = "s3rvic3T0k3nAbCdEfGhIjKlMn"')
