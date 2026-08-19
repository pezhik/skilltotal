"""Values that look like credentials but are published on purpose.

Sampling the MCP-registry survey, every one of the first four components carrying an
"embedded secret" was one of these: a PostHog project key, a Solana program address, or a
vendor's documented public constant. Reporting them turns well-known projects `high` for
shipping exactly what their vendor tells them to ship.

Precedent in this scanner: Algolia DocSearch search keys and client-telemetry ingestion keys
are already recognised and routed to needs_review rather than scored.
"""

from __future__ import annotations

from skilltotal.engine import analyze_directory
from skilltotal.models import Component

# PostHog documents the project API key as safe to expose in client code; the `phc_` prefix is
# the public form (the private personal API key uses a different prefix).
POSTHOG_PUBLIC = "phc_" + "9aPzNVOhUXbYcmZoLpQrStUvWxYz0123456789abcdef"
# Solana SPL Token program address: a fixed, on-chain, public constant.
SOLANA_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"


def _report(tmp_path, code: str, name: str = "index.ts"):
    (tmp_path / name).write_text(code, encoding="utf-8")
    return analyze_directory(
        tmp_path, Component(name="x", type="directory", source=str(tmp_path))
    )


def _ids(report) -> set[str]:
    return {f.id for f in report.findings}


def test_posthog_project_key_is_not_a_leak(tmp_path):
    report = _report(tmp_path, f'export const POSTHOG_API_KEY = "{POSTHOG_PUBLIC}";')
    assert "ST-SECRET-EMBEDDED" not in _ids(report)


def test_posthog_key_is_still_disclosed(tmp_path):
    """Demoted, not dropped: the reader still learns the component ships a telemetry key."""
    report = _report(tmp_path, f'export const POSTHOG_API_KEY = "{POSTHOG_PUBLIC}";')
    assert report.needs_review


def test_solana_program_address_is_not_a_secret(tmp_path):
    report = _report(tmp_path, f'const SPL_TOKEN = "{SOLANA_PROGRAM}";')
    assert "ST-SECRET-EMBEDDED" not in _ids(report)


def test_a_solana_keypair_is_still_a_secret(tmp_path):
    """The exclusion is length-bounded: an address is <=44 chars, a keypair is ~88."""
    keypair = (
        "4wBqpZM9k69W87zdYXT2bMwSDLpvMcctuZbLNjPGCtBG"
        "jTMTUFSN4YsdNQ2LSKmxLBWjNKPBaBqTXDNSbfpuvNVQ"
    )
    report = _report(tmp_path, f'const secret = "{keypair}";')
    assert "ST-SECRET-EMBEDDED" in _ids(report)


def test_a_real_provider_token_is_unaffected(tmp_path):
    token = "ghu_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    report = _report(tmp_path, f'const token = "{token}";')
    assert "ST-SECRET-EMBEDDED" in _ids(report)


def test_a_comment_mentioning_eval_is_not_dynamic_execution(tmp_path):
    """`// guarded string eval (no DOM types)` describes code; it does not execute any."""
    code = "// Guarded string eval (no DOM types).\nconst safe = 1;\n"
    assert "ST-DYN-NODE" not in _ids(_report(tmp_path, code, name="app.ts"))


def test_real_eval_is_still_reported(tmp_path):
    assert "ST-DYN-NODE" in _ids(_report(tmp_path, 'eval(userInput);\n', name="app.ts"))
