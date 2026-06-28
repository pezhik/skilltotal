"""Tier-1 offline calibration: the deterministic detection floor (no network).

This is the "did the engine break?" gate. It scans a fixed set of *committed* components
through the real pipeline (``detect_component`` + ``analyze_directory``) and asserts each one
lands on the expected side of the malware line:

  - **must-detect**: known-malicious fixtures — the engine MUST treat each as malicious
    (a malicious-indicator finding) or at least elevate it to high/critical risk. A drop here
    means a detection regression.
  - **must-stay-clean**: trusted-shaped fixtures — the engine MUST NOT raise a malicious
    indicator. A regression here is a false positive, the thing that erodes trust.

Because it is offline and deterministic, it runs in the normal ``pytest`` suite on *every*
change (and therefore inside the deploy gate's ``engine pytest`` step). The network corpus
(ops ``calibrate.py`` / ``run-calibration.ps1``) is a trend signal, not a gate — real malware
gets pulled from registries, so it cannot be the floor. The samples here always exist.

Detection metric mirrors ``tests/manual_eval/calibrate.py``'s ``_judge``: ``has_malicious``
covers low-noise malicious indicators (e.g. hidden Unicode), ``risk in {high, critical}`` covers
risky-construct stealers that don't trip a named malicious indicator (e.g. fs-read + egress).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.models import RiskLevel

_TESTS = Path(__file__).parent
_MALICIOUS = _TESTS / "manual_eval" / "malicious"
_FIXTURES = _TESTS / "fixtures"

# Known-malicious samples the engine MUST flag. Mix of the manual_eval corpus (realistic
# attack shapes) and the unit fixtures, so this one gate covers every malicious archetype.
MUST_DETECT = [
    _MALICIOUS / "agent-instruction-override",  # instruction override (prompt injection)
    _MALICIOUS / "mcp-tool-poisoning",          # MCP tool-description poisoning
    _MALICIOUS / "npm-trapdoor-stealer",        # install-time fs-read + network egress
    _MALICIOUS / "pypi-importtime-stealer",     # import-time decode-and-exec exfil
    _MALICIOUS / "zero-width-injection",        # hidden Unicode ASCII smuggling
    _MALICIOUS / "pypi-typosquat-dropper",      # OSSF archetype: import-time decode+exec dropper
    _MALICIOUS / "npm-postinstall-exfil",       # OSSF archetype: postinstall credential exfil
    _MALICIOUS / "py-marshal-loader",           # remote deserialize-and-exec dropper (marshal)
    _MALICIOUS / "sh-base64-exec",              # shell decode-and-execute + remote pipe-to-shell
    _MALICIOUS / "pypi-pth-backdoor",           # .pth startup-persistence auto-exec backdoor
    _MALICIOUS / "py-email-stealer",            # reads ~/.aws + exfiltrates via SMTP (email egress)
    _FIXTURES / "malicious_npm_pkg",            # npm stealer (steal.js)
    _FIXTURES / "malicious_py_pkg",             # python stealer
    _FIXTURES / "prompt_injection",             # poisoned skill
]

# Trusted-shaped samples that MUST NOT raise a malicious indicator (false-positive guard).
MUST_STAY_CLEAN = [
    _FIXTURES / "clean_pkg",
    _FIXTURES / "mcp_server",
]

# Real-world false-positive shapes (sanitized repros of the ruleset-20 calibration). Each is a
# legitimate component that previously got over-scored. Stronger than MUST_STAY_CLEAN: they must
# not only avoid a malicious indicator but also stay off the HIGH/CRITICAL tier and must not
# synthesize a credential-exfiltration combo. This is the anti-noise floor.
MUST_NOT_BE_ELEVATED = [
    _FIXTURES / "fp_eval_dataset",    # prompt-injection only in an eval/benchmark dataset
    _FIXTURES / "fp_shell_comment",   # pipe-to-shell only in a `# Usage:` comment
    _FIXTURES / "fp_denylist_paths",  # credential paths in a denylist + unrelated network
    _FIXTURES / "fp_algolia_key",     # public Algolia DocSearch search key
    _FIXTURES / "fp_e2e_tests",       # command-injection only in an e2e test tree
    _FIXTURES / "fp_mcp_sdk_comments",  # security prose in .ts comments / a defensive error string
    _FIXTURES / "fp_rust_inline_test_secret",  # fake key only in inline #[cfg(test)] Rust code
]


def _analyze(path: Path):
    component = detect_component(path, source=str(path))
    return analyze_directory(path, component)


def _is_detected(report) -> bool:
    """Engine produced a malicious verdict OR elevated the component to high/critical risk."""
    verdict = report.verdict or {}
    has_malicious = bool(verdict.get("has_malicious_indicators"))
    elevated = report.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    return has_malicious or elevated


@pytest.mark.parametrize("path", MUST_DETECT, ids=lambda p: p.name)
def test_known_malicious_is_detected(path: Path) -> None:
    assert path.exists(), f"missing must-detect fixture: {path}"
    report = _analyze(path)
    has_mal = bool(report.verdict.get("has_malicious_indicators")) if report.verdict else None
    assert _is_detected(report), (
        f"DETECTION REGRESSION: {path.name} was not flagged "
        f"(has_malicious={has_mal}, risk={report.risk_level.value}). The engine must treat "
        f"this known-malicious sample as malicious or high/critical risk."
    )


@pytest.mark.parametrize("path", MUST_STAY_CLEAN, ids=lambda p: p.name)
def test_trusted_shape_has_no_malicious_indicator(path: Path) -> None:
    assert path.exists(), f"missing must-stay-clean fixture: {path}"
    report = _analyze(path)
    verdict = report.verdict or {}
    assert not verdict.get("has_malicious_indicators"), (
        f"FALSE POSITIVE: {path.name} raised a malicious indicator "
        f"(risk={report.risk_level.value}). Trusted-shaped components must not be called malicious."
    )


@pytest.mark.parametrize("path", MUST_NOT_BE_ELEVATED, ids=lambda p: p.name)
def test_benign_fp_shape_is_not_elevated(path: Path) -> None:
    assert path.exists(), f"missing benign-FP fixture: {path}"
    report = _analyze(path)
    verdict = report.verdict or {}
    ids = {f.id for f in report.findings}
    assert not verdict.get("has_malicious_indicators"), (
        f"FALSE POSITIVE (malicious): {path.name} (risk={report.risk_level.value})."
    )
    assert report.risk_level not in (RiskLevel.HIGH, RiskLevel.CRITICAL), (
        f"FALSE POSITIVE (over-scored): {path.name} reached {report.risk_level.value}; "
        f"a benign FP shape must stay below high. findings={sorted(ids)}"
    )
    assert "ST-COMBO-EXFIL" not in ids and "ST-FLOW-TRIFECTA" not in ids, (
        f"FALSE POSITIVE (synthesized exfil): {path.name} -> {sorted(ids)}"
    )
