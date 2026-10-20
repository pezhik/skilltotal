"""Research 2026-10-20: five detection gaps from AI-tooling attacks of the prior ~45 days.

Each gap pairs an attack shape with an honest look-alike that must stay clean. Sanitized
fixtures only: hosts are ``.invalid`` / documentation IPs, tokens are obviously fake, commands
are inert, nothing is executed.

* ``ST-AGENT-CRED-HELPER-EXEC`` -- a distributable config artifact (provider card / shipped
  settings.json) whose Claude Code credential helper fetches-and-runs or exfiltrates a secret
  (LeanFlip provider-switcher, Oct 2026). A helper that prints a fixed key stays clean.
* ``ST-AGENT-DOTENV-EXEC`` -- an agent-config ``.env`` (``.gemini/.env``) whose sandbox/proxy
  command variable carries shell metacharacters (CVE-2026-12537). Plain values stay clean.
* ``ST-PY-STDLIB-SHADOW`` -- a module named after a stdlib module that runs code on import and
  re-exports the real one (embracethered, Aug/Sep 2026). A same-named local helper with no
  import-time side effect stays clean.
* ``ST-MCP-STATIC-AUTH-EXEC`` -- an MCP server that runs host commands behind a hard-coded bearer
  token (Gentlemen RaaS affiliate, Oct 2026). Reading the token from the environment stays clean.
* ``ST-WORKFLOW-HISTORY-EXFIL`` -- a ``.github/workflows`` job that harvests provider-key prefixes
  and posts them off GitHub (GhostAction, Oct 2026). A secret-scan that never exfiltrates stays
  clean.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory

_CORPUS = Path(__file__).resolve().parent / "eval_corpus"


def _report(root: Path):
    return analyze_directory(root, detect_component(root, source=str(root)))


def _ids(root: Path) -> set[str]:
    return {f.id for f in _report(root).findings}


def _pos(technique: str, variant: str) -> Path:
    return _CORPUS / "positive" / "AST01" / technique / variant


def _neg(technique: str, variant: str) -> Path:
    return _CORPUS / "negative" / "AST01" / technique / variant


_PAIRS = [
    ("ST-AGENT-CRED-HELPER-EXEC", "agent-cred-helper-exec", "provider-card", "static-key-helper"),
    ("ST-AGENT-DOTENV-EXEC", "agent-dotenv-exec", "gemini-proxy-command", "gemini-plain-sandbox"),
    ("ST-PY-STDLIB-SHADOW", "stdlib-shadow", "struct-import-exec", "local-struct-helper"),
    ("ST-MCP-STATIC-AUTH-EXEC", "mcp-static-auth-exec", "exec-session", "env-token-server"),
    ("ST-WORKFLOW-HISTORY-EXFIL", "workflow-history-exfil", "security-audit", "legit-secret-scan"),
]


def test_each_attack_flagged_and_lookalike_clean():
    for rule_id, technique, positive, negative in _PAIRS:
        pos = _report(_pos(technique, positive))
        assert rule_id in {f.id for f in pos.findings}, f"{rule_id} missed its positive"
        assert pos.verdict.get("has_malicious_indicators") is True, technique

        neg = _report(_neg(technique, negative))
        neg_ids = {f.id for f in neg.findings}
        assert rule_id not in neg_ids, f"{rule_id} fired on its look-alike {negative}"
        assert neg.verdict.get("has_malicious_indicators") is not True, negative
        assert neg.risk_level.value not in ("high", "critical"), negative


def test_cred_helper_prints_fixed_key_stays_clean():
    # A helper that just echoes an env var is lower risk and must not be a malicious indicator.
    clean = _neg("agent-cred-helper-exec", "static-key-helper")
    assert "ST-AGENT-CRED-HELPER-EXEC" not in _ids(clean)


def test_stdlib_shadow_requires_import_time_execution():
    # Same filename, functions only, no import-time side effect -> clean.
    assert "ST-PY-STDLIB-SHADOW" not in _ids(_neg("stdlib-shadow", "local-struct-helper"))


def test_workflow_history_exfil_scores_despite_ci_demotion():
    # The malicious workflow runs on the scanned repo's own CI; its finding must keep its CI
    # evidence and still score (engine._CI_SCORED_RULES).
    report = _report(_pos("workflow-history-exfil", "security-audit"))
    assert "ST-WORKFLOW-HISTORY-EXFIL" in {f.id for f in report.findings}
    assert report.risk_level.value in ("high", "critical")


def test_new_findings_carry_evidence():
    for _rule_id, technique, positive, _negative in _PAIRS:
        report = _report(_pos(technique, positive))
        for f in report.findings:
            assert f.evidence, f"{f.id} has no evidence"
            for ev in f.evidence:
                assert ev.snippet
