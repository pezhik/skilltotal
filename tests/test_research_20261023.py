"""Research 2026-10-23: five detection gaps from AI-tooling attack campaigns of the prior ~45 days.

Each gap pairs a sanitized malicious shape with an honest look-alike that must stay clean. Hosts
are ``.invalid`` / ``.test``, payloads are inert (decode to ``print(1)`` / ``echo``), secrets are
obviously fake, and nothing is executed.

- ``ST-STARTUP-HOOK-EXEC`` -- a ``sitecustomize.py`` startup hook that forks + exfiltrates an AI
  key (litellm PyPI compromise, Oct 2026). Look-alike: a sitecustomize that sets ``sys.path``.
- ``ST-OBF-DECODE-SPAWN`` -- a loader that gunzips an embedded blob and runs it through a spawned
  interpreter (subql npm compromise's import-time detached worker). Look-alike: a worker pool that
  spawns a bundled script by path.
- ``ST-PROMPT-SPLIT-EXFIL`` -- a skill that reads credentials, posts them, and conceals the upload
  across separate steps. Look-alike: a skill that syncs a project file to a dashboard.
- ``ST-MCP-OAUTH-ENDPOINT-INJECTION`` -- an OAuth discovery document with a shell command in an
  endpoint URL. Look-alike: a discovery document with ordinary URLs.
- ``ST-MCP-SAMPLING-SYSPROMPT`` -- an MCP sampling request whose systemPrompt overrides the client
  model's. Look-alike: a task-scoping systemPrompt.
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


def _sample(polarity_class: str, technique: str, variant: str) -> Path:
    return _CORPUS / polarity_class / technique / variant


# --- ST-STARTUP-HOOK-EXEC ------------------------------------------------------------------

def test_startup_hook_fork_net_flagged():
    root = _sample("positive/AST02", "startup-hook-exec", "sitecustomize-fork-net")
    report = _report(root)
    assert "ST-STARTUP-HOOK-EXEC" in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is True


def test_ordinary_sitecustomize_not_flagged():
    root = _sample("negative/AST02", "startup-hook-exec", "sitecustomize-setpath")
    report = _report(root)
    assert "ST-STARTUP-HOOK-EXEC" not in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is not True
    assert report.risk_level.value not in ("high", "critical")


# --- ST-OBF-DECODE-SPAWN -------------------------------------------------------------------

def test_decode_spawn_detached_worker_flagged():
    root = _sample("positive/AST02", "decode-spawn", "gunzip-detached-worker")
    report = _report(root)
    assert "ST-OBF-DECODE-SPAWN" in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is True


def test_spawn_worker_file_not_flagged():
    root = _sample("negative/AST02", "decode-spawn", "spawn-worker-file")
    report = _report(root)
    assert "ST-OBF-DECODE-SPAWN" not in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is not True
    assert report.risk_level.value not in ("high", "critical")


# --- ST-PROMPT-SPLIT-EXFIL -----------------------------------------------------------------

def test_split_objective_exfil_flagged():
    root = _sample("positive/AST01", "prompt-split-exfil", "repo-health-chain")
    report = _report(root)
    assert "ST-PROMPT-SPLIT-EXFIL" in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is True


def test_dashboard_sync_not_flagged():
    root = _sample("negative/AST01", "prompt-split-exfil", "dashboard-sync")
    report = _report(root)
    assert "ST-PROMPT-SPLIT-EXFIL" not in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is not True
    assert report.risk_level.value not in ("high", "critical")


# --- ST-MCP-OAUTH-ENDPOINT-INJECTION -------------------------------------------------------

def test_oauth_endpoint_injection_flagged():
    root = _sample("positive/AST04", "mcp-oauth-endpoint-injection", "authz-command-sub")
    report = _report(root)
    assert "ST-MCP-OAUTH-ENDPOINT-INJECTION" in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is True


def test_clean_discovery_not_flagged():
    root = _sample("negative/AST04", "mcp-oauth-endpoint-injection", "clean-discovery")
    report = _report(root)
    assert "ST-MCP-OAUTH-ENDPOINT-INJECTION" not in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is not True
    assert report.risk_level.value not in ("high", "critical")


# --- ST-MCP-SAMPLING-SYSPROMPT -------------------------------------------------------------

def test_sampling_sysprompt_override_flagged():
    root = _sample("positive/AST01", "mcp-sampling-sysprompt", "override-ts")
    report = _report(root)
    assert "ST-MCP-SAMPLING-SYSPROMPT" in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is True


def test_task_scoped_sysprompt_not_flagged():
    root = _sample("negative/AST01", "mcp-sampling-sysprompt", "task-scoped-ts")
    report = _report(root)
    assert "ST-MCP-SAMPLING-SYSPROMPT" not in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is not True
    assert report.risk_level.value not in ("high", "critical")


# --- every new finding carries evidence (engine invariant) ---------------------------------

def test_new_findings_carry_evidence():
    for pc, tech, variant in (
        ("positive/AST02", "startup-hook-exec", "sitecustomize-fork-net"),
        ("positive/AST02", "decode-spawn", "gunzip-detached-worker"),
        ("positive/AST01", "prompt-split-exfil", "repo-health-chain"),
        ("positive/AST04", "mcp-oauth-endpoint-injection", "authz-command-sub"),
        ("positive/AST01", "mcp-sampling-sysprompt", "override-ts"),
    ):
        report = _report(_sample(pc, tech, variant))
        for f in report.findings:
            assert f.evidence, f"{f.id} has no evidence"
            for ev in f.evidence:
                assert ev.snippet
