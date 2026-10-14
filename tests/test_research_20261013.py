"""Research 2026-10-13: two detection gaps from AI-tooling attack campaigns of the prior ~45 days.

Gap A -- supply-chain worms (Socket/Sonatype 2026-10-08) re-infect every
project a victim opens by WRITING an auto-executing agent/editor config into it: a VS Code task
gated on ``folderOpen`` or an agent-settings ``hooks`` block. Those files shipped as component
*content* were already covered (autorun.py); package *code* that writes them at install/import was
not. ``ST-AGENT-CONFIG-PERSIST`` closes that, gated on the auto-execution marker so a generator
writing a manually-invoked build task stays clean.

Gap B -- a "hostage token" monitor ran a downloaded next stage through
Invoke-Expression. ``ST-SHELL-EVASION`` caught only the one-line ``IEX (New-Object
Net.WebClient).DownloadString(...)`` idiom, as a risky construct. ``ST-PS-DOWNLOAD-EXEC`` is the
malicious-indicator reading of the whole cradle family: it adds ``Invoke-RestMethod`` / ``irm``
(and curl/wget aliases), the piped order, and the two-statement form where the download lands in a
variable that Invoke-Expression runs later.

Each attack is paired with an honest look-alike that must stay clean. Sanitized fixtures only:
hosts are ``.invalid``, commands are inert, nothing is executed.
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


def _positive(polarity_class: str, technique: str, variant: str) -> Path:
    return _CORPUS / polarity_class / technique / variant


# --- Gap A: ST-AGENT-CONFIG-PERSIST --------------------------------------------------------

def test_vscode_folderopen_write_flagged():
    root = _positive("positive/AST01", "agent-config-persist", "vscode-folderopen")
    report = _report(root)
    assert "ST-AGENT-CONFIG-PERSIST" in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is True


def test_claude_sessionstart_write_flagged():
    root = _positive("positive/AST01", "agent-config-persist", "claude-sessionstart")
    assert "ST-AGENT-CONFIG-PERSIST" in _ids(root)


def test_scaffold_build_task_not_flagged():
    # A generator writing a manually-invoked build task (no folderOpen, no hooks) stays clean.
    root = _positive("negative/AST01", "agent-config-persist", "scaffold-build-task")
    report = _report(root)
    assert "ST-AGENT-CONFIG-PERSIST" not in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is not True
    assert report.risk_level.value not in ("high", "critical")


# --- Gap B: ST-PS-DOWNLOAD-EXEC ------------------------------------------------------------

def test_ps_download_exec_variable_flagged():
    root = _positive("positive/AST01", "powershell-download-exec", "irm-variable")
    report = _report(root)
    assert "ST-PS-DOWNLOAD-EXEC" in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is True


def test_ps_download_exec_piped_flagged():
    root = _positive("positive/AST01", "powershell-download-exec", "iex-pipe")
    assert "ST-PS-DOWNLOAD-EXEC" in _ids(root)


def test_ps_local_iex_and_plain_fetch_not_flagged():
    root = _positive("negative/AST01", "powershell-download-exec", "local-iex-and-plain-fetch")
    report = _report(root)
    assert "ST-PS-DOWNLOAD-EXEC" not in {f.id for f in report.findings}
    assert report.verdict.get("has_malicious_indicators") is not True
    assert report.risk_level.value not in ("high", "critical")


# --- every finding carries evidence (engine invariant) -------------------------------------

def test_new_findings_carry_evidence():
    for pc, tech, variant in (
        ("positive/AST01", "agent-config-persist", "vscode-folderopen"),
        ("positive/AST01", "agent-config-persist", "claude-sessionstart"),
        ("positive/AST01", "powershell-download-exec", "irm-variable"),
        ("positive/AST01", "powershell-download-exec", "iex-pipe"),
    ):
        report = _report(_positive(pc, tech, variant))
        for f in report.findings:
            assert f.evidence, f"{f.id} has no evidence"
            for ev in f.evidence:
                assert ev.snippet
