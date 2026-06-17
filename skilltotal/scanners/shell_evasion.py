"""Defense-evasion OS-command idioms.

Beyond plain shell execution, real droppers use a small set of unmistakable evasion idioms:
PowerShell execution-policy bypass / encoded commands / hidden windows, macOS code-signing
bypass, and launching a payload detached from a world-writable temp dir. These are rarely benign;
flagged as a risky construct (not a malware verdict on their own — convergence elevates when they
co-occur with other malicious indicators).
"""

from __future__ import annotations

import re

from skilltotal.models import Severity, ThreatClass
from skilltotal.scanners.base import PatternScanner, RuleSpec, alternation

# Where these idioms appear: shell, PowerShell, batch, and source that shells out.
_EVASION_SUFFIXES = (
    ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".pyw",
)

R_SHELL_EVASION = "ST-SHELL-EVASION"


class ShellEvasionScanner(PatternScanner):
    name = "shell_evasion"
    rules = [
        RuleSpec(
            id=R_SHELL_EVASION,
            category="defense_evasion",
            severity=Severity.HIGH,
            title="Defense-evasion command idiom",
            description=(
                "A command uses a known defense-evasion idiom: PowerShell execution-policy "
                "bypass / encoded command / hidden window, macOS code-signing bypass, or "
                "launching a payload from a world-writable temp directory. These are hallmarks "
                "of droppers and rarely appear in legitimate code."
            ),
            recommendation=(
                "Verify why the component bypasses execution policy / code signing or runs from a "
                "temp directory; these patterns are characteristic of malware staging."
            ),
            capability=None,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            suffixes=_EVASION_SUFFIXES,
            # A behaviour detector matches its own pattern literals in .py source; demote those.
            code_context="strings_and_comments",
            pattern=alternation(
                r"(?:-ep|-executionpolicy)\s+bypass",
                r"-encodedcommand\b",
                r"(?:powershell|pwsh)\b[^\n]{0,80}-enc\b",
                r"-windowstyle\s+hidden\b",
                r"codesign\b[^\n]*--force[^\n]*--deep",
                r"\bnohup\b[^\n]*\s/tmp/\S",
                r"\bchmod\s+\+x\b[^\n]*(?:/tmp/|/dev/shm/)",
                r"(?:iex|invoke-expression)\b[^\n]*"
                r"(?:downloadstring|invoke-webrequest|\biwr\b|net\.webclient)",
                flags=re.IGNORECASE,
            ),
        ),
    ]
