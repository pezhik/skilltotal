"""Auto-executing ``.pth`` file detection.

Python runs any line in a ``site-packages/*.pth`` file that starts with ``import`` at every
interpreter startup — a stealthy persistence/auto-exec vector used by real supply-chain malware
(payload runs with no import of the package, and even on ``pip``/``python -c``). Legitimate
``.pth`` files contain only paths or namespace/editable-install plumbing (``import sys``,
``__import__('importlib…')``, a finder ``.install()``) — they never decode, exec, spawn, or reach
the network. So a ``.pth`` carrying any of those code-execution / obfuscation tokens is a
high-confidence malicious indicator.
"""

from __future__ import annotations

from skilltotal.models import Capability, Severity, ThreatClass
from skilltotal.scanners.base import PatternScanner, RuleSpec, alternation

R_PTH_EXEC = "ST-PTH-EXEC"


class PthExecScanner(PatternScanner):
    name = "pth_exec"
    rules = [
        RuleSpec(
            id=R_PTH_EXEC,
            category="obfuscation",
            severity=Severity.HIGH,
            title="Auto-executing .pth file (startup persistence)",
            description=(
                "A .pth file contains code-execution / obfuscation primitives (exec, eval, "
                "base64, subprocess, os.system, marshal/pickle, or a network client). Python "
                "executes .pth 'import' lines at every interpreter startup, so this runs "
                "automatically and unreviewed — a known supply-chain persistence vector."
            ),
            recommendation=(
                "A legitimate .pth file lists import paths only. Treat decode/exec/network code "
                "in a .pth as malicious; remove the package and rotate any exposed secrets."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            suffixes=(".pth",),
            pattern=alternation(
                r"\bexec\s*\(",
                r"\beval\s*\(",
                r"\bcompile\s*\(",
                r"\bbase64\b",
                r"\bb64decode\b",
                r"\bbytes\.fromhex\b",
                r"\bcodecs\.decode\b",
                r"\bsubprocess\b",
                r"\bos\.system\b",
                r"\bos\.popen\b",
                r"\bmarshal\b",
                r"\bpickle\b",
                r"\bsocket\b",
                r"\burllib\.request\b",
                r"\brequests\.",
            ),
        ),
    ]
