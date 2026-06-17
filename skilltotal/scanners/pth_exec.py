"""Auto-executing ``.pth`` file detection.

Python runs any line in a ``site-packages/*.pth`` file that starts with ``import`` at every
interpreter startup — a stealthy persistence/auto-exec vector used by real supply-chain malware
(payload runs with no import of the package, and even on ``pip``/``python -c``).

We flag a ``.pth`` that **decodes, deserializes, spawns a process, or reaches the network** —
the signature of a malicious payload (e.g. ``exec(base64.b64decode(...))``). A bare ``exec`` of
readable inline code is intentionally NOT enough: a few legitimate tools do that in their ``.pth``
(notably coverage.py's subprocess-measurement bootstrap, ``exec('… process_startup() …')``), so
keying on the decode/spawn/network tokens keeps this false-positive-free while still catching
the real droppers. Ordinary ``.pth`` files (paths, namespace/editable-install plumbing) never carry
any of these tokens.
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
                "A .pth file decodes, deserializes, spawns a process, or reaches the network "
                "(base64/hex/codecs decode, marshal/pickle, subprocess/os.system, or a network "
                "client) — a malicious-payload signature. Python executes .pth 'import' lines at "
                "every interpreter startup, so this runs automatically and unreviewed (a known "
                "supply-chain persistence vector)."
            ),
            recommendation=(
                "A legitimate .pth file lists import paths only. Treat decode/spawn/network code "
                "in a .pth as malicious; remove the package and rotate any exposed secrets."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            suffixes=(".pth",),
            # NOTE: a bare exec/eval is deliberately NOT flagged — coverage.py's subprocess
            # bootstrap legitimately does `exec('… coverage.process_startup() …')`. We require a
            # decode / deserialize / spawn / network token, which real droppers carry and legit
            # .pth files never do.
            pattern=alternation(
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
