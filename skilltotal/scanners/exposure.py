"""Network-exposure posture: a component that listens on all interfaces or runs a debug
server. Not malware — a ``risky_construct`` that widens the attack surface (often combined
with missing auth), e.g. an MCP/agent server bound to 0.0.0.0 or a Flask app with debug=True.
"""

from __future__ import annotations

import re

from skilltotal.models import Severity, ThreatClass
from skilltotal.scanners.base import PatternScanner, RuleSpec, alternation

CODE_SUFFIXES = (".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

CATEGORY = "network_exposure"


class ExposureScanner(PatternScanner):
    name = "exposure"
    rules = [
        RuleSpec(
            id="ST-EXPOSE-BIND",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            title="Server bound to all network interfaces",
            description=(
                "The component binds a server to 0.0.0.0 / :: (all interfaces), exposing it "
                "beyond localhost. Without authentication this lets other hosts reach the "
                "server (a common MCP/agent exposure and DNS-rebinding surface)."
            ),
            recommendation=(
                "Bind to 127.0.0.1 for local-only use, or require authentication and "
                "restrict access if remote exposure is intended."
            ),
            capability=None,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            suffixes=CODE_SUFFIXES,
            pattern=alternation(
                # A quoted 0.0.0.0 literal in code is, in practice, always a bind address
                # (host=, ("0.0.0.0", port), listen(port, "0.0.0.0"), sock.bind(...)).
                r"""['"]0\.0\.0\.0['"]""",
                r"""--host[=\s]+0\.0\.0\.0""",                   # CLI launcher form
                r"""['"]::['"]\s*,\s*\d""",                      # IPv6 all-interfaces, (host, port)
                flags=re.IGNORECASE,
            ),
        ),
        RuleSpec(
            id="ST-EXPOSE-DEBUG",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            title="Debug server enabled",
            description=(
                "A web framework debug mode was detected (e.g. Flask debug=True). Debug "
                "servers expose interactive consoles / stack traces and must never run in "
                "an exposed or production setting."
            ),
            recommendation=(
                "Disable debug mode for anything reachable beyond local development; it can "
                "allow remote code execution via the debugger."
            ),
            capability=None,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            suffixes=CODE_SUFFIXES,
            pattern=alternation(
                r"\.run\([^)]*\bdebug\s*=\s*True",          # Flask app.run(debug=True)
                r"app\.debug\s*=\s*True",
                flags=re.IGNORECASE,
            ),
        ),
    ]
