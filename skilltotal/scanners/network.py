"""Network egress detection for Node.js.

Python network egress is handled by the AST scanner
(:mod:`skilltotal.scanners.python_ast`).
"""

from __future__ import annotations

import re

from skilltotal.models import Capability, Severity
from skilltotal.scanners.base import PatternScanner, RuleSpec, alternation

NODE_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

CATEGORY = "network_egress"


class NetworkScanner(PatternScanner):
    name = "network"
    rules = [
        RuleSpec(
            id="ST-NET-NODE",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            title="Node.js network egress",
            description=(
                "Node.js HTTP/network client usage was detected "
                "(fetch / axios / http.request / https.request)."
            ),
            recommendation=(
                "Confirm the destination hosts are expected and that no sensitive data "
                "is sent off-host."
            ),
            capability=Capability.NETWORK_EGRESS,
            suffixes=NODE_SUFFIXES,
            pattern=alternation(
                r"\bfetch\s*\(",
                r"\baxios\b",
                r"\bhttps?\.request\s*\(",
                r"\bhttps?\.get\s*\(",
                r"require\(\s*['\"]node:?https?['\"]\s*\)",
                r"from\s+['\"]node:?https?['\"]",
                flags=re.MULTILINE,
            ),
        ),
    ]
