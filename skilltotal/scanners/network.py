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
                "Node.js HTTP/network/email client usage was detected "
                "(fetch / axios / http.request / https.request / nodemailer / SendGrid / SES / "
                "DNS lookups)."
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
                # The module itself, so `const h = require("https"); h.request(…)` counts too.
                r"require\(\s*['\"](?:node:)?https?['\"]\s*\)",
                r"from\s+['\"](?:node:)?https?['\"]",
                # E-mail is an egress channel too (e.g. the Postmark MCP BCC-exfil backdoor).
                r"\bnodemailer\b",
                r"\.sendMail\s*\(",
                r"@sendgrid/mail",
                r"\bSendEmailCommand\b",
                r"\bmailgun\b",
                # DNS lookups are an egress channel: a crafted hostname leaks data to an
                # attacker-controlled zone (DNS tunnelling), dodging HTTP-based detection.
                # Quantifiers are bounded (no nested repetition) so the pattern is ReDoS-safe.
                r"\bdns\.(?:resolve\w*|lookup)\s*\(",
                r"\bdns\.promises\.(?:resolve\w*|lookup)\s*\(",
                r"\bdnsPromises\.(?:resolve\w*|lookup)\s*\(",
                # The dns module however it is bound (`const d = require("dns")`, a destructured or
                # dynamic import, dns/promises), not only a variable named `dns`.
                r"require\(\s*['\"](?:node:)?dns(?:/promises)?['\"]\s*\)",
                r"from\s+['\"](?:node:)?dns(?:/promises)?['\"]",
                r"\bimport\(\s*['\"](?:node:)?dns(?:/promises)?['\"]\s*\)",
                flags=re.MULTILINE,
            ),
        ),
    ]
