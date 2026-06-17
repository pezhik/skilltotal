"""Hardcoded BCC/CC exfiltration recipient in email-sending code.

A backdoor can siphon mail by injecting a constant attacker address into the BCC/CC of every
outgoing message (the Postmark MCP compromise did exactly this) — with no credential read, so the
sensitive-data + egress combo does not fire. This scanner flags a ``bcc``/``cc`` field set to a
**hardcoded string-literal email address** in a file that actually sends email. Legitimate code
rarely hardcodes a constant BCC (it's usually dynamic/config), so this is high-signal; emitted as a
risky_construct (not a malware verdict) and scoped to email-sending files to keep it low-FP.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_PER_FINDING,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
)

R_EMAIL_BCC_EXFIL = "ST-EMAIL-BCC-EXFIL"

_CODE_SUFFIXES = (".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
# The file must actually send email for a hardcoded bcc/cc to be an exfiltration signal.
_EMAIL_SEND = re.compile(
    r"\bsmtplib\b|\.send(?:mail|_message|Mail)\s*\(|\bnodemailer\b|@sendgrid/mail|"
    r"\bSendEmailCommand\b|\bmailgun\b",
    re.IGNORECASE,
)
# A bcc/cc field assigned a hardcoded literal email address (a variable/config value won't match).
_BCC_LITERAL = re.compile(
    r"""\bb?cc\b["']?\s*[:=]\s*["'][^"'@\s]+@[^"'\s]+["']""",
    re.IGNORECASE,
)


class EmailExfilScanner(Scanner):
    name = "email_exfil"
    rules = [
        RuleSpec(
            id=R_EMAIL_BCC_EXFIL,
            category="exfiltration_path",
            severity=Severity.MEDIUM,
            title="Hardcoded BCC/CC recipient in email-sending code",
            description=(
                "Email-sending code assigns a hardcoded string-literal address to a bcc/cc field. "
                "A constant BCC silently copies outgoing mail to a fixed recipient — the email "
                "exfiltration pattern used by mail backdoors."
            ),
            recommendation=(
                "Confirm the hardcoded BCC/CC recipient is intended; a constant address that "
                "copies all outgoing mail off to a third party is an exfiltration backdoor."
            ),
            capability=None,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        for f in index.select(suffixes=_CODE_SUFFIXES):
            if not _EMAIL_SEND.search(f.text):
                continue
            for m in _BCC_LITERAL.finditer(f.text):
                evidence.append(f.evidence_for_span(m.start(), m.end()))
                if len(evidence) >= MAX_EVIDENCE_PER_FINDING:
                    break
            if len(evidence) >= MAX_EVIDENCE_PER_FINDING:
                break
        if evidence:
            return ScanResult(findings=[_finding_from_rule(self.rules[0], evidence)])
        return ScanResult()
