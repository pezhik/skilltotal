"""Encrypted-archive evasion signal.

A password-protected ZIP bundled inside a component is a scanning-evasion indicator: the
contents cannot be statically reviewed, and malware uses it to smuggle a payload past
automated analysis. Encrypted archives are binary, so the text index skips them — this scanner
inspects archive files directly from the component root.

Conservative by design: only ZIP entries with the encryption GP-flag bit set are flagged, as a
``risky_construct`` (not a malware verdict — legitimate encrypted assets exist), so it raises
risk for review without tripping the benign false-positive gate.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from skilltotal.file_index import SKIP_DIRS, FileIndex
from skilltotal.models import Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_PER_FINDING,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
)

R_ENCRYPTED_ARCHIVE = "ST-ENCRYPTED-ARCHIVE"
_ZIP_SUFFIXES = frozenset({".zip"})


class EncryptedArchiveScanner(Scanner):
    name = "encrypted_archive"
    rules = [
        RuleSpec(
            id=R_ENCRYPTED_ARCHIVE,
            category="obfuscation",
            severity=Severity.MEDIUM,
            title="Password-protected archive (analysis evasion)",
            description=(
                "A component bundles a password-protected / encrypted ZIP whose contents cannot "
                "be statically reviewed. Encrypted archives are a known technique for smuggling a "
                "payload past automated scanning."
            ),
            recommendation=(
                "Verify why the component ships an encrypted archive; unpack and review its "
                "contents, or remove it if it is not needed."
            ),
            capability=None,  # an evasion signal, not a capability the component exercises
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        for path in sorted(index.root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in _ZIP_SUFFIXES:
                continue
            rel_parts = path.relative_to(index.root).parts
            if any(part in SKIP_DIRS for part in rel_parts):
                continue
            count = _encrypted_entry_count(path)
            if count:
                rel = path.relative_to(index.root).as_posix()
                evidence.append(
                    Evidence(
                        file=rel,
                        line_start=1,
                        line_end=1,
                        snippet=f"<password-protected archive: {rel} ({count} encrypted entr"
                        f"{'y' if count == 1 else 'ies'})>",
                    )
                )
                if len(evidence) >= MAX_EVIDENCE_PER_FINDING:
                    break
        if evidence:
            return ScanResult(findings=[_finding_from_rule(self.rules[0], evidence)])
        return ScanResult()


def _encrypted_entry_count(path: Path) -> int:
    """Number of encrypted entries in a ZIP (GP-flag bit 0), or 0 if not a/readable ZIP."""
    try:
        with zipfile.ZipFile(path) as zf:
            return sum(1 for info in zf.infolist() if info.flag_bits & 0x1)
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return 0
