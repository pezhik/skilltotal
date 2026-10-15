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

from skilltotal.file_index import FileIndex, component_files
from skilltotal.models import Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
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
        # The same link-free walk as the index (build output included, as it always was): an
        # archive behind a symlink or a junction may lie outside the component.
        for path in sorted(component_files(index.root, skip_build_output=False)):
            if path.suffix.lower() not in _ZIP_SUFFIXES:
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
                if len(evidence) >= MAX_EVIDENCE_SCANNED:
                    break
        if evidence:
            return ScanResult(findings=[_finding_from_rule(self.rules[0], evidence)])
        return ScanResult()


# Reading a ZIP's directory loads one entry object per member, so a crafted archive with millions
# of entries in a small file could take gigabytes (security review, 2026-10-15). Past these, the
# archive is not opened; any other failure to read one counts as "not a readable ZIP".
_MAX_ZIP_BYTES = 64 * 1024 * 1024
_MAX_ZIP_DIRECTORY_BYTES = 8 * 1024 * 1024


def _encrypted_entry_count(path: Path) -> int:
    """Number of encrypted entries in a ZIP (GP-flag bit 0), or 0 if not a/readable ZIP."""
    try:
        if path.stat().st_size > _MAX_ZIP_BYTES or _directory_size(path) > _MAX_ZIP_DIRECTORY_BYTES:
            return 0
        with zipfile.ZipFile(path) as zf:
            return sum(1 for info in zf.infolist() if info.flag_bits & 0x1)
    except Exception:  # noqa: BLE001 - a crafted archive must not stop the scan
        return 0


def _directory_size(path: Path) -> int:
    """The size of the central directory the ZIP's end record declares (0 when there is none)."""
    with path.open("rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - 65_557))  # the end record and the longest comment it may carry
        tail = fh.read()
    at = tail.rfind(b"PK\x05\x06")
    if at < 0 or len(tail) < at + 22:
        return 0
    return int.from_bytes(tail[at + 12:at + 16], "little")
