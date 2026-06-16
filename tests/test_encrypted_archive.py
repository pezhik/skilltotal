"""Encrypted-archive evasion signal (ST-ENCRYPTED-ARCHIVE)."""

from __future__ import annotations

import zipfile
from pathlib import Path

from skilltotal.file_index import FileIndex
from skilltotal.models import ThreatClass
from skilltotal.scanners.encrypted_archive import EncryptedArchiveScanner


def _make_zip(path: Path, *, encrypted: bool) -> None:
    """Write a tiny ZIP; if ``encrypted``, set the GP encryption flag bit in the headers.

    zipfile can't *write* real encryption, so we craft a clean ZIP then flip bit 0 of the
    general-purpose flag in every local-file (PK\\x03\\x04, +6) and central-dir (PK\\x01\\x02, +8)
    header — which is exactly what the scanner reads (``flag_bits & 0x1``).
    """
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("secret.bin", b"payload-bytes")
    if not encrypted:
        return
    data = bytearray(path.read_bytes())
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        pos = 0
        while (j := data.find(sig, pos)) >= 0:
            data[j + off] |= 0x1
            pos = j + 4
    path.write_bytes(bytes(data))


def _scan(tmp_path: Path):
    result = EncryptedArchiveScanner().scan(FileIndex.build(tmp_path))
    return {f.id for f in result.findings}


def test_encrypted_zip_is_flagged(tmp_path: Path):
    _make_zip(tmp_path / "payload.zip", encrypted=True)
    result = EncryptedArchiveScanner().scan(FileIndex.build(tmp_path))
    ids = {f.id for f in result.findings}
    assert "ST-ENCRYPTED-ARCHIVE" in ids
    f = next(f for f in result.findings if f.id == "ST-ENCRYPTED-ARCHIVE")
    assert f.threat_class == ThreatClass.RISKY_CONSTRUCT
    assert "payload.zip" in f.evidence[0].snippet


def test_plain_zip_is_not_flagged(tmp_path: Path):
    _make_zip(tmp_path / "assets.zip", encrypted=False)
    assert "ST-ENCRYPTED-ARCHIVE" not in _scan(tmp_path)


def test_no_archive_no_finding(tmp_path: Path):
    (tmp_path / "readme.txt").write_text("hello", encoding="utf-8")
    assert _scan(tmp_path) == set()
