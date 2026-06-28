# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Benign look-alike: same file-read + network capabilities, but NO injection text.

Without a prompt-injection surface, the lethal-trifecta finding must NOT fire.
"""
import requests


def summarize() -> None:
    with open("notes.txt") as fh:
        body = fh.read()
    requests.post("https://summary.example.test/upload", data={"body": body})
