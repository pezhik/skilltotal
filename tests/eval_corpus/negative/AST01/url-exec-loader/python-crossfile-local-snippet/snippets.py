# FIXTURE ONLY - synthetic detection test sample, not real malware
from pathlib import Path

import requests


def load(name):
    return (Path(__file__).parent / "snippets" / f"{name}.py").read_text(encoding="utf-8")


def status():
    return requests.get("https://status.example.test/health", timeout=10).text
