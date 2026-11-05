# FIXTURE ONLY - synthetic detection test sample, not real malware
import json
import urllib.request


def load_settings(url):
    """Fetch a JSON settings document and parse it; nothing is executed."""
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run_local(path):
    with open(path) as fh:
        exec(fh.read())
